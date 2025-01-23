#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{fentry, lsm, map},
    maps::{Array, PerCpuArray, PerfEventArray},
    programs::{FEntryContext, LsmContext},
    EbpfContext,
};
use aya_log_ebpf::info;

#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[rustfmt::skip]
mod vmlinux;

use ayaya_common::{Event, EventVariant, FilenameBuf, FilterPath, PathBuf, PATH_BUF_MAX};

// The main pipeline to send data to the userland program
#[map]
pub static PIPELINE: PerfEventArray<Event> = PerfEventArray::new(0);

#[map]
pub(crate) static FILTER_PATH: Array<FilterPath> = Array::with_max_entries(1, 0);

#[map]
pub(crate) static BUFFER: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

// LSM_HOOK(int, 0, file_open, struct file *file)
#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };
    let path = unsafe { &((*file).f_path) as *const _ };

    match event_from_path(&ctx, path, EventVariant::Open) {
        Ok(event) => {
            let path = path_buf_as_str(&event.primary_path);
            info!(&ctx, "lsm/file_open called for a file in {}", path);
            0
        }
        // TODO: maybe set it 0 even on fails since this is a tracing program.
        Err(ret) => {
            if ret != -4095 {
                info!(&ctx, "lsm/file_open failed");
            }
            0
        }
    }
}

// LSM_HOOK(int, 0, path_unlink, const struct path *dir, struct dentry *dentry)
#[lsm(hook = "path_unlink")]
pub fn path_unlink(ctx: LsmContext) -> i32 {
    match split_path_lsm(&ctx, EventVariant::Unlink) {
        Ok(event) => {
            let path = path_buf_as_str(&event.primary_path);
            info!(&ctx, "lsm/path_unlink called for a file in {}", path);
            0
        }
        Err(ret) => {
            if ret != -4095 {
                info!(&ctx, "lsm/path_unlink failed ");
            }
            0
        }
    }
}

// LSM_HOOK(int, 0, path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode)
#[lsm(hook = "path_mkdir")]
pub fn path_mkdir(ctx: LsmContext) -> i32 {
    match split_path_lsm(&ctx, EventVariant::Mkdir) {
        Ok(event) => {
            let path = path_buf_as_str(&event.primary_path);
            info!(&ctx, "lsm/path_mkdir called for a file in {}", path);
            0
        }
        Err(ret) => {
            if ret != -4095 {
                info!(&ctx, "lsm/path_mkdir failed");
            }
            0
        }
    }
}

// LSM_HOOK(int, 0, path_truncate, const struct path *path)
#[lsm(hook = "path_truncate")]
pub fn path_truncate(ctx: LsmContext) -> i32 {
    let path: *const vmlinux::path = unsafe { ctx.arg(0) };
    match event_from_path(&ctx, path, EventVariant::Truncate) {
        Ok(event) => {
            let path = path_buf_as_str(&event.primary_path);
            info!(&ctx, "lsm/path_truncate called for a file {}", path);
            0
        }
        Err(ret) => {
            if ret != -4095 {
                info!(&ctx, "lsm/path_truncate failed");
            }
            0
        }
    }
}

// LSM_HOOK(int, 0, path_rmdir, const struct path *dir, struct dentry *dentry)
#[lsm(hook = "path_rmdir")]
pub fn path_rmdir(ctx: LsmContext) -> i32 {
    match split_path_lsm(&ctx, EventVariant::Rmdir) {
        Ok(event) => {
            let path = path_buf_as_str(&event.primary_path);
            info!(&ctx, "lsm/path_rmdir called for a file in {}", path);
            0
        }
        Err(ret) => {
            if ret != -4095 {
                info!(&ctx, "lsm/path_rmdir failed");
            }
            0
        }
    }
}
// LSM_HOOK(int, 0, path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name)
#[lsm(hook = "path_symlink")]
pub fn path_symlink(ctx: LsmContext) -> i32 {
    match try_path_symlink(&ctx) {
        Ok(event) => {
            let path = path_buf_as_str(&event.primary_path);
            info!(&ctx, "lsm/path_symlink called for a file in {}", path);
            0
        }
        // TODO: maybe set it 0 even on fails since this is a tracing program.
        Err(ret) => {
            if ret != -4095 {
                info!(&ctx, "lsm/path_symlink failed");
            }
            0
        }
    }
}

fn try_path_symlink(ctx: &LsmContext) -> Result<&'static mut Event, i32> {
    let event = get_event(&BUFFER)?;

    let primary_path: *const vmlinux::path = unsafe { ctx.arg(0) };
    let primary_dentry: *const vmlinux::dentry = unsafe { ctx.arg(1) };

    bpf_d_path(primary_path, &mut event.primary_path)?;
    dentry_name_to_buf(primary_dentry, &mut event.primary_path.filename)?;

    {
        let old_path: *const u8 = unsafe { ctx.arg(2) };
        let written = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(
                old_path,
                &mut event.secondary_path.buf,
            )
            .map_err(|_| 0)?
        };

        event.secondary_path.len = written.len();
    }

    if !matches_filtered_path_no_trailing(&event.primary_path)
        && !matches_filtered_path(&event.primary_path)
    {
        return Err(-4095);
    }

    event.variant = EventVariant::Symlink;
    fill_event(event, ctx);

    PIPELINE.output(ctx, event, 0);
    return Ok(event);
}

// path_link does provide the old d_entry but since we don't like traversing the dentry tree
// we will be ignoring it.
// LSM_HOOK(int, 0, path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry)
#[lsm(hook = "path_link")]
pub fn path_link(ctx: LsmContext) -> i32 {
    match try_path_link(&ctx) {
        Ok(event) => {
            let path = path_buf_as_str(&event.primary_path);
            info!(&ctx, "lsm/path_link called for a file in {}", path);
            0
        }
        // TODO: maybe set it 0 even on fails since this is a tracing program.
        Err(ret) => {
            if ret != -4095 {
                info!(&ctx, "lsm/path_link failed");
            }
            0
        }
    }
}

fn try_path_link(ctx: &LsmContext) -> Result<&'static mut Event, i32> {
    let event = get_event(&BUFFER)?;

    let primary_path: *const vmlinux::path = unsafe { ctx.arg(1) };
    let primary_dentry: *const vmlinux::dentry = unsafe { ctx.arg(2) };

    bpf_d_path(primary_path, &mut event.primary_path)?;
    dentry_name_to_buf(primary_dentry, &mut event.primary_path.filename)?;

    if !matches_filtered_path_no_trailing(&event.primary_path)
        && !matches_filtered_path(&event.primary_path)
    {
        return Err(-4095);
    }

    event.variant = EventVariant::Link;
    fill_event(event, ctx);

    PIPELINE.output(ctx, event, 0);
    return Ok(event);
}

// LSM_HOOK(int, 0, path_rename, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
#[lsm(hook = "path_rename")]
pub fn path_rename(ctx: LsmContext) -> i32 {
    match try_path_rename(&ctx) {
        Ok(event) => {
            let path = path_buf_as_str(&event.primary_path);
            info!(&ctx, "lsm/path_rename called for a file in {}", path);
            0
        }
        // TODO: maybe set it 0 even on fails since this is a tracing program.
        Err(ret) => {
            if ret != -4095 {
                info!(&ctx, "lsm/path_rename failed");
            }
            0
        }
    }
}

fn try_path_rename(ctx: &LsmContext) -> Result<&'static mut Event, i32> {
    let event = get_event(&BUFFER)?;

    // old path
    let secondary_path: *const vmlinux::path = unsafe { ctx.arg(0) };
    let secondary_dentry: *const vmlinux::dentry = unsafe { ctx.arg(1) };

    bpf_d_path(secondary_path, &mut event.secondary_path)?;
    dentry_name_to_buf(secondary_dentry, &mut event.secondary_path.filename)?;

    // new path
    let primary_path: *const vmlinux::path = unsafe { ctx.arg(2) };
    let primary_dentry: *const vmlinux::dentry = unsafe { ctx.arg(3) };

    bpf_d_path(primary_path, &mut event.primary_path)?;
    dentry_name_to_buf(primary_dentry, &mut event.primary_path.filename)?;

    if !matches_filtered_path_no_trailing(&event.primary_path)
        && !matches_filtered_path(&event.primary_path)
        && !matches_filtered_path_no_trailing(&event.secondary_path)
        && !matches_filtered_path(&event.secondary_path)
    {
        return Err(-4095);
    }

    event.variant = EventVariant::Rename;
    fill_event(event, ctx);

    PIPELINE.output(ctx, event, 0);
    return Ok(event);
}

// LSM_HOOK(int, 0, path_chmod, const struct path *path, umode_t mode)
#[lsm(hook = "path_chmod")]
pub fn path_chmod(ctx: LsmContext) -> i32 {
    let path: *const vmlinux::path = unsafe { ctx.arg(0) };

    match event_from_path(&ctx, path, EventVariant::Chmod) {
        Ok(event) => {
            let path = path_buf_as_str(&event.primary_path);
            info!(&ctx, "lsm/path_chmod called for a file in {}", path);
            0
        }
        // TODO: maybe set it 0 even on fails since this is a tracing program.
        Err(ret) => {
            if ret != -4095 {
                info!(&ctx, "lsm/path_chmod failed");
            }
            0
        }
    }
}

// LSM_HOOK(int, 0, path_chown, const struct path *path, kuid_t uid, kgid_t gid)
#[lsm(hook = "path_chown")]
pub fn path_chown(ctx: LsmContext) -> i32 {
    let path: *const vmlinux::path = unsafe { ctx.arg(0) };

    match event_from_path(&ctx, path, EventVariant::Chown) {
        Ok(event) => {
            let path = path_buf_as_str(&event.primary_path);
            info!(&ctx, "lsm/path_chown called for a file in {}", path);
            0
        }
        // TODO: maybe set it 0 even on fails since this is a tracing program.
        Err(ret) => {
            if ret != -4095 {
                info!(&ctx, "lsm/path_chown failed");
            }
            0
        }
    }
}

// LSM_HOOK(int, 0, bprm_creds_for_exec, struct linux_binprm *bprm)
#[lsm(hook = "bprm_creds_for_exec")]
pub fn bprm_creds_for_exec(ctx: LsmContext) -> i32 {
    let binprm: *const vmlinux::linux_binprm = unsafe { ctx.arg(0) };
    let file = unsafe { (*binprm).file };
    let path = unsafe { &((*file).f_path) as *const _ };

    match event_from_path(&ctx, path, EventVariant::Exec) {
        Ok(event) => {
            let path = path_buf_as_str(&event.primary_path);
            info!(&ctx, "lsm/bprm_creds_for_exec called for a file {}", path);
            0
        }
        // TODO: maybe set it 0 even on fails since this is a tracing program.
        Err(ret) => {
            if ret != -4095 {
                info!(&ctx, "lsm/bprm_creds_for_exec failed");
            }
            0
        }
    }
}

#[fentry(function = "security_file_permission")]
pub fn security_file_permission(ctx: FEntryContext) -> i32 {
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };
    let path = unsafe { &((*file).f_path) as *const _ };

    // information about masks
    // https://github.com/torvalds/linux/blob/ffd294d346d185b70e28b1a28abe367bbfe53c04/security/selinux/hooks.c#L1957-L2005
    let mask: u32 = unsafe { ctx.arg(1) };

    match event_from_path(&ctx, path, EventVariant::ReadOrWrite) {
        Ok(event) => {
            let path = path_buf_as_str(&event.primary_path);
            info!(
                &ctx,
                "fentry/security_file_permission called for a file {}", path
            );
            0
        }
        Err(ret) => {
            if ret != -4095 {
                info!(&ctx, "fentry/security_file_permission failed");
            }
            0
        }
    }
}

fn get_event(array: &'static PerCpuArray<Event>) -> Result<&'static mut Event, i8> {
    let event: &'static mut Event = unsafe {
        let raw_ptr = array.get_ptr_mut(0).ok_or(0)?;
        core::mem::transmute(raw_ptr)
    };

    event.primary_path.filename.len = 0;
    event.secondary_path.filename.len = 0;

    return Ok(event);
}

fn matches_filtered_path(path: &PathBuf) -> bool {
    // Get the first element from the FILTER_PATH
    // or early exit with a 0
    let filter_buf = if let Some(filter_buf) = FILTER_PATH.get(0) {
        filter_buf
    } else {
        return false;
    };

    let filter = filter_buf.buf.get(0..filter_buf.length);

    return filter.is_some() && path.buf.get(0..filter_buf.length) == filter;
}

// compares path without the trailing slash in the filter path
fn matches_filtered_path_no_trailing(path: &PathBuf) -> bool {
    // Get the first element from the FILTER_PATH
    // or early exit with a 0
    let filter_buf = if let Some(filter_buf) = FILTER_PATH.get(0) {
        filter_buf
    } else {
        return false;
    };

    let filter = filter_buf.buf.get(0..filter_buf.length - 1);

    return filter.is_some() && path.buf.get(0..filter_buf.length - 1) == filter;
}

// Fill fields in events from any applicable
fn fill_event(event: &mut Event, ctx: &impl EbpfContext) {
    event.pid = ctx.pid();
    event.gid = ctx.gid();
    event.tgid = ctx.tgid();
    event.uid = ctx.uid();
    // NOTE: time elapsed since system boot, in nanoseconds. DOES include time the system was
    // suspended.
    event.timestamp = unsafe { aya_ebpf::helpers::gen::bpf_ktime_get_boot_ns() };
}

#[inline(always)]
fn path_buf_as_str(path_buf: &PathBuf) -> &str {
    let len = path_buf.len;
    if len < path_buf.buf.len() {
        unsafe { core::str::from_utf8_unchecked(&path_buf.buf[0..len]) }
    } else {
        "<PLACEHOLDER>"
    }
}

fn dentry_name_to_buf(
    dentry: *const vmlinux::dentry,
    filename_buf: &mut FilenameBuf,
) -> Result<usize, i32> {
    let file_name = unsafe { (*dentry).d_name.name };
    let written = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(
            file_name as *const u8,
            &mut filename_buf.buf,
        )
        .map_err(|_| 0)?
    };
    filename_buf.len = written.len();

    Ok(written.len())
}

#[inline(always)]
pub fn bpf_d_path(path: *const vmlinux::path, path_buf: &mut PathBuf) -> Result<usize, i8> {
    // Get a pointer to the file path
    let written = unsafe {
        aya_ebpf::helpers::gen::bpf_d_path(
            path as *mut aya_ebpf::bindings::path,
            path_buf.buf.as_mut_ptr() as *mut i8,
            path_buf.buf.len() as u32,
        )
    };

    let written = written as usize;
    if written <= 1 || written >= path_buf.buf.len() {
        return Err(-1);
    }

    path_buf.len = written;
    return Ok(written);
}

#[inline(always)]
fn split_path_lsm(ctx: &LsmContext, variant: EventVariant) -> Result<&mut Event, i32> {
    let path: *const vmlinux::path = unsafe { ctx.arg(0) };
    let dentry: *const vmlinux::dentry = unsafe { ctx.arg(1) };

    let event = get_event(&BUFFER)?;

    bpf_d_path(path, &mut event.primary_path)?;
    dentry_name_to_buf(dentry, &mut event.primary_path.filename)?;

    if !matches_filtered_path_no_trailing(&event.primary_path)
        && !matches_filtered_path(&event.primary_path)
    {
        return Err(-4095);
    }

    event.variant = variant;
    fill_event(event, ctx);

    PIPELINE.output(ctx, event, 0);
    Ok(event)
}

#[inline(always)]
fn event_from_path(
    ctx: &impl EbpfContext,
    path: *const vmlinux::path,
    variant: EventVariant,
) -> Result<&mut Event, i32> {
    let event = get_event(&BUFFER)?;

    bpf_d_path(path, &mut event.primary_path)?;

    if !matches_filtered_path(&event.primary_path) {
        return Err(-4095);
    }

    event.variant = variant;
    fill_event(event, ctx);

    PIPELINE.output(ctx, event, 0);
    Ok(event)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
