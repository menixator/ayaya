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

/// Allocates a PerCpuArray for a specific type
macro_rules! alloc {
    ($static_name:ident, $inner:ty) => {
        #[map]
        pub(crate) static $static_name: PerCpuArray<$inner> = PerCpuArray::with_max_entries(1, 0);
    };
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        // TODO: maybe set it 0 even on fails since this is a tracing program.
        Err(ret) => ret,
    }
}

// LSM_HOOK(int, 0, file_open, struct file *file)
fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // Fetch the file struct being opened
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };

    alloc!(FILE_OPEN_EVENT_BUF, Event);
    let event = get_event(&FILE_OPEN_EVENT_BUF)?;

    let written = get_path_from_file(file, &mut event.primary_path)?;
    if !matches_filtered_path(&event.primary_path) {
        return Ok(0);
    }

    let path = path_buf_as_str(&event.primary_path);
    info!(&ctx, "lsm/file_open called for {}", path);

    event.variant = EventVariant::Open;
    fill_event(event, &ctx);

    PIPELINE.output(&ctx, event, 0);
    Ok(0)
}

#[lsm(hook = "path_unlink")]
pub fn path_unlink(ctx: LsmContext) -> i32 {
    match try_path_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// LSM_HOOK(int, 0, path_unlink, const struct path *dir, struct dentry *dentry)
fn try_path_unlink(ctx: LsmContext) -> Result<i32, i32> {
    let path: *const vmlinux::path = unsafe { ctx.arg(0) };
    let dentry: *const vmlinux::dentry = unsafe { ctx.arg(1) };

    alloc!(PATH_UNLINK_EVENT_BUF, Event);
    let event = get_event(&PATH_UNLINK_EVENT_BUF)?;

    get_path_from_path(path, &mut event.primary_path)?;

    dentry_name_to_buf(dentry, &mut event.primary_filename)?;

    if !matches_filtered_path_no_trailing(&event.primary_path)
        && !matches_filtered_path(&event.primary_path)
    {
        return Ok(0);
    }

    let path = path_buf_as_str(&event.primary_path);
    info!(&ctx, "lsm/path_unlink called for a file in {}", path);

    event.variant = EventVariant::Unlink;
    fill_event(event, &ctx);

    PIPELINE.output(&ctx, event, 0);
    Ok(0)
}

#[lsm(hook = "path_mkdir")]
pub fn path_mkdir(ctx: LsmContext) -> i32 {
    match try_path_mkdir(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// LSM_HOOK(int, 0, path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode)
fn try_path_mkdir(ctx: LsmContext) -> Result<i32, i32> {
    let path: *const vmlinux::path = unsafe { ctx.arg(0) };
    let dentry: *const vmlinux::dentry = unsafe { ctx.arg(1) };

    alloc!(PATH_MKDIR_EVENT_BUF, Event);
    let event = get_event(&PATH_MKDIR_EVENT_BUF)?;

    get_path_from_path(path, &mut event.primary_path)?;

    dentry_name_to_buf(dentry, &mut event.primary_filename)?;

    if !matches_filtered_path_no_trailing(&event.primary_path)
        && !matches_filtered_path(&event.primary_path)
    {
        return Ok(0);
    }

    let path = path_buf_as_str(&event.primary_path);
    info!(&ctx, "lsm/path_mkdir called for a file in {}", path);

    event.variant = EventVariant::Unlink;
    fill_event(event, &ctx);

    PIPELINE.output(&ctx, event, 0);
    Ok(0)
}

#[lsm(hook = "bprm_creds_for_exec")]
pub fn bprm_creds_for_exec(ctx: LsmContext) -> i32 {
    match try_bprm_creds_for_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_bprm_creds_for_exec(ctx: LsmContext) -> Result<i32, i32> {
    // Fetch the file struct being opened
    let binprm: *const vmlinux::linux_binprm = unsafe { ctx.arg(0) };
    let file = unsafe { (*binprm).file };

    alloc!(BPRM_CREDS_FOR_EXEC_EVENT_BUF, Event);

    let event = get_event(&BPRM_CREDS_FOR_EXEC_EVENT_BUF)?;

    get_path_from_file(file, &mut event.primary_path)?;
    if !matches_filtered_path(&event.primary_path) {
        return Ok(0);
    }

    let path = path_buf_as_str(&event.primary_path);
    info!(&ctx, "lsm/bprm_creds_for_exec called for {}", path);

    event.variant = EventVariant::Exec;
    fill_event(event, &ctx);

    PIPELINE.output(&ctx, event, 0);

    Ok(0)
}

#[fentry(function = "security_file_permission")]
pub fn security_file_permission(ctx: FEntryContext) -> u32 {
    match try_security_file_permission(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

fn try_security_file_permission(ctx: FEntryContext) -> Result<u32, i64> {
    // Fetch the file struct being opened
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };
    // information about masks
    // https://github.com/torvalds/linux/blob/ffd294d346d185b70e28b1a28abe367bbfe53c04/security/selinux/hooks.c#L1957-L2005
    let mask: u32 = unsafe { ctx.arg(1) };

    alloc!(SECURITY_FILE_PERMISSION_EVENT_BUF, Event);

    let event = get_event(&SECURITY_FILE_PERMISSION_EVENT_BUF)?;

    get_path_from_file(file, &mut event.primary_path)?;
    if !matches_filtered_path(&event.primary_path) {
        return Ok(0);
    }

    let path = path_buf_as_str(&event.primary_path);
    info!(
        &ctx,
        "fentry/security_file_permission called for {} with mask={}", path, mask
    );

    event.variant = EventVariant::ReadOrWrite;
    fill_event(event, &ctx);

    PIPELINE.output(&ctx, event, 0);

    Ok(0)
}

fn get_event(array: &'static PerCpuArray<Event>) -> Result<&'static mut Event, i8> {
    let event: &'static mut Event = unsafe {
        let raw_ptr = array.get_ptr_mut(0).ok_or(0)?;
        core::mem::transmute(raw_ptr)
    };

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
    // NOTE: time elapsed since system boot, in nanoseconds. Does not include time the system was
    // suspended.
    event.timestamp = unsafe { aya_ebpf::helpers::gen::bpf_ktime_get_ns() };
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
    filename: &mut FilenameBuf,
) -> Result<usize, i32> {
    let file_name = unsafe { (*dentry).d_name.name };
    let written = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(
            file_name as *const u8,
            &mut filename.buf,
        )
        .map_err(|_| 0)?
    };
    filename.len = written.len();

    Ok(written.len())
}

#[inline(always)]
pub fn get_path_from_file(file: *const vmlinux::file, path_buf: &mut PathBuf) -> Result<usize, i8> {
    // Get a pointer to the file path
    let path = unsafe { &((*file).f_path) as *const _ };
    get_path_from_path(path, path_buf)
}

#[inline(always)]
pub fn get_path_from_path(path: *const vmlinux::path, path_buf: &mut PathBuf) -> Result<usize, i8> {
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
