#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{lsm, map},
    maps::{Array, PerCpuArray, PerfEventArray},
    programs::LsmContext,
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

use ayaya_common::{Event, EventVariant, FilterPath, PATH_BUF_MAX};

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

pub fn get_path_from_file(file: *const vmlinux::file, buf: &mut [u8]) -> Result<usize, i8> {
    // Get a pointer to the file path
    let path = unsafe { &((*file).f_path) as *const _ as *mut aya_ebpf::bindings::path };
    let written = unsafe {
        aya_ebpf::helpers::gen::bpf_d_path(path, buf.as_mut_ptr() as *mut i8, buf.len() as u32)
    };

    let written = written as usize;
    if written <= 1 || written >= buf.len() {
        return Err(-1);
    }
    return Ok(written);
}

// LSM_HOOK(int, 0, file_open, struct file *file)
fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // Fetch the file struct being opened
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };

    alloc!(FILE_OPEN_EVENT_BUF, Event);
    let event: &'static mut Event = unsafe {
        let raw_ptr = FILE_OPEN_EVENT_BUF.get_ptr_mut(0).ok_or(0)?;
        core::mem::transmute(raw_ptr)
    };

    let written = get_path_from_file(file, &mut event.path)?;
    if !matches_filtered_path(&event.path) {
        return Ok(0);
    }

    event.path_len = written - 1;

    let path_as_str = unsafe { core::str::from_utf8_unchecked(&event.path[0..written]) };
    info!(&ctx, "lsm/file_open called for {}", path_as_str);

    event.variant = EventVariant::Open;
    fill_event(event, &ctx);

    PIPELINE.output(&ctx, event, 0);
    Ok(0)
}

fn matches_filtered_path(path: &[u8]) -> bool {
    // Get the first element from the FILTER_PATH
    // or early exit with a 0
    let filter_buf = if let Some(filter_buf) = FILTER_PATH.get(0) {
        filter_buf
    } else {
        return false;
    };

    let filter = filter_buf.buf.get(0..filter_buf.length);

    return filter.is_some() && path.get(0..filter_buf.length) == filter;
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
