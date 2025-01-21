#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{lsm, map},
    maps::{Array, PerCpuArray},
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

type PathBuffer = [u8; PATH_BUF_MAX];

#[map]
pub(crate) static FILTER_PATH: Array<FilterPath> = Array::with_max_entries(1, 0);

macro_rules! path_buf_init {
    ($static_name:ident) => {
        #[map]
        pub(crate) static $static_name: PerCpuArray<PathBuffer> =
            PerCpuArray::with_max_entries(1, 0);
    };
}

macro_rules! gen_buf_init {
    ($static_name:ident, $inner:ty) => {
        #[map]
        pub(crate) static $static_name: PerCpuArray<[u8; ::core::mem::size_of::<$inner>()]> =
            PerCpuArray::with_max_entries(1, 0);
    };
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
pub fn get_path_from_file(file: *const vmlinux::file, buf: &PathBuffer) -> i64 {
    // Get a pointer to the file path
    let path = unsafe { &((*file).f_path) as *const _ as *mut aya_ebpf::bindings::path };
    let written = unsafe {
        aya_ebpf::helpers::gen::bpf_d_path(path, buf as *const u8 as *mut i8, buf.len() as u32)
    };
    return written;
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // Fetch the file struct being opened
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };

    gen_buf_init!(FILE_OPEN_EVENT_BUF, Event);

    let event_buf: &'static mut Event = unsafe {
        let raw_ptr = FILE_OPEN_EVENT_BUF.get_ptr_mut(0).ok_or(0)?;
        core::mem::transmute(raw_ptr)
    };

    event_buf.pid = ctx.pid();
    event_buf.gid = ctx.gid();
    event_buf.tgid = ctx.tgid();
    event_buf.uid = ctx.uid();
    event_buf.variant = EventVariant::Open;
    // NOTE: time elapsed since system boot, in nanoseconds. Does not include time the system was suspended.
    event_buf.timestamp = unsafe { aya_ebpf::helpers::gen::bpf_ktime_get_ns() };

    info!(
        &ctx,
        "pid={}, gid={}, tid={}, uid={}",
        event_buf.pid,
        event_buf.gid,
        event_buf.tgid,
        event_buf.uid
    );

    path_buf_init!(FILE_OPEN_PATH_BUF);
    // FIXME?: kinda iffy getting an immutable reference here but
    // getting a mutable one gives a raw ptr
    let buf = FILE_OPEN_PATH_BUF.get(0).ok_or(0)?;

    let written = get_path_from_file(file, buf);
    let written = written as usize;

    if written >= PATH_BUF_MAX {
        return Ok(0);
    }

    // Get the first element from the FILTER_PATH
    // or early exit with a 0
    let filter_buf = FILTER_PATH.get(0).ok_or(0)?;

    let filter = filter_buf.buf.get(0..filter_buf.length);
    if buf.get(0..filter_buf.length) != filter || filter.is_none() {
        return Ok(0);
    }

    let path_as_str = unsafe { core::str::from_utf8_unchecked(&buf[0..written]) };

    info!(&ctx, "lsm/file_open called for {}", path_as_str);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
