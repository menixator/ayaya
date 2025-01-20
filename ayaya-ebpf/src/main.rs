#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{lsm, map},
    maps::{Array, PerCpuArray},
    programs::LsmContext,
};
use aya_log_ebpf::info;

#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[rustfmt::skip]
mod vmlinux;

use ayaya_common::{FilterPath, PATH_BUF_MAX};

#[map]
pub(crate) static FILTER_PATH: Array<FilterPath> = Array::with_max_entries(1, 0);

macro_rules! path_buf_init {
    ($static_name:ident) => {
        #[map]
        pub(crate) static $static_name: PerCpuArray<[u8; PATH_BUF_MAX]> =
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

pub fn get_path_from_file(file: *const vmlinux::file, buf: *const u8, size: u32) -> i64 {
    // Get a pointer to the file path
    let path = unsafe { &((*file).f_path) as *const _ as *mut aya_ebpf::bindings::path };
    let written = unsafe { aya_ebpf::helpers::gen::bpf_d_path(path, buf as *mut i8, size) };
    return written;
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // Fetch the file struct being opened
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };

    path_buf_init!(FILE_OPEN_PATH_BUF);
    let buf = unsafe { FILE_OPEN_PATH_BUF.get(0).ok_or(0)? };

    let written = get_path_from_file(file, buf as *const u8, buf.len() as u32);
    let written = written as usize;

    if written >= 256 {
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
