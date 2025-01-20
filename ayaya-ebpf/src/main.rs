#![no_std]
#![no_main]

use aya_ebpf::{macros::lsm, programs::LsmContext};
use aya_log_ebpf::info;

#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[rustfmt::skip]
mod vmlinux;



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

    let mut buf: [u8; 256] = [0; 256];

    let written = get_path_from_file(file, &buf as *const u8, 256);
    let written = written as usize;

    if written >= 256 {
        return Ok(0);
    }

    let filter = "/home/menixator/test/".as_bytes();

    match buf.get(0..21) {
        Some(buf) if buf != filter => return Ok(0),
        _ => {}
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
