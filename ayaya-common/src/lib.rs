#![no_std]

pub const PATH_BUF_MAX: usize = 4096;

/// A struct used to share the filter path between the userland program and the ebpf program so as
/// to allow the filter path to be dynamic without recompiling the ebpf program
#[derive(Copy, Clone)]
#[repr(C)]
pub struct FilterPath {
    /// Written bytes
    pub length: usize,
    pub buf: [u8; PATH_BUF_MAX],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FilterPath {}
