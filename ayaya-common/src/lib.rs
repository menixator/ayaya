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

/// Common data to be shared between the ebpf context and userspace context for all events
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Event {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub tgid: u32,
    pub timestamp: u64,
    pub path_len: usize,
    pub path: [u8; PATH_BUF_MAX],
    pub variant: EventVariant,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub enum EventVariant {
    // TODO: add file.f_mode
    Open,
}
