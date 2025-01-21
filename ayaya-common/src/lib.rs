#![no_std]

pub const PATH_BUF_MAX: usize = 2048;
pub const FILENAME_BUF_MAX: usize = 256;

#[cfg_attr(feature = "user", derive(Debug))]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PathBuf {
    pub len: usize,
    pub buf: [u8; PATH_BUF_MAX],
}

#[cfg_attr(feature = "user", derive(Debug))]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct FilenameBuf {
    pub len: usize,
    pub buf: [u8; FILENAME_BUF_MAX],
}

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

#[cfg_attr(feature = "user", derive(Debug))]
/// Common data to be shared between the ebpf context and userspace context for all events
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Event {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub tgid: u32,
    pub timestamp: u64,
    pub primary_path: PathBuf,
    pub primary_filename: FilenameBuf,
    pub secondary_path: PathBuf,
    pub secondary_filename: FilenameBuf,
    pub variant: EventVariant,
}

#[cfg_attr(feature = "user", derive(Debug))]
#[derive(Copy, Clone)]
#[repr(C)]
pub enum EventVariant {
    // TODO: add file.f_mode
    Open,
    // TODO: Split into two based on intent
    ReadOrWrite,
    Exec,
    Unlink,
    Mkdir,
    Rmdir,
}
