use ayaya_common::EventVariant;

pub struct EventProxy {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub tgid: u32,
    pub timestamp: u64,
    pub primary_path: std::path::PathBuf,
    pub secondary_path: Option<std::path::PathBuf>,
    pub variant: EventVariant,
}
