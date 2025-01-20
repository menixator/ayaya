use aya::{programs::Lsm, Btf};
#[rustfmt::skip]
use log::{debug, warn};
use anyhow::anyhow;
use aya::maps::Array;
use ayaya_common::{FilterPath, PATH_BUF_MAX};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ayaya"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let mut array = Array::try_from(ebpf.map_mut("FILTER_PATH").unwrap())?;

    use std::os::unix::ffi::OsStrExt;

    // The first argument will be the filter path
    let mut filter_path: std::path::PathBuf = match std::env::args_os().nth(1) {
        Some(filter_path) => filter_path.into(),
        None => return Err(anyhow!("No filter path provided.")),
    };

    // Force a trailing slash
    if !filter_path.as_os_str().is_empty() {
        let mut name = filter_path
            .file_name()
            .map(ToOwned::to_owned)
            .unwrap_or_default();
        name.push("/");
        filter_path.set_file_name(name);
    }

    println!(
        "ayaya will watch for file events from: {}",
        filter_path.display()
    );

    // Fetch the bytes from filter_path
    let filter_path = filter_path.as_os_str().as_bytes();

    let mut filter = FilterPath {
        length: filter_path.len(),
        buf: [0; PATH_BUF_MAX],
    };

    // Copy it into buf
    (&mut filter.buf[0..filter_path.len()]).copy_from_slice(&filter_path);

    // Set the first element of FILTER_PATH to the created struct
    array.set(0, filter, 0)?;

    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = ebpf.program_mut("file_open").unwrap().try_into()?;
    program.load("file_open", &btf)?;
    program.attach()?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
