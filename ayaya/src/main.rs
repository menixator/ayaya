use aya::{
    programs::{FEntry, Lsm},
    Btf,
};
#[rustfmt::skip]
use log::{debug, warn};
use anyhow::{anyhow, Context};
use aya::maps::{perf::PerfBufferError, Array, AsyncPerfEventArray};
use ayaya_common::{Event, FilterPath, PATH_BUF_MAX};
use bytes::BytesMut;
use sqlx::PgPool;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let pool = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;

    // TODO: the migrations along with this macro will be moved to the backend
    sqlx::migrate!("../migrations").run(&pool).await?;

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

    let program: &mut Lsm = ebpf
        .program_mut("bprm_creds_for_exec")
        .unwrap()
        .try_into()?;
    program.load("bprm_creds_for_exec", &btf)?;
    program.attach()?;

    let program: &mut Lsm = ebpf.program_mut("path_unlink").unwrap().try_into()?;
    program.load("path_unlink", &btf)?;
    program.attach()?;

    let program: &mut Lsm = ebpf.program_mut("path_mkdir").unwrap().try_into()?;
    program.load("path_mkdir", &btf)?;
    program.attach()?;

    let program: &mut Lsm = ebpf.program_mut("path_rmdir").unwrap().try_into()?;
    program.load("path_rmdir", &btf)?;
    program.attach()?;

    let program: &mut Lsm = ebpf.program_mut("path_truncate").unwrap().try_into()?;
    program.load("path_truncate", &btf)?;
    program.attach()?;

    let program: &mut Lsm = ebpf.program_mut("path_chmod").unwrap().try_into()?;
    program.load("path_chmod", &btf)?;
    program.attach()?;

    let program: &mut Lsm = ebpf.program_mut("path_chown").unwrap().try_into()?;
    program.load("path_chown", &btf)?;
    program.attach()?;

    let program: &mut Lsm = ebpf.program_mut("path_rename").unwrap().try_into()?;
    program.load("path_rename", &btf)?;
    program.attach()?;

    let program: &mut Lsm = ebpf.program_mut("path_link").unwrap().try_into()?;
    program.load("path_link", &btf)?;
    program.attach()?;

    let program: &mut Lsm = ebpf.program_mut("path_symlink").unwrap().try_into()?;
    program.load("path_symlink", &btf)?;
    program.attach()?;

    let program: &mut FEntry = ebpf
        .program_mut("security_file_permission")
        .unwrap()
        .try_into()?;
    program.load("security_file_permission", &btf)?;
    program.attach()?;

    println!("started");
    println!("event size is {} bytes", std::mem::size_of::<Event>());

    // This is an arbitrary limit. Could not get around it
    // assert!(
    //     std::mem::size_of::<Event>() <= 8168,
    //     "Event size cannot be bigger than 8168."
    // );

    // try to convert the PERF_ARRAY map to an AsyncPerfEventArray
    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("PIPELINE").unwrap())?;

    // getconf PAGESIZE to get PAGESIZE
    // (size ofstruct * max_bufferered_events)/ PAGE_SIZE
    let optimal_page_count = ((std::mem::size_of::<Event>() * 20) / 4096).next_power_of_two();

    for cpu_id in aya::util::online_cpus().map_err(|(_, error)| error)? {
        // open a separate perf buffer for each cpu
        let mut buf = perf_array.open(cpu_id, Some(optimal_page_count))?;

        // process each perf buffer in a separate task
        tokio::task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<Event>().next_power_of_two()))
                .collect::<Vec<_>>();

            loop {
                // wait for events
                let events = buf.read_events(&mut buffers).await?;

                println!("read {} event(s)", events.read);
                // events.read contains the number of events that have been read,
                // and is always <= buffers.len()
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const Event;
                    let event = unsafe { ptr.read_unaligned() };

                    let primary_path = build_path(event.primary_path);

                    // TODO: cache
                    let user = users::get_user_by_uid(event.uid).ok_or_else(|| {
                        anyhow!("failed to resolve uid({}) into a username", event.uid)
                    })?;
                    let username = user.name().to_str().ok_or_else(|| {
                        anyhow!(
                            "uid({}) has invalid utf8 sequences in the usernmae",
                            event.uid
                        )
                    })?;

                    let group = users::get_group_by_gid(event.gid).ok_or_else(|| {
                        anyhow!("failed to resolve gid({}) into a groupname", event.gid)
                    })?;

                    let groupname = group.name().to_str().ok_or_else(|| {
                        anyhow!(
                            "gid({}) has invalid utf8 sequences in the groupname",
                            event.gid
                        )
                    })?;
                    use time::{format_description::well_known::Iso8601, OffsetDateTime};

                    // event.timestamp uses bpf_ktime_get_boot_ns. IT DOES include the time that
                    let uptime = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)?;
                    // We're associating the above uptime duration with this utc timestamp
                    // and pretending that they happened at the same instant.
                    // There WILL be neglibile differences between the "true" time because these
                    // are two different calls and the time will drift between events by a
                    // _neglibile_ amount too. But hey, tradeoffs...
                    // The alternative is getting a OffsetDateTime to exactly when the system was
                    // booted and using that as reference but if the time was changed (eg: user
                    // interverion, ntpd) that will fuck all subsequent events.
                    let utc_now = time::OffsetDateTime::now_utc();

                    let uptime = time::Duration::new(
                        uptime.tv_sec(),
                        uptime
                            .tv_nsec()
                            .try_into()
                            .with_context(|| "uptime nanosecond conversion failure")?,
                    );
                    let event_timestamp = time::Duration::nanoseconds(event.timestamp as i64);

                    // TODO: replace offset with a localoffset
                    let timestamp =
                        utc_now.to_offset(time::macros::offset!(+5)) - (uptime - event_timestamp);

                    let timestamp = timestamp.format(&Iso8601::DEFAULT)?;

                    println!(
                        "{} {:#?} {username}:{groupname} {}",
                        timestamp,
                        event.variant,
                        primary_path.display()
                    )
                }
            }

            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        });
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn build_path(path_buf: ayaya_common::PathBuf) -> std::path::PathBuf {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    let path = OsStr::from_bytes(&path_buf.buf[0..path_buf.len]);
    let mut path = std::path::Path::new(path).to_owned();

    let filename_buf = path_buf.filename;

    // There might be a filename
    if filename_buf.len > 0 {
        let filename = OsStr::from_bytes(&filename_buf.buf[0..filename_buf.len]);
        path.push(filename);
    }
    return path;
}
