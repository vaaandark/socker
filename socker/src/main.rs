use std::ffi::CStr;

use aya::maps::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{debug, info, warn};
use pretty_hex::{config_hex, HexConfig};
use socker_common::PacketLog;
use tokio::{signal, task};

fn to_str_if_http_request(data: &[u8]) -> Option<&str> {
    if data[..4] == [b'H', b'T', b'T', b'P'] {
        Some(
            unsafe { CStr::from_ptr(data as *const [u8] as *const i8) }
                .to_str()
                .unwrap(),
        )
    } else {
        None
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
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
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/socker"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/socker"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let stream_sendmsg: &mut KProbe = bpf
        .program_mut("kprobe_unix_stream_sendmsg")
        .unwrap()
        .try_into()?;
    stream_sendmsg.load()?;
    stream_sendmsg.attach("unix_stream_sendmsg", 0)?;

    let dgram_sendmsg: &mut KProbe = bpf
        .program_mut("kprobe_unix_dgram_sendmsg")
        .unwrap()
        .try_into()?;
    dgram_sendmsg.load()?;
    dgram_sendmsg.attach("unix_dgram_sendmsg", 0)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    let cfg = HexConfig {
        title: false,
        width: 8,
        group: 0,
        ..HexConfig::default()
    };

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            let events = buf.read_events(&mut buffers).await.unwrap();
            for buf in buffers.iter_mut().take(events.read) {
                let ptr = buf.as_ptr() as *const PacketLog;
                let packet_log = unsafe { ptr.read_unaligned() };
                info!(">>>Get a packet<<<");

                let comm = unsafe { CStr::from_ptr(&packet_log.comm as *const u8 as *const i8) }
                    .to_str()
                    .unwrap_or("");
                let path = if packet_log.path[0] == b'\0' {
                    &packet_log.path[1..]
                } else {
                    &packet_log.path
                };
                let path = unsafe { CStr::from_ptr(path as *const [u8] as *const i8) }
                    .to_str()
                    .unwrap_or("bad unix socket path");
                println!(
                    "{} ({} > {}) {} {} bytes",
                    comm, packet_log.pid, packet_log.peer_pid, path, packet_log.len
                );
                let data = &packet_log.data[..packet_log.len];
                if let Some(http) = to_str_if_http_request(data) {
                    println!("{}", http);
                } else {
                    let data = data
                        .iter()
                        .rposition(|&c| c != b'\0')
                        .map_or(data, |idx| &data[..=idx]);
                    println!("{}", config_hex(&data, cfg));
                }
                println!();
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
