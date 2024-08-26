use std::ffi::CStr;

use aya::maps::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{debug, info, warn};
use socker_common::PacketLog;
use tokio::{signal, task};

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

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            let events = buf.read_events(&mut buffers).await.unwrap();
            for buf in buffers.iter_mut().take(events.read) {
                let ptr = buf.as_ptr() as *const PacketLog;
                let mut packet_log = unsafe { ptr.read_unaligned() };
                info!(">>>Get a packet<<<");

                let comm = unsafe { CStr::from_ptr(&packet_log.comm as *const u8 as *const i8) }
                    .to_str()
                    .unwrap_or("");
                if packet_log.path[0] == b'\0' {
                    packet_log.path[0] = b'@';
                }
                let path = unsafe { CStr::from_ptr(&packet_log.path as *const u8 as *const i8) }
                    .to_str()
                    .unwrap_or("bad unix socket path");
                info!(
                    "src: {} | dst: {} | length: {} | cmd: {:?} | path: {:?}",
                    packet_log.pid, packet_log.peer_pid, packet_log.len, comm, path
                );
                info!(
                    "data: {:?}",
                    packet_log
                        .data
                        .iter()
                        .rposition(|&c| c != b'\0')
                        .map_or(&packet_log.data[..], |idx| &packet_log.data[..=idx])
                );
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
