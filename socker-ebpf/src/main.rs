#![no_std]
#![no_main]

use core::mem::offset_of;

use aya_ebpf::bindings::BPF_F_CURRENT_CPU;
use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel_buf};
use aya_ebpf::maps::{PerCpuArray, PerfEventArray};
use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{kprobe, map},
    programs::ProbeContext,
};
use socker_common::*;
use aya_log_ebpf::info;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod binding;
use crate::binding::{msghdr, sockaddr_un, socket, unix_address, unix_sock};

struct Config {
    pid: u32,
    seg_size: usize,
    seg_per_msg: usize,
    sock_path: UnixPathBuffer,
}

static mut CONFIG: Config = Config {
    pid: 0,
    seg_size: SS_MAX_SEG_SIZE,
    seg_per_msg: SS_MAX_SEGS_PER_MSG,
    sock_path: [b'\0'; UNIX_PATH_MAX],
};

#[map]
static PACKETLOGS: PerCpuArray<PacketLog> = PerCpuArray::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

fn is_path_matched(path: &UnixPathBuffer) -> bool {
    let path = if path[0] == b'\0' && path[1] != b'\0' {
        &path[1..]
    } else {
        path
    };

    let config_path = unsafe { CONFIG.sock_path };
    let config_path_len = config_path
        .iter()
        .position(|&x| x == b'\0')
        .unwrap_or(config_path.len());
    if config_path_len == 0 {
        return true;
    }

    let path_len = path.iter().position(|&x| x == b'\0').unwrap_or(path.len());
    config_path_len <= path_len && config_path[..config_path_len] == path[..config_path_len]
}

fn is_sock_path_matched(sock: *const unix_sock, path: &mut UnixPathBuffer) -> Result<bool, i64> {
    let addr =
        unsafe { bpf_probe_read_kernel(bpf_probe_read_kernel(&((*sock).addr)).or(Err(1i64))?) }
            .or(Err(1i64))?;
    if addr.len == 0 {
        return Ok(false);
    }
    let sock_path = unsafe {
        ((&addr as *const unix_address) as *const u8)
            .add(offset_of!(unix_address, name) + offset_of!(sockaddr_un, sun_path))
    };
    if unsafe { bpf_probe_read_kernel_str_bytes(sock_path, path) }.is_ok() {
        Ok(is_path_matched(path))
    } else {
        Err(1i64)
    }
}

fn collect_data(ctx: &ProbeContext, packet_log: &mut PacketLog, buff: *const c_void, len: usize) {
    let seg_size = unsafe { CONFIG.seg_size };

    packet_log.flags = 0;
    packet_log.len = len;

    let n = len.min(seg_size - 1);
    let buf = &mut packet_log.data[..n];
    if let Err(e) = unsafe { bpf_probe_read_kernel_str_bytes(buff as *const u8, buf) } {
        info!(ctx, "Failed to read: {}", e);
    }
    packet_log.data[n.min(SS_MAX_SEG_SIZE - 1)] = b'\0';

    EVENTS.output(ctx, &packet_log, 0);
}

#[allow(unused)]
fn capture(
    ctx: &ProbeContext,
    sock: *const socket,
    msg: *const msghdr,
    len: usize,
) -> Result<u32, i64> {
    let pid: u32 = (bpf_get_current_pid_tgid() >> 32) as u32;

    if unsafe { CONFIG.pid != 0 && CONFIG.pid != pid } {
        return Ok(0);
    }

    let packet_log = unsafe { PACKETLOGS.get_ptr_mut(0).ok_or(1i64)?.as_mut() }.ok_or(1i64)?;

    let sock = unsafe { bpf_probe_read_kernel(sock) }.or(Err(1i64))?;

    let unix_sock =
        unsafe { bpf_probe_read_kernel(&((sock.sk as *const c_void) as *const unix_sock)) }
            .or(Err(1))?;

    let peer_unix_sock = unsafe {
        bpf_probe_read_kernel(
            &(((&((*unix_sock).peer) as *const *mut binding::sock) as *const c_void)
                as *const unix_sock),
        )
    }
    .or(Err(1))?;

    let path = &mut packet_log.path;
    if !is_sock_path_matched(unix_sock, path)? || is_sock_path_matched(peer_unix_sock, path)? {
        // return Ok(0);
    }

    packet_log.pid = pid;
    packet_log.comm = bpf_get_current_comm().or(Err(1i64))?;
    packet_log.peer_pid = unsafe {
        bpf_probe_read_kernel(
            unsafe { bpf_probe_read_kernel(&((*unix_sock).sk.sk_peer_pid)) }.or(Err(1i64))?,
        )
    }
    .or(Err(1i64))?
    .numbers
    .first()
    .ok_or(1i64)?
    .nr as u32;

    let mut iov =
        unsafe { bpf_probe_read_kernel(&(*msg).msg_iter.__bindgen_anon_1.iov) }.or(Err(1i64))?;

    // TODO: there are better methods in new kernel

    let n = unsafe { CONFIG.seg_per_msg }.min(SS_MAX_SEGS_PER_MSG);
    let nsegs = unsafe { bpf_probe_read_kernel(&(*msg).msg_iter.__bindgen_anon_2.nr_segs) }
        .or(Err(1i64))?;
    for i in 0..SS_MAX_SEGS_PER_MSG as u64 {
        if i >= nsegs || i >= n as u64 {
            break;
        }
        {

            let iov = unsafe {bpf_probe_read_kernel(iov)}.or(Err(1i64))?;
        // let iov_base = unsafe { bpf_probe_read_kernel(&(*iov).iov_base) }.or(Err(1i64))?;
        // let iov_len = unsafe { bpf_probe_read_kernel(&(*iov).iov_len) }.or(Err(1i64))?;
            collect_data(ctx, packet_log, iov.iov_base, iov.iov_len as usize);
        }
        iov = unsafe { iov.add(1) };
    }

    Ok(0)
}

fn try_kprobe_unix_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
    let sock: *mut socket = ctx.arg(0).ok_or(1i64)?;
    let msg: *const msghdr = ctx.arg(1).ok_or(1i64)?;
    let len: usize = ctx.arg(2).ok_or(1i64)?;
    capture(&ctx, sock, msg, len)
}

#[kprobe]
fn kprobe_unix_stream_sendmsg(ctx: ProbeContext) -> u32 {
    try_kprobe_unix_sendmsg(ctx).unwrap_or(1)
}

#[kprobe]
fn kprobe_unix_dgram_sendmsg(ctx: ProbeContext) -> u32 {
    try_kprobe_unix_sendmsg(ctx).unwrap_or(1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
