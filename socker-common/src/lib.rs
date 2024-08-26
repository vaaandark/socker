#![no_std]

pub const TASK_COMM_LEN: usize = 16;
pub const UNIX_PATH_MAX: usize = 108;
pub const SS_MAX_SEG_SIZE: usize = 1024 * 4;
pub const SS_MAX_SEGS_PER_MSG: usize = 10;

pub type UnixPathBuffer = [u8; UNIX_PATH_MAX];
pub type CommBuffer = [u8; TASK_COMM_LEN];
pub type DataBuffer = [u8; SS_MAX_SEG_SIZE];

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketLog {
    pub pid: u32,
    pub peer_pid: u32,
    pub len: usize,
    pub flags: u32,
    pub comm: CommBuffer,
    pub path: UnixPathBuffer,
    pub data: DataBuffer,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub pid: u32,
    pub seg_size: usize,
    pub seg_per_msg: usize,
    pub sock_path: UnixPathBuffer,
}
