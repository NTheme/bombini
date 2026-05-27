use crate::constants::MAX_FILE_PREFIX;
use crate::event::process::ProcessKey;

pub const SYSENUMMON_CHAIN_MAX: usize = 14;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct SysEnumMonKernelConfig {
    pub chain_size: u8,
    pub window_ns: u64,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ChainItem {
    pub timestamp_ns: u64,
    pub process: ProcessKey,
    pub name_len: u16,
    pub bit_idx: u8,
    pub file_open: bool,
    pub name: [u8; MAX_FILE_PREFIX],
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct SysEnumMonState {
    pub chain_len: u8,
    pub chain: [ChainItem; SYSENUMMON_CHAIN_MAX],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for SysEnumMonKernelConfig {}
    unsafe impl aya::Pod for ChainItem {}
    unsafe impl aya::Pod for SysEnumMonState {}
}
