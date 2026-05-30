//! SysEnum event module

use crate::constants::{MAX_FILE_PREFIX, MAX_FILENAME_SIZE};
use crate::event::process::ProcessKey;

pub const SYSENUMMON_CHAIN_MAX: usize = 15;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum ChainItemType {
    Exec([u8; MAX_FILENAME_SIZE]) = 0,
    FileOpen([u8; MAX_FILE_PREFIX]) = 1,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ChainItem {
    pub timestamp_ns: u64,
    pub entry: ChainItemType,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SysEnumMsg {
    pub chain_len: u8,
    pub process: ProcessKey,
    pub watch_ids: [u8; SYSENUMMON_CHAIN_MAX],
    pub chain: [ChainItem; SYSENUMMON_CHAIN_MAX],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for ChainItemType {}
    unsafe impl aya::Pod for ChainItem {}
    unsafe impl aya::Pod for SysEnumMsg {}
}
