//! SysEnum event module

use crate::config::sysenummon::{ChainItem, SYSENUMMON_CHAIN_MAX};

#[derive(Clone, Debug)]
#[repr(C)]
pub struct SysEnumMonMsg {
    pub chain_len: u8,
    pub chain: [ChainItem; SYSENUMMON_CHAIN_MAX],
}
