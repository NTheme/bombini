#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct SysEnumMonKernelConfig {
    pub chain_size: u8,
    pub window_ns: u64,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for SysEnumMonKernelConfig {}
}
