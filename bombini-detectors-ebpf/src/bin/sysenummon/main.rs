#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_ANY,
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel_buf,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{
        array::Array,
        hash_map::{HashMap, LruHashMap},
        lpm_trie::{Key, LpmTrie},
        per_cpu_array::PerCpuArray,
    },
    programs::LsmContext,
};

use bombini_common::config::rule::{FileNameMapKey, PathMapKey, PathPrefixMapKey};
use bombini_common::config::sysenummon::{
    ChainItem, SYSENUMMON_CHAIN_MAX, SysEnumMonKernelConfig, SysEnumMonState,
};
use bombini_common::constants::{MAX_FILE_PATH, MAX_FILE_PREFIX};
use bombini_common::event::process::{ProcInfo, ProcessKey};
use bombini_common::event::sysenum::SysEnumMonMsg;
use bombini_common::event::{Event, GenericEvent, MSG_SYSENUM};
use bombini_detectors_ebpf::co_re::{self, core_read_kernel};
use bombini_detectors_ebpf::{event_capture, util};

#[map]
static SYSENUMMON_CONFIG: Array<SysEnumMonKernelConfig> = Array::with_max_entries(1, 0);

#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

#[map]
static SYSENUMMON_STATE: LruHashMap<u32, SysEnumMonState> = LruHashMap::with_max_entries(4096, 0);

#[map]
static SYSENUMMON_NAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static SYSENUMMON_PATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static SYSENUMMON_PATH_PREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static SYSENUMMON_PATH_HEAP: PerCpuArray<[u8; MAX_FILE_PATH]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static SYSENUMMON_NAME_KEY_HEAP: PerCpuArray<FileNameMapKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static SYSENUMMON_PATH_KEY_HEAP: PerCpuArray<PathMapKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static SYSENUMMON_PREFIX_KEY_HEAP: PerCpuArray<Key<PathPrefixMapKey>> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static SYSENUMMON_STATE_HEAP: PerCpuArray<SysEnumMonState> = PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_SYSENUM, true, try_bprm_check)
}

#[lsm(hook = "file_open")]
pub fn file_open_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_SYSENUM, true, try_file_open)
}

fn try_bprm_check(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::SysEnum(ref mut event) = generic_event.event else {
        return Err(-1);
    };

    let name_key_ptr = SYSENUMMON_NAME_KEY_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let name_key = unsafe { name_key_ptr.as_mut() }.ok_or(-1i32)?;
    name_key.rule_idx = 0;
    name_key.name.fill(0);

    unsafe {
        let binprm = co_re::linux_binprm::from_ptr(ctx.arg(0));
        let d_name = core_read_kernel!(binprm, file, f_path, dentry, d_name, name).ok_or(-1i32)?;
        bpf_probe_read_kernel_str_bytes(d_name, &mut name_key.name).map_err(|_| -1i32)?;
    }

    let &bit_idx = unsafe { SYSENUMMON_NAME_MAP.get(name_key) }.ok_or(0i32)?;
    let (ppid, process) = current_keys()?;
    record_hit(
        event,
        ppid,
        generic_event.ktime,
        process,
        bit_idx,
        false,
        &name_key.name,
    )
}

fn try_file_open(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::SysEnum(ref mut event) = generic_event.event else {
        return Err(-1);
    };

    let path_ptr = SYSENUMMON_PATH_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let path = unsafe { path_ptr.as_mut() }.ok_or(-1i32)?;
    path.fill(0);

    let path_key_ptr = SYSENUMMON_PATH_KEY_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let path_key = unsafe { path_key_ptr.as_mut() }.ok_or(-1i32)?;
    path_key.rule_idx = 0;
    path_key.path.fill(0);

    let prefix_key_ptr = SYSENUMMON_PREFIX_KEY_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let prefix_key = unsafe { prefix_key_ptr.as_mut() }.ok_or(-1i32)?;
    prefix_key.prefix_len = (MAX_FILE_PREFIX * 8) as u32;
    prefix_key.data.rule_idx = 0;
    prefix_key.data.path_prefix.fill(0);

    unsafe {
        let fp = co_re::file::from_ptr(ctx.arg(0));
        let f_path = core_read_kernel!(fp, f_path).ok_or(-1i32)?;
        let _ = bpf_d_path(
            f_path.as_ptr() as *mut aya_ebpf::bindings::path,
            path.as_mut_ptr() as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path.as_ptr(), &mut path_key.path).map_err(|_| -1i32)?;
        let _ = bpf_probe_read_kernel_buf(path.as_ptr(), &mut prefix_key.data.path_prefix);
    }

    let mut bit_idx: u8 = 0;
    let mut hit = false;
    if let Some(&b) = unsafe { SYSENUMMON_PATH_MAP.get(path_key) } {
        bit_idx = b;
        hit = true;
    } else if let Some(&b) = SYSENUMMON_PATH_PREFIX_MAP.get(prefix_key) {
        bit_idx = b;
        hit = true;
    }
    if !hit {
        return Err(0);
    }

    let (ppid, process) = current_keys()?;
    record_hit(
        event,
        ppid,
        generic_event.ktime,
        process,
        bit_idx,
        true,
        path,
    )
}

#[inline(always)]
fn current_keys() -> Result<(u32, ProcessKey), i32> {
    let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let cur_proc = unsafe { PROCMON_PROC_MAP.get(&current_pid) }.ok_or(0i32)?;
    let mut process = ProcessKey { pid: 0, start: 0 };
    util::process_key_init(&mut process, cur_proc);
    Ok((cur_proc.ppid, process))
}

#[inline(always)]
fn record_hit(
    event: &mut SysEnumMonMsg,
    ppid: u32,
    now: u64,
    process: ProcessKey,
    bit_idx: u8,
    file_open: bool,
    name: &[u8],
) -> Result<i32, i32> {
    let config_ptr = SYSENUMMON_CONFIG.get_ptr(0).ok_or(-1i32)?;
    let config = unsafe { config_ptr.as_ref() }.ok_or(-1i32)?;
    let chain_size = config.chain_size;
    let window_ns = config.window_ns;
    if chain_size == 0 {
        return Err(0);
    }

    let state_ptr = if let Some(ptr) = SYSENUMMON_STATE.get_ptr_mut(&ppid) {
        ptr
    } else {
        let tmpl_ptr = SYSENUMMON_STATE_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
        unsafe { core::ptr::write_bytes(tmpl_ptr, 0, 1) };
        let tmpl = unsafe { &*tmpl_ptr };
        SYSENUMMON_STATE
            .insert(&ppid, tmpl, BPF_ANY as u64)
            .map_err(|x| x as i32)?;
        SYSENUMMON_STATE.get_ptr_mut(&ppid).ok_or(-1i32)?
    };
    let state = unsafe { &mut *state_ptr };

    if state.chain_len > 0 && now.saturating_sub(state.chain[0].timestamp_ns) > window_ns {
        state.chain_len = 0;
    }

    let len = state.chain_len as usize;
    let mut i: usize = 0;
    while i < SYSENUMMON_CHAIN_MAX {
        if i >= len {
            break;
        }
        if state.chain[i].bit_idx == bit_idx {
            return Err(0);
        }
        i += 1;
    }

    if (state.chain_len as usize) >= SYSENUMMON_CHAIN_MAX {
        return Err(0);
    }
    let pos = state.chain_len as usize;
    state.chain[pos].timestamp_ns = now;
    state.chain[pos].process = process;
    state.chain[pos].bit_idx = bit_idx;
    state.chain[pos].file_open = file_open;
    state.chain[pos].name_len = name.len().min(MAX_FILE_PREFIX) as u16;
    unsafe {
        let _ = bpf_probe_read_kernel_buf(name.as_ptr(), &mut state.chain[pos].name);
    }
    state.chain_len = state.chain_len.saturating_add(1);

    if state.chain_len < chain_size {
        return Err(0);
    }

    event.chain_len = state.chain_len;
    let len = state.chain_len as usize;
    let mut i: usize = 0;
    while i < SYSENUMMON_CHAIN_MAX {
        if i >= len {
            break;
        }
        let dst = unsafe {
            core::slice::from_raw_parts_mut(
                &mut event.chain[i] as *mut ChainItem as *mut u8,
                core::mem::size_of::<ChainItem>(),
            )
        };
        unsafe {
            let _ =
                bpf_probe_read_kernel_buf(&state.chain[i] as *const ChainItem as *const u8, dst);
        }
        i += 1;
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
