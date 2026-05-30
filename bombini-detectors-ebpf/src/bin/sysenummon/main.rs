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

use bombini_common::config::sysenummon::SysEnumMonKernelConfig;
use bombini_common::constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE};
use bombini_common::event::process::{ProcInfo, ProcessKey};
use bombini_common::event::sysenum::{ChainItem, ChainItemType, SYSENUMMON_CHAIN_MAX, SysEnumMsg};
use bombini_common::event::{Event, GenericEvent, MSG_SYSENUM};
use bombini_detectors_ebpf::co_re::{self, core_read_kernel};
use bombini_detectors_ebpf::{event_capture, util};

#[map]
static SYSENUMMON_CONFIG: Array<SysEnumMonKernelConfig> = Array::with_max_entries(1, 0);

#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

/// Per-parent (ppid) correlation state.
#[map]
static SYSENUMMON_STATE: LruHashMap<u32, SysEnumMsg> = LruHashMap::with_max_entries(4096, 0);

/// Watched basename -> watch_idx.
#[map]
static SYSENUMMON_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> = HashMap::with_max_entries(1, 0);

/// Watched full path -> watch_idx.
#[map]
static SYSENUMMON_PATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> = HashMap::with_max_entries(1, 0);

/// Watched path prefix -> watch_idx (LPM).
#[map]
static SYSENUMMON_PATH_PREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static SYSENUMMON_PATH_HEAP: PerCpuArray<[u8; MAX_FILE_PATH]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static SYSENUMMON_NAME_KEY_HEAP: PerCpuArray<[u8; MAX_FILENAME_SIZE]> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static SYSENUMMON_PATH_KEY_HEAP: PerCpuArray<[u8; MAX_FILE_PATH]> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static SYSENUMMON_PREFIX_KEY_HEAP: PerCpuArray<Key<[u8; MAX_FILE_PREFIX]>> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static SYSENUMMON_STATE_HEAP: PerCpuArray<SysEnumMsg> = PerCpuArray::with_max_entries(1, 0);

#[map]
static SYSENUMMON_ITEM_HEAP: PerCpuArray<ChainItem> = PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "bprm_check_security")]
pub fn sysmon_bprm_check(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_SYSENUM, true, try_bprm_check)
}

#[lsm(hook = "file_open")]
pub fn sysmon_file_open(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_SYSENUM, true, try_file_open)
}

fn try_bprm_check(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::SysEnum(ref mut event) = generic_event.event else {
        return Err(-1);
    };

    let name_ptr = SYSENUMMON_NAME_KEY_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let name = unsafe { name_ptr.as_mut() }.ok_or(-1i32)?;
    name.fill(0);

    unsafe {
        let binprm = co_re::linux_binprm::from_ptr(ctx.arg(0));
        let d_name = core_read_kernel!(binprm, file, f_path, dentry, d_name, name).ok_or(-1i32)?;
        bpf_probe_read_kernel_str_bytes(d_name, name).map_err(|_| -1i32)?;
    }

    let watch_idx = unsafe { SYSENUMMON_NAME_MAP.get(name) }
        .copied()
        .ok_or(0i32)?;
    let ppid = current_ppid()?;
    record_hit(
        event,
        ppid,
        generic_event.ktime,
        watch_idx,
        ChainItemType::Exec(*name),
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
    path_key.fill(0);

    let prefix_key_ptr = SYSENUMMON_PREFIX_KEY_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let prefix_key = unsafe { prefix_key_ptr.as_mut() }.ok_or(-1i32)?;
    prefix_key.prefix_len = (MAX_FILE_PREFIX * 8) as u32;
    prefix_key.data.fill(0);

    unsafe {
        let fp = co_re::file::from_ptr(ctx.arg(0));
        let f_path = core_read_kernel!(fp, f_path).ok_or(-1i32)?;
        let _ = bpf_d_path(
            f_path.as_ptr() as *mut aya_ebpf::bindings::path,
            path.as_mut_ptr() as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path.as_ptr(), path_key).map_err(|_| -1i32)?;
        let _ = bpf_probe_read_kernel_buf(path.as_ptr(), &mut prefix_key.data);
    }

    let watch_idx = unsafe { SYSENUMMON_PATH_MAP.get(path_key) }
        .or_else(|| SYSENUMMON_PATH_PREFIX_MAP.get(prefix_key))
        .copied()
        .ok_or(0i32)?;

    let ppid = current_ppid()?;
    record_hit(
        event,
        ppid,
        generic_event.ktime,
        watch_idx,
        ChainItemType::FileOpen(prefix_key.data),
    )
}

#[inline(always)]
fn current_ppid() -> Result<u32, i32> {
    let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let cur_proc = unsafe { PROCMON_PROC_MAP.get(&current_pid) }.ok_or(0i32)?;
    Ok(cur_proc.ppid)
}

#[inline(always)]
fn record_hit(
    event: &mut SysEnumMsg,
    ppid: u32,
    now: u64,
    watch_idx: u8,
    entry: ChainItemType,
) -> Result<i32, i32> {
    let config_ptr = SYSENUMMON_CONFIG.get_ptr(0).ok_or(-1i32)?;
    let config = unsafe { config_ptr.as_ref() }.ok_or(-1i32)?;
    let chain_size = config.chain_size;
    let window_ns = config.window_ns;
    if chain_size == 0 {
        return Err(0);
    }

    let process = match unsafe { PROCMON_PROC_MAP.get(&ppid) } {
        Some(parent) if !parent.exited => {
            let mut key = ProcessKey { pid: 0, start: 0 };
            util::process_key_init(&mut key, parent);
            key
        }
        _ => {
            let _ = SYSENUMMON_STATE.remove(&ppid);
            return Err(0);
        }
    };

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

    let len = (state.chain_len as usize) & SYSENUMMON_CHAIN_MAX;

    // Skip if this watch_idx is already in the current chain (dedup).
    let mut i = 0;
    while i < len {
        if state.watch_ids[i] == watch_idx {
            return Err(0);
        }
        i += 1;
    }

    if len >= SYSENUMMON_CHAIN_MAX {
        return Err(0);
    }

    let pos = len;
    state.process = process;
    state.watch_ids[pos] = watch_idx;

    let item_ptr = SYSENUMMON_ITEM_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let item = unsafe { &mut *item_ptr };
    item.timestamp_ns = now;
    item.entry = entry;

    let dst = unsafe {
        core::slice::from_raw_parts_mut(
            &mut state.chain[pos] as *mut ChainItem as *mut u8,
            core::mem::size_of::<ChainItem>(),
        )
    };
    unsafe {
        let _ = bpf_probe_read_kernel_buf(item_ptr as *const u8, dst);
    }

    let new_len = (len + 1) as u8;
    state.chain_len = new_len;

    if new_len >= chain_size {
        let event_dst = unsafe {
            core::slice::from_raw_parts_mut(
                event as *mut SysEnumMsg as *mut u8,
                core::mem::size_of::<SysEnumMsg>(),
            )
        };
        unsafe {
            let _ = bpf_probe_read_kernel_buf(state as *const SysEnumMsg as *const u8, event_dst);
        }
        return Ok(0);
    }

    Err(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
