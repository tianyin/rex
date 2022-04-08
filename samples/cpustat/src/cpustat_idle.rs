#![no_std]
#![no_main]

extern crate rlibc;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};
mod stub;

pub const MAX_CPU: u32 = 8;
pub const MAX_PSTATE_ENTRIES: u32 = 5;
pub const MAX_CSTATE_ENTRIES: u32 = 3;

pub const MAP_OFF_CSTATE_TIME: u32 = 0;
pub const MAP_OFF_CSTATE_IDX: u32 = 1;
pub const MAP_OFF_PSTATE_TIME: u32 = 2;
pub const MAP_OFF_PSTATE_IDX: u32 = 3;
pub const MAP_OFF_NUM: u32 = 4;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cpu_args {
    pub pad: u64,
    pub state: u32,
    pub cpu_id: u32,
}

fn bpf_map_lookup_elem<K, V>(map: u32, key: K) -> Option<V>
where
    V: Copy,
{
    let f_ptr = stub::STUB_BPF_LOOKUP_ELEM as *const ();
    let helper: extern "C" fn(u32, *const K) -> *mut V = unsafe { core::mem::transmute(f_ptr) };

    let value = helper(map, &key) as *mut V;

    if value.is_null() {
        None
    } else {
        Some(unsafe { *value })
    }
}

fn bpf_map_update_elem<K, V>(map: u32, key: K, value: V, flags: u64) -> u64 {
    let f_ptr = stub::STUB_BPF_UPDATE_ELEM as *const ();
    let helper: extern "C" fn(u32, *const K, *const V, u64) -> u64 =
        unsafe { core::mem::transmute(f_ptr) };

    helper(map, &key, &value, flags)
}

fn bpf_ktime_get_ns() -> u64 {
    let f_ptr = stub::STUB_BPF_KTIME_GET_NS as *const ();
    let helper: extern "C" fn() -> u64 = unsafe { core::mem::transmute(f_ptr) };
    helper()
}

fn find_cpu_pstate_idx (frequency: u32) -> u32 {
    let mut i: u32 = 0;
    let cpu_opps = [ 208000, 432000, 729000, 960000, 1200000 ];
    for elem in cpu_opps {
        if frequency == elem {
            return i;
        }
        i += 1;
    }
    return i;
}

#[no_mangle]
pub extern "C" fn _start(ctx: &cpu_args) -> u32 {
    let (cstate_duration, pstate_duration, my_map): (u32, u32, u32) = (0, 1, 2);
    let (mut cts, mut pts, mut cstate, pstate, prev_state, cur_ts, mut delta): (u64, u64, u64, u64, u64, u64, u64);
	let (ctkey, cskey, ptkey, pskey, vkey, cpu, pstate_idx): (u32, u32, u32, u32, u32, u32, u32);
    let value = AtomicU64::new(0);

    if ctx.cpu_id > MAX_CPU {
		return 0;
    }

	cpu = ctx.cpu_id;
    ctkey = cpu * MAP_OFF_NUM + MAP_OFF_CSTATE_TIME;
    match bpf_map_lookup_elem::<u32, u64>(my_map, ctkey) {
        None => {
            return 0;
        }
        Some(val) => {
            cts = val;
        }
    }

    cskey = cpu * MAP_OFF_NUM + MAP_OFF_CSTATE_IDX;
    match bpf_map_lookup_elem::<u32, u64>(my_map, cskey) {
        None => {
            return 0;
        }
        Some(val) => {
            cstate = val;
        }
    }

    ptkey = cpu * MAP_OFF_NUM + MAP_OFF_PSTATE_TIME;
    match bpf_map_lookup_elem::<u32, u64>(my_map, ptkey) {
        None => {
            return 0;
        }
        Some(val) => {
            pts = val;
        }
    }

    pskey = cpu * MAP_OFF_NUM + MAP_OFF_PSTATE_IDX;
    match bpf_map_lookup_elem::<u32, u64>(my_map, pskey) {
        None => {
            return 0;
        }
        Some(val) => {
            pstate = val;
        }
    }

    prev_state = cstate;
    cstate = ctx.state as u64;
    bpf_map_update_elem(my_map, cskey, cstate, stub::BPF_ANY);

    if cts == 0 {
        cts = bpf_ktime_get_ns();
        bpf_map_update_elem(my_map, ctkey, cts, stub::BPF_ANY);
        return 0;
    }
    cur_ts = bpf_ktime_get_ns();
    delta = cur_ts - cts;
    cts = cur_ts;
    bpf_map_update_elem(my_map, ctkey, cts, stub::BPF_ANY);

    if ctx.state != u32::MAX {
        if pts == 0 {
            return 0;
        }
        delta = cur_ts - pts;
        pstate_idx = find_cpu_pstate_idx(pstate as u32);
        if pstate_idx >= MAX_PSTATE_ENTRIES {
            return 0;
        }
        vkey = cpu * MAX_PSTATE_ENTRIES + pstate_idx;
        match bpf_map_lookup_elem::<u32, u64>(pstate_duration, vkey) {
            None => {

            }
            Some(val) => {
                value.store(val, Ordering::Relaxed);
                value.fetch_add(delta, Ordering::Relaxed);
                bpf_map_update_elem(pstate_duration, vkey, value.load(Ordering::Relaxed), stub::BPF_ANY);
            }
        }
    }
    else {
        vkey = cpu * MAX_CSTATE_ENTRIES + prev_state as u32;
        match bpf_map_lookup_elem::<u32, u64>(cstate_duration, vkey) {
            None => {

            }
            Some(val) => {
                value.store(val, Ordering::Relaxed);
                value.fetch_add(delta, Ordering::Relaxed);
                bpf_map_update_elem(cstate_duration, vkey, value.load(Ordering::Relaxed), stub::BPF_ANY);
            }
        }
    }

    if pts != 0 {
        pts = cur_ts;
        bpf_map_update_elem(my_map, ptkey, pts, stub::BPF_ANY);
    }
    return 0;
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}