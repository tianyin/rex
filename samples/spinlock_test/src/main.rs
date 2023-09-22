#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::{entry_link, Result, MAP_DEF};
use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::linux::bpf::{bpf_spin_lock, BPF_MAP_TYPE_ARRAY};
use inner_unikernel_rt::spinlock::iu_spinlock_guard;
use inner_unikernel_rt::map::IUMap;

#[repr(C)]
struct MapEntry {
    data: u64,
    lock: bpf_spin_lock,
}

MAP_DEF!(map_array, u32, MapEntry, BPF_MAP_TYPE_ARRAY, 256, 0);

fn iu_prog1_fn(obj: &tracepoint, _: tp_ctx) -> Result {
    if let Some(entry) = obj.bpf_map_lookup_elem(&map_array, &0) {
        // entry.lock locked in iu_spinlock_guard::new
        let _guard = iu_spinlock_guard::new(&mut entry.lock);
        entry.data = 1;
        // entry.lock is automatically released when _guard goes out of scope
    }
    Ok(0)
}

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_dup)]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_type::Void);
