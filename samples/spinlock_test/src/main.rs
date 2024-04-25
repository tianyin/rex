#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::linux::bpf::bpf_spin_lock;
use inner_unikernel_rt::map::IUArrayMap;
use inner_unikernel_rt::spinlock::iu_spinlock_guard;
use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::{entry_link, rex_map, Result};

#[repr(C)]
struct MapEntry {
    data: u64,
    lock: bpf_spin_lock,
}

#[rex_map]
static MAP_ARRAY: IUArrayMap<MapEntry> = IUArrayMap::new(256, 0);

fn test1(obj: &tracepoint) {
    if let Some(entry) = obj.bpf_map_lookup_elem(&MAP_ARRAY, &0) {
        // entry.lock locked in iu_spinlock_guard::new
        let _guard = iu_spinlock_guard::new(&mut entry.lock);
        entry.data = 1;
        // entry.lock is automatically released when _guard goes out of scope
    }
}

fn test2(obj: &tracepoint) {
    if let Some(entry) = obj.bpf_map_lookup_elem(&MAP_ARRAY, &0) {
        // entry.lock locked in iu_spinlock_guard::new
        let _guard = iu_spinlock_guard::new(&mut entry.lock);
        entry.data = 1;
        panic!("test\n");
        // entry.lock is automatically released by cleanup mechanism
    }
}

#[inline(always)]
fn iu_prog1_fn(obj: &tracepoint, _: tp_ctx) -> Result {
    test1(obj);
    test2(obj);
    Ok(0)
}

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_dup)]
static PROG: tracepoint =
    tracepoint::new(iu_prog1_fn, "iu_prog1", tp_type::Void);
