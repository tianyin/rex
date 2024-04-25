#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::linux::bpf::bpf_spin_lock;
use inner_unikernel_rt::map::IUArrayMap;
use inner_unikernel_rt::spinlock::iu_spinlock_guard;
use inner_unikernel_rt::xdp::*;
use inner_unikernel_rt::{entry_link, rex_map, Result};

#[repr(C)]
struct MapEntry {
    data: u64,
    lock: bpf_spin_lock,
}

#[rex_map]
static MAP_ARRAY: IUArrayMap<MapEntry> = IUArrayMap::new(256, 0);

#[inline(always)]
fn iu_prog1_fn(obj: &xdp, _: &mut xdp_md) -> Result {
    if let Some(entry) = obj.bpf_map_lookup_elem(&MAP_ARRAY, &0) {
        let start = obj.bpf_ktime_get_ns();
        {
            let _guard = iu_spinlock_guard::new(&mut entry.lock);
        }
        let end = obj.bpf_ktime_get_ns();
        bpf_printk!(
            obj,
            "Spinlock allocation and cleanup: %llu ns",
            end - start
        );
        Ok(XDP_PASS as i32)
    } else {
        bpf_printk!(obj, "Unable to look up map");
        Err(XDP_PASS as i32)
    }
}

#[entry_link(inner_unikernel/xdp)]
static PROG1: xdp = xdp::new(iu_prog1_fn, "iu_prog1", BPF_PROG_TYPE_XDP as u64);
