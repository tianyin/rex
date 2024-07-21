#![no_std]
#![no_main]

extern crate rex;

use rex::linux::bpf::bpf_spin_lock;
use rex::map::RexArrayMap;
use rex::spinlock::rex_spinlock_guard;
use rex::xdp::*;
use rex::{bpf_printk, rex_xdp};
use rex::{rex_map, Result};

#[repr(C)]
struct MapEntry {
    data: u64,
    lock: bpf_spin_lock,
}

#[rex_map]
static MAP_ARRAY: RexArrayMap<MapEntry> = RexArrayMap::new(256, 0);

#[rex_xdp]
fn rex_prog1(obj: &xdp, _: &mut xdp_md) -> Result {
    if let Some(entry) = obj.bpf_map_lookup_elem(&MAP_ARRAY, &0) {
        let start = obj.bpf_ktime_get_ns();
        {
            let _guard = rex_spinlock_guard::new(&mut entry.lock);
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
