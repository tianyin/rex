#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::linux::bpf::*;
use inner_unikernel_rt::map::*;
use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::{bpf_printk, entry_link, rex_map, Result};

#[rex_map]
static MAP_HASH: IUHashMap<u32, u64> = IUHashMap::new(1, 0);

#[rex_map]
static MAP_ARRAY: IUArrayMap<u64> = IUArrayMap::new(1, 0);

fn iu_prog1_fn(obj: &tracepoint, _: tp_ctx) -> Result {
    let zero = 0u32;

    let random = obj.bpf_get_prandom_u32() as u64;
    obj.bpf_map_update_elem(&MAP_HASH, &zero, &random, BPF_ANY as u64)?;

    let start = obj.bpf_ktime_get_ns();
    obj.bpf_map_lookup_elem(&MAP_HASH, &zero);
    let end = obj.bpf_ktime_get_ns();

    bpf_printk!(obj, "Time elapsed: %llu", end - start);

    // let random = obj.bpf_get_prandom_u32() as u64;
    // obj.bpf_map_update_elem(&MAP_ARRAY, &zero, &random, BPF_ANY as u64)?;
    //
    // let start = obj.bpf_ktime_get_ns();
    // obj.bpf_map_lookup_elem(&MAP_ARRAY, &zero);
    // let end = obj.bpf_ktime_get_ns();
    //
    // bpf_printk!(obj, "Time elapsed: %llu", end - start);

    Ok(0)
}

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_getcwd)]
static PROG: tracepoint =
    tracepoint::new(iu_prog1_fn, "iu_prog1", tp_type::Void);
