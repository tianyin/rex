#![no_std]
#![no_main]

extern crate rex;

use rex::linux::bpf::*;
use rex::map::*;
use rex::tracepoint::*;
use rex::{bpf_printk, rex_map, rex_tracepoint, Result};

#[rex_map]
static MAP_HASH: RexHashMap<u32, u64> = RexHashMap::new(1, 0);

#[rex_map]
static MAP_ARRAY: RexArrayMap<u64> = RexArrayMap::new(1, 0);

#[rex_tracepoint(name = "syscalls/sys_enter_getcwd", tp_type = "Void")]
fn rex_prog1_fn(obj: &tracepoint, _: tp_ctx) -> Result {
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
