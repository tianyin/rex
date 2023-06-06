#![no_std]
#![no_main]

extern crate inner_unikernel_rt;
extern crate rlibc;

use inner_unikernel_rt::linux::bpf::*;
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::MAP_DEF;
use inner_unikernel_rt::{bpf_printk, tracepoint::*};

MAP_DEF!(map_hash, __map_1, u32, i64, BPF_MAP_TYPE_HASH, 1024, 0);
MAP_DEF!(map_array, __map_2, u32, u64, BPF_MAP_TYPE_ARRAY, 256, 0);

fn map_test1<const MT: bpf_map_type, K, V>(obj: &tracepoint, map: &IUMap<MT, K, V>) -> u32 {
    let key: u32 = 0;

    bpf_printk!(obj, "Map Testing 1 Start with key %u\n", key as u64);

    match obj.bpf_map_lookup_elem(map_hash, key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu.\n", (*val) as u64);
        }
    }

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, "Rust program triggered from PID %llu\n", pid as u64);

    obj.bpf_map_update_elem(map_hash, key, pid as i64, BPF_ANY.into());
    obj.bpf_trace_printk("Map Updated\n", 0, 0, 0);

    match obj.bpf_map_lookup_elem(map_hash, key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu.\n", (*val) as u64);
        }
    }

    obj.bpf_map_delete_elem(map_hash, key);
    bpf_printk!(obj, "Map delete key\n");

    match obj.bpf_map_lookup_elem(map_hash, key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu.\n", (*val) as u64);
        }
    }

    0
}

fn map_test2<const MT: bpf_map_type, K, V>(obj: &tracepoint, map: &IUMap<MT, K, V>) -> u32 {
    bpf_printk!(obj, "Array Map Testing Start\n");
    let key = 0;

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, "Rust program triggered from PID %llu\n", pid as u64);

    // Add a new element
    obj.bpf_map_update_elem(map_hash, key, pid as i64, BPF_ANY.try_into().unwrap());
    obj.bpf_trace_printk("Map Updated\n", 0, 0, 0);

    match obj.bpf_map_lookup_elem(map_hash, key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu.\n", (*val).try_into().unwrap());
        }
    }
    // let ret = obj.bpf_map_push_elem(map_array, pid as u64, BPF_EXIST.into());
    // bpf_printk!(obj, "Map push ret=%llu\n", ret.try_into().unwrap());

    0
}

fn iu_prog1_fn(obj: &tracepoint, ctx: &tp_ctx) -> u32 {
    map_test1(obj, map_hash);
    map_test1(obj, map_array)
}

#[link_section = "tracepoint/syscalls/sys_enter_dup"]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_ctx::Void);
