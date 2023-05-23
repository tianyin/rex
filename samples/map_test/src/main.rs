#![no_std]
#![no_main]

extern crate inner_unikernel_rt;
extern crate rlibc;

use inner_unikernel_rt::linux::bpf::{BPF_ANY, BPF_MAP_TYPE_HASH};
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::MAP_DEF;

MAP_DEF!(map1, __map_1, i32, i64, BPF_MAP_TYPE_HASH, 1024, 0);

fn iu_prog1_fn(obj: &tracepoint, ctx: &tp_ctx) -> u32 {
    let key: i32 = 0;

    match obj.bpf_map_lookup_elem(map1, key) {
        None => {
            obj.bpf_trace_printk("Not found.\n", 0, 0, 0);
        }
        Some(val) => {
            obj.bpf_trace_printk("Val=%llu.\n", *val as u64, 0, 0);
        }
    }

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    obj.bpf_trace_printk("Rust program triggered from PID %u.\n", pid as u64, 0, 0);
    obj.bpf_map_update_elem(map1, key, pid as i64, BPF_ANY.into());

    return 0;
}

#[link_section = "tracepoint/syscalls/sys_enter_dup"]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_ctx::Void);
