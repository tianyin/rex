#![no_std]
#![no_main]
#![feature(bench_black_box)]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::entry_link;
use inner_unikernel_rt::linux::bpf::BPF_MAP_TYPE_ARRAY;
use inner_unikernel_rt::map::IUMap;
// use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::kprobe::*;
use inner_unikernel_rt::Result;
use inner_unikernel_rt::MAP_DEF;

MAP_DEF!(data_map, u32, u32, BPF_MAP_TYPE_ARRAY, 2, 0);

#[inline(always)]
fn iu_recursive(obj: &kprobe, _:&mut pt_regs) -> Result {
    let curr_pid: i32 = if let Some(task_struct) = obj.bpf_get_current_task() {
        task_struct.get_pid()
    } else {
    bpf_printk!(obj, "error 1");
        return Err(0);
    };

    let stored_pid: u32 = if let Some(val) = obj.bpf_map_lookup_elem(&data_map, &0) {
        *val
    } else {
    bpf_printk!(obj, "error 2");
        return Err(0);
    };

    // if (stored_pid as i32) != curr_pid {
    // bpf_printk!(obj, "error 3");
    //     return Err(0);
    // }

    let start_time: u64 = obj.bpf_ktime_get_ns();
    bpf_printk!(obj, "Start time: %ul", start_time);
    let n: u32 = if let Some(val) = obj.bpf_map_lookup_elem(&data_map, &1) {
        *val
    } else {
    bpf_printk!(obj, "error 4");
        return Err(0);
    };

    bpf_printk!(obj, "Received n: %d", n as u64);
    let result = calculate_tail_factorial(n, 1);
    bpf_printk!(obj, "Result: %d", result as u64);

    let end_time: u64 = obj.bpf_ktime_get_ns();
    bpf_printk!(obj, "End time: %ul", end_time);

    Ok(0)
}

use core::hint::black_box;
#[inline(never)]
fn calculate_tail_factorial(n: u32, accum: u32) -> u32 {
    if n == 1 {
        return accum;
    }

    return black_box(calculate_tail_factorial(n - 1, accum * n));
}

#[entry_link(inner_unikernel/kprobe/kprobe_target_func)]
static PROG: kprobe = kprobe::new(iu_recursive, "iu_recursive");
