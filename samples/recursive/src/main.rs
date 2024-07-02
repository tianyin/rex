#![no_std]
#![no_main]
#![feature(bench_black_box)]

extern crate rex;

use rex::bpf_printk;
use rex::entry_link;
use rex::linux::bpf::BPF_MAP_TYPE_ARRAY;
use rex::map::RexMap;
// use rex::tracepoint::*;
use core::hint::black_box;
use rex::kprobe::*;
use rex::map::RexArrayMap;
use rex::rex_map;
use rex::Result;

#[rex_map]
static data_map: RexArrayMap<u32> = RexArrayMap::new(2, 0);

#[inline(always)]
fn iu_recursive(obj: &kprobe, ctx: &mut pt_regs) -> Result {
    // let curr_pid: i32 = if let Some(task_struct) = obj.bpf_get_current_task()
    // {     task_struct.get_pid()
    // } else {
    //     return Err(0);
    // };

    // let stored_pid: u32 = if let Some(val) =
    // obj.bpf_map_lookup_elem(&data_map, &0) {     *val
    // } else {
    //     return Err(0);
    // };

    let n = ctx.rdi() as u32;
    // let n: u32 = if let Some(val) = obj.bpf_map_lookup_elem(&data_map, &1) {
    //     *val
    // } else {
    //     return Err(0);
    // };

    // bpf_printk!(obj, "Received n: %d", n as u64);
    let start_time: u64 = obj.bpf_ktime_get_ns();
    calculate_tail_fib(n);
    let end_time: u64 = obj.bpf_ktime_get_ns();
    // bpf_printk!(obj, "Result: %d", result as u64);

    bpf_printk!(obj, "Time: %llu", end_time - start_time);

    Ok(0)
}

#[inline(never)]
fn calculate_tail_fib(n: u32) {
    if n == 0 {
        return;
    }

    black_box(calculate_tail_fib(n - 1))
}

#[entry_link(inner_unikernel/kprobe/kprobe_target_func)]
static PROG: kprobe = kprobe::new(iu_recursive, "iu_recursive");
