#![no_std]
#![no_main]

extern crate inner_unikernel_rt;
extern crate rlibc;

use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::linux::bpf::*;
use inner_unikernel_rt::sysctl::{str_to_i64, str_to_u64};
use inner_unikernel_rt::tracepoint::*;

fn iu_prog1_fn(obj: &tracepoint, ctx: &tp_ctx) -> u32 {
    let option_task = obj.bpf_get_current_task();

    let time = obj.bpf_ktime_get_ns();
    bpf_printk!(obj, "Time: %llu\n", time);
    let origin_time = obj.bpf_ktime_get_boot_ns_origin();
    bpf_printk!(obj, "Origin Time: %llu\n", origin_time);
    assert!(origin_time - time < u64::MAX / 10000);

    let boot_time = obj.bpf_ktime_get_boot_ns();
    bpf_printk!(obj, "Boot Time: %llu\n", boot_time);
    let origin_boot_time = obj.bpf_ktime_get_boot_ns_origin();
    bpf_printk!(obj, "Origin Boot Time: %llu\n", origin_boot_time);
    assert!(origin_boot_time - boot_time < u64::MAX / 10000);

    let coarse_time = obj.bpf_ktime_get_coarse_ns();
    bpf_printk!(obj, "Coarse Time: %llu\n", coarse_time);

    let u32_random = obj.bpf_get_prandom_u32();
    bpf_printk!(obj, "Random: %llu\n", u32_random as u64);

    // test string_to_u64
    let test_num = str_to_u64("1234234");
    bpf_printk!(obj, "Test Num: %llu\n", test_num);

    0
}

#[link_section = "tracepoint/syscalls/sys_enter_dup"]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_ctx::Void);
