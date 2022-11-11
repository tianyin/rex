#![no_std]
#![no_main]

extern crate rlibc;

extern crate inner_unikernel_rt;

use core::panic::PanicInfo;

use inner_unikernel_rt::linux::bpf::*;
use inner_unikernel_rt::map::*;
use inner_unikernel_rt::perf_event::*;
use inner_unikernel_rt::prog_type::prog_type;
use inner_unikernel_rt::{MAP_DEF, PROG_DEF};

use core::mem::size_of;
use core::mem::size_of_val;

MAP_DEF!(counts, __counts, key_t, u64, BPF_MAP_TYPE_HASH, 10000, 0);

MAP_DEF!(
    stackmap,
    __stackmap,
    u32,
    [u64; PERF_MAX_STACK_DEPTH],
    BPF_MAP_TYPE_STACK_TRACE,
    10000,
    0
);

pub const KERN_STACKID_FLAGS: u64 = (0 | BPF_F_FAST_STACK_CMP) as u64;
pub const USER_STACKID_FLAGS: u64 = (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK) as u64;

fn PT_REGS_IP(x: &pt_regs) -> u64 {
    return (*x).ip;
}

fn __iu_prog1(ctx: &bpf_perf_event_data) -> i32 {
    let cpu: u32 = bpf_get_smp_processor_id();
    let value_buf: bpf_perf_event_value = bpf_perf_event_value {
        counter: 0,
        enabled: 0,
        running: 0,
    };
    let mut key: key_t = key_t {
        comm: [0; TASK_COMM_LEN],
        kernstack: 0,
        userstack: 0,
    };

    if ((*ctx).sample_period < 10000) {
        return 0;
    }
    bpf_get_current_comm::<i8>(&key.comm[0], size_of_val(&key.comm));
    key.kernstack = bpf_get_stackid_pe(ctx, stackmap, KERN_STACKID_FLAGS) as u32;
    key.userstack = bpf_get_stackid_pe(ctx, stackmap, USER_STACKID_FLAGS) as u32;
    if ((key.kernstack as i32) < 0 && (key.userstack as i32) < 0) {
        bpf_trace_printk!(
            "CPU-%d period %lld ip %llx",
            cpu,
            (*ctx).sample_period,
            PT_REGS_IP(&((*ctx).regs))
        );
        return 0;
    }

    let ret: i32 =
        bpf_perf_prog_read_value(ctx, &value_buf, size_of::<bpf_perf_event_value>()) as i32;
    if (ret == 0) {
        bpf_trace_printk!(
            "Time Enabled: %llu, Time Running: %llu",
            value_buf.enabled,
            value_buf.running
        );
    } else {
        bpf_trace_printk!("Get Time Failed, ErrCode: %d", ret);
    }

    if ((*ctx).addr != 0) {
        bpf_trace_printk!("Address recorded on event: %llx", (*ctx).addr);
    }

    match bpf_map_lookup_elem::<key_t, u64>(counts, key) {
        None => {
            bpf_map_update_elem(counts, key, 1, BPF_NOEXIST.into());
        }
        Some(val) => {
            bpf_map_update_elem(counts, key, val + 1, BPF_EXIST.into());
        }
    }
    return 0;
}

PROG_DEF!(__iu_prog1, iu_prog1, perf_event);

#[no_mangle]
fn _start(ctx: *const ()) -> i64 {
    iu_prog1(ctx)
}
