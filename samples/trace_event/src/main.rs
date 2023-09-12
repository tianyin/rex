#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::linux::bpf::*;
use inner_unikernel_rt::linux::perf_event::PERF_MAX_STACK_DEPTH;
use inner_unikernel_rt::map::*;
use inner_unikernel_rt::perf_event::*;
use inner_unikernel_rt::{entry_link, MAP_DEF};

pub const TASK_COMM_LEN: usize = 16;

// What if user does not use repr(C)?
#[repr(C)]
#[derive(Copy, Clone)]
pub struct KeyT {
    pub comm: [i8; TASK_COMM_LEN],
    pub kernstack: u32,
    pub userstack: u32,
}

MAP_DEF!(counts, KeyT, u64, BPF_MAP_TYPE_HASH, 10000, 0);

MAP_DEF!(
    stackmap,
    u32,
    [u64; PERF_MAX_STACK_DEPTH as usize],
    BPF_MAP_TYPE_STACK_TRACE,
    10000,
    0
);

pub const KERN_STACKID_FLAGS: u64 = BPF_F_FAST_STACK_CMP as u64;
pub const USER_STACKID_FLAGS: u64 = (BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK) as u64;

fn iu_prog1_fn(obj: &perf_event, ctx: &bpf_perf_event_data) -> u32 {
    let cpu: u32 = obj.bpf_get_smp_processor_id();
    let value_buf: bpf_perf_event_value = bpf_perf_event_value {
        counter: 0,
        enabled: 0,
        running: 0,
    };
    let mut key: KeyT = KeyT {
        comm: [0; TASK_COMM_LEN],
        kernstack: 0,
        userstack: 0,
    };
    if ctx.sample_period < 10000 {
        return 0;
    }

    if let Some(current) = obj.bpf_get_current_task() {
        current.get_comm(&mut key.comm);
    } else {
        return 0;
    }

    key.kernstack = obj.bpf_get_stackid_pe(ctx, &stackmap, KERN_STACKID_FLAGS) as u32;
    key.userstack = obj.bpf_get_stackid_pe(ctx, &stackmap, USER_STACKID_FLAGS) as u32;

    if (key.kernstack as i32) < 0 && (key.userstack as i32) < 0 {
        obj.bpf_trace_printk(
            "CPU-%d period %lld ip %llx",
            cpu as u64,
            ctx.sample_period,
            ctx.regs.rip(),
        );
        return 0;
    }

    let ret = obj.bpf_perf_prog_read_value(ctx, &value_buf);

    if ret == 0 {
        obj.bpf_trace_printk(
            "Time Enabled: %llu, Time Running: %llu",
            value_buf.enabled,
            value_buf.running,
            0,
        );
    } else {
        obj.bpf_trace_printk("Get Time Failed, ErrCode: %d", ret as u64, 0, 0);
    }

    if ctx.addr != 0 {
        obj.bpf_trace_printk("Address recorded on event: %llx", ctx.addr, 0, 0);
    }

    match obj.bpf_map_lookup_elem(&counts, key) {
        None => {
            obj.bpf_map_update_elem(&counts, key, 1, BPF_NOEXIST as u64);
        }
        Some(val) => {
            *val += 1;
        }
    }
    0
}

#[entry_link(inner_unikernel/perf_event)]
static PROG: perf_event = perf_event::new(iu_prog1_fn, "iu_prog1");
