#![no_std]
#![no_main]

extern crate rlibc;
use core::panic::PanicInfo;

mod stub;

mod map;
use crate::map::*;

mod helper;
use crate::helper::*;

mod linux;
use crate::linux::bpf::*;

use crate::linux::bpf_perf_event::bpf_perf_event_data;
use crate::linux::bpf_perf_event::pt_regs;

use core::mem::size_of;
use core::mem::size_of_val;

MAP_DEF!(
    counts, __counts,
    key_t, u64, BPF_MAP_TYPE_HASH, 10000, 0
);

MAP_DEF!(
    stackmap, __stackmap,
    u32, [u64; PERF_MAX_STACK_DEPTH], BPF_MAP_TYPE_STACK_TRACE, 10000, 0
);

pub const KERN_STACKID_FLAGS: u64 = (0 | BPF_F_FAST_STACK_CMP) as u64;
pub const USER_STACKID_FLAGS: u64 = (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK) as u64;

fn PT_REGS_IP(x: &pt_regs) -> u64 {
    return (*x).rip;
}

#[no_mangle]
#[link_section = "perf_event"]
fn iu_prog1(ctx: &bpf_perf_event_data) -> i32 {
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
    key.kernstack = bpf_get_stackid_pe::<bpf_perf_event_data, IUMap<u32, [u64; PERF_MAX_STACK_DEPTH]>>(
        ctx,
        stackmap,
        KERN_STACKID_FLAGS,
    ) as u32;
    key.userstack = bpf_get_stackid_pe::<bpf_perf_event_data, IUMap<u32, [u64; PERF_MAX_STACK_DEPTH]>>(
        ctx,
        stackmap,
        USER_STACKID_FLAGS,
    ) as u32;
    if ((key.kernstack as i32) < 0 && (key.userstack as i32) < 0) {
        bpf_trace_printk!(
            "CPU-%d period %lld ip %llx",
            u32: cpu,
            u64: (*ctx).sample_period,
            u64: PT_REGS_IP(&((*ctx).regs))
        );
        return 0;
    }

    let ret: i32 = bpf_perf_prog_read_value(ctx, &value_buf, size_of::<bpf_perf_event_value>()) as i32;
    if (ret == 0) {
        bpf_trace_printk!("Time Enabled: %llu, Time Running: %llu", u64: value_buf.enabled, u64: value_buf.running);
    } else {
        bpf_trace_printk!("Get Time Failed, ErrCode: %d", i32: ret);
    }

    if ((*ctx).addr != 0) {
        bpf_trace_printk!("Address recorded on event: %llx", u64: (*ctx).addr);
    }

    match bpf_map_lookup_elem::<key_t, u64>(counts, key) {
        None => {
            // bpf_trace_printk!("`key' is encontered the first time. Create record in the map with count one.\n");
            bpf_map_update_elem(counts, key, 1, BPF_NOEXIST.into());
        }
        Some(val) => {
            // bpf_trace_printk!("`key' is already in the map. Previous count is %llu. Update its count.\n", u64: val);
            bpf_map_update_elem(counts, key, val+1, BPF_EXIST.into());
        }
    }
    return 0;
}

#[no_mangle]
fn _start(ctx: &bpf_perf_event_data) -> i32 {
    iu_prog1(ctx)
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
