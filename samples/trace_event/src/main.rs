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

MAP_DEF!(
    counts, __counts,
    key_t, u64, BPF_MAP_TYPE_HASH, 10000, 0
);

MAP_DEF!(
    stackmap, __stackmap,
    u32, [u64; PERF_MAX_STACK_DEPTH], BPF_MAP_TYPE_STACK_TRACE, 10000, 0
);

// #define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
// #define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)
pub const KERN_STACKID_FLAGS: u64 = (0 | BPF_F_FAST_STACK_CMP) as u64;
pub const USER_STACKID_FLAGS: u64 = (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK) as u64;

#[no_mangle]
#[link_section = "perf_event"]
fn iu_prog1(ctx: &bpf_perf_event_data) -> i32 {
    let mut key: key_t = key_t {
        comm: [0; TASK_COMM_LEN],
        kernstack: 0,
        userstack: 0,
    };

    bpf_trace_printk!("sample period: %lu\n", u64: (*ctx).sample_period);

    if ((*ctx).sample_period < 10000) {
        return 0;
    }

    bpf_get_current_comm::<i8>(&key.comm[0], TASK_COMM_LEN);

    bpf_trace_printk!("command: %s\n", &i8: &key.comm[0]);

    key.kernstack = bpf_get_stackid::<bpf_perf_event_data, IUMap<u32, [u64; PERF_MAX_STACK_DEPTH]>>(
        ctx,
        stackmap,
        KERN_STACKID_FLAGS,
    ) as u32;

    bpf_trace_printk!("kernstack: %u\n", u32: key.kernstack);

    match bpf_map_lookup_elem::<key_t, u64>(counts, key) {
        None => {
            bpf_trace_printk!("`key' is encontered the first time. Create record in the map with count one.\n");
            bpf_map_update_elem(counts, key, 1, BPF_NOEXIST.into());
        }
        Some(val) => {
            bpf_trace_printk!("`key' is already in the map. Previous count is %llu. Update its count.\n", u64: val);
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
