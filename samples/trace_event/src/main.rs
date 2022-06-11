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

MAP_DEF!(map1, __map_1, i32, i64, BPF_MAP_TYPE_HASH, 1024, 0);

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
#[link_section = "tracepoint/"]
fn iu_prog1() -> i32 {
    let key: i32 = 0;

    match bpf_map_lookup_elem::<i32, i64>(map1, key) {
        None => {
            bpf_trace_printk!("Not found.\n");
        }
        Some(val) => {
            bpf_trace_printk!("Val=%llu.\n", i64: val);
        }
    }

    let pid = (bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    bpf_trace_printk!("Rust program triggered from PID %u.\n", u32: pid);

    bpf_map_update_elem(map1, key, pid as i64, BPF_ANY.into());
    return 0;
}

#[no_mangle]
fn _start() -> i32 {
    iu_prog1()
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
