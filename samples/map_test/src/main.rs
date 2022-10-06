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

#[no_mangle]
#[link_section = "tracepoint/syscalls/sys_enter_dup"]
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
