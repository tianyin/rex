#![no_std]
#![no_main]

extern crate rlibc;
use core::panic::PanicInfo;

pub mod helper;
pub mod stub;
use crate::helper::*;

#[no_mangle]
#[link_section = "tracepoint/"]
pub extern "C" fn _start() -> i32 {
    let pid = (bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    bpf_trace_printk!("Rust triggered from PID %u.\n", u32: pid);
    return 0;
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
