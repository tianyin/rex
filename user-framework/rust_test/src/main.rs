#![no_std]
#![no_main]

use core::panic::PanicInfo;
pub mod interface;

#[inline(always)]
fn bpf_get_current_pid_tgid() -> u32 {
    let ptr = interface::STUB_BPF_GET_CURRENT_PID_TGID as *const ();
    let code: extern "C" fn() -> u64 = unsafe { core::mem::transmute(ptr) };
    let ret = (code)();
    (ret & 0xFFFFFFFF) as u32
}

macro_rules! bpf_trace_printk {
    ($s:expr,$($t:ty : $a:expr),*) => {
        let ptr = interface::STUB_BPF_TRACE_PRINTK as *const ();
        let code: extern "C" fn(&str, $($t),*) -> i64 = unsafe { core::mem::transmute(ptr) };
        code($s, $($a),*)
    };
}

#[no_mangle]
pub extern "C" fn _start() -> i32 {
    let pid = bpf_get_current_pid_tgid();
    bpf_trace_printk!("Rust triggered from PID %u.\n\0", u32: pid);
    return 0;
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
