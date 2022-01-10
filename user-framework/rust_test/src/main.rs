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
        {
            // Add the missing null terminator
            let mut fmt_arr: [u8; $s.len() + 1] = Default::default();
            for (i, c) in $s.chars().enumerate() {
                fmt_arr[i] = c as u8
            }
            fmt_arr[$s.len()] = 0;
            let fmt_str = fmt_arr.as_mut_ptr();

            let ptr = interface::STUB_BPF_TRACE_PRINTK as *const ();
            let code: extern "C" fn(*const u8, u32, $($t),*) -> i64 = unsafe { core::mem::transmute(ptr) };
            code(fmt_str, ($s.len() + 1) as u32, $($a),*)
        }
    };
}

#[no_mangle]
pub extern "C" fn _start() -> i32 {
    let pid = bpf_get_current_pid_tgid();
    bpf_trace_printk!("Rust triggered from PID %u.\n", u32: pid);
    return 0;
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
