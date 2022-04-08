#![no_std]
#![no_main]

extern crate rlibc;
use core::panic::PanicInfo;
pub mod interface;

fn bpf_get_current_pid_tgid() -> u64 {
    let ptr = interface::STUB_BPF_GET_CURRENT_PID_TGID as *const ();
    let code: extern "C" fn() -> u64 = unsafe { core::mem::transmute(ptr) };
    code()
}

macro_rules! bpf_trace_printk {
    ($s:expr) => {
        {
            // Add the missing null terminator
            let mut fmt_arr: [u8; $s.len() + 1] = [0; $s.len() + 1];
            for (i, c) in $s.chars().enumerate() {
                fmt_arr[i] = c as u8
            }
            fmt_arr[$s.len()] = 0;
            let fmt_str = fmt_arr.as_ptr();

            let ptr = interface::STUB_BPF_TRACE_PRINTK as *const ();
            let code: extern "C" fn(*const u8, u32) -> i64 =
                unsafe { core::mem::transmute(ptr) };

            code(fmt_str, ($s.len() + 1) as u32)
        }
    };

    ($s:expr,$($t:ty : $a:expr),*) => {
        {
            // Add the missing null terminator
            let mut fmt_arr: [u8; $s.len() + 1] = [0; $s.len() + 1];
            for (i, c) in $s.chars().enumerate() {
                fmt_arr[i] = c as u8
            }
            fmt_arr[$s.len()] = 0;
            let fmt_str = fmt_arr.as_ptr();

            let ptr = interface::STUB_BPF_TRACE_PRINTK as *const ();
            let code: extern "C" fn(*const u8, u32, $($t),*) -> i64 =
                unsafe { core::mem::transmute(ptr) };

            code(fmt_str, ($s.len() + 1) as u32, $($a),*)
        }
    };
}

#[no_mangle]
pub extern "C" fn _start() -> i32 {
    let pid = bpf_get_current_pid_tgid();
    bpf_trace_printk!("Rust triggered from PID %u.\n", u32: pid as u32);
    return 0;
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
