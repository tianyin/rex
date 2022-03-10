#![no_std]
#![no_main]

mod helpers;
mod linux_bpf;
mod stub;
use crate::helpers::*;
use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn _start() -> i32 {
    return 0;
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
