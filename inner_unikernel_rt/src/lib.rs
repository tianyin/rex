#![no_std]

pub mod linux;
pub mod perf_event;

mod prog_type;
mod stub;

// extern crate rlibc;

use core::panic::PanicInfo;

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
