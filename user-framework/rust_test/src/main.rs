
#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let ptr = 0x0000000000401370 as *const ();
    let code: extern "C" fn() = unsafe { core::mem::transmute(ptr) };
    (code)();
    loop {}
}

/// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}


