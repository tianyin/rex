#![no_std]

pub mod linux;
pub mod map;
//pub mod perf_event; FIXME later
pub mod prog_type;
pub mod tracepoint;

mod base_helper;
mod stub;

use core::panic::PanicInfo;

#[macro_export]
macro_rules! PROG_DEF {
    ($f:ident, $n:ident, perf_event) => {
        #[no_mangle]
        #[link_section = "perf_event"]
        pub extern "C" fn $n(ctx: *const ()) -> i64 {
            // convert ctx
            let new_ctx = <perf_event>::new().convert_ctx(ctx);
            $f(&new_ctx).into()
        }
    };

    ($f:ident, $n:ident, tracepoint, $t:ident) => {
        TP_DEF!($f, $n, $t);
    };
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
