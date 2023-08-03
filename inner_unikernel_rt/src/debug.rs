use core::any::Any;
use core::ffi::VaList;

use core::ffi::{c_int, CStr};

use crate::stub;

// WARN must add "\0" at the end of &str, c_str is differ from rust str
#[allow(improper_ctypes_definitions)]
pub(crate) unsafe extern "C" fn printk(fmt: &str, mut ap: ...) -> c_int {
    let printk_kern: extern "C" fn(*const u8, ...) -> i32 =
        unsafe { core::mem::transmute(stub::_printk_addr()) };
    printk_kern(fmt.as_ptr(), ap)
}
