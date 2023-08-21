use core::any::Any;
use core::ffi::{c_uchar, VaList};

use core::ffi::{c_char, c_int, CStr};

use crate::stub;

// WARN must add "\0" at the end of &str, c_str is different from rust str
#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub(crate) unsafe extern "C" fn printk(fmt: &str, mut ap: ...) -> c_int {
    let printk_kern: extern "C" fn(*const c_uchar, VaList) -> i32 =
        unsafe { core::mem::transmute(stub::vprintk_addr()) };
    printk_kern(fmt.as_ptr() as *const c_uchar, ap.as_va_list())
}
