use core::ffi::{self as core_ffi, CStr};

use crate::bindings::linux::kernel::task_struct;
use crate::ffi;
use crate::per_cpu::this_cpu_read;
use crate::pt_regs::PtRegs;

// Bindgen has problem generating these constants
const TOP_OF_KERNEL_STACK_PADDING: u64 = 0;
const PAGE_SHIFT: u64 = 12;
const PAGE_SIZE: u64 = 1u64 << PAGE_SHIFT;
const THREAD_SIZE_ORDER: u64 = 2; // assume no kasan
const THREAD_SIZE: u64 = PAGE_SIZE << THREAD_SIZE_ORDER;

pub struct TaskStruct {
    // struct task_struct * should always live longer than program execution
    // given the RCU read lock
    pub(crate) kptr: &'static task_struct,
}

impl TaskStruct {
    #[inline(always)]
    pub(crate) const fn new(kp: &'static task_struct) -> Self {
        Self { kptr: kp }
    }

    pub(crate) fn get_current_task() -> Option<Self> {
        let current: *mut task_struct =
            unsafe { this_cpu_read(&raw const ffi::current_task) };

        if current.is_null() {
            None
        } else {
            Some(TaskStruct::new(unsafe { &*current }))
        }
    }

    #[inline(always)]
    pub fn get_pid(&self) -> i32 {
        self.kptr.pid
    }

    #[inline(always)]
    pub fn get_tgid(&self) -> i32 {
        self.kptr.tgid
    }

    // Design decision: the equivalent BPF helper writes the program name to
    // a user-provided buffer, here we can take advantage of Rust's ownership by
    // just providing a &CStr instead
    pub fn get_comm(&self) -> Result<&CStr, core_ffi::FromBytesUntilNulError> {
        // casting from c_char to u8 is sound, see:
        // https://doc.rust-lang.org/src/core/ffi/c_str.rs.html#264
        let comm_bytes =
            unsafe { &*(&self.kptr.comm[..] as *const _ as *const [u8]) };
        CStr::from_bytes_until_nul(comm_bytes)
    }

    pub fn get_pt_regs(&self) -> &'static PtRegs {
        // X86 specific
        // stack_top is actually bottom of the kernel stack, it refers to the
        // highest address of the stack pages
        let stack_top =
            self.kptr.stack as u64 + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
        let reg_addr = stack_top - core::mem::size_of::<PtRegs>() as u64;
        // The pt_regs should always be on the top of the stack
        unsafe { &*(reg_addr as *const PtRegs) }
    }
}
