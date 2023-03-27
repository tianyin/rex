use crate::bindings::linux::kernel::task_struct;
use crate::bindings::uapi::linux::errno::EINVAL;
use crate::kprobe::pt_regs;
use crate::stub;

use core::cmp::max;

// Bindgen has problem generating these constants
const TOP_OF_KERNEL_STACK_PADDING: u64 = 0;
const PAGE_SHIFT: u64 = 12;
const PAGE_SIZE: u64 = 1u64 << PAGE_SHIFT;
const THREAD_SIZE_ORDER: u64 = 2; // assume no kasan
const THREAD_SIZE: u64 = PAGE_SIZE << THREAD_SIZE_ORDER;

pub struct TaskStruct<'a> {
    pub(crate) kptr: &'a task_struct,
}

impl<'a> TaskStruct<'a> {
    #[inline(always)]
    pub(crate) const fn new(kp: &'a task_struct) -> TaskStruct<'a> {
        Self { kptr: kp }
    }

    /// Currently returns u64 until `task_struct` binding is generated
    pub(crate) fn get_current_task() -> Option<Self> {
        unsafe {
            let mut current: *const task_struct;
            core::arch::asm!(
                "mov {}, gs:[rcx]",
                out(reg) current,
                in("rcx") stub::current_task_addr(),
            );

            if current.is_null() {
                None
            } else {
                Some(TaskStruct::new(&*current))
            }
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

    // Design decision: the original BPF interface does not have type safety,
    // since buf is just a buffer. But in Rust we can use const generics to
    // restrict it to only [u8; N] given that comm is a cstring. This also
    // automatically achieves size check, since N is a constexpr.
    pub fn get_comm<const N: usize>(&self, buf: &mut [i8; N]) -> i32 {
        if N == 0 {
            return -(EINVAL as i32);
        }

        let size = max::<usize>(N - 1, self.kptr.comm.len());
        if size == 0 {
            return -(EINVAL as i32);
        }

        buf[..size].copy_from_slice(&self.kptr.comm);
        buf[size] = 0;
        0
    }
    
    pub fn get_pt_regs(&self) -> &pt_regs {
        // X86 sepcific
        // stack_top is actually bottom of the kernel stack, it refers to the
        // highest address of the stack pages
        let stack_top =
            self.kptr.stack as u64 + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
        // The pt_regs should always be on the top of the stack
        unsafe {
            core::mem::transmute(
                stack_top - core::mem::size_of::<pt_regs>() as u64,
            )
        }
    }
}
