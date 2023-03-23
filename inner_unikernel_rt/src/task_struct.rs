use crate::stub;
use crate::bindings::linux::kernel::task_struct;
use crate::bindings::uapi::linux::errno::EINVAL;

use core::cmp::max;

pub struct TaskStruct<'a> {
    pub(crate) kptr: &'a task_struct
}

impl<'a> TaskStruct<'a> {
    #[inline(always)]
    pub(crate) const fn new(kp:&'a task_struct) -> TaskStruct<'a> {
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

            let scalar: u64 = current as *const () as u64;

            if current.is_null() {
                None
            } else {
                Some(TaskStruct::new(&*current))
            }
        }
    }

    #[inline(always)]
    pub fn getpid(&self) -> i32 {
        self.kptr.pid
    }

    #[inline(always)]
    pub fn gettgid(&self) -> i32 {
        self.kptr.tgid
    }

    // Design decision: the original BPF interface does not have type safety,
    // since buf is just a buffer. But in Rust we can use const generics to
    // restrict it to only [u8; N] given that comm is a cstring. This also
    // automatically achieves size check, since N is a constexpr.
    pub fn getcomm<const N: usize>(&self, buf: &mut [i8; N]) -> i32 {
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
}

