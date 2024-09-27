use crate::bindings::linux::kernel::CONFIG_NR_CPUS as NR_CPUS;
use crate::stub;

use core::ptr::addr_of;

pub(crate) trait PerCPURead<T> {
    unsafe fn this_cpu_read(addr: u64) -> T;
}

impl PerCPURead<u64> for u64 {
    #[inline(always)]
    unsafe fn this_cpu_read(addr: u64) -> u64 {
        let mut var: u64;
        unsafe {
            core::arch::asm!(
                "mov {0:r}, gs:[{1:r}]",
                out(reg) var,
                in(reg) addr,
                options(readonly, nostack),
            );
        }
        var
    }
}

impl PerCPURead<u32> for u32 {
    #[inline(always)]
    unsafe fn this_cpu_read(addr: u64) -> u32 {
        let mut var: u32;
        unsafe {
            core::arch::asm!(
                "mov {0:e}, gs:[{1:r}]",
                out(reg) var,
                in(reg) addr,
                options(readonly, nostack),
            );
        }
        var
    }
}

impl PerCPURead<u16> for u16 {
    #[inline(always)]
    unsafe fn this_cpu_read(addr: u64) -> u16 {
        let mut var: u16;
        unsafe {
            core::arch::asm!(
                "mov {0:x}, gs:[{1:r}]",
                out(reg) var,
                in(reg) addr,
                options(readonly, nostack),
            );
        }
        var
    }
}

impl PerCPURead<u8> for u8 {
    #[inline(always)]
    unsafe fn this_cpu_read(addr: u64) -> u8 {
        let mut var: u8;
        unsafe {
            core::arch::asm!(
                "mov {0}, gs:[{1:r}]",
                out(reg_byte) var,
                in(reg) addr,
                options(readonly, nostack),
            );
        }
        var
    }
}

impl<T> PerCPURead<*const T> for *const T {
    #[inline(always)]
    unsafe fn this_cpu_read(addr: u64) -> *const T {
        let mut var: *const T;
        unsafe {
            core::arch::asm!(
                "mov {0:r}, gs:[{1:r}]",
                out(reg) var,
                in(reg) addr,
                options(readonly, nostack),
            );
        }
        var
    }
}

/// We have migrate_disable
impl<T> PerCPURead<*mut T> for *mut T {
    #[inline(always)]
    unsafe fn this_cpu_read(addr: u64) -> *mut T {
        let mut var: *mut T;
        unsafe {
            core::arch::asm!(
                "mov {0:r}, gs:[{1:r}]",
                out(reg) var,
                in(reg) addr,
                options(readonly, nostack),
            );
        }
        var
    }
}

/// For values of per-cpu variables
#[inline(always)]
pub(crate) unsafe fn this_cpu_read<T: PerCPURead<T>>(pcp_addr: u64) -> T {
    <T as PerCPURead<T>>::this_cpu_read(pcp_addr)
}

/// For addresses of per-cpu variables
/// This is more expensive (in terms of # of insns)
#[inline(always)]
unsafe fn __this_cpu_ptr(pcp_addr: u64) -> u64 {
    pcp_addr + this_cpu_read::<u64>(addr_of!(stub::this_cpu_off) as u64)
}

pub(crate) unsafe fn this_cpu_ptr<T>(pcp_addr: u64) -> *const T {
    __this_cpu_ptr(pcp_addr) as *const T
}

pub(crate) unsafe fn this_cpu_ptr_mut<T>(pcp_addr: u64) -> *mut T {
    __this_cpu_ptr(pcp_addr) as *mut T
}

#[inline(always)]
pub(crate) fn current_task() -> *const () {
    unsafe {
        addr_of!(
            stub::pcpu_hot
                .__bindgen_anon_1
                .__bindgen_anon_1
                .current_task
        ) as *const *const () as *const ()
    }
}

#[inline(always)]
pub(crate) fn cpu_number() -> *const () {
    unsafe {
        addr_of!(stub::pcpu_hot.__bindgen_anon_1.__bindgen_anon_1.cpu_number)
            as *const ()
    }
}
