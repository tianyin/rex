#![no_std]
#![no_main]

extern crate compiler_builtins;

mod helpers;
mod linux_errno;
mod linux_ptrace;
mod linux_seccomp;
mod linux_unistd;
mod stub;

use crate::helpers::*;
use crate::linux_errno::*;
use crate::linux_ptrace::pt_regs;
use crate::linux_seccomp::seccomp_data;
use crate::linux_unistd::*;
use core::panic::PanicInfo;

pub fn func_sys_write(ctx: &pt_regs) -> i32 {
    let sd: seccomp_data = seccomp_data {
        nr: 0,
        arch: 0,
        instruction_pointer: 0,
        args: [0; 6],
    };

    let unsafe_ptr = ctx.rsi as *const ();
    let ret = bpf_probe_read_kernel(&sd, unsafe_ptr);

    if ret < 0 {
        return ret as i32;
    }

    if sd.args[2] == 512 {
        bpf_trace_printk!(
            "write(fd=%d, buf=%p, size=%d)\n",
            u64: sd.args[0],
            u64: sd.args[1],
            u64: sd.args[2]
        );
    }

    return 0;
}

pub fn func_sys_read(ctx: &pt_regs) -> i32 {
    let sd: seccomp_data = seccomp_data {
        nr: 0,
        arch: 0,
        instruction_pointer: 0,
        args: [0; 6],
    };

    let unsafe_ptr = ctx.rsi as *const ();
    let ret = bpf_probe_read_kernel(&sd, unsafe_ptr);

    if ret < 0 {
        return ret as i32;
    }

    if sd.args[2] > 128 && sd.args[2] <= 1024 {
        bpf_trace_printk!(
            "read(fd=%d, buf=%p, size=%d)\n",
            u64: sd.args[0],
            u64: sd.args[1],
            u64: sd.args[2]
        );
    }

    return 0;
}

pub fn func_sys_mmap(ctx: &pt_regs) -> i32 {
    bpf_trace_printk!("mmap\n");
    return 0;
}

#[no_mangle]
pub extern "C" fn _start(ctx: *const pt_regs) -> i32 {
    if !ctx.is_null() {
        let regs = unsafe { *ctx };
        match regs.rdi as u32 {
            __NR_read => {
                return func_sys_read(&regs);
            }
            __NR_write => {
                return func_sys_write(&regs);
            }
            __NR_mmap => {
                return func_sys_mmap(&regs);
            }
            __NR_getuid..=__NR_getsid => {
                bpf_trace_printk!("syscall=%d (one of get/set uid/pid/gid)\n");
                return 0;
            }
            _ => {
                return 0;
            }
        }
    } else {
        return -(EINVAL as i32);
    }
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
