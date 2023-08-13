#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::kprobe::*;
use inner_unikernel_rt::linux::seccomp::seccomp_data;
use inner_unikernel_rt::linux::unistd::*;
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::MAP_DEF;

pub fn func_sys_write(obj: &kprobe, ctx: &pt_regs) -> u32 {
    let mut sd: seccomp_data = seccomp_data {
        nr: 0,
        arch: 0,
        instruction_pointer: 0,
        args: [0; 6],
    };

    let unsafe_ptr = ctx.rsi() as *const ();
    obj.bpf_probe_read_kernel(&mut sd, unsafe_ptr);

    if sd.args[2] == 512 {
        obj.bpf_trace_printk(
            "write(fd=%d, buf=%p, size=%d)\n",
            sd.args[0],
            sd.args[1],
            sd.args[2],
        );
    }
    0
}

pub fn func_sys_read(obj: &kprobe, ctx: &pt_regs) -> u32 {
    let mut sd: seccomp_data = seccomp_data {
        nr: 0,
        arch: 0,
        instruction_pointer: 0,
        args: [0; 6],
    };

    let unsafe_ptr = ctx.rsi() as *const ();
    obj.bpf_probe_read_kernel(&mut sd, unsafe_ptr);

    if sd.args[2] > 128 && sd.args[2] <= 1024 {
        obj.bpf_trace_printk(
            "read(fd=%d, buf=%p, size=%d)\n",
            sd.args[0],
            sd.args[1],
            sd.args[2],
        );
    }
    0
}

pub fn func_sys_mmap(obj: &kprobe, ctx: &pt_regs) -> u32 {
    let mut sd: seccomp_data = seccomp_data {
        nr: 0,
        arch: 0,
        instruction_pointer: 0,
        args: [0; 6],
    };
    let unsafe_ptr = ctx.rsi() as *const ();
    obj.bpf_trace_printk("seccomp_data addr: 0x%lx", ctx.rsi(), 0, 0);
    obj.bpf_probe_read_kernel(&mut sd, unsafe_ptr);

    obj.bpf_trace_printk(
        "mmap(addr=0x%lx, len=%ld, prot=%ld...)\n",
        sd.args[0],
        sd.args[1],
        sd.args[2],
    );
    0
}

fn iu_prog1_fn(obj: &kprobe, ctx: &mut pt_regs) -> u32 {
    match ctx.rdi() as u32 {
        __NR_read => {
            func_sys_read(obj, ctx)
        }
        __NR_write => {
            func_sys_write(obj, ctx)
        }
        __NR_mmap => {
            func_sys_mmap(obj, ctx)
        }
        __NR_getuid..=__NR_getsid => {
            obj.bpf_trace_printk("syscall=%d (one of get/set uid/pid/gid)\n", ctx.rdi(), 0, 0);
            0
        }
        _ => {
            0
        }
    }
}

#[link_section = "inner_unikernel/kprobe/__seccomp_filter"]
static PROG: kprobe = kprobe::new(iu_prog1_fn, "iu_prog1");
