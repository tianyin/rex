#![no_std]
#![no_main]

extern crate inner_unikernel_rt;
extern crate rlibc;

use core::panic::PanicInfo;

use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::{bpf_trace_printk, bpf_trace_printk_fn, terminate_str};

pub fn iu_prog1(obj: &tracepoint, ctx: &tp_ctx) -> u32 {
    let pid = (obj.bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    bpf_trace_printk!("Rust triggered from PID %u.\n", pid);
    return 0;
}

static PROG: tracepoint = tracepoint::new(tp_ctx::Void, iu_prog1);
