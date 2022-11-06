#![no_std]
#![no_main]

extern crate inner_unikernel_rt;
extern crate rlibc;

use core::panic::PanicInfo;

use inner_unikernel_rt::tracepoint::*;

pub fn iu_prog1(obj: &tracepoint, ctx: &tp_ctx) -> u32 {
    let pid = (obj.bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    obj.bpf_trace_printk("Rust triggered from PID %u.\n", pid as u64, 0, 0);
    return 0;
}

#[link_section = "tracepoint"]
static PROG: tracepoint = tracepoint::new(iu_prog1, "_start", tp_ctx::Void);
