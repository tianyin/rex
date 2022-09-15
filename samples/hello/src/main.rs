#![no_std]
#![no_main]

extern crate inner_unikernel_rt;
extern crate rlibc;

use core::panic::PanicInfo;

use inner_unikernel_rt::prog_type::prog_type;
use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::{MAP_DEF, PROG_DEF, TP_DEF};

pub fn iu_prog1(ctx: &tp_ctx) -> i32 {
    let pid = (bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    bpf_trace_printk!("Rust triggered from PID %u.\n", pid);
    return 0;
}

PROG_DEF!(iu_prog1, _start, tracepoint, Void);
