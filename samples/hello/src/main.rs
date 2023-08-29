#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::entry_link;

fn iu_prog1_fn(obj: &tracepoint, ctx: &tp_ctx) -> u32 {
    let option_task = obj.bpf_get_current_task();
    if let Some(task) = option_task {
        let pid = task.get_pid();
        bpf_printk!(obj, "Rust triggered from PID %u.\n", pid as u64);
    }
    0
}

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_dup)]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_ctx::Void);
