#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::{bpf_printk, entry_link, Result};
use core::sync::atomic::{AtomicU64, Ordering};

static ATOM: AtomicU64 = AtomicU64::new(42);

#[inline(always)]
fn iu_prog1_fn(obj: &tracepoint, _: tp_ctx) -> Result {
    let random = obj.bpf_get_prandom_u32() as u64;
    ATOM.store(random, Ordering::Relaxed);

    let start = obj.bpf_ktime_get_ns();
    let val = ATOM.load(Ordering::Relaxed);
    let end = obj.bpf_ktime_get_ns();

    bpf_printk!(obj, "Time elapsed: %llu", end - start, val);

    Ok(0)
}

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_getcwd)]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_type::Void);
