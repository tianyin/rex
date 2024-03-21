#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::entry_link;
use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::Result;

#[inline(always)]
fn iu_prog1_fn(_obj: &tracepoint, _: tp_ctx) -> Result {
    Ok(0)
}

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_dup)]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_type::Void);
