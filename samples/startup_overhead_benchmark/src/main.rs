#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::entry_link;
use inner_unikernel_rt::kprobe::*;
use inner_unikernel_rt::Result;

#[inline(always)]
fn iu_prog1_fn(_obj: &kprobe, _ctx: &mut pt_regs) -> Result {
    Ok(0)
}

#[entry_link(inner_unikernel/kprobe/kprobe_target_func)]
static PROG: kprobe = kprobe::new(iu_prog1_fn, "iu_prog1");
