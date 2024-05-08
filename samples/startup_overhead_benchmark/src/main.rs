#![no_std]
#![no_main]

extern crate rex;

use rex::entry_link;
use rex::kprobe::*;
use rex::Result;

#[inline(always)]
fn iu_prog1_fn(_obj: &kprobe, _ctx: &mut pt_regs) -> Result {
    Ok(0)
}

#[entry_link(inner_unikernel/kprobe/kprobe_target_func)]
static PROG: kprobe = kprobe::new(iu_prog1_fn, "iu_prog1");
