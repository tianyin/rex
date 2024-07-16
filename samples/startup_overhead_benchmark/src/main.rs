#![no_std]
#![no_main]

extern crate rex;

use rex::kprobe::*;
use rex::rex_kprobe;
use rex::Result;

#[rex_kprobe(function = "kprobe_target_func")]
fn rex_prog1_fn(_obj: &kprobe, _ctx: &mut pt_regs) -> Result {
    Ok(0)
}
