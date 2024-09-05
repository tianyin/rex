#![no_std]
#![no_main]

extern crate rex;

use rex::bpf_printk;
use rex::rex_tracepoint;
use rex::tracepoint::*;
use rex::Result;

#[rex_tracepoint(name = "syscalls/sys_enter_dup", tp_type = "Void")]
fn rex_prog1(obj: &tracepoint, _: tp_ctx) -> Result {
    // bpf_printk!(
    //     obj,
    //     c"BPF program to test program termination.\n
    //  Calls dummy_long_running_helper which simulates a long running helper"
    // );
    // //let mut target = obj.bpf_ktime_get_ns();
    // for i in 0..10000000 {
    //     bpf_printk!(obj, c"Rust triggered %u.\n", i as u64);
    //     obj.dummy_long_running_helper();
    // }
    // bpf_printk!(obj, c"Done\n");
    // panic!("Termination panic")
    loop {
        
    }
}
