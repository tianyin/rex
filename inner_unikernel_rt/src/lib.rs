#![no_std]
#![feature(const_mut_refs)]
#![feature(panic_info_message)]

pub mod kprobe;
pub mod map;
pub mod perf_event;
pub mod prog_type;
pub mod tracepoint;

mod base_helper;
mod bindings;
mod stub;
pub mod task_struct;

use crate::prog_type::iu_prog;
use core::panic::PanicInfo;

#[no_mangle]
fn __iu_entry_tracepoint(prog: &tracepoint::tracepoint, ctx: *const ()) -> u32 {
    prog.prog_run(ctx)
}

#[no_mangle]
fn __iu_entry_kprobe(prog: &kprobe::kprobe, ctx: *const ()) -> u32 {
    prog.prog_run(ctx)
}

#[no_mangle]
fn __iu_entry_perf_event(prog: &perf_event::perf_event, ctx: *const ()) -> u32 {
    prog.prog_run(ctx)
}

// This function is called on panic.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut msg = [0u8; 128];
    if let Some(args) = info.message() {
        // Only works in the most trivial case: no format args
        if let Some(s) = args.as_str() {
            let len = core::cmp::min(msg.len() - 1, s.len());
            msg[..len].copy_from_slice(&(*s).as_bytes()[..len]);
            msg[len] = 0u8;
        } else {
            let s = "Rust program panicked\n\0";
            msg[..s.len()].copy_from_slice(s.as_bytes());
        }
    } else if let Some(s) = info.payload().downcast_ref::<&str>() {
        let len = core::cmp::min(msg.len() - 1, s.len());
        msg[..len].copy_from_slice(&(*s).as_bytes()[..len]);
        msg[len] = 0u8;
    } else {
        let s = "Rust program panicked\n\0";
        msg[..s.len()].copy_from_slice(s.as_bytes());
    }

    unsafe {
        let panic_fn: unsafe extern "C" fn(*const u8) -> ! = 
            core::mem::transmute(stub::panic_addr());
        panic_fn(msg.as_ptr())
    }
}

pub use bindings::uapi::*;
