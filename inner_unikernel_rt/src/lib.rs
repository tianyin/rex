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
mod panic;
mod per_cpu;
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

pub use bindings::uapi::*;
