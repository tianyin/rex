#![no_std]
#![feature(const_mut_refs)]
#![feature(panic_info_message)]
#![feature(c_variadic)]
#![allow(non_camel_case_types)]

pub mod kprobe;
pub mod map;
pub mod perf_event;
pub mod prog_type;
//pub mod sysctl;
pub mod task_struct;
// pub mod timekeeping;
pub mod tracepoint;
pub mod xdp;
pub mod sched_cls;

mod barrier;
mod base_helper;
mod bindings;
mod debug;
mod panic;
mod per_cpu;
mod random32;
mod read_once;
//mod seqlock;
mod stub;

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

#[no_mangle]
fn __iu_entry_xdp(prog: &xdp::xdp, ctx: *const ()) -> u32 {
    prog.prog_run(ctx)
}

#[no_mangle]
fn __iu_entry_sched_cls(prog: &sched_cls::sched_cls, ctx: *const ()) -> u32 {
    prog.prog_run(ctx)
}

pub use bindings::uapi::*;
