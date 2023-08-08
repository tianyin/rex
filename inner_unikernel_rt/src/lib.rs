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
pub mod sched_cls;
pub mod tracepoint;
pub mod xdp;

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

#[cfg(CONFIG_CC_IS_CLANG = "y")]
static CC_IS_CLANG: bool = true;
#[cfg(not(CONFIG_CC_IS_CLANG = "y"))]
static CC_IS_GCC: bool = true;

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
