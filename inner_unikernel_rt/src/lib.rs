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

extern crate paste;
extern crate rlibc;

use crate::prog_type::iu_prog;
use core::panic::PanicInfo;

use paste::paste;

#[cfg(CONFIG_CC_IS_CLANG = "y")]
static CC_IS_CLANG: bool = true;
#[cfg(not(CONFIG_CC_IS_CLANG = "y"))]
static CC_IS_GCC: bool = true;

macro_rules! define_prog_entry {
    ($prog_ty:ident) => {
        paste! {
            #[no_mangle]
            fn [<__iu_entry_ $prog_ty>](
                prog: &$prog_ty::$prog_ty,
                ctx: *const(),
            ) -> u32 {
                prog.prog_run(ctx)
            }
        }
    };
}

define_prog_entry!(tracepoint);
define_prog_entry!(kprobe);
define_prog_entry!(perf_event);
define_prog_entry!(xdp);
define_prog_entry!(sched_cls);

pub use bindings::uapi::*;
