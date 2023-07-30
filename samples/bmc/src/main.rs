#![no_std]
#![no_main]

extern crate inner_unikernel_rt;
extern crate rlibc;

use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::MAP_DEF;
use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::linux::bpf::{BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY};

mod bmc_common;
use crate::bmc_common::*;

MAP_DEF!(map_hash, __map_1, u32, i64, BPF_MAP_TYPE_HASH, 1024, 0);
MAP_DEF!(map_array, __map_2, u32, u64, BPF_MAP_TYPE_ARRAY, 256, 0);

fn iu_prog1_fn(obj: &tracepoint, ctx: &tp_ctx) -> u32 {
    0
}

#[link_section = "tracepoint/syscalls/sys_enter_dup"]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_ctx::Void);
