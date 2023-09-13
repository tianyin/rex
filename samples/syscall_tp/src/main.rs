#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::{MAP_DEF, entry_link};
use inner_unikernel_rt::linux::bpf::{BPF_MAP_TYPE_ARRAY, BPF_NOEXIST};
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::tracepoint::{tracepoint, tp_ctx, tp_type};

MAP_DEF!(enter_open_map, u32, u32, BPF_MAP_TYPE_ARRAY, 1, 0);
MAP_DEF!(exit_open_map, u32, u32, BPF_MAP_TYPE_ARRAY, 1, 0);

type SyscallTpMap = IUMap<BPF_MAP_TYPE_ARRAY, u32, u32>;

fn count(obj: &tracepoint, map: &'static SyscallTpMap) {
    let (key, init_val): (u32, u32) = (0, 1);
    let mut value: u32;
    match obj.bpf_map_lookup_elem(map, key) {
        None => {
            obj.bpf_map_update_elem(map, key, init_val, BPF_NOEXIST.into());
        }
        Some(val) => {
            *val += 1;
        }
    }
}

fn trace_enter_open(obj: &tracepoint, _: tp_ctx) -> u32 {
    count(obj, &enter_open_map);
    0
}

fn trace_enter_open_at(obj: &tracepoint, _: tp_ctx) -> u32 {
    count(obj, &enter_open_map);
    0
}

fn trace_enter_exit(obj: &tracepoint, _: tp_ctx) -> u32 {
    count(obj, &exit_open_map);
    0
}

fn trace_enter_exit_at(obj: &tracepoint, _: tp_ctx) -> u32 {
    count(obj, &exit_open_map);
    0
}

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_open)]
static PROG1: tracepoint = tracepoint::new(trace_enter_open, "trace_enter_open", tp_type::SyscallsEnterOpen);

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_openat)]
static PROG2: tracepoint = tracepoint::new(trace_enter_open_at, "trace_enter_open_at", tp_type::SyscallsEnterOpen);

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_exit_open)]
static PROG3: tracepoint = tracepoint::new(trace_enter_exit, "trace_enter_exit", tp_type::SyscallsExitOpen);

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_exit_openat)]
static PROG4: tracepoint = tracepoint::new(trace_enter_exit_at, "trace_enter_exit_at", tp_type::SyscallsExitOpen);