#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::linux::bpf::{BPF_MAP_TYPE_ARRAY, BPF_NOEXIST};
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::tracepoint::{tp_ctx, tp_type, tracepoint};
use inner_unikernel_rt::Result;
use inner_unikernel_rt::{entry_link, MAP_DEF};

MAP_DEF!(enter_open_map, u32, u32, BPF_MAP_TYPE_ARRAY, 1, 0);
MAP_DEF!(exit_open_map, u32, u32, BPF_MAP_TYPE_ARRAY, 1, 0);

type SyscallTpMap = IUMap<BPF_MAP_TYPE_ARRAY, u32, u32>;

fn count(obj: &tracepoint, map: &'static SyscallTpMap) -> Result {
    match obj.bpf_map_lookup_elem(map, &0) {
        None => {
            obj.bpf_map_update_elem(map, &0, &1, BPF_NOEXIST.into())?;
        }
        Some(val) => {
            *val += 1;
        }
    }

    Ok(0)
}

fn trace_enter_open(obj: &tracepoint, _: tp_ctx) -> Result {
    count(obj, &enter_open_map)
}

fn trace_enter_open_at(obj: &tracepoint, _: tp_ctx) -> Result {
    count(obj, &enter_open_map)
}

fn trace_enter_exit(obj: &tracepoint, _: tp_ctx) -> Result {
    count(obj, &exit_open_map)
}

fn trace_enter_exit_at(obj: &tracepoint, _: tp_ctx) -> Result {
    count(obj, &exit_open_map)
}

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_open)]
static PROG1: tracepoint = tracepoint::new(
    trace_enter_open,
    "trace_enter_open",
    tp_type::SyscallsEnterOpen,
);

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_openat)]
static PROG2: tracepoint = tracepoint::new(
    trace_enter_open_at,
    "trace_enter_open_at",
    tp_type::SyscallsEnterOpen,
);

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_exit_open)]
static PROG3: tracepoint = tracepoint::new(
    trace_enter_exit,
    "trace_enter_exit",
    tp_type::SyscallsExitOpen,
);

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_exit_openat)]
static PROG4: tracepoint = tracepoint::new(
    trace_enter_exit_at,
    "trace_enter_exit_at",
    tp_type::SyscallsExitOpen,
);
