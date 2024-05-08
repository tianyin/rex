#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]

extern crate rex;

use rex::linux::bpf::BPF_NOEXIST;
use rex::map::IUArrayMap;
use rex::tracepoint::{tp_ctx, tp_type, tracepoint};
use rex::Result;
use rex::{entry_link, rex_map};

#[rex_map]
static enter_open_map: IUArrayMap<u32> = IUArrayMap::new(1, 0);

#[rex_map]
static exit_open_map: IUArrayMap<u32> = IUArrayMap::new(1, 0);

type SyscallTpMap = IUArrayMap<u32>;

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

#[inline(always)]
fn trace_enter_open(obj: &tracepoint, _: tp_ctx) -> Result {
    count(obj, &enter_open_map)
}

#[inline(always)]
fn trace_enter_open_at(obj: &tracepoint, _: tp_ctx) -> Result {
    count(obj, &enter_open_map)
}

#[inline(always)]
fn trace_enter_exit(obj: &tracepoint, _: tp_ctx) -> Result {
    count(obj, &exit_open_map)
}

#[inline(always)]
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
