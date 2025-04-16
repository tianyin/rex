#![no_std]
#![no_main]

extern crate rex;

use rex::linux::bpf::BPF_NOEXIST;
use rex::map::RexArrayMap;
use rex::tracepoint::*;
use rex::{rex_map, rex_tracepoint, Result};

#[rex_map]
static enter_open_map: RexArrayMap<u32> = RexArrayMap::new(1, 0);

#[rex_map]
static exit_open_map: RexArrayMap<u32> = RexArrayMap::new(1, 0);

type SyscallTpMap = RexArrayMap<u32>;

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

#[rex_tracepoint(name = "syscalls/sys_enter_open")]
fn trace_enter_open(
    obj: &tracepoint,
    _: &'static SyscallsEnterOpenArgs,
) -> Result {
    count(obj, &enter_open_map)
}

#[rex_tracepoint(name = "syscalls/sys_enter_openat")]
fn trace_enter_open_at(
    obj: &tracepoint,
    _: &'static SyscallsEnterOpenArgs,
) -> Result {
    count(obj, &enter_open_map)
}

#[rex_tracepoint(name = "syscalls/sys_exit_open")]
fn trace_enter_exit(
    obj: &tracepoint,
    _: &'static SyscallsExitOpenArgs,
) -> Result {
    count(obj, &exit_open_map)
}

#[rex_tracepoint(name = "syscalls/sys_exit_openat")]
fn trace_enter_exit_at(
    obj: &tracepoint,
    _: &'static SyscallsExitOpenArgs,
) -> Result {
    count(obj, &exit_open_map)
}
