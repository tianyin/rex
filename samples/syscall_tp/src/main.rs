#![no_std]
#![no_main]

extern crate rlibc;
use core::panic::PanicInfo;

mod stub;

mod map;
use crate::map::*;

mod helper;
use crate::helper::*;

mod linux;
use crate::linux::bpf::*;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct syscalls_enter_open_args {
	pub unused: u64,
	pub syscall_nr: i64,
	pub filename_ptr: i64,
	pub flags: i64,
	pub mode: i64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct syscalls_exit_open_args {
	pub unused: u64,
	pub syscall_nr: i64,
	pub ret: i64,
}

MAP_DEF!(enter_open_map, __enter_open_map, u32, u32, BPF_MAP_TYPE_ARRAY, 1, 0);
MAP_DEF!(exit_open_map, __exit_open_map, u32, u32, BPF_MAP_TYPE_ARRAY, 1, 0);

#[inline(always)]
pub fn count (map: &IUMap<u32, u32>) {
    let (key, init_val): (u32, u32) = (0, 1);
    let mut value: u32;
    match bpf_map_lookup_elem::<u32, u32>(map, key) {
        None => {
            bpf_map_update_elem(map, key, init_val, BPF_NOEXIST.into());
        }
        Some(val) => {
            value = val + 1;
            bpf_map_update_elem(map, key, value, BPF_ANY.into());
        }
    }
}

#[no_mangle]
#[link_section = "tracepoint/syscalls/sys_enter_open"]
fn trace_enter_open(ctx: &syscalls_enter_open_args) -> i32 {
    count(enter_open_map);
    return 0;
}

#[no_mangle]
#[link_section = "tracepoint/syscalls/sys_enter_openat"]
fn trace_enter_open_at(ctx: &syscalls_enter_open_args) -> i32 {
    count(enter_open_map);
    return 0;
}

#[no_mangle]
#[link_section = "tracepoint/syscalls/sys_exit_open"]
fn trace_enter_exit(ctx: &syscalls_exit_open_args) -> i32 {
    count(exit_open_map);
    return 0;
}

#[no_mangle]
#[link_section = "tracepoint/syscalls/sys_exit_openat"]
fn trace_enter_exit_at(ctx: &syscalls_exit_open_args) -> i32 {
    count(exit_open_map);
    return 0;
}

#[no_mangle]
fn _start(ctx: *const ()) -> i64 {
    trace_enter_open(unsafe { core::mem::transmute(ctx) });
    trace_enter_open_at(unsafe { core::mem::transmute(ctx) });
    trace_enter_exit(unsafe { core::mem::transmute(ctx) });
    trace_enter_exit_at(unsafe { core::mem::transmute(ctx) });
    return 0;
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
