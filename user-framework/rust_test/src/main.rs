#![no_std]
#![no_main]

extern crate rlibc;
use core::panic::PanicInfo;
pub mod interface;

fn bpf_get_current_pid_tgid() -> u64 {
    let ptr = interface::STUB_BPF_GET_CURRENT_PID_TGID as *const ();
    let code: extern "C" fn() -> u64 = unsafe { core::mem::transmute(ptr) };
    code()
}

macro_rules! bpf_trace_printk {
    ($s:expr) => {
        {
            // Add the missing null terminator
            let mut fmt_arr: [u8; $s.len() + 1] = [0; $s.len() + 1];
            for (i, c) in $s.chars().enumerate() {
                fmt_arr[i] = c as u8
            }
            fmt_arr[$s.len()] = 0;
            let fmt_str = fmt_arr.as_ptr();

            let ptr = interface::STUB_BPF_TRACE_PRINTK as *const ();
            let code: extern "C" fn(*const u8, u32) -> i64 =
                unsafe { core::mem::transmute(ptr) };

            code(fmt_str, ($s.len() + 1) as u32)
        }
    };

    ($s:expr,$($t:ty : $a:expr),*) => {
        {
            // Add the missing null terminator
            let mut fmt_arr: [u8; $s.len() + 1] = [0; $s.len() + 1];
            for (i, c) in $s.chars().enumerate() {
                fmt_arr[i] = c as u8
            }
            fmt_arr[$s.len()] = 0;
            let fmt_str = fmt_arr.as_ptr();

            let ptr = interface::STUB_BPF_TRACE_PRINTK as *const ();
            let code: extern "C" fn(*const u8, u32, $($t),*) -> i64 =
                unsafe { core::mem::transmute(ptr) };

            code(fmt_str, ($s.len() + 1) as u32, $($a),*)
        }
    };
}

fn bpf_map_lookup_elem<K, V>(map: i32, key: K) -> Option<V>
where
    V: Copy,
{
    let f_ptr = interface::STUB_BPF_LOOKUP_ELEM as *const ();
    let helper: extern "C" fn(i32, *const K) -> *mut V = unsafe { core::mem::transmute(f_ptr) };

    let value = helper(map, &key) as *mut V;

    if value.is_null() {
        None
    } else {
        Some(unsafe { *value })
    }
}

fn bpf_map_update_elem<K, V>(map: i32, key: K, value: V, flags: u64) -> i64 {
    let f_ptr = interface::STUB_BPF_UPDATE_ELEM as *const ();
    let helper: extern "C" fn(i32, *const K, *const V, u64) -> i64 =
        unsafe { core::mem::transmute(f_ptr) };

    helper(map, &key, &value, flags)
}

#[no_mangle]
pub extern "C" fn _start() -> i32 {
    let map: i32 = 0;
    let key: i32 = 0;

    match bpf_map_lookup_elem::<i32, i64>(map, key) {
        None => {
            bpf_trace_printk!("Not found.\n");
        }
        Some(val) => {
            bpf_trace_printk!("Val=%llu.\n", i64: val);
        }
    }

    let pid = (bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    bpf_trace_printk!("Rust program triggered from PID %u.\n", u32: pid);

    bpf_map_update_elem(map, key, pid as i64, interface::BPF_ANY);
    return 0;
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
