use crate::linux::bpf::*;
use crate::stub;

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

            let ptr = stub::STUB_BPF_TRACE_PRINTK as *const ();
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

            let ptr = stub::STUB_BPF_TRACE_PRINTK as *const ();
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
    let f_ptr = stub::STUB_BPF_MAP_LOOKUP_ELEM as *const ();
    let helper: extern "C" fn(i32, *const K) -> *const V = unsafe { core::mem::transmute(f_ptr) };

    let value = helper(map, &key) as *const V;

    if value.is_null() {
        None
    } else {
        Some(unsafe { *value })
    }
}

fn bpf_spin_lock(lock: &bpf_spin_lock) -> i64 {
    let f_ptr = stub::STUB_BPF_SPIN_LOCK as *const ();
    let helper: extern "C" fn(*const bpf_spin_lock) -> i64 = unsafe { core::mem::transmute(f_ptr) };
    helper(lock)
}

fn bpf_spin_unlock(lock: &bpf_spin_lock) -> i64 {
    let f_ptr = stub::STUB_BPF_SPIN_UNLOCK as *const ();
    let helper: extern "C" fn(*const bpf_spin_lock) -> i64 = unsafe { core::mem::transmute(f_ptr) };
    helper(lock)
}

fn bpf_xdp_adjust_head(xdp_md: &xdp_md, delta: i32) -> i64 {
    let f_ptr = stub::STUB_BPF_XDP_ADJUST_HEAD as *const ();
    let helper: extern "C" fn(*const xdp_md, i32) -> i64 = unsafe { core::mem::transmute(f_ptr) };
    helper(xdp_md, delta)
}

fn bpf_xdp_adjust_tail(xdp_md: &xdp_md, delta: i32) -> i64 {
    let f_ptr = stub::STUB_BPF_XDP_ADJUST_TAIL as *const ();
    let helper: extern "C" fn(*const xdp_md, i32) -> i64 = unsafe { core::mem::transmute(f_ptr) };
    helper(xdp_md, delta)
}
