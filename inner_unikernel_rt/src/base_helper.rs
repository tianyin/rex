use crate::map::IUMap;
use crate::stub;

pub(crate) fn bpf_get_current_pid_tgid() -> u64 {
    let ptr = stub::STUB_BPF_GET_CURRENT_PID_TGID as *const ();
    let code: extern "C" fn() -> u64 = unsafe { core::mem::transmute(ptr) };
    code()
}

pub(crate) fn bpf_get_current_comm<T>(buf: &T, size_of_buf: usize) -> i64 {
    let ptr = stub::STUB_BPF_GET_CURRENT_COMM as *const ();
    let code: extern "C" fn(&T, u32) -> i64 = unsafe { core::mem::transmute(ptr) };
    code(buf, size_of_buf as u32)
}

pub(crate) fn bpf_get_smp_processor_id() -> u32 {
    let ptr = stub::STUB_BPF_GET_SMP_PROCESSOR_ID as *const ();
    let code: extern "C" fn() -> u32 = unsafe { core::mem::transmute(ptr) };
    code()
}

pub unsafe fn bpf_trace_printk_fn<T1, T2, T3>(
    fmt: *const u8,
    fmt_size: usize,
    arg1: T1,
    arg2: T2,
    arg3: T3,
) -> i32 {
    let ptr = stub::STUB_BPF_TRACE_PRINTK as *const ();
    let code: extern "C" fn(*const u8, u32, T1, T2, T3) -> i32 =
        unsafe { core::mem::transmute(ptr) };

    code(fmt, fmt_size as u32, arg1, arg2, arg3)
}

#[macro_export]
macro_rules! terminate_str {
    ($s:expr) => {{
        let mut fmt_arr: [u8; $s.len() + 1] = [0; $s.len() + 1];

        for (i, c) in $s.chars().enumerate() {
            fmt_arr[i] = c as u8;
        }

        fmt_arr[$s.len()] = 0;
        fmt_arr.as_ptr()
    }};
}
pub use terminate_str;

#[macro_export]
macro_rules! bpf_trace_printk {
    ($s:expr) => {{
        let fmt_str = terminate_str!($s);
        unsafe { bpf_trace_printk_fn(fmt_str, $s.len() + 1, 0, 0, 0) }
    }};

    ($s:expr, $a1:expr) => {{
        let fmt_str = terminate_str!($s);
        unsafe { bpf_trace_printk_fn(fmt_str, $s.len() + 1, $a1, 0, 0) }
    }};

    ($s:expr, $a1:expr, $a2:expr) => {{
        let fmt_str = terminate_str!($s);
        unsafe { bpf_trace_printk_fn(fmt_str, $s.len() + 1, $a1, $a2, 0) }
    }};

    ($s:expr, $a1:expr, $a2:expr, $a3:expr) => {{
        let fmt_str = terminate_str!($s);
        unsafe { bpf_trace_printk_fn(fmt_str, $s.len() + 1, $a1, $a2, $a3) }
    }};
}
pub use bpf_trace_printk;

pub(crate) fn bpf_map_lookup_elem<K, V>(map: &IUMap<K, V>, key: K) -> Option<V>
where
    V: Copy,
{
    let f_ptr = stub::STUB_BPF_MAP_LOOKUP_ELEM as *const ();
    let helper: extern "C" fn(&IUMap<K, V>, *const K) -> *const V =
        unsafe { core::mem::transmute(f_ptr) };

    let value = helper(map, &key) as *mut V;

    if value.is_null() {
        None
    } else {
        Some(unsafe { *value })
    }
}

pub(crate) fn bpf_map_update_elem<K, V>(map: &IUMap<K, V>, key: K, value: V, flags: u64) -> i64 {
    let f_ptr = stub::STUB_BPF_MAP_UPDATE_ELEM as *const ();
    let helper: extern "C" fn(&IUMap<K, V>, *const K, *const V, u64) -> i64 =
        unsafe { core::mem::transmute(f_ptr) };

    helper(map, &key, &value, flags)
}

macro_rules! base_helper_defs {
    () => {
        pub fn bpf_get_current_comm<T>(&self, buf: &T, size_of_buf: usize) -> i64 {
            crate::base_helper::bpf_get_current_comm::<T>(buf, size_of_buf)
        }

        pub fn bpf_get_current_pid_tgid(&self) -> u64 {
            crate::base_helper::bpf_get_current_pid_tgid()
        }

        pub fn bpf_get_smp_processor_id(&self) -> u32 {
            crate::base_helper::bpf_get_smp_processor_id()
        }

        pub fn bpf_map_lookup_elem<K, V>(&self, map: &IUMap<K, V>, key: K) -> Option<V>
        where
            V: Copy,
        {
            crate::base_helper::bpf_map_lookup_elem::<K, V>(map, key)
        }

        pub fn bpf_map_update_elem<K, V>(
            &self,
            map: &IUMap<K, V>,
            key: K,
            value: V,
            flags: u64,
        ) -> i64 {
            crate::base_helper::bpf_map_update_elem::<K, V>(map, key, value, flags)
        }
    };
}

pub(crate) use base_helper_defs;
