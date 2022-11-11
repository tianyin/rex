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

pub(crate) fn bpf_trace_printk(fmt: &str, arg1: u64, arg2: u64, arg3: u64) -> i32 {
    let ptr = stub::STUB_BPF_TRACE_PRINTK_IU as *const ();
    let code: extern "C" fn(*const u8, u32, u64, u64, u64) -> i32 =
        unsafe { core::mem::transmute(ptr) };

    code(fmt.as_ptr(), fmt.len() as u32, arg1, arg2, arg3)
}

pub(crate) fn bpf_map_lookup_elem<K, V>(map: &IUMap<K, V>, key: K) -> Option<&mut V> {
    let f_ptr = stub::STUB_BPF_MAP_LOOKUP_ELEM as *const ();
    let helper: extern "C" fn(&IUMap<K, V>, *const K) -> *const V =
        unsafe { core::mem::transmute(f_ptr) };

    let value = helper(map, &key) as *mut V;

    if value.is_null() {
        None
    } else {
        Some(unsafe { &mut *value })
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

        pub fn bpf_trace_printk(&self, fmt: &str, arg1: u64, arg2: u64, arg3: u64) -> i32 {
            crate::base_helper::bpf_trace_printk(fmt, arg1, arg2, arg3)
        }

        // Self should already have impl<'a>
        pub fn bpf_map_lookup_elem<K, V>(&self, map: &'a IUMap<K, V>, key: K) -> Option<&mut V> {
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
