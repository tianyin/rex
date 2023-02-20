use crate::map::IUMap;
use crate::stub;

pub(crate) fn bpf_get_current_pid_tgid() -> u64 {
    let ptr = stub::STUB_BPF_GET_CURRENT_PID_TGID as *const ();
    let code: extern "C" fn() -> u64 = unsafe { core::mem::transmute(ptr) };
    code()
}

// Design decision: the original BPF interface does not have type safety,
// since buf is just a buffer. But in Rust we can use const generics to
// restrict it to only [u8; N] given that comm is a cstring. This also
// automatically achieves size check, since N is a constexpr.
pub(crate) fn bpf_get_current_comm<const N: usize>(buf: &mut [u8; N]) -> i64 {
    let ptr = stub::STUB_BPF_GET_CURRENT_COMM as *const ();
    let code: extern "C" fn(*mut u8, u32) -> i64 = unsafe { core::mem::transmute(ptr) };
    code(buf.as_mut_ptr(), N as u32)
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

// Design decision: Make the destination a generic type so that probe read
// kernel can directly fill in variables of certain type. This also achieves
// size checking, since T is known at compile time for monomorphization
pub(crate) fn bpf_probe_read_kernel<T>(dst: &mut T, unsafe_ptr: *const ()) -> i64 {
    let f_ptr = stub::STUB_BPF_PROBE_READ_KERNEL as *const ();
    let helper: extern "C" fn(*mut (), u32, *const ()) -> i64 =
        unsafe { core::mem::transmute(f_ptr) };

    helper(
        dst as *mut T as *mut (),
        core::mem::size_of::<T>() as u32,
        unsafe_ptr,
    )
}

macro_rules! base_helper_defs {
    () => {
        #[inline(always)]
        pub fn bpf_get_current_comm<const N: usize>(&self, buf: &mut [u8; N]) -> i64 {
            crate::base_helper::bpf_get_current_comm::<N>(buf)
        }

        #[inline(always)]
        pub fn bpf_get_current_pid_tgid(&self) -> u64 {
            crate::base_helper::bpf_get_current_pid_tgid()
        }

        #[inline(always)]
        pub fn bpf_get_smp_processor_id(&self) -> u32 {
            crate::base_helper::bpf_get_smp_processor_id()
        }

        #[inline(always)]
        pub fn bpf_trace_printk(&self, fmt: &str, arg1: u64, arg2: u64, arg3: u64) -> i32 {
            crate::base_helper::bpf_trace_printk(fmt, arg1, arg2, arg3)
        }

        // Self should already have impl<'a>
        #[inline(always)]
        pub fn bpf_map_lookup_elem<K, V>(&self, map: &'a IUMap<K, V>, key: K) -> Option<&mut V> {
            crate::base_helper::bpf_map_lookup_elem::<K, V>(map, key)
        }

        #[inline(always)]
        pub fn bpf_map_update_elem<K, V>(
            &self,
            map: &IUMap<K, V>,
            key: K,
            value: V,
            flags: u64,
        ) -> i64 {
            crate::base_helper::bpf_map_update_elem::<K, V>(map, key, value, flags)
        }

        #[inline(always)]
        pub fn bpf_probe_read_kernel<T>(&self, dst: &mut T, unsafe_ptr: *const ()) -> i64 {
            crate::base_helper::bpf_probe_read_kernel::<T>(dst, unsafe_ptr)
        }
    };
}

pub(crate) use base_helper_defs;
