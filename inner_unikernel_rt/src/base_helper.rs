use crate::bindings::uapi::linux::bpf::bpf_spin_lock;
use crate::debug::printk;
use crate::linux::bpf::bpf_map_type;
use crate::linux::errno::EINVAL;
use crate::map::IUMap;
use crate::per_cpu::this_cpu_read;
use crate::random32::bpf_user_rnd_u32;
use crate::stub;
// use crate::timekeeping::*;

pub(crate) fn bpf_get_smp_processor_id() -> u32 {
    unsafe { this_cpu_read(stub::cpu_number_addr()) }
}

pub(crate) fn bpf_trace_printk(
    fmt: &str,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> i32 {
    let code: extern "C" fn(*const u8, u32, u64, u64, u64) -> i32 =
        unsafe { core::mem::transmute(stub::bpf_trace_printk_iu_addr()) };
    code(fmt.as_ptr(), fmt.len() as u32, arg1, arg2, arg3)
}

pub(crate) fn bpf_map_lookup_elem<const MT: bpf_map_type, K, V>(
    map: &'static IUMap<MT, K, V>,
    key: K,
) -> Option<&mut V> {
    if map.kptr.is_null() {
        return None;
    }

    let helper: extern "C" fn(*mut (), *const K) -> *const V =
        unsafe { core::mem::transmute(stub::bpf_map_lookup_elem_addr()) };
    let value = helper(map.kptr, &key) as *mut V;

    if value.is_null() {
        None
    } else {
        Some(unsafe { &mut *value })
    }
}

pub(crate) fn bpf_map_update_elem<const MT: bpf_map_type, K, V>(
    map: &'static IUMap<MT, K, V>,
    key: K,
    value: V,
    flags: u64,
) -> i64 {
    if map.kptr.is_null() {
        return -(EINVAL as i64);
    }

    let helper: extern "C" fn(*mut (), *const K, *const V, u64) -> i64 =
        unsafe { core::mem::transmute(stub::bpf_map_update_elem_addr()) };
    helper(map.kptr, &key, &value, flags)
}

pub(crate) fn bpf_map_delete_elem<const MT: bpf_map_type, K, V>(
    map: &'static IUMap<MT, K, V>,
    key: K,
) -> i64 {
    if map.kptr.is_null() {
        return -(EINVAL as i64);
    }

    let helper: extern "C" fn(*mut (), *const K) -> i64 =
        unsafe { core::mem::transmute(stub::bpf_map_delete_elem_addr()) };
    helper(map.kptr, &key)
}

pub(crate) fn bpf_map_push_elem<const MT: bpf_map_type, K, V>(
    map: &'static IUMap<MT, K, V>,
    value: V,
    flags: u64,
) -> i64 {
    if map.kptr.is_null() {
        return -(EINVAL as i64);
    }

    let helper: extern "C" fn(*mut (), *const V, u64) -> i64 =
        unsafe { core::mem::transmute(stub::bpf_map_push_elem_addr()) };
    helper(map.kptr, &value, flags)
}

pub(crate) fn bpf_map_pop_elem<const MT: bpf_map_type, K, V>(
    map: &'static IUMap<MT, K, V>,
    value: V,
) -> i64 {
    if map.kptr.is_null() {
        return -(EINVAL as i64);
    }

    let helper: extern "C" fn(*mut (), *const V) -> i64 =
        unsafe { core::mem::transmute(stub::bpf_map_pop_elem_addr()) };
    helper(map.kptr, &value)
}

pub(crate) fn bpf_map_peek_elem<const MT: bpf_map_type, K, V>(
    map: &'static IUMap<MT, K, V>,
    value: V,
) -> i64 {
    if map.kptr.is_null() {
        return -(EINVAL as i64);
    }

    let helper: extern "C" fn(*mut (), *const V) -> i64 =
        unsafe { core::mem::transmute(stub::bpf_map_peek_elem_addr()) };
    helper(map.kptr, &value)
}

/*
pub(crate) fn bpf_for_each_map_elem<const MT: bpf_map_type, K, V>(
    map: &IUMap<MT, K, V>,
    callback_fn: *const (),
    callback_ctx: *const (),
    flags: u64,
) -> i64 {
    let helper: extern "C" fn(
        &IUMap<MT, K, V>,
        *const (),
        *const (),
        u64,
    ) -> i64 =
        unsafe { core::mem::transmute(stub::bpf_for_each_map_elem_addr()) };
    helper(map, callback_fn, callback_ctx, flags)
}

pub(crate) fn bpf_spin_lock(lock: &mut bpf_spin_lock) -> i64 {
    let helper: extern "C" fn(*mut bpf_spin_lock) -> i64 =
        unsafe { core::mem::transmute(stub::bpf_spin_lock_addr()) };
    helper(lock as *mut bpf_spin_lock)
}

pub(crate) fn bpf_spin_unlock(lock: &mut bpf_spin_lock) -> i64 {
    let helper: extern "C" fn(*mut bpf_spin_lock) -> i64 =
        unsafe { core::mem::transmute(stub::bpf_spin_unlock_addr()) };
    helper(lock as *mut bpf_spin_lock)
}
*/

// Design decision: Make the destination a generic type so that probe read
// kernel can directly fill in variables of certain type. This also achieves
// size checking, since T is known at compile time for monomorphization
pub(crate) fn bpf_probe_read_kernel<T>(
    dst: &mut T,
    unsafe_ptr: *const (),
) -> i64 {
    let helper: extern "C" fn(*mut (), u32, *const ()) -> i64 =
        unsafe { core::mem::transmute(stub::bpf_probe_read_kernel_addr()) };
    helper(
        dst as *mut T as *mut (),
        core::mem::size_of::<T>() as u32,
        unsafe_ptr,
    )
}

pub(crate) fn bpf_strcmp(s1: &str, s2: &str) -> i32 {
    let mut cs1 = s1.chars();
    let mut cs2 = s2.chars();

    loop {
        let rc1 = cs1.next();
        let rc2 = cs2.next();

        match (rc1, rc2) {
            (Some(c1), Some(c2)) => {
                if c1 == c2 {
                    continue;
                }
                return if c1 < c2 { -1 } else { 1 };
            }
            (None, Some(_)) => {
                return -1;
            }
            (Some(_), None) => {
                return 1;
            }
            (None, None) => {
                break;
            }
        };
    }
    0
}

pub(crate) fn bpf_strncmp(s1: &str, s2: &str, cnt: usize) -> i32 {
    let mut cs1 = s1.chars();
    let mut cs2 = s2.chars();
    let mut idx = 0;

    while idx < cnt {
        let rc1 = cs1.next();
        let rc2 = cs2.next();
        idx += 1;

        match (rc1, rc2) {
            (Some(c1), Some(c2)) => {
                if c1 == c2 {
                    continue;
                }
                return if c1 < c2 { -1 } else { 1 };
            }
            (None, Some(_)) => {
                return -1;
            }
            (Some(_), None) => {
                return 1;
            }
            (None, None) => {
                break;
            }
        };
    }
    0
}

pub(crate) fn bpf_jiffies64() -> u64 {
    unsafe { core::ptr::read_volatile(stub::jiffies_addr() as *const u64) }
}

/// Assumes `CONFIG_USE_PERCPU_NUMA_NODE_ID`
pub(crate) fn bpf_get_numa_node_id() -> i64 {
    let id = unsafe { this_cpu_read::<u64>(stub::numa_node_addr()) };
    id as i64
}

// This two functions call the original helper directly, so that confirm the
// return value is correct
pub(crate) fn bpf_ktime_get_ns_origin() -> u64 {
    let helper: extern "C" fn() -> u64 =
        unsafe { core::mem::transmute(stub::ktime_get_mono_fast_ns_addr()) };
    helper()
}

pub(crate) fn bpf_ktime_get_boot_ns_origin() -> u64 {
    let helper: extern "C" fn() -> u64 =
        unsafe { core::mem::transmute(stub::ktime_get_boot_fast_ns_addr()) };
    helper()
}

/*
pub(crate) fn bpf_ktime_get_ns() -> u64 {
    ktime_get_mono_fast_ns()
}

pub(crate) fn bpf_ktime_get_boot_ns() -> u64 {
    ktime_get_boot_fast_ns()
}

pub(crate) fn bpf_ktime_get_coarse_ns() -> u64 {
    ktime_get_coarse() as u64
}
*/

pub(crate) fn bpf_get_prandom_u32() -> u32 {
    bpf_user_rnd_u32()
}

// In document it says that data is a pointer to an array of 64-bit values.
pub(crate) fn bpf_snprintf<const N: usize, const M: usize>(
    str: &mut [u8; N],
    fmt: &str,
    data: &[u64; M],
) -> i64 {
    let helper: extern "C" fn(*mut u8, u32, *const u8, *const u64, u32) -> i64 =
        unsafe { core::mem::transmute(stub::bpf_snprintf_addr()) };
    helper(
        str.as_mut_ptr(),
        N as u32,
        fmt.as_ptr(),
        data.as_ptr(),
        M as u32,
    )
}

macro_rules! base_helper_defs {
    () => {
        #[inline(always)]
        pub fn bpf_get_smp_processor_id(&self) -> u32 {
            crate::base_helper::bpf_get_smp_processor_id()
        }

        #[inline(always)]
        pub fn bpf_trace_printk(
            &self,
            fmt: &str,
            arg1: u64,
            arg2: u64,
            arg3: u64,
        ) -> i32 {
            crate::base_helper::bpf_trace_printk(fmt, arg1, arg2, arg3)
        }

        // Self should already have impl<'a>
        #[inline(always)]
        pub fn bpf_map_lookup_elem<const MT: bpf_map_type, K, V>(
            &self,
            map: &'static IUMap<MT, K, V>,
            key: K,
        ) -> Option<&mut V> {
            crate::base_helper::bpf_map_lookup_elem(map, key)
        }

        #[inline(always)]
        pub fn bpf_map_update_elem<const MT: bpf_map_type, K, V>(
            &self,
            map: &'static IUMap<MT, K, V>,
            key: K,
            value: V,
            flags: u64,
        ) -> i64 {
            crate::base_helper::bpf_map_update_elem(map, key, value, flags)
        }

        #[inline(always)]
        pub fn bpf_map_delete_elem<const MT: bpf_map_type, K, V>(
            &self,
            map: &'static IUMap<MT, K, V>,
            key: K,
        ) -> i64 {
            crate::base_helper::bpf_map_delete_elem(map, key)
        }

        #[inline(always)]
        pub fn bpf_map_push_elem<const MT: bpf_map_type, K, V>(
            &self,
            map: &'static IUMap<MT, K, V>,
            value: V,
            flags: u64,
        ) -> i64 {
            crate::base_helper::bpf_map_push_elem(map, value, flags)
        }

        #[inline(always)]
        pub fn bpf_map_pop_elem<const MT: bpf_map_type, K, V>(
            &self,
            map: &'static IUMap<MT, K, V>,
            value: V,
        ) -> i64 {
            crate::base_helper::bpf_map_pop_elem(map, value)
        }

        #[inline(always)]
        pub fn bpf_map_peek_elem<const MT: bpf_map_type, K, V>(
            &self,
            map: &'static IUMap<MT, K, V>,
            value: V,
        ) -> i64 {
            crate::base_helper::bpf_map_peek_elem(map, value)
        }

        #[inline(always)]
        pub fn bpf_probe_read_kernel<T>(
            &self,
            dst: &mut T,
            unsafe_ptr: *const (),
        ) -> i64 {
            crate::base_helper::bpf_probe_read_kernel(dst, unsafe_ptr)
        }

        #[inline(always)]
        pub fn bpf_get_numa_node_id(&self) -> i64 {
            crate::base_helper::bpf_get_numa_node_id()
        }
        #[inline(always)]
        pub fn bpf_ktime_get_ns_origin(&self) -> u64 {
            crate::base_helper::bpf_ktime_get_ns_origin()
        }

        #[inline(always)]
        pub fn bpf_ktime_get_boot_ns_origin(&self) -> u64 {
            crate::base_helper::bpf_ktime_get_boot_ns_origin()
        }

        /*
        #[inline(always)]
        pub fn bpf_ktime_get_ns(&self) -> u64 {
            crate::base_helper::bpf_ktime_get_ns()
        }

        #[inline(always)]
        pub fn bpf_ktime_get_boot_ns(&self) -> u64 {
            crate::base_helper::bpf_ktime_get_boot_ns()
        }

        #[inline(always)]
        pub fn bpf_ktime_get_coarse_ns(&self) -> u64 {
            crate::base_helper::bpf_ktime_get_coarse_ns()
        }
        */

        #[inline(always)]
        pub fn bpf_get_prandom_u32(&self) -> u32 {
            crate::base_helper::bpf_get_prandom_u32()
        }

        /*
        #[inline(always)]
        pub fn bpf_spin_lock(
            &self,
            lock: &mut crate::bindings::uapi::linux::bpf::bpf_spin_lock,
        ) -> i64 {
            crate::base_helper::bpf_spin_lock(lock)
        }

        #[inline(always)]
        pub fn bpf_spin_unlock(
            &self,
            lock: &mut crate::bindings::uapi::linux::bpf::bpf_spin_lock,
        ) -> i64 {
            crate::base_helper::bpf_spin_unlock(lock)
        }
        */

        #[inline(always)]
        pub fn bpf_snprintf<const N: usize, const M: usize>(
            &self,
            buf: &mut [u8; N],
            fmt: &str,
            data: &[u64; M],
        ) -> i64 {
            crate::base_helper::bpf_snprintf(buf, fmt, data)
        }
    };
}

#[macro_export]
macro_rules! bpf_printk {
    ($obj:expr, $fmt:expr) => {
        $obj.bpf_trace_printk($fmt, 0, 0, 0)
    };

    ($obj:expr, $fmt:expr, $arg1:expr) => {
        $obj.bpf_trace_printk($fmt, $arg1, 0, 0)
    };

    ($obj:expr, $fmt:expr, $arg1:expr, $arg2:expr) => {
        $obj.bpf_trace_printk($fmt, $arg1, $arg2, 0)
    };

    ($obj:expr, $fmt:expr, $arg1:expr, $arg2:expr, $arg3:expr) => {
        $obj.bpf_trace_printk($fmt, $arg1, $arg2, $arg3)
    };
}

pub(crate) use base_helper_defs;
pub use bpf_printk;
