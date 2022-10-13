use crate::map::IUMap;
use crate::stub;

pub fn bpf_map_lookup_elem<K, V>(map: &IUMap<K, V>, key: K) -> Option<V>
where
    V: Copy,
{
    let f_ptr = stub::STUB_BPF_MAP_LOOKUP_ELEM as *const ();
    let helper: extern "C" fn(&IUMap<K, V>, *const K) -> *mut V =
        unsafe { core::mem::transmute(f_ptr) };

    let value = helper(map, &key) as *mut V;

    if value.is_null() {
        None
    } else {
        Some(unsafe { *value })
    }
}

pub fn bpf_map_update_elem<K, V>(map: &IUMap<K, V>, key: K, value: V, flags: u64) -> i64 {
    let f_ptr = stub::STUB_BPF_MAP_UPDATE_ELEM as *const ();
    let helper: extern "C" fn(&IUMap<K, V>, *const K, *const V, u64) -> i64 =
        unsafe { core::mem::transmute(f_ptr) };

    helper(map, &key, &value, flags)
}
