use crate::{base_helper::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_peek_elem, bpf_map_pop_elem, bpf_map_push_elem, bpf_map_update_elem}, linux::bpf::{
    bpf_map_type, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_RINGBUF,
    BPF_MAP_TYPE_STACK_TRACE,
}};
use core::{marker::PhantomData, mem, ptr};

#[repr(C)]
pub struct IUMap<const MT: bpf_map_type, K, V> {
    // Map metadata
    map_type: u32,
    key_size: u32,
    val_size: u32,
    max_size: u32,
    map_flag: u32,

    // Actual kernel side map pointer
    pub(crate) kptr: *mut (),

    // Zero-sized marker
    key_type: PhantomData<K>,
    val_type: PhantomData<V>,
}

impl<const MT: bpf_map_type, K, V> IUMap<MT, K, V> {
    pub const fn new(ms: u32, mf: u32) -> IUMap<MT, K, V> {
        Self {
            map_type: MT,
            key_size: mem::size_of::<K>() as u32,
            val_size: mem::size_of::<V>() as u32,
            max_size: ms,
            map_flag: mf,
            kptr: ptr::null_mut(),
            key_type: PhantomData,
            val_type: PhantomData,
        }
    }
}

unsafe impl<const MT: bpf_map_type, K, V> Sync for IUMap<MT, K, V> {}

#[macro_export]
macro_rules! MAP_DEF {
    ($n:ident, $k:ty, $v:ty, $mt:expr, $ms:expr, $mf:expr) => {
        #[no_mangle]
        #[link_section = ".maps"]
        pub(crate) static $n: IUMap<$mt, $k, $v> = IUMap::new($ms, $mf);
    };
}

pub type IUArrayMap<V> = IUMap<BPF_MAP_TYPE_ARRAY, u32, V>;
pub type IUHashMap<K, V> = IUMap<BPF_MAP_TYPE_HASH, K, V>;
pub type IURingBuf = IUMap<BPF_MAP_TYPE_RINGBUF, (), ()>;
pub type IUStackMap<K, V> = IUMap<BPF_MAP_TYPE_STACK_TRACE, K, V>;

impl IUHashMap<K, V> {
    fn new(max_size: u32, map_flag: u32) -> IUHashMap<K, V> {
        IUMap::new(max_size, map_flag)
    }
    fn insert(&mut self, key: &K, value: &V) -> Result {
        bpf_map_update_elem(self, key, value, self.map_flag)
    }
    fn get(&self, key: &K) -> Option<&V> {
        bpf_map_lookup_elem(self, key)
    }
    fn delete(&mut self, key: &K) -> Result {
        bpf_map_delete_elem(self, key)
    }
}

impl core::ops::Index<Idx: u32> for IUArrayMap<V> {
    type Output = V;
    fn index(&self, index: Idx) -> &Self::Output {
        bpf_map_lookup_elem(self, &index).unwrap()
    }
}

impl core::ops::IndexMut<Idx: u32> for IUArrayMap<V> {
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        bpf_map_lookup_elem(self, &index).unwrap()
    }
}

impl IURingBuf {
    fn new(max_size: u32, map_flag: u32) -> IURingBuf {
        IUMap::new(max_size, map_flag)
    }
    fn push(&mut self, value: &V) -> Result {
        bpf_map_push_elem(self, value, self.map_flag)
    }
    fn pop(&mut self, value: &V) -> Result {
        bpf_map_pop_elem(self, value)
    }
    fn peek(&self, value: &V) -> Result {
        bpf_map_peek_elem(self, value)
    }
}

impl IUStackMap<K, V> {
    fn new(max_size: u32, map_flag: u32) -> IUStackMap<K, V> {
        IUMap::new(max_size, map_flag)
    }
    fn push(&mut self, value: &V) -> Result {
        bpf_map_push_elem(self, value, self.map_flag)
    }
    fn pop(&mut self, value: &V) -> Result {
        bpf_map_pop_elem(self, value)
    }
    fn peek(&self, value: &V) -> Result {
        bpf_map_peek_elem(self, value)
    }
}