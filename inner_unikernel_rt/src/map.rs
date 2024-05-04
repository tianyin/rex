use crate::base_helper::bpf_ringbuf_query;
use crate::utils::{to_result, Result};
use crate::{
    base_helper::{
        bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_peek_elem,
        bpf_map_pop_elem, bpf_map_push_elem, bpf_map_update_elem,
        bpf_ringbuf_discard, bpf_ringbuf_reserve, bpf_ringbuf_submit,
    },
    linux::bpf::{
        bpf_map_type, BPF_ANY, BPF_EXIST, BPF_MAP_TYPE_ARRAY,
        BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_STACK, BPF_MAP_TYPE_QUEUE,
        BPF_MAP_TYPE_STACK_TRACE,
        BPF_NOEXIST, BPF_RB_AVAIL_DATA, BPF_RB_CONS_POS, BPF_RB_PROD_POS,
        BPF_RB_RING_SIZE,
    },
};
use core::{marker::PhantomData, mem, ptr};

#[repr(C)]
pub struct IUMapHandle<const MT: bpf_map_type, K, V> {
    // Map metadata
    map_type: u32,
    key_size: u32,
    val_size: u32,
    max_size: u32,
    map_flag: u32,

    // Actual kernel side map pointer
    pub kptr: *mut (),

    // Zero-sized marker
    key_type: PhantomData<K>,
    val_type: PhantomData<V>,
}

impl<const MT: bpf_map_type, K, V> IUMapHandle<MT, K, V> {
    pub const fn new(ms: u32, mf: u32) -> IUMapHandle<MT, K, V> {
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

unsafe impl<const MT: bpf_map_type, K, V> Sync for IUMapHandle<MT, K, V> {}

#[macro_export]
macro_rules! MAP_DEF {
    ($n:ident, $k:ty, $v:ty, $mt:expr, $ms:expr, $mf:expr) => {
        #[no_mangle]
        #[link_section = ".maps"]
        pub(crate) static $n: IUMapHandle<$mt, $k, $v> =
            IUMapHandle::new($ms, $mf);
    };
}

pub type IUArray<V> = IUMapHandle<BPF_MAP_TYPE_ARRAY, u32, V>;
pub type IUHashMap<K, V> = IUMapHandle<BPF_MAP_TYPE_HASH, K, V>;
pub type IURingBuf = IUMapHandle<BPF_MAP_TYPE_RINGBUF, (), ()>;
pub type IUStack<V> = IUMapHandle<BPF_MAP_TYPE_STACK, (), V>;
pub type IUQueue<V> = IUMapHandle<BPF_MAP_TYPE_QUEUE, (), V>;
pub type IUStackTrace<K, V> = IUMapHandle<BPF_MAP_TYPE_STACK_TRACE, K, V>;

impl<'a, K, V> IUHashMap<K, V> {
    pub fn insert(&'static self, key: &K, value: &V) -> Result {
        bpf_map_update_elem(self, key, value, BPF_ANY as u64)
    }

    pub fn insert_new(&'static self, key: &K, value: &V) -> Result {
        bpf_map_update_elem(self, key, value, BPF_NOEXIST as u64)
    }

    pub fn update(&'static self, key: &K, value: &V) -> Result {
        bpf_map_update_elem(self, key, value, BPF_EXIST as u64)
    }

    pub fn get_mut(&'static self, key: &'a K) -> Option<&'a mut V> {
        bpf_map_lookup_elem(self, key)
    }

    pub fn delete(&'static self, key: &K) -> Result {
        bpf_map_delete_elem(self, key)
    }
}

impl<'a, V> IUArray<V> {
    pub fn insert(&'static self, key: &u32, value: &V) -> Result {
        bpf_map_update_elem(self, key, value, BPF_ANY as u64)
    }

    pub fn get_mut(&'static self, key: &'a u32) -> Option<&'a mut V> {
        bpf_map_lookup_elem(self, key)
    }

    pub fn delete(&'static self, key: &u32) -> Result {
        bpf_map_delete_elem(self, key)
    }
}

// impl<V> core::ops::Index<u32> for IUArrayMap<V> {
//     type Output = V;

//     fn index(&self, index: u32) -> &Self::Output {
//         bpf_map_lookup_elem(self, &index).unwrap()
//     }
// }

// impl<V> core::ops::IndexMut<u32> for IUArrayMap<V> {
//     fn index_mut(&mut self, index: u32) -> &mut Self::Output {
//         bpf_map_lookup_elem(self, &index).unwrap()
//     }
// }

impl IURingBuf {
    pub fn reserve(
        &'static self,
        size: u64,
        submit_by_default: bool,
    ) -> Option<IURingBufEntry> {
        bpf_ringbuf_reserve(self, size, 0).map(|data| IURingBufEntry {
            data,
            submit_by_default,
            has_used: false,
        })
    }

    pub fn available_bytes(&'static self) -> Option<u64> {
        bpf_ringbuf_query(self, BPF_RB_AVAIL_DATA as u64)
    }

    pub fn size(&'static self) -> Option<u64> {
        bpf_ringbuf_query(self, BPF_RB_RING_SIZE as u64)
    }

    pub fn consumer_position(&'static self) -> Option<u64> {
        bpf_ringbuf_query(self, BPF_RB_CONS_POS as u64)
    }

    pub fn producer_position(&'static self) -> Option<u64> {
        bpf_ringbuf_query(self, BPF_RB_PROD_POS as u64)
    }
}

impl<V> IUStack<V> {
    pub fn push(&'static self, value: &V) -> Result {
        bpf_map_push_elem(self, value, BPF_ANY as u64)
    }

    pub fn force_push(&'static self, value: &V) -> Result {
        bpf_map_push_elem(self, value, BPF_EXIST as u64)
    }

    pub fn pop(&'static self, value: &V) -> Result {
        bpf_map_pop_elem(self, value)
    }

    pub fn peek(&'static self, value: &V) -> Result {
        bpf_map_peek_elem(self, value)
    }
}

impl<V> IUQueue<V> {
    pub fn push(&'static self, value: &V) -> Result {
        bpf_map_push_elem(self, value, BPF_ANY as u64)
    }

    pub fn force_push(&'static self, value: &V) -> Result {
        bpf_map_push_elem(self, value, BPF_EXIST as u64)
    }

    pub fn pop(&'static self, value: &V) -> Result {
        bpf_map_pop_elem(self, value)
    }

    pub fn peek(&'static self, value: &V) -> Result {
        bpf_map_peek_elem(self, value)
    }
}

pub struct IURingBufEntry<'a> {
    data: &'a mut [u8],
    submit_by_default: bool,
    has_used: bool,
}

impl<'a> IURingBufEntry<'a> {
    pub fn submit(mut self) {
        self.has_used = true;
        bpf_ringbuf_submit(self.data, 0)
    }

    pub fn discard(mut self) {
        self.has_used = true;
        bpf_ringbuf_discard(self.data, 0)
    }
}

impl<'a> core::ops::Drop for IURingBufEntry<'a> {
    fn drop(&mut self) {
        if !self.has_used {
            if self.submit_by_default {
                bpf_ringbuf_submit(self.data, 0);
            } else {
                bpf_ringbuf_discard(self.data, 0);
            }
        }
    }
}
