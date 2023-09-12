use crate::linux::bpf::bpf_map_type;
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
        #[used]
        #[link_section = ".maps"]
        static $n: IUMap<$mt, $k, $v> = IUMap::new($ms, $mf);
    };
}
