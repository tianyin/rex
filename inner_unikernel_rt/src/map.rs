use crate::linux::bpf::bpf_map_type;
use core::marker::PhantomData;
use core::mem::size_of;

#[repr(C)]
pub struct IUMap<const MT: bpf_map_type, K, V> {
    map_type: u32,
    key_size: u32,
    val_size: u32,
    max_size: u32,
    map_flag: u32,
    key_type: PhantomData<K>,
    val_type: PhantomData<V>,
}

impl<const MT: bpf_map_type, K, V> IUMap<MT, K, V> {
    pub const fn new(ms: u32, mf: u32) -> IUMap<MT, K, V> {
        Self {
            map_type: MT,
            key_size: size_of::<K>() as u32,
            val_size: size_of::<V>() as u32,
            max_size: ms,
            map_flag: mf,
            key_type: PhantomData,
            val_type: PhantomData,
        }
    }
}

#[macro_export]
macro_rules! MAP_DEF {
    ($n:ident, $in:ident, $k:ty, $v:ty, $mt:expr, $ms:expr, $mf:expr) => {
        #[no_mangle]
        #[used]
        #[link_section = ".maps"]
        static $in: IUMap<$mt, $k, $v> = IUMap::new($ms, $mf);

        #[no_mangle]
        #[used]
        #[link_section = ".maps"]
        static $n: &IUMap<$mt, $k, $v> = &$in;
    };
}
