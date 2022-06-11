use core::marker::PhantomData;
use core::mem::size_of;

// #define TASK_COMM_LEN 16
// #define PERF_MAX_STACK_DEPTH 127

pub const TASK_COMM_LEN: usize = 16;
pub const PERF_MAX_STACK_DEPTH: usize = 127;

// struct key_t {
//     char comm[TASK_COMM_LEN];
//     u32 kernstack;
//     u32 userstack;
// };

#[derive(Copy, Clone)]
pub struct key_t {
    pub comm: [u8; TASK_COMM_LEN],
    pub kernstack: u32,
    pub userstack: u32,
}

#[repr(C)]
pub struct IUMap<K, V> {
    map_type: u32,
    key_size: u32,
    val_size: u32,
    max_size: u32,
    map_flag: u32,
    key_type: PhantomData<K>,
    val_type: PhantomData<V>,
}

impl<K, V> IUMap<K, V> {
    pub const fn new(mt: u32, ms: u32, mf: u32) -> IUMap<K, V> {
        Self {
            map_type: mt,
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
        static $in: IUMap<$k, $v> = IUMap::new($mt, $ms, $mf);

        #[no_mangle]
        #[used]
        #[link_section = ".maps"]
        static $n: &IUMap<$k, $v> = &$in;
    };
}
