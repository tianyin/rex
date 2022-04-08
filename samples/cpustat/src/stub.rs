pub const STUB_BPF_LOOKUP_ELEM: u64 = 0xffffffff81208f90;
pub const STUB_BPF_UPDATE_ELEM: u64 = 0xffffffff81208fc0;
pub const STUB_BPF_KTIME_GET_NS: u64 = 0xffffffff81208530;
/* flags for BPF_MAP_UPDATE_ELEM command */
pub const BPF_ANY: u64 = 0;
pub const BPF_NOEXIST: u64 = 1;
pub const BPF_EXIST: u64 = 2;
pub const BPF_F_LOCK: u64 = 4;