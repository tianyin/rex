use crate::common::*;
use crate::FastProgTc::*;
use crate::FastProgXdp::*;
use core::mem::size_of;
use inner_unikernel_rt::linux::bpf::{
    bpf_spin_lock, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_PERCPU_ARRAY,
    BPF_MAP_TYPE_RINGBUF,
};
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::utils::*;
use inner_unikernel_rt::xdp::*;
use inner_unikernel_rt::FieldTransmute;
use inner_unikernel_rt::MAP_DEF;

#[repr(C)]
struct paxos_quorum {
    view: u32,
    opnum: u32,
    bitset: u32,
}

#[repr(C)]
struct paxos_ctr_state {
    state: ReplicaStatus,
    my_idx: u32,
    leader_idx: u32,
    batch_size: u32,
    view: u64,
    last_op: u64,
}

#[repr(C)]
struct paxos_batch {
    counter: u32,
    lock: bpf_spin_lock,
}

MAP_DEF!(
    map_configure,
    u32,
    PaxosConfigure,
    BPF_MAP_TYPE_ARRAY,
    FAST_REPLICA_MAX,
    0
);

MAP_DEF!(
    map_ctr_state,
    u32,
    paxos_ctr_state,
    BPF_MAP_TYPE_ARRAY,
    1,
    0
);

MAP_DEF!(map_msg_last_op, u32, u64, BPF_MAP_TYPE_ARRAY, 1, 0);

MAP_DEF!(
    map_quorum,
    u32,
    paxos_quorum,
    BPF_MAP_TYPE_ARRAY,
    QUORUM_BITSET_ENTRY,
    0
);

MAP_DEF!(batch_context, u32, paxos_batch, BPF_MAP_TYPE_ARRAY, 1, 0);

MAP_DEF!(map_prepare_buffer, (), (), BPF_MAP_TYPE_RINGBUF, 1 << 20, 0);
MAP_DEF!(map_request_buffer, (), (), BPF_MAP_TYPE_RINGBUF, 1 << 20, 0);

#[derive(FieldTransmute)]
#[repr(C, packed)]
pub struct eth_header {
    pub h_dest: [u8; ETH_ALEN],
    pub h_source: [u8; ETH_ALEN],
    pub h_proto: u16,
}
