#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

extern crate inner_unikernel_rt;

use core::mem::size_of;
use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::entry_link;
use inner_unikernel_rt::linux::bpf::{
    BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_PERCPU_ARRAY,
};
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::sched_cls::*;
use inner_unikernel_rt::utils::*;
use inner_unikernel_rt::xdp::*;
use inner_unikernel_rt::FieldTransmute;
use inner_unikernel_rt::MAP_DEF;

const BMC_MAX_PACKET_LENGTH: usize = 1500;
const BMC_CACHE_ENTRY_COUNT: u32 = 25000;
const BMC_MAX_KEY_LENGTH: u32 = 230;
const BMC_MAX_KEY_IN_MULTIGET: u32 = 30;
const BMC_MAX_KEY_IN_PACKET: u32 = BMC_MAX_KEY_IN_MULTIGET;

const FNV_OFFSET_BASIS_32: u32 = 2166136261;
const FNV_PRIME_32: u32 = 16777619;

#[derive(FieldTransmute)]
#[repr(C, packed)]
pub struct memcached_udp_header {
    request_id: u16,
    seq_num: u16,
    num_dgram: u16,
    unused: u16,
}

#[derive(FieldTransmute)]
#[repr(C, packed)]
pub struct eth_header {
    pub h_dest: [u8; 6usize],
    pub h_source: [u8; 6usize],
    pub h_proto: u16,
}

#[repr(C)]
pub struct bmc_cache_entry {
    // struct bpf_spin_lock lock;
    pub len: u32,
    pub valid: u8,
    pub hash: u32,
    pub data: [u8; BMC_MAX_PACKET_LENGTH],
}

#[repr(C)]
struct memcached_key {
    hash: u32,
    data: [u8; BMC_MAX_KEY_LENGTH as usize],
    len: u32,
}

struct parsing_context {
    key_count: u32,
    current_key: u32,
    read_pkt_offset: u8,
    write_pkt_offset: u8,
}

MAP_DEF!(map_hash, __map_1, u32, i64, BPF_MAP_TYPE_HASH, 1024, 0);
MAP_DEF!(map_array, __map_2, u32, u64, BPF_MAP_TYPE_ARRAY, 256, 0);
MAP_DEF!(
    map_kcache,
    __map_3,
    u32,
    bmc_cache_entry,
    BPF_MAP_TYPE_ARRAY,
    BMC_CACHE_ENTRY_COUNT,
    0
);
MAP_DEF!(
    map_keys,
    __map_4,
    u32,
    memcached_key,
    BPF_MAP_TYPE_PERCPU_ARRAY,
    BMC_MAX_KEY_IN_PACKET,
    0
);

#[inline(always)]
fn hash_key(obj: &xdp, ctx: &xdp_md, pctx: &parsing_context, payload: &[u8]) -> u32 {
    let mut key = match obj.bpf_map_lookup_elem(map_keys, pctx.key_count) {
        None => return XDP_PASS,
        Some(k) => k,
    };

    key.hash = FNV_OFFSET_BASIS_32;

    let (mut off, mut done_parsing, mut key_len) = (0usize, 0u32, 0u32);

    while off < BMC_MAX_KEY_LENGTH as usize + 1
        && pctx.read_pkt_offset as usize + off + 1 <= ctx.data_length
    {
        if (payload[off] == b'\r') {
            done_parsing = 1;
            break;
        } else if (payload[off] == b' ') {
            break;
        } else if (payload[off] != b' ') {
            key.hash ^= payload[off] as u32;
            key.hash *= FNV_PRIME_32;
            key_len += 1;
        }
        off += 1;
    }

    0
}

fn xdp_rx_filter_fn(obj: &xdp, ctx: &xdp_md) -> u32 {
    let eth_header = eth_header::new(&ctx.data_slice[0..14]);
    let ip_header = obj.ip_header(ctx);

    match u8::from_be(ip_header.protocol) as u32 {
        IPPROTO_TCP => {
            // NOTE: currently we only take care of UDP memcached
        }
        IPPROTO_UDP => {
            let udp_header = obj.udp_header(ctx);
            let port = u16::from_be(obj.udp_header(ctx).dest);
            let header_len = size_of::<ethhdr>()
                + size_of::<iphdr>()
                + size_of::<udphdr>()
                + size_of::<memcached_udp_header>();
            let payload = &ctx.data_slice[header_len..];

            // check if using the memcached port
            // check if the payload has enough space for a memcached request
            if (port != 11211 || payload.len() < 4) {
                return XDP_PASS;
            }

            // check if a get request
            if !payload.starts_with(b"get ") {
                return XDP_PASS;
            }

            let mut off = 4;
            // move offset to the start of the first key
            while (off < BMC_MAX_PACKET_LENGTH && off + 1 < payload.len() && payload[off] == b' ') {
                off += 1;
            }
            off += header_len;

            let pctx = parsing_context {
                key_count: 0,
                current_key: 0,
                read_pkt_offset: off as u8,
                write_pkt_offset: 0,
            };

            // hash the key
            hash_key(obj, ctx, &pctx, payload);

            bpf_printk!(obj, "offset is %d\n", off as u64);
        }
        _ => {}
    };

    XDP_PASS
}
fn xdp_tx_filter_fn(obj: &sched_cls, skb: &__sk_buff) -> u32 {
    0
}
#[entry_link(inner_unikernel/xdp)]
static PROG1: xdp = xdp::new(xdp_rx_filter_fn, "xdp_rx_filter", BPF_PROG_TYPE_XDP as u64);

#[entry_link(inner_unikernel/tc)]
static PROG2: sched_cls = sched_cls::new(
    xdp_tx_filter_fn,
    "xdp_tx_filter",
    BPF_PROG_TYPE_SCHED_CLS as u64,
);
