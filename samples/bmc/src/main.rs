#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

extern crate inner_unikernel_rt;

use core::mem::{size_of, swap};

use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::entry_link;
use inner_unikernel_rt::linux::bpf::{
    bpf_spin_lock, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY,
};
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::sched_cls::*;
use inner_unikernel_rt::spinlock::*;
use inner_unikernel_rt::utils::*;
use inner_unikernel_rt::xdp::*;
use inner_unikernel_rt::FieldTransmute;
use inner_unikernel_rt::MAP_DEF;

const BMC_MAX_PACKET_LENGTH: usize = 1500;
const BMC_CACHE_ENTRY_COUNT: u32 = 3250000;
const BMC_MAX_KEY_LENGTH: usize = 230;
const BMC_MAX_VAL_LENGTH: usize = 1000;
const BMC_MAX_ADDITIONAL_PAYLOAD_BYTES: usize = 53;
const BMC_MAX_CACHE_DATA_SIZE: usize =
    BMC_MAX_KEY_LENGTH + BMC_MAX_VAL_LENGTH + BMC_MAX_ADDITIONAL_PAYLOAD_BYTES;
const BMC_MAX_KEY_IN_MULTIGET: u32 = 30;
const BMC_MAX_KEY_IN_PACKET: u32 = BMC_MAX_KEY_IN_MULTIGET;

// const FNV_OFFSET_BASIS_32: Wrapping<u32> = Wrapping(216613);
const FNV_OFFSET_BASIS_32: u32 = 2166136261;
const FNV_PRIME_32: u32 = 16777619;
// const FNV_PRIME_32: u32 = 5;
const ETH_ALEN: usize = 6;
const MEMCACHED_PORT: u16 = 11211;

// TODO: use simple hash function, may need update in the future
macro_rules! hash_func {
    ($hash:expr, $value:expr) => {
        $hash ^= $value as u32;
        $hash = $hash.wrapping_mul(FNV_PRIME_32);
    };
}

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
    pub h_dest: [u8; ETH_ALEN],
    pub h_source: [u8; ETH_ALEN],
    pub h_proto: u16,
}

#[repr(C)]
pub struct bmc_cache_entry {
    lock: bpf_spin_lock,
    pub len: u32,
    pub valid: u8,
    pub hash: u32,
    pub data: [u8; BMC_MAX_PACKET_LENGTH],
}

#[repr(C)]
struct memcached_key {
    hash: u32,
    data: [u8; BMC_MAX_KEY_LENGTH],
    len: usize,
}

#[repr(C)]
pub struct bmc_stats {
    get_recv_count: u32,
    set_recv_count: u32,
    get_resp_count: u32,
    hit_misprediction: u32,
    hit_count: u32,
    miss_count: u32,
    update_count: u32,
    invalidation_count: u32,
}

struct parsing_context {
    key_count: u32,
    current_key: u32,
    read_pkt_offset: u8,
    _write_pkt_offset: u8,
}

MAP_DEF!(
    map_kcache,
    u32,
    bmc_cache_entry,
    BPF_MAP_TYPE_ARRAY,
    BMC_CACHE_ENTRY_COUNT,
    0
);
MAP_DEF!(
    map_keys,
    u32,
    memcached_key,
    BPF_MAP_TYPE_PERCPU_ARRAY,
    BMC_MAX_KEY_IN_PACKET,
    0
);

MAP_DEF!(map_stats, u32, bmc_stats, BPF_MAP_TYPE_PERCPU_ARRAY, 1, 0);

// payload after header and 'get '
#[inline(always)]
fn hash_key(
    obj: &xdp,
    ctx: &mut xdp_md,
    pctx: &mut parsing_context,
    payload_index: usize,
    stats: &mut bmc_stats,
) -> Result {
    let (mut off, mut done_parsing) = (0usize, false);
    let payload = &ctx.data_slice[payload_index..];

    while !done_parsing {
        let mut key = obj
            .bpf_map_lookup_elem(&map_keys, &pctx.key_count)
            .ok_or(0i32)?;

        key.hash = FNV_OFFSET_BASIS_32;

        let payload = &payload
            [..(BMC_MAX_KEY_LENGTH + 1).min(ctx.data_length() - pctx.read_pkt_offset as usize)];

        let key_len = payload
            .iter()
            .take_while(|&&byte| byte != b'\r' && byte != b' ')
            .inspect(|&&byte| {
                hash_func!(key.hash, byte);
            })
            .count(); // Returns the number of elements processed, effectively the key length

        done_parsing = payload[key_len] == b'\r';

        // no key found
        if key_len == 0 || key_len as usize > BMC_MAX_KEY_LENGTH {
            return Ok(XDP_PASS as i32);
        }

        // get the cache entry
        let cache_idx: u32 = key.hash % BMC_CACHE_ENTRY_COUNT;
        let entry = obj
            .bpf_map_lookup_elem(&map_kcache, &cache_idx)
            .ok_or(0i32)?;

        let entry_valid;
        {
            let _guard = iu_spinlock_guard::new(&mut entry.lock);
            entry_valid = entry.valid == 1 && entry.hash == key.hash
        }

        // potential cache hit
        if entry_valid {
            // bpf_printk!(obj, "potential cache hit\n");
            key.data[0..key_len].clone_from_slice(&payload[0..key_len]);
            key.len = key_len;
            pctx.key_count += 1;
        } else {
            // cache miss
            stats.miss_count += 1;
        }

        if done_parsing {
            if pctx.key_count > 0 {
                return prepare_packet(obj, ctx, payload_index, pctx, stats);
            }
        } else {
            // process more keys
            off += 1;
            pctx.read_pkt_offset += off as u8;
        }
    }

    Ok(XDP_PASS as i32)
}

macro_rules! swap_field {
    ($field1:expr, $field2:expr, $size:ident) => {
        for i in 0..$size {
            swap(&mut $field1[i], &mut $field2[i])
        }
    };
}

// payload after header and 'get '
#[inline(always)]
fn prepare_packet(
    obj: &xdp,
    ctx: &mut xdp_md,
    payload_index: usize,
    pctx: &mut parsing_context,
    stats: &mut bmc_stats,
) -> Result {
    let eth_header = obj.eth_header(ctx);
    // exchange src and dst ip and mac
    swap_field!(eth_header.h_dest, eth_header.h_source, ETH_ALEN);

    let ip_header_mut = obj.ip_header(ctx);
    swap(&mut ip_header_mut.saddr, &mut ip_header_mut.daddr);

    let udp_header = obj.udp_header(ctx);
    swap(&mut udp_header.source, &mut udp_header.dest);

    write_pkt_reply(obj, ctx, payload_index, pctx, stats)
}

// payload after headers and 'get '
#[inline(always)]
fn write_pkt_reply(
    obj: &xdp,
    ctx: &mut xdp_md,
    payload_index: usize,
    pctx: &mut parsing_context,
    stats: &mut bmc_stats,
) -> Result {
    let key = obj
        .bpf_map_lookup_elem(&map_keys, &pctx.current_key)
        .ok_or(XDP_PASS as i32)?;

    let (mut cache_hit, _written) = (false, 0u32);

    let cache_idx = key.hash % BMC_CACHE_ENTRY_COUNT;
    let entry = obj
        .bpf_map_lookup_elem(&map_kcache, &cache_idx)
        .ok_or(XDP_DROP as i32)?;

    let _guard = iu_spinlock_guard::new(&mut entry.lock);

    if entry.valid == 1 && entry.hash == key.hash {
        // bpf_printk!(
        //     obj,
        //     "memcaced %s, entry %s\n",
        //     key.data.as_ptr() as u64,
        //     entry.data[6..6 + key.len].as_ptr() as u64
        // );
        if key.len >= BMC_MAX_KEY_LENGTH {
            cache_hit = false;
        } else {
            let entry_data_key = &entry.data[6..6 + key.len];
            cache_hit = key
                .data
                .iter()
                .zip(entry_data_key.iter())
                .all(|(a, b)| a == b);
            if !cache_hit {
                stats.hit_misprediction += 1;
            }
        }
    }

    // copy cache data
    if cache_hit {
        // bpf_printk!(obj, "cache hit\n");
        let _off = 0usize;
        let stats = obj.bpf_map_lookup_elem(&map_stats, &0).ok_or(0i32)?;
        stats.hit_count += 1;

        // bpf_printk!(obj, "length before %d\n", ctx.data_length as u64);
        // const U64_SIZE: usize = size_of::<u64>();
        // NOTE: data end is determined by slice length limit, may changed in future
        // while off + U64_SIZE < BMC_MAX_CACHE_DATA_SIZE && off + U64_SIZE <= entry.len as usize {}
        let padding = (entry.len as i32 - (ctx.data_length() - payload_index) as i32) + 1;
        // bpf_printk!(
        //     obj,
        //     "entry len %d payload_index %d padding %d\n",
        //     entry.len as u64,
        //     payload_index as u64,
        //     padding as u64
        // );

        match obj.bpf_xdp_adjust_tail(ctx, padding) {
            Ok(_) => {}
            Err(_) => {
                bpf_printk!(obj, "adjust tail failed\n");
                return Ok(XDP_DROP as i32);
            }
        }
        // bpf_printk!(obj, "length after %d\n", ctx.data_length as u64);

        // INFO: currently only support single key

        // udp check not required
        let ip_header_mut = obj.ip_header(ctx);
        ip_header_mut.tot_len = (u16::from_be(ip_header_mut.tot_len) + padding as u16).to_be();
        ip_header_mut.check = compute_ip_checksum(ip_header_mut);

        let udp_header = obj.udp_header(ctx);
        udp_header.len = (u16::from_be(udp_header.len) + padding as u16).to_be();
        udp_header.check = 0;

        let payload = &mut ctx.data_slice[payload_index - 4..];
        payload[0..entry.len as usize].clone_from_slice(&entry.data[0..entry.len as usize]);

        let end = b"END\r\n";
        for i in entry.len as usize..(entry.len + 5) as usize {
            payload[i] = end[i - entry.len as usize];
        }
    } else {
        stats.miss_count += 1;
    }

    Ok(XDP_TX as i32)
}

#[inline(always)]
fn bmc_invalidate_cache(obj: &xdp, ctx: &mut xdp_md) -> Result {
    let header_len = size_of::<ethhdr>() + size_of::<iphdr>() + size_of::<tcphdr>();
    let tcp_header = obj.tcp_header(ctx);
    let port = u16::from_be(tcp_header.dest);

    // start after the tcp header
    let payload = &ctx.data_slice[header_len..];

    // check if using the memcached port
    // check if the payload has enough space for a memcached request
    if port != MEMCACHED_PORT
        || payload.len() < 4
        || payload.len() > BMC_MAX_PACKET_LENGTH - header_len
    {
        return Ok(XDP_PASS as i32);
    }

    // get the index for the set command in the payload
    let set_iter =
        payload
            .windows(4)
            .enumerate()
            .filter_map(|(i, v)| if v == b"set " { Some(i) } else { None });

    // iterate through the possible set commands
    for index in set_iter {
        let stats = obj.bpf_map_lookup_elem(&map_stats, &0).ok_or(0i32)?;
        stats.set_recv_count += 1;

        let mut hash = FNV_OFFSET_BASIS_32;
        let payload = &payload[index + 4..];

        // limit the size of key
        // hash the key until the first space
        payload.iter().take_while(|&&c| c != b' ').for_each(|&c| {
            hash_func!(hash, c);
        });

        // get the cache entry
        let cache_idx: u32 = hash % BMC_CACHE_ENTRY_COUNT;

        let entry = obj
            .bpf_map_lookup_elem(&map_kcache, &cache_idx)
            .ok_or(0i32)?;
        if entry.valid == 1 {
            stats.invalidation_count += 1;
            // bpf_printk!(
            //     obj,
            //     "cache_idx %d, hash %x, key %s",
            //     cache_idx as u64,
            //     hash as u64,
            //     payload[0..16].as_ptr() as u64
            // );
            let _guard = iu_spinlock_guard::new(&mut entry.lock);
            entry.valid = 0;
        }
    }

    Ok(XDP_PASS as i32)
}

#[inline(always)]
fn xdp_rx_filter_fn(obj: &xdp, ctx: &mut xdp_md) -> Result {
    let ip_header_mut = obj.ip_header(ctx);

    match u8::from_be(ip_header_mut.protocol) as u32 {
        IPPROTO_TCP => {
            return bmc_invalidate_cache(obj, ctx);
        }
        IPPROTO_UDP => {
            let header_len = size_of::<ethhdr>()
                + size_of::<iphdr>()
                + size_of::<udphdr>()
                + size_of::<memcached_udp_header>();
            let udp_header = obj.udp_header(ctx);
            let port = u16::from_be(udp_header.dest);
            let payload = &ctx.data_slice[header_len..];

            // check if using the memcached port
            // check if the payload has enough space for a memcached request
            if port != MEMCACHED_PORT || payload.len() < 4 {
                return Ok(XDP_PASS as i32);
            }

            // check if a get command
            if !payload.starts_with(b"get ") {
                return Ok(XDP_PASS as i32);
            }

            let stats = obj
                .bpf_map_lookup_elem(&map_stats, &0)
                .ok_or(XDP_PASS as i32)?;
            stats.get_recv_count += 1;

            let mut off = 4;
            // move offset to the start of the first key
            while off < BMC_MAX_PACKET_LENGTH && off + 1 < payload.len() && payload[off] == b' ' {
                off += 1;
            }
            off += header_len;

            let mut pctx = parsing_context {
                key_count: 0,
                current_key: 0,
                read_pkt_offset: off as u8,
                _write_pkt_offset: 0,
            };

            // bpf_printk!(obj, "offset is %d\n", off as u64);
            // TODO: not sure if there is a better way
            return hash_key(obj, ctx, &mut pctx, off, stats);
        }
        _ => {}
    };

    Ok(XDP_PASS as i32)
}

// payload after all headers
#[inline(always)]
fn bmc_update_cache(
    obj: &sched_cls,
    skb: &__sk_buff,
    payload: &[u8],
    header_len: usize,
    stats: &mut bmc_stats,
) -> Result {
    let mut hash = FNV_OFFSET_BASIS_32;

    let mut off = 6usize;
    while off < BMC_MAX_KEY_LENGTH && header_len + off < skb.len() as usize && payload[off] != b' '
    {
        hash_func!(hash, payload[off]);
        // bpf_printk!(obj, "current tx hash %d payload %d\n", hash as u64, payload[off] as u64);
        off += 1;
    }
    let cache_idx: u32 = hash % BMC_CACHE_ENTRY_COUNT;
    // bpf_printk!(obj, "tx key cache idx %d\n", cache_idx as u64);

    let entry = obj
        // return TC_ACT_OK if the cache is not found or map error
        .bpf_map_lookup_elem(&map_kcache, &cache_idx)
        .ok_or(TC_ACT_OK as i32)?;
    // bpf_printk!(obj, "key hash function\n");

    let _guard = iu_spinlock_guard::new(&mut entry.lock);

    // check if the cache is up-to-date
    if entry.valid == 1 && entry.hash == hash {
        let mut diff = 0;
        off = 6;
        while off < BMC_MAX_KEY_LENGTH
            && header_len + off < payload.len() as usize
            && (payload[off] != b' ' || entry.data[off] != b' ')
        {
            if entry.data[off] != payload[off] {
                diff = 1;
                break;
            }
            off += 1;
        }

        // cache is up-to-date, no need to update
        if diff == 0 {
            // bpf_printk!(obj, "cache is up-to-date\n");
            return Ok(TC_ACT_OK as i32);
        }
    }

    // cache is not up-to-date, update it
    let (mut count, mut i) = (0usize, 0usize);
    entry.len = 0;
    // bpf_printk!(obj, "update_cace\n");
    while i < BMC_MAX_CACHE_DATA_SIZE && header_len + i < skb.len() as usize && count < 2 {
        entry.data[i] = payload[i];
        entry.len += 1;
        if payload[i] == b'\n' {
            count += 1;
        }
        i += 1;
    }

    // finished copying
    if count == 2 {
        // bpf_printk!(
        //     obj,
        //     "copying key success with data length %d\n",
        //     entry.len as u64
        // );
        entry.valid = 1;
        entry.hash = hash;
        stats.update_count += 1;
    }

    Ok(TC_ACT_OK as i32)
}

#[inline(always)]
fn xdp_tx_filter_fn(obj: &sched_cls, skb: &mut __sk_buff) -> Result {
    let header_len = size_of::<iphdr>()
        + size_of::<eth_header>()
        + size_of::<udphdr>()
        + size_of::<memcached_udp_header>();

    // check if the packet is long enough
    if skb.len() as usize <= header_len {
        return Ok(TC_ACT_OK as i32);
    }

    let ip_header = obj.ip_header(skb);

    if u8::from_be(ip_header.protocol) as u32 == IPPROTO_UDP {
        let udp_header = obj.udp_header(skb);
        let src_port = u16::from_be(udp_header.source);
        let payload = &skb.data_slice[header_len..];

        // confirm if using the memcached port
        if src_port != MEMCACHED_PORT && payload.len() < 6 {
            return Ok(TC_ACT_OK as i32);
        }

        // check if a VALUE command
        if !payload.starts_with(b"VALUE ") {
            return Ok(TC_ACT_OK as i32);
        }

        let stats = obj.bpf_map_lookup_elem(&map_stats, &0).ok_or(0i32)?;
        stats.get_resp_count += 1;

        // update cache map based on the packet
        bmc_update_cache(obj, skb, payload, header_len, stats)?;
    }

    Ok(TC_ACT_OK as i32)
}
#[entry_link(inner_unikernel/xdp)]
static PROG1: xdp = xdp::new(xdp_rx_filter_fn, "xdp_rx_filter", BPF_PROG_TYPE_XDP as u64);

#[entry_link(inner_unikernel/tc)]
static PROG2: sched_cls = sched_cls::new(
    xdp_tx_filter_fn,
    "xdp_tx_filter",
    BPF_PROG_TYPE_SCHED_CLS as u64,
);
