#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

extern crate inner_unikernel_rt;

use core::ffi::c_void;
use core::mem::{size_of, swap};
use core::num::Wrapping;
use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::entry_link;
use inner_unikernel_rt::linux::bpf::{
    bpf_spin_lock, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_PERCPU_ARRAY,
};
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::sched_cls::*;
use inner_unikernel_rt::spinlock::*;
use inner_unikernel_rt::utils::*;
use inner_unikernel_rt::xdp::*;
use inner_unikernel_rt::MAP_DEF;

pub mod common;
pub mod maps;

use common::*;
use maps::*;

// NOTE: function calls are not allowed while holding a lock....
// Cause Paxos is in fact a serialized protocol, we limit our to one-core, then no lock is needed.

fn fast_paxos_main(obj: &xdp, ctx: &mut xdp_md) -> Result {
    let header_len = size_of::<ethhdr>() + size_of::<iphdr>() + size_of::<udphdr>();
    let data_slice = obj.data_slice_mut(ctx);
    let ip_header = obj.ip_header(ctx);

    match u8::from_be(ip_header.protocol) as u32 {
        IPPROTO_TCP => {
            // NOTE: currently we only take care of UDP memcached
        }
        IPPROTO_UDP => {
            let udp_header = obj.udp_header(ctx);
            let port = u16::from_be(obj.udp_header(ctx).dest);
            let payload = &mut data_slice[header_len..];

            // port check, our process bound to 12345.
            // don't have magic bits...
            if (port != 12345 || payload.len() < MAGIC_LEN + size_of::<u64>()) {
                return Ok(XDP_PASS as i32);
            }

            // NOTE: currently, we don't support reassembly.
            if (payload[0] != 0x18
                || payload[1] != 0x03
                || payload[2] != 0x05
                || payload[3] != 0x20)
            {
                return Ok(XDP_PASS as i32);
            }

            // check the message type
            return handle_udp_fast_paxok(obj, ctx);
        }
        _ => {}
    };

    Ok(XDP_PASS as i32)
}

fn fast_broad_cast_main(obj: &sched_cls, skb: &__sk_buff) -> Result {
    let header_len = size_of::<iphdr>() + size_of::<eth_header>() + size_of::<udphdr>();

    // check if the packet is long enough
    if (skb.len as usize <= header_len) {
        return Ok(TC_ACT_OK as i32);
    }

    let eth_header = obj.eth_header(skb);
    let ip_header = obj.ip_header(skb);

    match u8::from_be(ip_header.protocol) as u32 {
        IPPROTO_UDP => {}
        _ => {}
    }

    Ok(TC_ACT_OK as i32)
}

#[inline(always)]
fn handle_udp_fast_paxok(obj: &xdp, ctx: &mut xdp_md) -> Result {
    let data_slice = obj.data_slice_mut(ctx);
    let header_len = size_of::<ethhdr>() + size_of::<iphdr>() + size_of::<udphdr>();
    let payload = &mut ctx.data_slice[header_len + MAGIC_LEN + size_of::<u64>()..];

    let (type_len_bytes, payload) = payload.split_at_mut(size_of::<u64>());
    let type_len = u64::from_ne_bytes(type_len_bytes.try_into().unwrap());
    bpf_printk!(obj, "type_len: {}\n", type_len);

    // Check the conditions
    let len = payload.len();
    if type_len >= MTU || len < type_len as usize {
        return Ok(XDP_PASS as i32);
    }
    let payload_index = header_len + MAGIC_LEN + size_of::<u64>();

    // PrepareMessage in `vr`.
    if len > PREPARE_TYPE_LEN && payload[19..27].starts_with(b"PrepareM") {
        let payload_index = payload_index + PREPARE_TYPE_LEN;
        return handle_prepare(obj, ctx, payload_index);
    }

    // PrepareOK message in `vr`.
    if len > PREPAREOK_TYPE_LEN && payload[19..27].starts_with(b"PrepareO") {
        return handle_prepare_ok(obj, ctx, payload_index);
    }

    if len > MYPREPAREOK_TYPE_LEN && payload[13..17].starts_with(b"MyPr") {
        return handle_prepare_ok(obj, ctx, payload_index);
    }

    return Ok(XDP_PASS as i32);
}

macro_rules! swap_field {
    ($field1:expr, $field2:expr, $size:ident) => {
        for i in 0..$size {
            swap(&mut $field1[i], &mut $field2[i])
        }
    };
}

#[inline(always)]
fn compute_message_type(payload: &[u8]) -> FastProgXdp {
    let len = payload.len();

    // if not a valid message, return FAILED
    if len < 13 || !payload[10..12].starts_with(b"vr") {
        return FastProgXdp::FAILED;
    }

    // check the message type
    if len > PREPARE_TYPE_LEN && payload[19..27].starts_with(b"PrepareM") {
        return FastProgXdp::FAST_PROG_XDP_HANDLE_PREPARE;
    } else if len > REQUEST_TYPE_LEN && payload[19..27].starts_with(b"RequestM") {
        return FastProgXdp::FAST_PROG_XDP_HANDLE_REQUEST;
    } else if len > PREPAREOK_TYPE_LEN && payload[19..27].starts_with(b"PrepareO") {
        return FastProgXdp::FAST_PROG_XDP_HANDLE_PREPAREOK;
    } else if len > MYPREPAREOK_TYPE_LEN && payload[13..17].starts_with(b"MyPr") {
        return FastProgXdp::FAST_PROG_XDP_HANDLE_PREPAREOK;
    }

    FastProgXdp::FAILED
}

#[inline(always)]
fn handle_prepare(obj: &xdp, ctx: &mut xdp_md, payload_index: usize) -> Result {
    // point to extra data
    let payload = &mut ctx.data_slice[payload_index..];

    // check the message len
    if payload.len() < FAST_PAXOS_DATA_LEN {
        return Ok(XDP_PASS as i32);
    }

    // NOTE: may update to struct later
    let msg_view = u32::from_ne_bytes(payload[0..4].try_into().unwrap()) as u64;
    let msg_last_op = u32::from_ne_bytes(payload[4..8].try_into().unwrap()) as u64;
    let msg_batch_start = u32::from_ne_bytes(payload[8..12].try_into().unwrap()) as u64;

    let zero = 0u32;
    let mut ctr_state = obj
        .bpf_map_lookup_elem(&map_ctr_state, &zero)
        .ok_or_else(|| 0i32)?;

    // rare case, not handled properly now.
    if ctr_state.state != ReplicaStatus::STATUS_NORMAL {
        return Ok(XDP_DROP as i32);
    }

    if msg_view < ctr_state.view {
        return Ok(XDP_DROP as i32);
    }

    if msg_view > ctr_state.view {
        return Ok(XDP_PASS as i32);
    }

    // Resend the prepareOK message
    if msg_last_op <= ctr_state.last_op {
        // call FAST_PROG_XDP_PREPARE_REPLY
    }

    // rare case, to user-space.
    if msg_batch_start > ctr_state.last_op + 1 {
        return Ok(XDP_PASS as i32);
    }

    ctr_state.last_op = payload_index as u64;
    // call FAST_PROG_XDP_WRITE_BUFFER

    return Ok(XDP_PASS as i32);
}

#[inline(always)]
fn prepare_fast_reply(obj: &xdp, ctx: &mut xdp_md, payload_index: usize) -> Result {
    let data_slice = obj.data_slice_mut(ctx);
    let mut payload = &mut data_slice[payload_index..];

    if payload.len() <= FAST_PAXOS_DATA_LEN + size_of::<u64>() {
        return Ok(XDP_PASS as i32);
    }

    // read our state
    // may update to function parameter later
    let zero = 0u32;
    let ctr_state = obj
        .bpf_map_lookup_elem(&map_ctr_state, &zero)
        .ok_or_else(|| 0i32)?;

    // struct paxos_configure *leaderInfo =
    // bpf_map_lookup_elem(&map_configure, &ctr_state->leaderIdx);
    let leader_info = obj
        .bpf_map_lookup_elem(&map_configure, &ctr_state.leader_idx)
        .ok_or_else(|| 0i32)?;

    // Write NONFRAG_MAGIC to the start of the payload
    // FIX: need to check to_ne_bytes or to_be_bytes
    payload[0..4].copy_from_slice(&NONFRAG_MAGIC.to_ne_bytes());
    payload = &mut payload[4..];
    // Write MYPREPAREOK_TYPE_LEN to the new start of the payload
    payload[0..8].copy_from_slice(&MYPREPAREOK_TYPE_LEN.to_ne_bytes());
    payload = &mut payload[8..];

    // change "specpaxos.vr.proto.PrepareMessage" to "specpaxos.vr.MyPrepareOK"
    let replacement: &[u8] = b"MyPrepareOK";
    for (i, &byte) in replacement.iter().enumerate() {
        payload[13 + i] = byte;
    }
    // Move the slice start by MYPREPAREOK_TYPE_LEN
    payload = &mut payload[MYPREPAREOK_TYPE_LEN..];

    // Write the view number, last_op and my_idx to the payload
    payload[0..4].copy_from_slice(&ctr_state.view.to_ne_bytes());
    payload[4..8].copy_from_slice(&payload_index.to_ne_bytes());
    payload[8..12].copy_from_slice(&ctr_state.my_idx.to_ne_bytes());
    // Move the slice start by FAST_PAXOS_DATA_LEN
    payload = &mut payload[FAST_PAXOS_DATA_LEN..];

    if payload.len() < (size_of::<u64>() * 3 + size_of::<u32>()) {
        return Ok(XDP_PASS as i32);
    }

    let size = (size_of::<u64>() * 2 + size_of::<u32>()) as u64;
    // write the len in the protocal, last_op and my_idx to the payload
    payload[0..8].copy_from_slice(&size.to_ne_bytes());
    payload[8..16].copy_from_slice(&ctr_state.view.to_ne_bytes());
    payload[16..24].copy_from_slice(&payload_index.to_ne_bytes());
    // Write ctr_state.my_idx
    payload[24..28].copy_from_slice(&ctr_state.my_idx.to_ne_bytes());
    // move the slice start by size_of::<u64>() * 3 + size_of::<u32>()
    let size = (size_of::<u64>() * 3 + size_of::<u32>()) as u64;
    payload = &mut payload[size..];

    let useless_len = payload.len();
    let new_len = ctx.data_length - useless_len;

    let eth_header = obj.eth_header(ctx);
    let ip_header = obj.ip_header(ctx);
    let udp_header = obj.udp_header(ctx);

    swap_field!(eth_header.h_dest, eth_header.h_source, ETH_ALEN);

    // update the port
    udp_header.source = udp_header.dest;
    udp_header.dest = leader_info.port;
    udp_header.check = 0;
    udp_header.len = new_len.to_be();

    ip_header.tot_len = (new_len + size_of::<iphdr>() as u16).to_be();
    ip_header.saddr = ip_header.daddr;
    ip_header.daddr = leader_info.addr;
    ip_header.check = compute_ip_checksum(ip_header);

    // FIX: need to consider the positive offset
    // but the original code check the length before adjust the tail
    match obj.bpf_xdp_adjust_tail(ctx, new_len - ctx.data_length) {
        0i32 => {}
        _ => {
            bpf_printk!(obj, "adjust tail failed\n");
            return Ok(XDP_DROP as i32);
        }
    }

    return Ok(XDP_PASS as i32);
}

#[inline(always)]
fn handle_prepare_ok(obj: &xdp, ctx: &mut xdp_md, payload_index: usize) -> Result {
    return Ok(XDP_PASS as i32);
}

#[entry_link(inner_unikernel/xdp)]
static PROG1: xdp = xdp::new(fast_paxos_main, "fast_paxos", BPF_PROG_TYPE_XDP as u64);

#[entry_link(inner_unikernel/tc)]
static PROG2: sched_cls = sched_cls::new(
    fast_broad_cast_main,
    "FastBroadCast",
    BPF_PROG_TYPE_SCHED_CLS as u64,
);
