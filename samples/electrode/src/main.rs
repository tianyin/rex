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

macro_rules! swap_field {
    ($field1:expr, $field2:expr, $size:ident) => {
        for i in 0..$size {
            swap(&mut $field1[i], &mut $field2[i])
        }
    };
}

fn fast_paxos_main(obj: &xdp, ctx: &mut xdp_md) -> Result {
    let header_len = size_of::<ethhdr>() + size_of::<iphdr>() + size_of::<udphdr>();
    let data_slice = obj.data_slice_mut(ctx);
    let eth_header = eth_header::new(&mut data_slice[0..14]);
    let ip_header_mut = obj.ip_header_mut(ctx);

    match u8::from_be(ip_header_mut.protocol) as u32 {
        IPPROTO_TCP => {
            // NOTE: currently we only take care of UDP memcached
        }
        IPPROTO_UDP => {
            let udp_header = obj.udp_header(ctx);
            let port = u16::from_be(obj.udp_header(ctx).dest);
            let mut payload = &ctx.data_slice[header_len..];

            // port check, our process bound to 12345.
            // don't have magic bits...
            if (port != 12345 || payload.len() < MAGIC_LEN) {
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
            payload = &payload[MAGIC_LEN..];

            // check if a get command
            if !payload.starts_with(b"get ") {
                return Ok(XDP_PASS as i32);
            }

            let mut off = 4;
            // TODO: not sure if there is a better way
            return Ok(XDP_PASS as i32);
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
#[entry_link(inner_unikernel/xdp)]
static PROG1: xdp = xdp::new(fast_paxos_main, "fast_paxos", BPF_PROG_TYPE_XDP as u64);

#[entry_link(inner_unikernel/tc)]
static PROG2: sched_cls = sched_cls::new(
    fast_broad_cast_main,
    "FastBroadCast",
    BPF_PROG_TYPE_SCHED_CLS as u64,
);
