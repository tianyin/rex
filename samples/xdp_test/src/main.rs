#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::entry_link;
use inner_unikernel_rt::linux::bpf::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH};
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::sched_cls::*;
use inner_unikernel_rt::utils::*;
use inner_unikernel_rt::xdp::*;
use inner_unikernel_rt::FieldTransmute;
use inner_unikernel_rt::MAP_DEF;
MAP_DEF!(map_hash, __map_1, u32, i64, BPF_MAP_TYPE_HASH, 1024, 0);
MAP_DEF!(map_array, __map_2, u32, u64, BPF_MAP_TYPE_ARRAY, 256, 0);

#[derive(FieldTransmute)]
#[repr(C, packed)]
pub struct MemcachedUdpHeader {
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

fn xdp_rx_filter_fn(obj: &xdp, ctx: &xdp_md) -> u32 {
    let eth_header = eth_header::new(&ctx.data_slice[0..14]);
    let ip_header = obj.ip_header(ctx);

    match u8::from_be(ip_header.protocol) as u32 {
        IPPROTO_TCP => {
            //  bpf_printk!(obj, "tcp packet.\n");

            //  let tcp_header = obj.tcp_header(ctx);

            //  bpf_printk!(
            //      obj,
            //      "tcp_src port: %d\n",
            //      u16::from_be(tcp_header.source) as u64
            //  );
            //  bpf_printk!(
            //      obj,
            //      "tcp_dst port: %d\n",
            //      u16::from_be(tcp_header.dest) as u64
            //  );
        }
        IPPROTO_UDP => {
            bpf_printk!(
                obj,
                "eth proto 0x%x\n",
                u16::from_be(eth_header.h_proto) as u64
            );

            bpf_printk!(obj, "udp packet.\n");
            let udp_header = obj.udp_header(ctx);

            bpf_printk!(
                obj,
                "udp_src port: %d\n",
                u16::from_be(udp_header.source) as u64
            );
            bpf_printk!(
                obj,
                "udp_dst port: %d\n",
                u16::from_be(udp_header.dest) as u64
            );

            obj.bpf_change_udp_port(ctx, 2000u16);
            bpf_printk!(obj, "udp packet.\n");
            let udp_header = obj.udp_header(ctx);

            bpf_printk!(
                obj,
                "udp_src port: %d\n",
                u16::from_be(udp_header.source) as u64
            );
            bpf_printk!(
                obj,
                "udp_dst port: %d\n",
                u16::from_be(udp_header.dest) as u64
            );
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

// ERROR need to add additional BPF_PROG_TYPE_SCHED_CLS in LLVM pass
#[entry_link(inner_unikernel/tc)]
static PROG2: sched_cls = sched_cls::new(
    xdp_tx_filter_fn,
    "xdp_tx_filter",
    BPF_PROG_TYPE_SCHED_CLS as u64,
);
