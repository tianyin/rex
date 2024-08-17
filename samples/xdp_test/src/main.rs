#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

extern crate rex;

use rex::bpf_printk;
use rex::sched_cls::*;
use rex::utils::*;
use rex::xdp::*;
use rex::{rex_tc, rex_xdp};

#[rex_xdp]
fn xdp_rx_filter(obj: &xdp, ctx: &mut xdp_md) -> Result {
    let ip_header_mut = obj.ip_header(ctx);

    match u8::from_be(ip_header_mut.protocol) as u32 {
        IPPROTO_TCP => {
            bpf_printk!(obj, "TCP packet!")
        }
        IPPROTO_UDP => {
            bpf_printk!(obj, "UDP packet!");
        }
        _ => {}
    };

    Ok(XDP_PASS as i32)
}

#[rex_tc]
fn xdp_tx_filter(obj: &sched_cls, skb: &mut __sk_buff) -> Result {
    let ip_header = obj.ip_header(skb);

    if u8::from_be(ip_header.protocol) as u32 == IPPROTO_UDP {
        bpf_printk!(obj, "UDP packet!");
    }

    Ok(TC_ACT_OK as i32)
}
