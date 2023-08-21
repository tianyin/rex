use crate::stub;

use crate::bindings::linux::kernel::{ethhdr, iphdr, tcphdr, udphdr, xdp_buff};
use crate::bindings::uapi::linux::bpf::bpf_map_type;
use crate::debug::printk;
use crate::prog_type::iu_prog;
use crate::utils::*;
use crate::{bpf_printk, map::*};
use core::ffi::{c_uchar, c_uint, c_void};
use core::{mem, slice};

// expose the following constants to the user
pub use crate::bindings::uapi::linux::bpf::{
    BPF_PROG_TYPE_XDP, XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_REDIRECT, XDP_TX,
};
pub use crate::bindings::uapi::linux::r#in::{IPPROTO_TCP, IPPROTO_UDP};

// pub type pt_regs = super::binding::pt_regs;

#[derive(Debug)]
pub struct xdp_md<'a> {
    // TODO check the kernel version xdp_md
    // pub regs: bpf_user_pt_regs_t,
    data: usize,
    data_end: usize,
    pub data_slice: &'a [c_uchar],
    pub data_length: usize,
    pub data_meta: usize,
    pub ingress_ifindex: u32,
    pub rx_qeueu_index: u32,
    pub egress_ifindex: u32,
    kptr: *const xdp_buff,
}

const ETH_ALEN: usize = 6;

#[derive(Debug)]
pub struct eth_header<'a> {
    h_dest: &'a [c_uchar; 6],
    h_source: &'a [c_uchar; 6],
    h_proto: u16,
}

// First 3 fields should always be rtti, prog_fn, and name
//
// rtti should be u64, therefore after compiling the
// packed struct type rustc generates for LLVM does
// not additional padding after rtti
//
// prog_fn should have &Self as its first argument
//
// name is a &str
#[repr(C)]
pub struct xdp<'a> {
    rtti: u64,
    // TODO update it
    prog: fn(&Self, &xdp_md) -> u32,
    name: &'a str,
}

impl<'a> xdp<'a> {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        // TODO update based on signature
        f: fn(&xdp<'a>, &xdp_md) -> u32,
        nm: &'a str,
        rtti: u64,
    ) -> xdp<'a> {
        Self {
            rtti,
            prog: f,
            name: nm,
        }
    }

    // Now returns a mutable ref, but since every reg is private the user prog
    // cannot change reg contents. The user should not be able to directly
    // assign this reference a new value either, given that they will not able
    // to create another instance of pt_regs (private fields, no pub ctor)
    fn convert_ctx(&self, ctx: *const ()) -> xdp_md {
        let kptr: &xdp_buff = unsafe {
            &*core::mem::transmute::<*const (), *const xdp_buff>(ctx)
        };

        // BUG may not work since directly truncate the pointer
        let data = kptr.data as usize;
        let data_end = kptr.data_end as usize;
        let data_meta = kptr.data_meta as usize;
        let data_length = data_end - data;

        // TODO should we use slice::from_raw_parts or slice::copy_from_slice?
        let data_slice = unsafe {
            slice::from_raw_parts(kptr.data as *const c_uchar, data_length)
        };

        let ingress_ifindex = kptr.rxq as u32;

        let rx_qeueu_index = unsafe { (*kptr.rxq).queue_index };

        // TODO https://elixir.bootlin.com/linux/v5.15.123/source/net/core/filter.c#L8271
        // egress_ifindex is valid only for BPF_XDP_DEVMAP option
        let egress_ifindex = 0;
        // let egress_ifindex = unsafe { (*(*kptr.txq).dev).ifindex as u32 };

        xdp_md {
            data,
            data_end,
            data_slice,
            data_length,
            data_meta,
            ingress_ifindex,
            rx_qeueu_index,
            egress_ifindex,
            kptr,
        }
    }

    // User can get the customized struct like memcached from the data_slice
    // TODO: maybe we should add safe version for this function
    // TODO: add a bound checking for this function, also check for the struct
    // member make sure no pointer
    pub fn convert_slice_to_struct<T>(&self, slice: &[c_uchar]) -> &T {
        let ptr = slice.as_ptr() as *const T;
        unsafe { &*(&core::ptr::read_unaligned(ptr) as *const T) }
    }

    pub fn convert_slice_to_struct_mut<T>(
        &self,
        slice: &mut [c_uchar],
    ) -> &mut T {
        let ptr = slice.as_ptr() as *mut T;
        unsafe { &mut *(slice.as_mut_ptr() as *mut T) }
    }

    pub fn udp_header(&self, ctx: &xdp_md) -> &udphdr {
        // WARN this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let part = &ctx.data_slice[begin..];
        let udp_header = self.convert_slice_to_struct::<udphdr>(part);

        udp_header
    }

    pub fn tcp_header(&self, ctx: &xdp_md) -> &tcphdr {
        // WARN this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let part = &ctx.data_slice[begin..];
        let tcp_header = self.convert_slice_to_struct::<tcphdr>(part);

        unsafe {
            printk("tcp_dest %d\n\0", u16::from_be(tcp_header.dest) as u32);
            printk("tcp_src %d\n\0", u16::from_be(tcp_header.source) as u32);
        }

        tcp_header
    }

    pub fn ip_header(&self, ctx: &xdp_md) -> &iphdr {
        // WARN this assumes packet has ethhdr
        let begin = mem::size_of::<ethhdr>();
        let part = &ctx.data_slice[begin..];
        let ip_header = self.convert_slice_to_struct::<iphdr>(part);

        ip_header
    }

    pub fn eth_header<'b>(&self, ctx: &'b xdp_md) -> eth_header<'b> {
        // TODO big endian may be different in different arch this is x86
        // version
        let combined: u16 =
            ((ctx.data_slice[13] as u16) << 8) | (ctx.data_slice[12] as u16);

        let h_dest = <[u8; 6] as FromCharBufSafe>::from_char_buf_safe(
            &ctx.data_slice[0..6],
        );
        let h_source = <[u8; 6] as FromCharBufSafe>::from_char_buf_safe(
            &ctx.data_slice[6..12],
        );
        let h_proto = u16::from_be(
            *<u16 as FromCharBufSafe>::from_char_buf_safe(
                &ctx.data_slice[12..14],
            )
            .unwrap(),
        );

        let eth_header = eth_header {
            h_dest: h_dest.unwrap(),
            h_source: h_source.unwrap(),
            h_proto,
        };
        unsafe {
            printk("eth_protocol 0x%x\n\0", eth_header.h_proto as u32);
        }
        eth_header
    }

    pub fn bpf_change_udp_port(&self, ctx: &xdp_md, port_num: u16) {
        let kptr = unsafe { *(ctx.kptr) };

        // may not work since directly truncate the pointer
        let data = kptr.data as usize;
        let data_end = kptr.data_end as usize;
        let data_meta = kptr.data_meta as usize;
        let data_length = data_end - data;

        // TODO should we use slice::from_raw_parts or slice::copy_from_slice?
        let data_slice = unsafe {
            slice::from_raw_parts_mut(kptr.data as *mut c_uchar, data_length)
        };

        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let part = &mut data_slice[begin..];
        let mut udp_header = self.convert_slice_to_struct_mut::<udphdr>(part);

        unsafe {
            printk(
                "udp_dest change before %d\n\0",
                u16::from_be(udp_header.dest) as u32,
            );
        }
        udp_header.dest = port_num.to_be();

        let mut udp_header_2 = self.convert_slice_to_struct_mut::<udphdr>(part);
        unsafe {
            printk(
                "udp_dest change to %d\n\0",
                u16::from_be(udp_header_2.dest) as u32,
            );
        }
    }

    // TODO: update based on xdp_md to convert to xdp_buff
    pub fn bpf_xdp_adjust_head(&self, xdp: &mut xdp_buff, offset: i32) -> i32 {
        let helper: extern "C" fn(*mut xdp_buff, i32) -> i32 =
            unsafe { core::mem::transmute(stub::bpf_xdp_adjust_head_addr()) };
        helper(xdp, offset)
    }

    // TODO: update based on xdp_md to convert to xdp_buff
    pub fn bpf_xdp_adjust_tail(&self, xdp: &mut xdp_buff, offset: i32) -> i32 {
        let helper: extern "C" fn(*mut xdp_buff, i32) -> i32 =
            unsafe { core::mem::transmute(stub::bpf_xdp_adjust_tail_addr()) };
        helper(xdp, offset)
    }
}
impl iu_prog for xdp<'_> {
    fn prog_run(&self, ctx: *const ()) -> u32 {
        let mut newctx = self.convert_ctx(ctx);
        (self.prog)(self, &mut newctx)
    }
}
