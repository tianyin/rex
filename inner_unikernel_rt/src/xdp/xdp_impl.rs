use crate::stub;

pub use crate::bindings::linux::kernel::{
    ethhdr, iphdr, tcphdr, udphdr, xdp_buff,
};
use crate::bindings::uapi::linux::bpf::bpf_map_type;
use crate::debug::printk;
use crate::prog_type::iu_prog;
use crate::utils::*;
use crate::{bpf_printk, map::*};
use core::ffi::{c_uchar, c_uint, c_void};
use core::{mem, mem::size_of, slice};

// expose the following constants to the user
pub use crate::bindings::uapi::linux::bpf::{
    BPF_PROG_TYPE_XDP, XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_REDIRECT, XDP_TX,
};
pub use crate::bindings::uapi::linux::r#in::{IPPROTO_TCP, IPPROTO_UDP};

#[inline(always)]
pub fn compute_ip_checksum(ip_header: &mut iphdr) -> u16 {
    let mut sum: u32 = 0;
    let mut checksum: u16 = 0;
    ip_header.check = 0;

    let count = size_of::<iphdr>() >> 1;

    let u16_slice = unsafe {
        core::slice::from_raw_parts(ip_header as *const _ as *const u16, count)
    };

    for &word in u16_slice {
        sum += word as u32;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    !sum as u16
}

pub struct xdp_md<'a> {
    // TODO check the kernel version xdp_md
    // pub regs: bpf_user_pt_regs_t,
    data: usize,
    data_end: usize,
    data_slice: &'a mut [c_uchar],
    data_length: usize,
    data_meta: usize,
    ingress_ifindex: u32,
    rx_qeueu_index: u32,
    egress_ifindex: u32,
    kptr: &'a mut xdp_buff,
}

// Define accessors of program-accessible fields
impl<'a> xdp_md<'a> {
    #[inline(always)]
    pub fn data_slice(&'a mut self) -> &'a mut [c_uchar] {
        self.data_slice
    }

    #[inline(always)]
    pub fn data_length(&self) -> usize {
        self.data_length
    }

    #[inline(always)]
    pub fn data_meta(&self) -> usize {
        self.data_meta
    }

    #[inline(always)]
    pub fn ingress_ifindex(&self) -> u32 {
        self.ingress_ifindex
    }

    #[inline(always)]
    pub fn rx_qeueu_index(&self) -> u32 {
        self.rx_qeueu_index
    }

    #[inline(always)]
    pub fn egress_ifindex(&self) -> u32 {
        self.egress_ifindex
    }
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
    prog: fn(&Self, &mut xdp_md) -> Result,
    name: &'a str,
}

impl<'a> xdp<'a> {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        f: fn(&xdp<'a>, &mut xdp_md) -> Result,
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
    #[inline(always)]
    fn convert_ctx(&self, ctx: *mut ()) -> xdp_md {
        let kptr: &mut xdp_buff = unsafe { &mut *(ctx as *mut xdp_buff) };

        // BUG may not work since directly truncate the pointer
        let data = kptr.data as usize;
        let data_end = kptr.data_end as usize;
        let data_meta = kptr.data_meta as usize;
        let data_length = data_end - data;

        let data_slice = unsafe {
            slice::from_raw_parts_mut(kptr.data as *mut c_uchar, data_length)
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

    #[inline(always)]
    pub fn tcp_header<'b>(&'b self, ctx: &'b mut xdp_md) -> &'b mut tcphdr {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<tcphdr>() + begin;

        unsafe {
            convert_slice_to_struct_mut::<tcphdr>(
                &mut ctx.data_slice[begin..end],
            )
        }
    }

    #[inline(always)]
    pub fn udp_header<'b>(&self, ctx: &'b mut xdp_md) -> &'b mut udphdr {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<udphdr>() + begin;

        unsafe {
            convert_slice_to_struct_mut::<udphdr>(
                &mut ctx.data_slice[begin..end],
            )
        }
    }

    #[inline(always)]
    pub fn ip_header<'b>(&self, ctx: &'b mut xdp_md) -> &'b mut iphdr {
        // NOTE: this assumes packet has ethhdr
        let begin = mem::size_of::<ethhdr>();
        let end = mem::size_of::<iphdr>() + begin;

        unsafe {
            convert_slice_to_struct_mut::<iphdr>(
                &mut ctx.data_slice[begin..end],
            )
        }
    }

    #[inline(always)]
    pub fn eth_header<'b>(&self, ctx: &'b mut xdp_md) -> &'b mut ethhdr {
        unsafe {
            convert_slice_to_struct_mut::<ethhdr>(
                &mut ctx.data_slice[0..mem::size_of::<ethhdr>()],
            )
        }
    }

    // FIX: update based on xdp_md to convert to xdp_buff
    // pub fn bpf_xdp_adjust_head(&self, xdp: &mut xdp_buff, offset: i32) -> i32
    // {     unsafe { stub::bpf_xdp_adjust_head(xdp, offset) }
    // }

    // WARN: this function is unsafe
    #[inline(always)]
    pub fn bpf_xdp_adjust_tail(&self, ctx: &mut xdp_md, offset: i32) -> Result {
        let ret = unsafe { stub::bpf_xdp_adjust_tail(ctx.kptr, offset) };
        if ret != 0 {
            return Err(ret);
        }

        // Update xdp_md fields
        ctx.data = ctx.kptr.data as usize;
        ctx.data_end = ctx.kptr.data_end as usize;
        ctx.data_meta = ctx.kptr.data_meta as usize;
        ctx.data_length = ctx.data_end - ctx.data;

        ctx.data_slice = unsafe {
            slice::from_raw_parts_mut(
                ctx.kptr.data as *mut c_uchar,
                ctx.data_length,
            )
        };

        ctx.ingress_ifindex = ctx.kptr.rxq as u32;
        ctx.rx_qeueu_index = unsafe { (*ctx.kptr.rxq).queue_index };
        ctx.egress_ifindex = 0;

        Ok(0)
    }
}
impl iu_prog for xdp<'_> {
    fn prog_run(&self, ctx: *mut ()) -> u32 {
        let mut newctx = self.convert_ctx(ctx);
        // Return XDP_PASS if Err, i.e. discard event
        // FIX:map the error as XDP_PASS or err code
        ((self.prog)(self, &mut newctx)).unwrap_or_else(|e| XDP_PASS as i32)
            as u32
    }
}
