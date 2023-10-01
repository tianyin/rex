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
use core::{mem, slice};

// expose the following constants to the user
pub use crate::bindings::uapi::linux::bpf::{
    BPF_PROG_TYPE_XDP, XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_REDIRECT, XDP_TX,
};
pub use crate::bindings::uapi::linux::r#in::{IPPROTO_TCP, IPPROTO_UDP};

// pub type pt_regs = super::binding::pt_regs;

pub struct xdp_md<'a> {
    // TODO check the kernel version xdp_md
    // pub regs: bpf_user_pt_regs_t,
    data: usize,
    data_end: usize,
    pub data_slice: &'a mut [c_uchar],
    pub data_length: usize,
    pub data_meta: usize,
    pub ingress_ifindex: u32,
    pub rx_qeueu_index: u32,
    pub egress_ifindex: u32,
    kptr: &'a xdp_buff,
}

// User can get the customized struct like memcached from the data_slice
// TODO: add a bound checking for this function, add size check
pub unsafe fn convert_slice_to_struct<T>(slice: &[c_uchar]) -> &T {
    assert!(
        slice.len() >= mem::size_of::<T>(),
        "size mismatch in convert_slice_to_struct"
    );

    unsafe { &*(slice.as_ptr() as *const T) }
}

pub unsafe fn convert_slice_to_struct_mut<T>(slice: &mut [c_uchar]) -> &mut T {
    assert!(
        slice.len() >= mem::size_of::<T>(),
        "size mismatch in convert_slice_to_struct_mut"
    );

    unsafe { &mut *(slice.as_mut_ptr() as *mut T) }
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
    fn convert_ctx(&self, ctx: *const ()) -> xdp_md {
        let kptr: &xdp_buff = unsafe {
            &*core::mem::transmute::<*const (), *const xdp_buff>(ctx)
        };

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

    pub fn udp_header<'b>(&self, ctx: &'b xdp_md) -> &'b udphdr {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<udphdr>() + begin;
        unsafe {
            convert_slice_to_struct::<udphdr>(&ctx.data_slice[begin..end])
        }
    }

    pub fn tcp_header(&'a self, ctx: &'a xdp_md) -> &tcphdr {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<tcphdr>() + begin;
        let tcp_header = unsafe {
            convert_slice_to_struct::<tcphdr>(&ctx.data_slice[begin..end])
        };

        tcp_header
    }

    pub fn ip_header<'b>(&self, ctx: &'b xdp_md) -> &'b iphdr {
        // NOTE: this assumes packet has ethhdr
        let begin = mem::size_of::<ethhdr>();
        let end = mem::size_of::<iphdr>() + begin;
        unsafe { convert_slice_to_struct::<iphdr>(&ctx.data_slice[begin..end]) }
    }

    pub fn udp_header_mut<'b>(&self, ctx: &'b xdp_md) -> &'b mut udphdr {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<udphdr>() + begin;
        let data_slice = unsafe {
            slice::from_raw_parts_mut(
                ctx.kptr.data as *mut c_uchar,
                ctx.data_length,
            )
        };
        unsafe {
            convert_slice_to_struct_mut::<udphdr>(&mut data_slice[begin..end])
        }
    }

    pub fn ip_header_mut<'b>(&self, ctx: &'b xdp_md) -> &'b mut iphdr {
        // NOTE: this assumes packet has ethhdr
        let begin = mem::size_of::<ethhdr>();
        let end = mem::size_of::<iphdr>() + begin;

        let data_slice = unsafe {
            slice::from_raw_parts_mut(
                ctx.kptr.data as *mut c_uchar,
                ctx.data_length,
            )
        };
        unsafe {
            convert_slice_to_struct_mut::<iphdr>(&mut data_slice[begin..end])
        }
    }

    pub fn eth_header<'b>(&self, ctx: &'b xdp_md) -> &'b ethhdr {
        direct_packet_access_ok::<[u8; 6]>();
        direct_packet_access_ok::<[u8; 6]>();
        direct_packet_access_ok::<u16>();

        unsafe { convert_slice_to_struct::<ethhdr>(&ctx.data_slice[0..14]) }
    }

    pub fn bpf_change_udp_port(&self, ctx: &xdp_md, port_num: u16) {
        let kptr = unsafe { *(ctx.kptr) };

        // may not work since directly truncate the pointer
        let data = kptr.data as usize;
        let data_end = kptr.data_end as usize;
        let data_meta = kptr.data_meta as usize;
        let data_length = data_end - data;

        let data_slice = unsafe {
            slice::from_raw_parts_mut(kptr.data as *mut c_uchar, data_length)
        };

        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let mut off = begin + mem::size_of::<udphdr>();
        data_slice[off] = b'0';

        let part = &mut data_slice[begin..begin + mem::size_of::<udphdr>()];
        let mut udp_header =
            unsafe { convert_slice_to_struct_mut::<udphdr>(part) };

        unsafe {
            printk(
                "udp_dest change before %d\n\0",
                u16::from_be(udp_header.dest) as u32,
            );
        }
        udp_header.dest = port_num.to_be();

        let part = &mut data_slice[begin..begin + mem::size_of::<udphdr>()];
        let mut udp_header_2 =
            unsafe { convert_slice_to_struct_mut::<udphdr>(part) };
        unsafe {
            printk(
                "udp_dest change to %d\n\0",
                u16::from_be(udp_header_2.dest) as u32,
            );
        }
    }

    // FIX: update based on xdp_md to convert to xdp_buff
    pub fn bpf_xdp_adjust_head(&self, xdp: &mut xdp_buff, offset: i32) -> i32 {
        let helper: extern "C" fn(*mut xdp_buff, i32) -> i32 =
            unsafe { core::mem::transmute(stub::bpf_xdp_adjust_head_addr()) };
        helper(xdp, offset)
    }

    // WARN: this function is unsafe
    pub fn bpf_xdp_adjust_tail(&self, ctx: &mut xdp_md, offset: i32) -> i32 {
        let kptr = unsafe { ctx.kptr as *const xdp_buff as *mut xdp_buff };

        let helper: extern "C" fn(*mut xdp_buff, i32) -> i32 =
            unsafe { core::mem::transmute(stub::bpf_xdp_adjust_tail_addr()) };
        let ret = helper(kptr, offset);
        if ret != 0 {
            return ret;
        }

        let kptr = ctx.kptr;

        // BUG may not work since directly truncate the pointer
        ctx.data = kptr.data as usize;
        ctx.data_end = kptr.data_end as usize;
        ctx.data_meta = kptr.data_meta as usize;
        ctx.data_length = ctx.data_end - ctx.data;

        ctx.data_slice = unsafe {
            slice::from_raw_parts_mut(
                kptr.data as *mut c_uchar,
                ctx.data_length,
            )
        };

        ctx.ingress_ifindex = kptr.rxq as u32;
        ctx.rx_qeueu_index = unsafe { (*kptr.rxq).queue_index };
        ctx.egress_ifindex = 0;

        0
    }

    pub fn data_slice_mut(&self, ctx: &xdp_md) -> &mut [c_uchar] {
        let kptr = unsafe { *(ctx.kptr) };
        // may not work since directly truncate the pointer
        let data = kptr.data as usize;
        let data_end = kptr.data_end as usize;
        let data_length = data_end - data;
        let data_slice = unsafe {
            slice::from_raw_parts_mut(data as *mut c_uchar, data_length)
        };
        data_slice
    }
}
impl iu_prog for xdp<'_> {
    fn prog_run(&self, ctx: *const ()) -> u32 {
        let mut newctx = self.convert_ctx(ctx);
        // Return XDP_PASS if Err, i.e. discard event
        // FIX:map the error as XDP_PASS or err code
        ((self.prog)(self, &mut newctx)).unwrap_or_else(|e| XDP_PASS as i32)
            as u32
    }
}
