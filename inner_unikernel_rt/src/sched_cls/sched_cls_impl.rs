use crate::debug::printk;
use crate::stub;

use crate::bindings::linux::kernel::{
    ethhdr, iphdr, net_device, sk_buff, sock, tcphdr, udphdr,
};
use crate::bindings::uapi::linux::bpf::bpf_map_type;
pub use crate::bindings::uapi::linux::bpf::BPF_PROG_TYPE_SCHED_CLS;
pub use crate::bindings::uapi::linux::pkt_cls::{
    TC_ACT_OK, TC_ACT_REDIRECT, TC_ACT_SHOT,
};
use crate::prog_type::iu_prog;
use crate::utils::*;

use crate::{bpf_printk, map::*};
use core::ffi::{c_char, c_uchar, c_uint, c_void};
use core::{mem, slice};

pub struct __sk_buff<'a> {
    // TODO: may need to append more based on __sk_buff
    len: u32,
    // be16
    protocol: u16be,
    priority: u32,
    ingress_ifindex: u32,
    ifindex: u32,
    hash: u32,
    mark: u32,

    // such as PACKET_HOST if_packet.h
    // /* if you move pkt_type around you also must adapt those constants */
    // #ifdef __BIG_ENDIAN_BITFIELD
    // #define PKT_TYPE_MAX	(7 << 5)
    // #else
    // #define PKT_TYPE_MAX	7
    // #endif
    pkt_type: u32,

    queue_mapping: u16,

    vlan_present: u32,
    vlan_tci: u16,
    vlan_proto: u16be,
    cb: [c_char; 48],

    tc_classid: u32,
    tc_index: u16,

    napi_id: u32,

    sk: &'a sock,
    data: u32,
    data_meta: u32,
    data_slice: &'a mut [c_uchar],
    kptr: &'a mut sk_buff,
}

// Define accessors of program-accessible fields
impl<'a> __sk_buff<'a> {
    #[inline(always)]
    pub fn len(&self) -> u32 {
        self.len
    }

    #[inline(always)]
    pub fn protocol(&self) -> u16be {
        self.protocol
    }

    #[inline(always)]
    pub fn priority(&self) -> u32 {
        self.priority
    }

    #[inline(always)]
    pub fn ingress_ifindex(&self) -> u32 {
        self.ingress_ifindex
    }

    #[inline(always)]
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    #[inline(always)]
    pub fn hash(&self) -> u32 {
        self.hash
    }

    #[inline(always)]
    pub fn mark(&self) -> u32 {
        self.mark
    }

    #[inline(always)]
    pub fn pkt_type(&self) -> u32 {
        self.pkt_type
    }

    #[inline(always)]
    pub fn queue_mapping(&self) -> u16 {
        self.queue_mapping
    }

    #[inline(always)]
    pub fn vlan_present(&self) -> u32 {
        self.vlan_present
    }

    #[inline(always)]
    pub fn vlan_tci(&self) -> u16 {
        self.vlan_tci
    }

    #[inline(always)]
    pub fn vlan_proto(&self) -> u16be {
        self.vlan_proto
    }

    #[inline(always)]
    pub fn cb(&self) -> &[c_char; 48] {
        &self.cb
    }

    #[inline(always)]
    pub fn tc_classid(&self) -> u32 {
        self.tc_classid
    }

    #[inline(always)]
    pub fn tc_index(&self) -> u16 {
        self.tc_index
    }

    #[inline(always)]
    pub fn napi_id(&self) -> u32 {
        self.napi_id
    }

    #[inline(always)]
    pub fn data_meta(&self) -> u32 {
        self.data_meta
    }

    #[inline(always)]
    pub fn data_slice(&'a mut self) -> &'a mut [c_uchar] {
        self.data_slice
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
pub struct sched_cls<'a> {
    rtti: u64,
    prog: fn(&Self, &mut __sk_buff) -> Result,
    name: &'a str,
}

impl<'a> sched_cls<'a> {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        // TODO update based on signature
        f: fn(&sched_cls<'a>, &mut __sk_buff) -> Result,
        nm: &'a str,
        rtti: u64,
    ) -> sched_cls<'a> {
        Self {
            rtti,
            prog: f,
            name: nm,
        }
    }

    // NOTE: copied from xdp impl, may change in the future
    #[inline(always)]
    pub fn eth_header<'b>(&self, skb: &'b mut __sk_buff) -> &'b mut ethhdr {
        unsafe {
            convert_slice_to_struct_mut::<ethhdr>(
                &mut skb.data_slice[0..mem::size_of::<ethhdr>()],
            )
        }
    }

    #[inline(always)]
    pub fn udp_header<'b>(&self, skb: &'b mut __sk_buff) -> &'b mut udphdr {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<udphdr>() + begin;

        unsafe {
            convert_slice_to_struct_mut::<udphdr>(
                &mut skb.data_slice[begin..end],
            )
        }
    }

    #[inline(always)]
    pub fn tcp_header<'b>(&self, skb: &'b mut __sk_buff) -> &'b mut tcphdr {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<tcphdr>() + begin;

        unsafe {
            convert_slice_to_struct_mut::<tcphdr>(
                &mut skb.data_slice[begin..end],
            )
        }
    }

    #[inline(always)]
    pub fn ip_header<'b>(&self, skb: &'b mut __sk_buff) -> &'b mut iphdr {
        // NOTE: this assumes packet has ethhdr
        let begin = mem::size_of::<ethhdr>();
        let end = mem::size_of::<iphdr>() + begin;

        unsafe {
            convert_slice_to_struct_mut::<iphdr>(
                &mut skb.data_slice[begin..end],
            )
        }
    }

    #[inline(always)]
    pub fn bpf_clone_redirect(
        &self,
        skb: &mut __sk_buff,
        ifindex: u32,
        flags: u64,
    ) -> Result {
        let ret = unsafe { stub::bpf_clone_redirect(skb.kptr, ifindex, flags) };

        if ret != 0 {
            return Err(ret);
        }

        skb.data = skb.kptr.data as u32;
        let data_length = skb.kptr.len as usize;

        skb.data_slice = unsafe {
            slice::from_raw_parts_mut(
                skb.kptr.data as *mut c_uchar,
                data_length,
            )
        };

        Ok(0)
    }

    // Now returns a mutable ref, but since every reg is private the user prog
    // cannot change reg contents. The user should not be able to directly
    // assign this reference a new value either, given that they will not able
    // to create another instance of pt_regs (private fields, no pub ctor)
    #[inline(always)]
    fn convert_ctx(&self, ctx: *mut ()) -> __sk_buff {
        let kptr: &mut sk_buff = unsafe { &mut *(ctx as *mut sk_buff) };

        let data = kptr.data as u32;
        let data_length = kptr.len as usize;

        // NOTE: currently we only added const data slice for read only
        let data_slice = unsafe {
            slice::from_raw_parts_mut(kptr.data as *mut c_uchar, data_length)
        };

        // bindgen for C union is kind of wired, so we have to do this
        let sk: &sock = unsafe { &*kptr.__bindgen_anon_2.sk };

        // TODO: UNION required unsafe, and need to update binding.rs
        let napi_id = 0;

        let net_dev: &net_device = unsafe {
            &*kptr.__bindgen_anon_1.__bindgen_anon_1.__bindgen_anon_1.dev
        };

        __sk_buff {
            // TODO: may need to append more based on __sk_buff
            len: kptr.len,
            protocol: u16be(kptr.protocol),
            priority: kptr.priority,
            ingress_ifindex: 0,
            ifindex: net_dev.ifindex as u32,
            hash: kptr.hash,
            mark: 0,
            pkt_type: 0,
            queue_mapping: kptr.queue_mapping,
            vlan_present: 0,
            vlan_tci: kptr.vlan_tci,
            vlan_proto: u16be(kptr.vlan_proto),
            cb: kptr.cb, // copy here
            tc_classid: 0,
            tc_index: kptr.tc_index,
            napi_id,
            sk,
            data,
            data_slice,
            data_meta: 0,
            kptr,
        }
    }
}

impl iu_prog for sched_cls<'_> {
    fn prog_run(&self, ctx: *mut ()) -> u32 {
        let mut newctx = self.convert_ctx(ctx);
        // return TC_ACT_OK if error
        ((self.prog)(self, &mut newctx)).unwrap_or_else(|e| TC_ACT_OK as i32)
            as u32
    }
}
