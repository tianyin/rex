use crate::debug::printk;
use crate::stub;

use crate::bindings::linux::kernel::{
    ethhdr, iphdr, sk_buff, sock, tcphdr, udphdr,
};
use crate::bindings::uapi::linux::bpf::bpf_map_type;
pub use crate::bindings::uapi::linux::bpf::BPF_PROG_TYPE_SCHED_CLS;
use crate::prog_type::iu_prog;
use crate::utils::*;
use crate::{bpf_printk, map::*};
use core::ffi::{c_char, c_uchar, c_uint, c_void};
use core::{mem, slice};

pub struct __sk_buff<'a> {
    // TODO: may need to append more based on __sk_buff
    pub len: u32,
    // be16
    pub protocol: u16be,
    pub priority: u32,
    pub ingress_ifindex: u32,
    pub ifindex: u32,
    pub hash: u32,
    pub mark: u32,

    // such as PACKET_HOST if_packet.h
    // /* if you move pkt_type around you also must adapt those constants */
    // #ifdef __BIG_ENDIAN_BITFIELD
    // #define PKT_TYPE_MAX	(7 << 5)
    // #else
    // #define PKT_TYPE_MAX	7
    // #endif
    pub pkt_type: u32,

    pub queue_mapping: u16,

    pub vlan_present: u32,
    pub vlan_tci: u16,
    pub vlan_proto: u16be,
    pub cb: &'a [c_char; 48],

    pub tc_classid: u32,
    pub tc_index: u16,

    pub napi_id: u32,

    // sk: &'a &sock,
    pub data_meta: u32,
    pub data_slice: &'a [c_uchar],
    kptr: *const sk_buff,
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
    prog: fn(&Self, &__sk_buff) -> u32,
    name: &'a str,
}

impl<'a> sched_cls<'a> {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        // TODO update based on signature
        f: fn(&sched_cls<'a>, &__sk_buff) -> u32,
        nm: &'a str,
        rtti: u64,
    ) -> sched_cls<'a> {
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
    fn convert_ctx(&self, ctx: *const ()) -> __sk_buff {
        let kptr: &sk_buff =
            unsafe { &*core::mem::transmute::<*const (), *const sk_buff>(ctx) };

        let data = kptr.data as usize;
        let data_length = kptr.data_len as usize;
        let data_slice = unsafe {
            slice::from_raw_parts(kptr.data as *const c_uchar, data_length)
        };
        unsafe {
            printk("data_len %d\n\0", data_length);
        }

        // bindgen for C union is kind of wired, so we have to do this
        let sk: &sock = unsafe { &*kptr.__bindgen_anon_2.sk };

        // TODO: UNION required unsafe, and need to update binding.rs
        let napi_id = 0;

        __sk_buff {
            // TODO: may need to append more based on __sk_buff
            len: kptr.len,
            protocol: u16be(kptr.protocol),
            priority: kptr.priority,
            ingress_ifindex: 0,
            ifindex: 0,
            hash: kptr.hash,
            mark: 0,
            pkt_type: 0,
            queue_mapping: kptr.queue_mapping,
            vlan_present: 0,
            vlan_tci: kptr.vlan_tci,
            vlan_proto: u16be(kptr.vlan_proto),
            cb: &kptr.cb,
            tc_classid: 0,
            tc_index: kptr.tc_index,
            napi_id,
            // sk,
            data_slice,
            data_meta: 0,
            kptr,
        }
    }
}

impl iu_prog for sched_cls<'_> {
    fn prog_run(&self, ctx: *const ()) -> u32 {
        let mut newctx = self.convert_ctx(ctx);
        (self.prog)(self, &mut newctx)
    }
}
