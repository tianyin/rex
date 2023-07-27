use crate::bindings::linux::kernel::xdp_buff;
use crate::bindings::uapi::linux::bpf::{bpf_map_type, BPF_PROG_TYPE_XDP};
use crate::map::*;
use crate::prog_type::iu_prog;
use crate::stub;
use core::ffi::{c_char, c_void};
use core::slice;

// pub type pt_regs = super::binding::pt_regs;

#[derive(Debug, Copy, Clone)]
pub struct xdp_md<'b> {
    // TODO check the kernel version xdp_md
    // pub regs: bpf_user_pt_regs_t,
    data: usize,
    data_end: usize,
    pub data_slice: &'b [c_void],
    pub data_length: usize,
    pub data_meta: usize,
    pub ingress_ifindex: u32,
    pub rx_qeueu_index: u32,
    pub egress_ifindex: u32,
    kptr: *const xdp_buff,
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
    prog: fn(&Self, &mut xdp_md) -> u32,
    name: &'a str,
}

impl<'a> xdp<'a> {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        // TODO update based on signature
        f: fn(&xdp<'a>, &mut xdp_md) -> u32,
        nm: &'a str,
    ) -> xdp<'a> {
        Self {
            rtti: BPF_PROG_TYPE_XDP as u64,
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

        // BUG may not work since directly truncate the pointer to u32
        let data = kptr.data as usize;
        let data_end = kptr.data_end as usize;
        let data_meta = kptr.data_meta as usize;
        let data_length = (data_end - data) as usize;

        // TODO should we use slice::from_raw_parts or slice::copy_from_slice?
        let data_slice = unsafe {
            slice::from_raw_parts(kptr.data as *const c_void, data_length)
        };

        let ingress_ifindex = kptr.rxq as u32;
        let rx_qeueu_index = unsafe { (*kptr.rxq).queue_index };
        let egress_ifindex = unsafe { (*(*kptr.txq).dev).ifindex as u32 };

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

    // TODO update based on xdp_md to convert to xdp_buff
    pub fn bpf_xdp_adjust_head(&self, xdp: &mut xdp_buff, offset: i32) -> i32 {
        let helper: extern "C" fn(*mut xdp_buff, i32) -> i32 =
            unsafe { core::mem::transmute(stub::bpf_xdp_adjust_head_addr()) };
        helper(xdp, offset)
    }

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
