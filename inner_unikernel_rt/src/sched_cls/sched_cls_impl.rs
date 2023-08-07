use crate::bindings::linux::kernel::{ethhdr, iphdr, sk_buff, tcphdr, udphdr};
use crate::bindings::uapi::linux::bpf::bpf_map_type;
pub use crate::bindings::uapi::linux::bpf::BPF_PROG_TYPE_SCHED_CLS;
use crate::prog_type::iu_prog;
use crate::stub;
use crate::{bpf_printk, map::*};

#[derive(Debug)]
pub struct __sk_buff {
    // TODO check the kernel version __sk_buff
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

        __sk_buff { kptr }
    }
}

impl iu_prog for sched_cls<'_> {
    fn prog_run(&self, ctx: *const ()) -> u32 {
        let mut newctx = self.convert_ctx(ctx);
        (self.prog)(self, &mut newctx)
    }
}
