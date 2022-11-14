use crate::linux::bpf::BPF_PROG_TYPE_KPROBE;
use crate::linux::ptrace::pt_regs;
use crate::map::*;
use crate::prog_type::iu_prog;

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
pub struct kprobe<'a> {
    rtti: u64,
    prog: fn(&Self, &pt_regs) -> u32,
    name: &'a str,
}

impl<'a> kprobe<'a> {
    pub const fn new(
        f: fn(&kprobe<'a>, &pt_regs) -> u32,
        nm: &'a str,
    ) -> kprobe<'a> {
        Self {
            rtti: BPF_PROG_TYPE_KPROBE as u64,
            prog: f,
            name: nm,
        }
    }

    fn convert_ctx(&self, ctx: *const ()) -> &pt_regs {
        unsafe { &*core::mem::transmute::<*const (), *const pt_regs>(ctx) }
    }

    crate::base_helper::base_helper_defs!();
}

impl iu_prog for kprobe<'_> {
    fn prog_run(&self, ctx: *const ()) -> u32 {
        let newctx = self.convert_ctx(ctx);
        (self.prog)(self, newctx)
    }
}