use crate::linux::bpf::BPF_PROG_TYPE_TRACEPOINT;
use crate::map::*;
use crate::prog_type::iu_prog;

pub enum tp_ctx {
    Void,
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
pub struct tracepoint<'a> {
    rtti: u64,
    prog: fn(&Self, &tp_ctx) -> u32,
    name: &'a str,
    tp_type: tp_ctx,
}

impl<'a> tracepoint<'a> {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        f: fn(&tracepoint<'a>, &tp_ctx) -> u32,
        nm: &'a str,
        tp_ty: tp_ctx,
    ) -> tracepoint<'a> {
        Self {
            rtti: BPF_PROG_TYPE_TRACEPOINT as u64,
            prog: f,
            name: nm,
            tp_type: tp_ty,
        }
    }

    fn convert_ctx(&self, ctx: *const ()) -> tp_ctx {
        match self.tp_type {
            tp_ctx::Void => tp_ctx::Void,
        }
    }
}

impl iu_prog for tracepoint<'_> {
    fn prog_run(&self, ctx: *const ()) -> u32 {
        let newctx = self.convert_ctx(ctx);
        (self.prog)(self, &newctx)
    }
}
