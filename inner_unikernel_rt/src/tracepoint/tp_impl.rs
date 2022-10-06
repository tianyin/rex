use crate::linux::bpf::BPF_PROG_TYPE_TRACEPOINT;
use crate::map::*;
use crate::prog_type::prog_type;

pub enum tp_ctx {
    Void,
}

#[repr(C)]
pub struct tracepoint {
    rtti: u32,
    tp_type: tp_ctx,
    prog: fn(&Self, &tp_ctx) -> u32,
}

impl tracepoint {
    pub const fn new(tp_ty: tp_ctx, f: fn(&Self, &tp_ctx) -> u32) -> Self {
        Self {
            rtti: BPF_PROG_TYPE_TRACEPOINT,
            tp_type: tp_ty,
            prog: f,
        }
    }

    fn convert_ctx(&self, ctx: *const ()) -> tp_ctx {
        match self.tp_type {
            tp_ctx::Void => tp_ctx::Void,
        }
    }

    crate::base_helper::base_helper_defs!();
}

impl prog_type for tracepoint {
    fn prog_run(&self, ctx: *const ()) -> u32 {
        let newctx = self.convert_ctx(ctx);
        (self.prog)(self, &newctx)
    }
}
