use crate::prog_type::prog_type;

pub enum tp_ctx {
    Void,
}

pub struct tracepoint {
    tp_type: tp_ctx, // not sure if we really need this
}

impl tracepoint {
    pub const fn new(tp_ty: tp_ctx) -> Self {
        Self { tp_type: tp_ty }
    }
}

impl prog_type for tracepoint {
    type ctx_ty = tp_ctx;
    fn convert_ctx(&mut self, ctx: *const ()) -> Self::ctx_ty {
        match self.tp_type {
            tp_ctx::Void => tp_ctx::Void,
        }
    }
}

#[macro_export]
macro_rules! TP_DEF {
    ($f:ident, $n:ident, Void) => {
        #[no_mangle]
        #[link_section = "tracepoint/"]
        pub extern "C" fn $n(ctx: *const ()) -> i64 {
            // convert ctx
            let new_ctx = <tracepoint>::new(tp_ctx::Void).convert_ctx(ctx);
            $f(&new_ctx).into()
        }
    };
}
