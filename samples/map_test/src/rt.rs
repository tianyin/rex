pub trait prog_type {
    type ctx_ty;
    fn convert_ctx(&mut self, ctx: *const ()) -> Self::ctx_ty;
}

pub struct tracepoint {
    placeholder: u64,
}

impl tracepoint {
    pub const fn new() -> Self {
        Self { placeholder: 0 }
    }
}

impl prog_type for tracepoint {
    type ctx_ty = *const ();
    fn convert_ctx(&mut self, ctx: *const ()) -> Self::ctx_ty {
        ctx
    }
}

#[macro_export]
macro_rules! PROG_DEF {
    ($f:ident, $n:ident, $pt:ty, $sec:literal) => {
        #[no_mangle]
        #[link_section = $sec]
        fn $n(ctx: *const ()) -> i64 {
            // convert ctx
            let new_ctx = <$pt>::new().convert_ctx(ctx);
            $f(new_ctx).into()
        }
    };
}
