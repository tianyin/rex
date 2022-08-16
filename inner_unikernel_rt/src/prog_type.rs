pub trait prog_type {
    type ctx_ty;
    fn convert_ctx(&mut self, ctx: *const ()) -> Self::ctx_ty;
}
