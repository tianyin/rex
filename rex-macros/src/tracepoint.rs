use proc_macro2::TokenStream;
use proc_macro_error::{abort_call_site, OptionExt};
use quote::{format_ident, quote};
use syn::{parse2, FnArg, ItemFn, Result, Type};

use crate::args::parse_string_args;

pub(crate) struct TracePoint {
    name: Option<String>,
    item: ItemFn,
}

// follow the sytle from aya
// https://github.com/aya-rs/aya/blob/1cf3d3c222bda0351ee6a2bacf9cee5349556764/aya-ebpf-macros/src/tracepoint.rs
impl TracePoint {
    // parse the argument of function
    pub(crate) fn parse(
        attrs: TokenStream,
        item: TokenStream,
    ) -> Result<TracePoint> {
        let item: ItemFn = parse2(item)?;
        let args = parse_string_args(attrs)?;

        let name = pop_string_args!(args, "name");

        Ok(TracePoint { name, item })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let fn_name = self.item.sig.ident.clone();

        // get context type and corresponding tp_type name
        let FnArg::Typed(context_arg) =
            self.item.sig.inputs.last().unwrap().clone()
        else {
            abort_call_site!("Program needs non-self arguments");
        };
        let Type::Reference(context_type_ref) = *context_arg.ty else {
            abort_call_site!("Context type needs to be behind a reference");
        };
        if context_type_ref
            .lifetime
            .expect_or_abort("Context reference needs to be static")
            .ident
            != "static"
        {
            abort_call_site!("Context reference needs to be static");
        }
        let context_type = match *context_type_ref.elem {
            Type::Verbatim(t) => parse2(t).unwrap(),
            Type::Path(p) => p.path.segments.last().unwrap().clone().ident,
            _ => {
                abort_call_site!("Tracepoint context needs to be a literal type or a path to such")
            }
        };
        let context_type_name = format!("{}", context_type);
        let ctx_variant = format_ident!(
            "{}",
            context_type_name
                .strip_suffix("Args")
                .expect_or_abort("Not valid context type")
        );

        // other tracepoint pieces
        let item = &self.item;
        let function_name = format!("{}", fn_name);
        let prog_ident =
            format_ident!("PROG_{}", fn_name.to_string().to_uppercase());

        let attached_name = format!(
            "rex/tracepoint/{}",
            self.name.as_ref().expect_or_abort(
                "Please provide valid tracepoint attached point"
            )
        );

        let tp_type = match ctx_variant.to_string().as_str() {
            "SyscallsEnterOpen" => quote!(tp_type::SyscallsEnterOpen),
            "SyscallsExitOpen" => quote!(tp_type::SyscallsExitOpen),
            "SyscallsEnterDup" => quote!(tp_type::SyscallsEnterDup),
            _ => abort_call_site!("Please provide valid context type"),
        };

        let wrapper_name = format_ident!("{}_wrapper", fn_name);

        let function_body_tokens = quote! {
            #[inline(always)]
            #item

            #[inline(always)]
            fn #wrapper_name(obj: &tracepoint, ctx_wrapper: tp_ctx) -> Result {
                let tp_ctx::#ctx_variant(ctx) = ctx_wrapper else {
                    return Err(0);
                };
                #fn_name(obj, ctx)
            }

            #[used]
            #[unsafe(link_section = #attached_name)]
            static #prog_ident: tracepoint =
                tracepoint::new(#wrapper_name, #function_name, #tp_type);
        };

        Ok(function_body_tokens)
    }
}
