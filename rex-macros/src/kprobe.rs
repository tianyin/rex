use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{parse2, ItemFn, Result};

pub(crate) struct KProbe {
    function: String,
    item: ItemFn,
}

impl KProbe {
    // parse the argument of function
    pub(crate) fn parse(
        attrs: TokenStream,
        item: TokenStream,
    ) -> Result<KProbe> {
        let item: ItemFn = parse2(item)?;
        // let mut args: Args = parse2(attrs)?;
        let function = attrs.to_string();
        Ok(KProbe { function, item })
    }

    // expand the function into two function with original function
    // #[entry_link(inner_unikernel/kprobe/__seccomp_filter)]
    // static PROG: kprobe = kprobe::new(iu_prog1_fn, "iu_prog1");
    pub(crate) fn expand(&self) -> Result<TokenStream> {
        // TODO: section may update in the future
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        let function_name = format!("{}", fn_name);
        let prog_ident = format_ident!("PROG_{}", fn_name);
        let attached_function = format!("rex/kprobe/{}", self.function);

        let function_body_tokens = quote! {
            #[inline(always)]
            #item

            #[used]
            #[link_section = #attached_function]
            static #prog_ident: kprobe =
                kprobe::new(#fn_name, #function_name);
        };

        Ok(function_body_tokens)
    }
}
