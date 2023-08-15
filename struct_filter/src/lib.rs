extern crate proc_macro;

use std::any::type_name;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Field, Fields, Type, TypePath};

fn type_checking(type_path: &TypePath) -> bool {
    let type_name = type_path.path.segments.last().unwrap().ident.to_string();

    match type_name.as_str() {
        "u8" => (),
        "i8" => (),
        "i16" => (),
        "u16" => (),
        "i32" => (),
        "u32" => (),
        "i64" => (),
        "u64" => (),
        _ => return false,
    }

    true
}

fn field_type(ty: Type) -> Result<(), TokenStream> {
    if let Type::Path(type_path) = ty {
        if !type_checking(&type_path) {
            return Err(
                syn::Error::new_spanned(&type_path, "All fields must be of numeric type")
                    .to_compile_error()
                    .into(),
            );
        }
    } else if let Type::Array(type_array) = ty {
        // convert [T; N] to T
        return field_type(*type_array.elem);
    } else if let Type::Reference(type_ref) = ty {
        // convert &'a T to T
        return field_type(*type_ref.elem);
    } else if let Type::Slice(type_slice) = ty {
        // convert [T] to T
        return field_type(*type_slice.elem);
    } else {
        // TODO: add more detailed type hints
        return Err(
            syn::Error::new_spanned(&ty, "All fields must be of validate type")
                .to_compile_error()
                .into(),
        );
    }
    Ok(())
}

#[proc_macro_derive(FieldChecker)]
pub fn ensure_numberic(input: TokenStream) -> TokenStream {
    let original_input = input.clone();
    let ast: DeriveInput = parse_macro_input!(input);

    match ast.data {
        Data::Struct(s) => match s.fields {
            Fields::Named(fields) => {
                for field in fields.named {
                    if let Err(err) = field_type(field.ty) {
                        return err;
                    }
                }
            }
            _ => (),
        },
        _ => (),
    }
    TokenStream::new()
    //  // You can still derive other traits, or just generate an empty implementation
    //  let name = ast.ident;
    //  let gen = quote! {
    //      impl #name {
    //          // You can insert additional code here
    //      }
    //  };
    //  gen.into()
}
