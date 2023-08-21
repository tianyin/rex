extern crate proc_macro;

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

fn field_type_check(ty: Type) -> Result<(), TokenStream> {
    if let Type::Path(type_path) = ty {
        if !type_checking(&type_path) {
            return Err(
                syn::Error::new_spanned(&type_path, "All fields must be numeric type")
                    .to_compile_error()
                    .into(),
            );
        }
    } else if let Type::Array(type_array) = ty {
        // convert [T; N] to T
        return field_type_check(*type_array.elem);
    } else if let Type::Reference(type_ref) = ty {
        // convert &'a T to T
        return field_type_check(*type_ref.elem);
    } else {
        // TODO: add more detailed type hints
        return Err(
            syn::Error::new_spanned(&ty, "All fields must be validate type")
                .to_compile_error()
                .into(),
        );
    }
    Ok(())
}

#[proc_macro_derive(FieldChecker)]
pub fn ensure_numberic(input: TokenStream) -> TokenStream {
    let original_input = input.clone();
    let ast: DeriveInput = parse_macro_input!(input as DeriveInput);
    let struct_name = ast.ident;
    let mut fields_token = vec![];

    if let Data::Struct(s) = ast.data {
        for field in s.fields {
            let field_type = &field.ty;
            let field_ident = field.ident.as_ref().unwrap();

            let token = quote!( direct_packet_access_ok::<#field_type>(); );
            println!("Field Name: {:?}", field_ident);
            println!("token is {}", token.to_string());
            fields_token.push(token);
        }
    }

    // match ast.data {
    //     Data::Struct(s) => match s.fields {
    //         Fields::Named(fields) => {
    //             for field in fields.named {
    //                 let field_type = &field.ty;
    //                 // let tokens = quote! { #field_type };
    //                 struct_fields.push((field.ident, field_type.clone()));

    //                 if let Err(err) = field_type_check(field.ty) {
    //                     return err;
    //                 }
    //             }
    //         }
    //         _ => (),
    //     },
    //     _ => (),
    // }
    // TokenStream::new()
    // You can still derive other traits, or just generate an empty implementation
    let gen = quote! {
        impl #struct_name {
            fn new(data: &[u8]) -> &#struct_name{
             #(#fields_token)*
             convert_slice_to_struct::<#struct_name>(data)
            }
        }
    };
    println!("generated code is:\n {}", gen.to_string());
    gen.into()
}
