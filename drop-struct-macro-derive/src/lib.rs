extern crate proc_macro;
use crate::proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::{quote, ToTokens};
use syn;

/// A struct that contains the name of a struct field and the corresponding type
#[derive(Debug)]
struct FieldNameType {
    field_name: String,
    field_type: proc_macro2::TokenStream,
}

/// The actual code to free the *const pointers
impl quote::ToTokens for FieldNameType {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let field_type = &self.field_type;
        // Convert field type to string for easy pattern matching
        let field_type_string = self
            .field_type
            .clone()
            .into_iter()
            .map(|token| token.to_string())
            .collect::<String>();
        match &field_type_string[..] {
            // Free string with `free_c_str`
            "libc::c_char" => {
                let field_name = Ident::new(&self.field_name, Span::call_site());
                let gen = quote! {
                    free_c_str(self.#field_name as *mut #field_type);
                };
                gen.to_tokens(tokens);
            }
            // Expect all others to be vectors
            _ => {
                if !self.field_name.ends_with("_ptr") {
                    panic!(
                        "Pointer needs to have field with `_ptr` as suffix. \
                         This field is named `{}`.",
                        self.field_name
                    )
                }
                // Field ends with `_ptr` so we can re-construct the corresponding length field
                let field_name_len = Ident::new(
                    &format!(
                        "{}{}",
                        &self.field_name[..&self.field_name.len() - 4],
                        "_len"
                    ),
                    Span::call_site(),
                );
                let field_name_ptr = Ident::new(&self.field_name, Span::call_site());
                let gen = quote! {
                    drop(Vec::from_raw_parts(
                            self.#field_name_ptr as *mut #field_type,
                            self.#field_name_len,
                            self.#field_name_len,
                    ));
                };
                gen.to_tokens(tokens);
            }
        }
    }
}

#[proc_macro_derive(DropStructMacro)]
pub fn drop_struct_macro_derive(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).unwrap();

    // A list of fields that should get dropped
    let mut to_be_dropped = Vec::new();

    // Only take *const pointers into account (also not *mut)
    match ast.data {
        syn::Data::Struct(ref data_struct) => {
            if let syn::Fields::Named(ref fields_named) = data_struct.fields {
                for field in fields_named.named.iter() {
                    if let syn::Type::Ptr(ref type_ptr) = field.ty {
                        if type_ptr.const_token.is_some() {
                            if let syn::Type::Path(ref type_path) = *type_ptr.elem {
                                let field_name = field.ident.clone().unwrap().to_string();
                                let field_type = type_path.path.clone().into_token_stream();
                                to_be_dropped.push(FieldNameType {
                                    field_name,
                                    field_type,
                                })
                            }
                        }
                    }
                }
            }
        }
        _ => panic!("Works only with structs"),
    }

    let name = &ast.ident;
    let gen = quote! {
        impl Drop for #name {
            fn drop(&mut self) {
                unsafe {
                    #(#to_be_dropped)*
                };
            }
        }
    };
    gen.into()
}
