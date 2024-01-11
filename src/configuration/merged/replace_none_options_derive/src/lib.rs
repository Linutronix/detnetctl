// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(ReplaceNoneOptions)]
pub fn replace_none_options(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let struct_name = &ast.ident;

    let gen = match ast.data {
        syn::Data::Struct(ref s) => {
            if let syn::Fields::Named(ref fields) = s.fields {
                let replace_fields = fields.named.iter().map(|field| {
                    let field_name = &field.ident;
                    if let syn::Type::Path(ref type_path) = field.ty {
                        if let Some(segment) = type_path.path.segments.last() {
                            if segment.ident.to_string() == "Option" {
                                // Field is of type Option<T>
                                quote! {
                                    if self.#field_name.is_none() {
                                        self.#field_name = fallback.#field_name;
                                    }
                                }
                            } else {
                                // This is not an Option<T>, so keep it intact.
                                quote! {
                                    // No action needed
                                }
                            }
                        } else {
                            quote! {
                                // No action needed
                            }
                        }
                    } else {
                        quote! {
                            // No action needed
                        }
                    }
                });
                quote! {
                    impl ReplaceNoneOptions for #struct_name {
                        fn replace_none_options(&mut self, fallback: Self) {
                            #( #replace_fields )*
                        }
                    }
                }
            } else {
                quote! {
                    compile_error!("Expected a struct with named fields for deriving ReplaceNoneOptions");
                }
            }
        }
        _ => {
            quote! {
                compile_error!("Expected a struct for deriving ReplaceNoneOptions");
            }
        }
    };

    gen.into()
}

