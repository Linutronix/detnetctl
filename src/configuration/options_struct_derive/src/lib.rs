// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, spanned::Spanned, DeriveInput};

#[proc_macro_derive(ReplaceNoneOptions)]
pub fn replace_none_options(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let struct_name = &ast.ident;

    let gen = match ast.data {
        syn::Data::Struct(ref s) => {
            let syn::Fields::Named(ref fields) = s.fields else {
                return quote! {
                    compile_error!("Expected a struct with named fields for deriving ReplaceNoneOptions");
                }.into();
            };

            let replace_fields = fields.named.iter().map(|field| {
                let Some(segment) = segment_from_field(field) else {
                    return quote! {
                        compile_error!("Cannot handle {:#?}", field);
                    };
                };

                let field_name = &field.ident;
                if segment.ident == "Option" {
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
            });
            quote! {
                impl ReplaceNoneOptions for #struct_name {
                    fn replace_none_options(&mut self, fallback: Self) {
                        #( #replace_fields )*
                    }
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

#[proc_macro_derive(OptionsGetters)]
pub fn options_getters(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let struct_name = &ast.ident;

    let gen = match ast.data {
        syn::Data::Struct(ref s) => {
            let syn::Fields::Named(ref fields) = s.fields else {
                return quote! {
                    compile_error!("Expected a struct with named fields for deriving OptionsGetters");
                }.into();
            };

            let getters = fields.named.iter().map(|field| {
                let field_name = &field.ident;
                let doc_comment = parse_doc_comment(&field.attrs);

                let Some(segment) = segment_from_field(field) else {
                    return quote! {
                        compile_error!("Cannot handle {:#?}", field);
                    };
                };

                if segment.ident == "Option" {
                    // Field is of type Option<T>

                    let generics_type = parse_option_generics(segment);

                    let field_name_string = field_name.as_ref().unwrap().to_string();
                    let struct_name_string = struct_name.to_string();
                    let opt_name = syn::Ident::new(&format!("{}_opt", field_name.as_ref().unwrap()), field_name.span());
                    let is_some_name = syn::Ident::new(&format!("{}_is_some", field_name.as_ref().unwrap()), field_name.span());
                    let is_some_comment = format!("If field `{}` contains a value", field_name.as_ref().unwrap());
                    let req_doc_comment = format!("{0}\n\nThis method should be used if a valid configuration is expected contain a `{1}` field.\n# Errors\nIf `{1}` does not contain a value, an error is returned.", doc_comment, field_name.as_ref().unwrap());
                    let opt_doc_comment = format!("{0}\n\nThis method should be used if the `{1}` field is optional in the configuration and the calling code will handle it accordingly.", doc_comment, field_name.as_ref().unwrap());

                    quote! {
                        #[doc=#req_doc_comment]
                        pub fn #field_name(&self) -> Result<&#generics_type> {
                            use anyhow::anyhow;
                            self.#field_name.as_ref().ok_or_else(|| anyhow!("Required field {} is missing in {}", #field_name_string, #struct_name_string))
                        }

                        #[doc=#opt_doc_comment]
                        pub fn #opt_name(&self) -> Option<&#generics_type> {
                            self.#field_name.as_ref()
                        }

                        #[doc=#is_some_comment]
                        pub fn #is_some_name(&self) -> bool {
                            self.#field_name.is_some()
                        }
                    }
                } else {
                    let field_type = &field.ty;

                    quote! {
                        #[doc=#doc_comment]
                        pub fn #field_name(&self) -> &#field_type {
                            &self.#field_name
                        }
                    }
                }
            });
            quote! {
                impl #struct_name {
                    #( #getters )*
                }
            }
        }
        _ => {
            quote! {
                compile_error!("Expected a struct for deriving OptionsGetters");
            }
        }
    };

    gen.into()
}

fn parse_doc_comment(attrs: &[syn::Attribute]) -> String {
    for attr in attrs {
        let meta = attr.parse_meta().unwrap();
        if let syn::Meta::NameValue(meta) = meta {
            if let syn::Lit::Str(doc) = meta.lit {
                return doc.value().trim().to_string();
            }
        }
    }

    "".to_owned()
}

fn parse_option_generics(segment: &syn::PathSegment) -> &syn::Type {
    let syn::PathArguments::AngleBracketed(generics) = &segment.arguments else {
        panic!("No type found in option");
    };

    let syn::GenericArgument::Type(generics_type) = generics.args.first().unwrap() else {
        panic!("No path type found in option");
    };

    generics_type
}

fn segment_from_field(field: &syn::Field) -> Option<&syn::PathSegment> {
    let syn::Type::Path(ref type_path) = field.ty else {
        return None;
    };

    let Some(segment) = type_path.path.segments.last() else {
        return None;
    };

    Some(segment)
}

#[proc_macro_derive(OptionsBuilder)]
pub fn options_builder(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let struct_name = &ast.ident;

    let gen = match ast.data {
        syn::Data::Struct(ref s) => {
            let syn::Fields::Named(ref fields) = s.fields else {
                return quote! {
                    compile_error!("Expected a struct with named fields for deriving OptionsGetters");
                }.into();
            };

            let builder_name =
                syn::Ident::new(&format!("{}Builder", struct_name), struct_name.span());

            let setters = fields.named.iter().map(|field| {
                let field_name = &field.ident;
                let doc_comment = parse_doc_comment(&field.attrs);

                let Some(segment) = segment_from_field(field) else {
                    return quote! {
                        compile_error!("Cannot handle {:#?}", field);
                    };
                };

                let field_type = &field.ty;

                if segment.ident == "Option" {
                    // Field is of type Option<T>

                    let generics_type = parse_option_generics(segment);
                    let opt_name = syn::Ident::new(
                        &format!("{}_opt", field_name.as_ref().unwrap()),
                        field_name.span(),
                    );

                    quote! {
                        #[doc=#doc_comment]
                        pub fn #field_name(mut self, #field_name: #generics_type) -> #builder_name {
                            self.obj.#field_name = Some(#field_name);
                            self
                        }

                        #[doc=#doc_comment]
                        pub fn #opt_name(mut self, #field_name: #field_type) -> #builder_name {
                            self.obj.#field_name = #field_name;
                            self
                        }
                    }
                } else {
                    quote! {
                        #[doc=#doc_comment]
                        pub fn #field_name(mut self, #field_name: #field_type) -> #builder_name {
                            self.obj.#field_name = #field_name;
                            self
                        }
                    }
                }
            });

            let initializers = fields.named.iter().map(|field| {
                let field_name = &field.ident;

                let Some(segment) = segment_from_field(field) else {
                    return quote! {
                        compile_error!("Cannot handle {:#?}", field);
                    };
                };

                if segment.ident == "Option" {
                    // Field is of type Option<T>
                    quote! {
                        #field_name: None,
                    }
                } else {
                    let field_type = &field.ty;

                    quote! {
                        #field_name: #field_type::default(),
                    }
                }
            });

            let doc_comment_builder = format!("Builder for {}", struct_name);
            let doc_comment_new_builder = format!("Generate a new builder for {}", struct_name);
            let doc_comment_build = format!("Generate a {}", struct_name);

            quote! {
                #[doc=#doc_comment_builder]
                pub struct #builder_name {
                    obj: #struct_name
                }

                impl #builder_name {
                    #[doc=#doc_comment_new_builder]
                    pub fn new() -> Self {
                        #builder_name {
                            obj: #struct_name {
                                #( #initializers )*
                            }
                        }
                    }

                    #[doc=#doc_comment_build]
                    pub fn build(self) -> #struct_name {
                        self.obj
                    }

                    #( #setters )*
                }
            }
        }
        _ => {
            quote! {
                compile_error!("Expected a struct for deriving OptionsGetters");
            }
        }
    };

    gen.into()
}

struct MethodList {
    object_expr: syn::Expr,
    field_names: syn::punctuated::Punctuated<syn::Ident, syn::token::Comma>,
}

impl syn::parse::Parse for MethodList {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let object_expr: syn::Expr = input.parse()?;

        input.parse::<syn::token::Comma>()?;

        Ok(MethodList {
            object_expr,
            field_names: syn::punctuated::Punctuated::parse_terminated(input)?,
        })
    }
}

#[proc_macro]
pub fn validate_are_some(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as MethodList);

    let object_expr = &input.object_expr;

    let checks = input.field_names.iter().map(|field| {
        let is_some = syn::Ident::new(&format!("{}_is_some", field), field.span());
        let field_name_string = field.to_string();
        let object_expr_string = quote! { #object_expr }.to_string();

        quote! {
            if !#object_expr.#is_some() {
                return Err(anyhow!("Validation failed! {} is missing for {}", #field_name_string, #object_expr_string))
            }
        }
    });

    quote! {
        (|| {
            use anyhow::anyhow;

            #( #checks )*

            return Ok(());
        })()
    }
    .into()
}
