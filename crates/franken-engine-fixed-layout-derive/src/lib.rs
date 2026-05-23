#![forbid(unsafe_code)]
//! Derive macro for the FixedLayout trait.
//!
//! This crate provides a `#[derive(FixedLayout)]` proc macro that implements
//! the FixedLayout trait for structs and enums with fixed-byte layouts.
//!
//! # Rules
//!
//! A type can derive FixedLayout if:
//! - All its fields implement FixedLayout (recursive check)
//! - It has a deterministic fixed-size representation
//! - It doesn't contain variable-length types (String, Vec, etc.)
//! - It implements Deterministic (enforced by FixedLayout trait bound)
//!
//! # Examples
//!
//! ```rust
//! use franken_engine_deterministic_trait::{Deterministic, FixedLayout};
//! use franken_engine_deterministic_derive::Deterministic;
//! use franken_engine_fixed_layout_derive::FixedLayout;
//!
//! #[derive(Deterministic, FixedLayout)]
//! struct Point {
//!     x: i32,
//!     y: i32,
//! }
//!
//! #[derive(Deterministic, FixedLayout)]
//! enum Status {
//!     Active,
//!     Inactive,
//!     Code(u16),
//! }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Ident, Type, Variant};

/// Derive macro for the FixedLayout trait.
#[proc_macro_derive(FixedLayout)]
pub fn derive_fixed_layout(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match generate_fixed_layout_impl(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => syn::Error::new_spanned(&input, err)
            .to_compile_error()
            .into(),
    }
}

fn generate_fixed_layout_impl(input: &DeriveInput) -> Result<proc_macro2::TokenStream, String> {
    let name = &input.ident;

    // Check for generic parameters - not supported for FixedLayout
    if !input.generics.params.is_empty() {
        return Err("FixedLayout cannot be derived for generic types - layout size must be known at compile time".to_string());
    }

    match &input.data {
        Data::Struct(data_struct) => generate_struct_impl(name, &data_struct.fields),
        Data::Enum(data_enum) => {
            generate_enum_impl(name, &data_enum.variants.iter().collect::<Vec<_>>())
        }
        Data::Union(_) => Err("FixedLayout cannot be derived for unions".to_string()),
    }
}

fn generate_struct_impl(name: &Ident, fields: &Fields) -> Result<proc_macro2::TokenStream, String> {
    match fields {
        Fields::Named(fields_named) => {
            let field_names: Vec<&Ident> = fields_named
                .named
                .iter()
                .map(|f| f.ident.as_ref().unwrap())
                .collect();
            let field_types: Vec<&Type> = fields_named.named.iter().map(|f| &f.ty).collect();

            // Generate size calculation
            let size_calculation = if field_types.is_empty() {
                quote! { 0 }
            } else {
                quote! { #( <#field_types as franken_engine_deterministic_trait::FixedLayout>::LAYOUT_SIZE )+* }
            };

            // Generate encode implementation
            let encode_impl = if field_names.is_empty() {
                quote! {
                    if !buffer.is_empty() {
                        panic!("Buffer size mismatch for empty struct");
                    }
                }
            } else {
                let encode_fields = field_names.iter().zip(&field_types).enumerate().map(|(i, (field_name, field_type))| {
                    if i == 0 {
                        quote! {
                            let mut offset = 0;
                            self.#field_name.encode_fixed(&mut buffer[offset..offset + <#field_type as franken_engine_deterministic_trait::FixedLayout>::LAYOUT_SIZE]);
                            offset += <#field_type as franken_engine_deterministic_trait::FixedLayout>::LAYOUT_SIZE;
                        }
                    } else {
                        quote! {
                            self.#field_name.encode_fixed(&mut buffer[offset..offset + <#field_type as franken_engine_deterministic_trait::FixedLayout>::LAYOUT_SIZE]);
                            offset += <#field_type as franken_engine_deterministic_trait::FixedLayout>::LAYOUT_SIZE;
                        }
                    }
                });

                quote! {
                    if buffer.len() != Self::LAYOUT_SIZE {
                        panic!("Buffer size mismatch: expected {}, got {}", Self::LAYOUT_SIZE, buffer.len());
                    }
                    #( #encode_fields )*
                }
            };

            // Generate decode implementation
            let decode_impl = if field_names.is_empty() {
                quote! {
                    if !buffer.is_empty() {
                        return Err(franken_engine_deterministic_trait::FixedLayoutError::InvalidBufferSize {
                            expected: 0,
                            actual: buffer.len(),
                        });
                    }
                    Ok(Self {})
                }
            } else {
                let decode_fields = field_names.iter().zip(&field_types).enumerate().map(|(i, (field_name, field_type))| {
                    if i == 0 {
                        quote! {
                            let mut offset = 0;
                            let #field_name = <#field_type as franken_engine_deterministic_trait::FixedLayout>::decode_fixed(
                                &buffer[offset..offset + <#field_type as franken_engine_deterministic_trait::FixedLayout>::LAYOUT_SIZE]
                            )?;
                            offset += <#field_type as franken_engine_deterministic_trait::FixedLayout>::LAYOUT_SIZE;
                        }
                    } else {
                        quote! {
                            let #field_name = <#field_type as franken_engine_deterministic_trait::FixedLayout>::decode_fixed(
                                &buffer[offset..offset + <#field_type as franken_engine_deterministic_trait::FixedLayout>::LAYOUT_SIZE]
                            )?;
                            offset += <#field_type as franken_engine_deterministic_trait::FixedLayout>::LAYOUT_SIZE;
                        }
                    }
                });

                let construct_struct = quote! {
                    Ok(Self {
                        #( #field_names, )*
                    })
                };

                quote! {
                    if buffer.len() != Self::LAYOUT_SIZE {
                        return Err(franken_engine_deterministic_trait::FixedLayoutError::InvalidBufferSize {
                            expected: Self::LAYOUT_SIZE,
                            actual: buffer.len(),
                        });
                    }
                    #( #decode_fields )*
                    #construct_struct
                }
            };

            Ok(quote! {
                impl franken_engine_deterministic_trait::FixedLayout for #name {
                    const LAYOUT_SIZE: usize = #size_calculation;

                    fn encode_fixed(&self, buffer: &mut [u8]) {
                        #encode_impl
                    }

                    fn decode_fixed(buffer: &[u8]) -> Result<Self, franken_engine_deterministic_trait::FixedLayoutError> {
                        #decode_impl
                    }
                }
            })
        }
        Fields::Unnamed(fields_unnamed) => {
            let field_types: Vec<&Type> = fields_unnamed.unnamed.iter().map(|f| &f.ty).collect();

            if field_types.len() != 1 {
                return Err(
                    "Tuple structs with FixedLayout must have exactly one field (newtype pattern)"
                        .to_string(),
                );
            }

            let field_type = &field_types[0];

            Ok(quote! {
                impl franken_engine_deterministic_trait::FixedLayout for #name {
                    const LAYOUT_SIZE: usize = <#field_type as franken_engine_deterministic_trait::FixedLayout>::LAYOUT_SIZE;

                    fn encode_fixed(&self, buffer: &mut [u8]) {
                        self.0.encode_fixed(buffer);
                    }

                    fn decode_fixed(buffer: &[u8]) -> Result<Self, franken_engine_deterministic_trait::FixedLayoutError> {
                        let inner = <#field_type as franken_engine_deterministic_trait::FixedLayout>::decode_fixed(buffer)?;
                        Ok(Self(inner))
                    }
                }
            })
        }
        Fields::Unit => Ok(quote! {
            impl franken_engine_deterministic_trait::FixedLayout for #name {
                const LAYOUT_SIZE: usize = 0;

                fn encode_fixed(&self, buffer: &mut [u8]) {
                    if !buffer.is_empty() {
                        panic!("Buffer size mismatch for unit struct");
                    }
                }

                fn decode_fixed(buffer: &[u8]) -> Result<Self, franken_engine_deterministic_trait::FixedLayoutError> {
                    if !buffer.is_empty() {
                        return Err(franken_engine_deterministic_trait::FixedLayoutError::InvalidBufferSize {
                            expected: 0,
                            actual: buffer.len(),
                        });
                    }
                    Ok(Self)
                }
            }
        }),
    }
}

fn generate_enum_impl(
    name: &Ident,
    variants: &[&Variant],
) -> Result<proc_macro2::TokenStream, String> {
    if variants.is_empty() {
        return Err("Cannot derive FixedLayout for empty enum".to_string());
    }

    // For enums, we use a discriminant byte plus the size of the largest variant
    let mut max_variant_size = 0;
    let mut variant_info = Vec::new();

    for (_index, variant) in variants.iter().enumerate() {
        let variant_name = &variant.ident;

        match &variant.fields {
            Fields::Unit => {
                variant_info.push((variant_name, 0, Vec::new()));
            }
            Fields::Unnamed(fields) => {
                if fields.unnamed.len() != 1 {
                    return Err(
                        "Enum variants with FixedLayout must have zero or one field".to_string()
                    );
                }
                let field_type = &fields.unnamed[0].ty;
                variant_info.push((variant_name, 1, vec![field_type]));
                max_variant_size = max_variant_size.max(1); // Will be calculated dynamically
            }
            Fields::Named(_) => {
                return Err("Enum variants with FixedLayout cannot have named fields".to_string());
            }
        }
    }

    // For simplicity, calculate max size at compile time using const_max helper
    let variant_size_calculations: Vec<_> = variant_info.iter().map(|(_, field_count, field_types)| {
        if *field_count == 0 {
            quote! { 0 }
        } else {
            let field_type = &field_types[0];
            quote! { <#field_type as franken_engine_deterministic_trait::FixedLayout>::LAYOUT_SIZE }
        }
    }).collect();

    // For now, use a simple approach: discriminant + largest possible variant (u64 = 8 bytes)
    // This is a simplification - in practice, we'd want to calculate the exact max size
    let size_calculation = if variant_size_calculations.is_empty() {
        quote! { 1 } // Just discriminant
    } else if variant_size_calculations.len() == 1 {
        let size = &variant_size_calculations[0];
        quote! { 1 + #size }
    } else {
        // For multiple variants, assume max 8 bytes (u64 size) for simplicity
        // TODO: Calculate exact max size at compile time
        quote! { 1 + 8 }
    };

    // Generate encode match arms
    let encode_arms: Vec<_> = variant_info
        .iter()
        .enumerate()
        .map(|(index, (variant_name, field_count, _))| {
            let discriminant = index as u8;
            if *field_count == 0 {
                quote! {
                    Self::#variant_name => {
                        buffer[0] = #discriminant;
                        // Zero-pad the rest
                        for i in 1..Self::LAYOUT_SIZE {
                            buffer[i] = 0;
                        }
                    }
                }
            } else {
                quote! {
                    Self::#variant_name(ref value) => {
                        buffer[0] = #discriminant;
                        value.encode_fixed(&mut buffer[1..1 + value.LAYOUT_SIZE]);
                        // Zero-pad the rest
                        for i in (1 + value.LAYOUT_SIZE)..Self::LAYOUT_SIZE {
                            buffer[i] = 0;
                        }
                    }
                }
            }
        })
        .collect();

    // Generate decode match arms
    let decode_arms: Vec<_> = variant_info.iter().enumerate().map(|(index, (variant_name, field_count, field_types))| {
        let discriminant = index as u8;
        if *field_count == 0 {
            quote! {
                #discriminant => Ok(Self::#variant_name),
            }
        } else {
            let field_type = &field_types[0];
            quote! {
                #discriminant => {
                    let field_size = <#field_type as franken_engine_deterministic_trait::FixedLayout>::LAYOUT_SIZE;
                    let value = <#field_type as franken_engine_deterministic_trait::FixedLayout>::decode_fixed(&buffer[1..1 + field_size])?;
                    Ok(Self::#variant_name(value))
                }
            }
        }
    }).collect();

    Ok(quote! {
        impl franken_engine_deterministic_trait::FixedLayout for #name {
            const LAYOUT_SIZE: usize = #size_calculation;

            fn encode_fixed(&self, buffer: &mut [u8]) {
                if buffer.len() != Self::LAYOUT_SIZE {
                    panic!("Buffer size mismatch: expected {}, got {}", Self::LAYOUT_SIZE, buffer.len());
                }

                match self {
                    #( #encode_arms )*
                }
            }

            fn decode_fixed(buffer: &[u8]) -> Result<Self, franken_engine_deterministic_trait::FixedLayoutError> {
                if buffer.len() != Self::LAYOUT_SIZE {
                    return Err(franken_engine_deterministic_trait::FixedLayoutError::InvalidBufferSize {
                        expected: Self::LAYOUT_SIZE,
                        actual: buffer.len(),
                    });
                }

                match buffer[0] {
                    #( #decode_arms )*
                    discriminant => Err(franken_engine_deterministic_trait::FixedLayoutError::InvalidData(
                        format!("Invalid enum discriminant: {}", discriminant)
                    )),
                }
            }
        }
    })
}
