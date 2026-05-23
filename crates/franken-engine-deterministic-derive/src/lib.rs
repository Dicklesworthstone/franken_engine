#![forbid(unsafe_code)]
//! Derive macro for the Deterministic marker trait.
//!
//! This crate provides a `#[derive(Deterministic)]` proc macro that implements
//! the Deterministic marker trait for structs and enums. The trait indicates
//! that a type has deterministic serialization behavior and can safely participate
//! in content hashing.
//!
//! # Rules
//!
//! A type is considered Deterministic if:
//! - All its fields are Deterministic (recursive check)
//! - It doesn't contain blacklisted non-deterministic types
//!
//! # Blacklisted Types
//!
//! The following types are explicitly rejected:
//! - `f64`, `f32` (floating point has non-deterministic edge cases)
//! - `HashMap`, `HashSet` (iteration order is non-deterministic)
//! - `*const T`, `*mut T` (pointer values are non-deterministic)
//!
//! # Examples
//!
//! ```rust
//! use franken_engine_deterministic_trait::Deterministic;
//! use franken_engine_deterministic_derive::Deterministic;
//!
//! #[derive(Deterministic)]
//! struct Point {
//!     x: i32,
//!     y: i32,
//! }
//!
//! #[derive(Deterministic)]
//! enum Direction {
//!     Up,
//!     Down,
//!     Left(i32),
//!     Right(i32),
//! }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Field, Fields, Type, TypePath, parse_macro_input};

/// Derive macro for the Deterministic marker trait.
///
/// # Panics
///
/// The derive macro will cause a compile-time error if:
/// - Any field contains a blacklisted non-deterministic type
/// - Any field's type doesn't implement Deterministic
#[proc_macro_derive(Deterministic)]
pub fn derive_deterministic(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match expand_deterministic(&input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

fn expand_deterministic(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;

    // Check all fields in the type
    match &input.data {
        Data::Struct(data_struct) => {
            check_fields(&data_struct.fields)?;
        }
        Data::Enum(data_enum) => {
            for variant in &data_enum.variants {
                check_fields(&variant.fields)?;
            }
        }
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "Deterministic cannot be derived for union types",
            ));
        }
    }

    // Generate the implementation
    let expanded = quote! {
        impl ::franken_engine_deterministic_trait::Deterministic for #name {}
    };

    Ok(expanded)
}

fn check_fields(fields: &Fields) -> syn::Result<()> {
    match fields {
        Fields::Named(fields) => {
            for field in &fields.named {
                check_field_type(field)?;
            }
        }
        Fields::Unnamed(fields) => {
            for field in &fields.unnamed {
                check_field_type(field)?;
            }
        }
        Fields::Unit => {
            // Unit structs/variants are always deterministic
        }
    }
    Ok(())
}

fn check_field_type(field: &Field) -> syn::Result<()> {
    check_type_deterministic(&field.ty)
}

fn check_type_deterministic(ty: &Type) -> syn::Result<()> {
    match ty {
        Type::Path(type_path) => {
            check_path_deterministic(type_path)?;
        }
        Type::Ptr(_) => {
            return Err(syn::Error::new_spanned(
                ty,
                "Raw pointers (*const T, *mut T) are non-deterministic and cannot be used in Deterministic types",
            ));
        }
        Type::Reference(type_ref) => {
            // References are OK, but check the referenced type
            check_type_deterministic(&type_ref.elem)?;
        }
        Type::Array(type_array) => {
            // Arrays are OK if their element type is deterministic
            check_type_deterministic(&type_array.elem)?;
        }
        Type::Slice(type_slice) => {
            // Slices are OK if their element type is deterministic
            check_type_deterministic(&type_slice.elem)?;
        }
        Type::Tuple(type_tuple) => {
            // Tuples are OK if all element types are deterministic
            for elem in &type_tuple.elems {
                check_type_deterministic(elem)?;
            }
        }
        _ => {
            // Other types (function pointers, trait objects, etc.) are conservatively rejected
            return Err(syn::Error::new_spanned(
                ty,
                "This type cannot be verified as deterministic",
            ));
        }
    }
    Ok(())
}

fn check_path_deterministic(type_path: &TypePath) -> syn::Result<()> {
    let path_str = quote!(#type_path).to_string();

    // Check for blacklisted types
    let blacklisted_types = [
        "f32",
        "f64",
        "HashMap",
        "HashSet",
        "std::collections::HashMap",
        "std::collections::HashSet",
        "::std::collections::HashMap",
        "::std::collections::HashSet",
    ];

    for blacklisted in &blacklisted_types {
        if path_str.contains(blacklisted) {
            return Err(syn::Error::new_spanned(
                type_path,
                format!(
                    "Type '{}' is non-deterministic and cannot be used in Deterministic types. \
                     Use BTreeMap/BTreeSet for collections or fixed-point arithmetic for numeric types.",
                    blacklisted
                ),
            ));
        }
    }

    // For generic types, check type arguments
    if let Some(last_segment) = type_path.path.segments.last()
        && let syn::PathArguments::AngleBracketed(args) = &last_segment.arguments
    {
        for arg in &args.args {
            if let syn::GenericArgument::Type(ty) = arg {
                check_type_deterministic(ty)?;
            }
        }
    }

    Ok(())
}
