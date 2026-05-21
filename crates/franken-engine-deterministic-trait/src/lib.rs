#![forbid(unsafe_code)]
//! Deterministic marker trait for franken-engine.
//!
//! This crate provides the core Deterministic trait and implementations for
//! standard library types that have deterministic behavior.

/// Marker trait indicating that a type has deterministic serialization behavior.
///
/// Types implementing Deterministic guarantee that:
/// 1. Their serialized representation is always the same for equivalent values
/// 2. They don't contain floating point or other non-deterministic data
/// 3. They can safely participate in content hashing for reproducible builds
///
/// This trait is automatically implemented by the derive macro in the
/// `franken-engine-deterministic-derive` crate.
pub trait Deterministic {}

// Implement Deterministic for common deterministic types
impl Deterministic for i8 {}
impl Deterministic for i16 {}
impl Deterministic for i32 {}
impl Deterministic for i64 {}
impl Deterministic for i128 {}
impl Deterministic for isize {}

impl Deterministic for u8 {}
impl Deterministic for u16 {}
impl Deterministic for u32 {}
impl Deterministic for u64 {}
impl Deterministic for u128 {}
impl Deterministic for usize {}

impl Deterministic for bool {}
impl Deterministic for char {}
impl Deterministic for str {}
impl Deterministic for String {}

impl<T: Deterministic> Deterministic for Option<T> {}
impl<T: Deterministic, E: Deterministic> Deterministic for Result<T, E> {}
impl<T: Deterministic> Deterministic for Vec<T> {}
impl<T: Deterministic> Deterministic for [T] {}
impl<T: Deterministic, const N: usize> Deterministic for [T; N] {}
impl<T: Deterministic> Deterministic for Box<T> {}
impl<T: Deterministic> Deterministic for std::rc::Rc<T> {}
impl<T: Deterministic> Deterministic for std::sync::Arc<T> {}

// BTreeMap and BTreeSet are deterministic (ordered)
impl<K: Deterministic, V: Deterministic> Deterministic for std::collections::BTreeMap<K, V> {}
impl<T: Deterministic> Deterministic for std::collections::BTreeSet<T> {}

// Tuples up to reasonable arity
impl Deterministic for () {}
impl<A: Deterministic> Deterministic for (A,) {}
impl<A: Deterministic, B: Deterministic> Deterministic for (A, B) {}
impl<A: Deterministic, B: Deterministic, C: Deterministic> Deterministic for (A, B, C) {}
impl<A: Deterministic, B: Deterministic, C: Deterministic, D: Deterministic> Deterministic
    for (A, B, C, D)
{
}
impl<A: Deterministic, B: Deterministic, C: Deterministic, D: Deterministic, E: Deterministic>
    Deterministic for (A, B, C, D, E)
{
}
