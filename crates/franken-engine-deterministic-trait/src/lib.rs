#![forbid(unsafe_code)]
//! Deterministic marker trait for franken-engine.
//!
//! This crate provides the core Deterministic trait and implementations for
//! standard library types that have deterministic behavior.
//!
//! Also provides the FixedLayout trait for types with fixed-byte canonical
//! encoding that composes with Deterministic for content hashing.

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

/// Marker trait indicating that a type has a fixed-byte canonical encoding.
///
/// Types implementing FixedLayout guarantee that:
/// 1. Their serialized representation has a fixed size (no variable-length fields)
/// 2. The encoding is canonical and deterministic
/// 3. They can be safely used in length-prefix-free content hashing
/// 4. The encoding layout is known at compile time
///
/// This trait composes with Deterministic - all FixedLayout types must also be
/// Deterministic. The derive macro enforces this constraint.
///
/// # Examples
///
/// Fixed layout types:
/// - Primitive integers: `u32`, `i64`
/// - Fixed-size arrays: `[u8; 32]`
/// - Structs with only fixed-layout fields: `struct Point { x: i32, y: i32 }`
///
/// NOT fixed layout:
/// - Variable-length types: `String`, `Vec<T>`
/// - Types with optional/variable fields
/// - Types with heap-allocated data
pub trait FixedLayout: Deterministic {
    /// Size in bytes of this type's canonical encoding.
    const LAYOUT_SIZE: usize;

    /// Encode this value into its canonical fixed-byte representation.
    fn encode_fixed(&self, buffer: &mut [u8]);

    /// Decode a value from its canonical fixed-byte representation.
    fn decode_fixed(buffer: &[u8]) -> Result<Self, FixedLayoutError>
    where
        Self: Sized;
}

/// Errors that can occur during FixedLayout operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixedLayoutError {
    /// Buffer size doesn't match expected LAYOUT_SIZE.
    InvalidBufferSize { expected: usize, actual: usize },
    /// Invalid data in buffer that can't be decoded.
    InvalidData(String),
}

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
// `?Sized` so smart pointers over unsized deterministic data (e.g. `Box<[u8]>`,
// `Arc<str>`) are themselves Deterministic. The derive macro's per-field bound
// check (see franken-engine-deterministic-derive) relies on these holding for
// boxed-slice fields such as `Box<[u8]>`.
impl<T: Deterministic + ?Sized> Deterministic for Box<T> {}
impl<T: Deterministic + ?Sized> Deterministic for std::rc::Rc<T> {}
impl<T: Deterministic + ?Sized> Deterministic for std::sync::Arc<T> {}

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

// FixedLayout implementations for primitive types
macro_rules! impl_fixed_layout_primitive {
    ($ty:ty, $size:expr) => {
        impl FixedLayout for $ty {
            const LAYOUT_SIZE: usize = $size;

            fn encode_fixed(&self, buffer: &mut [u8]) {
                if buffer.len() != Self::LAYOUT_SIZE {
                    panic!(
                        "Buffer size mismatch: expected {}, got {}",
                        Self::LAYOUT_SIZE,
                        buffer.len()
                    );
                }
                buffer.copy_from_slice(&self.to_be_bytes());
            }

            fn decode_fixed(buffer: &[u8]) -> Result<Self, FixedLayoutError> {
                if buffer.len() != Self::LAYOUT_SIZE {
                    return Err(FixedLayoutError::InvalidBufferSize {
                        expected: Self::LAYOUT_SIZE,
                        actual: buffer.len(),
                    });
                }
                let mut bytes = [0u8; $size];
                bytes.copy_from_slice(buffer);
                Ok(Self::from_be_bytes(bytes))
            }
        }
    };
}

impl_fixed_layout_primitive!(u8, 1);
impl_fixed_layout_primitive!(u16, 2);
impl_fixed_layout_primitive!(u32, 4);
impl_fixed_layout_primitive!(u64, 8);
impl_fixed_layout_primitive!(u128, 16);

impl_fixed_layout_primitive!(i8, 1);
impl_fixed_layout_primitive!(i16, 2);
impl_fixed_layout_primitive!(i32, 4);
impl_fixed_layout_primitive!(i64, 8);
impl_fixed_layout_primitive!(i128, 16);

impl FixedLayout for bool {
    const LAYOUT_SIZE: usize = 1;

    fn encode_fixed(&self, buffer: &mut [u8]) {
        if buffer.len() != Self::LAYOUT_SIZE {
            panic!("Buffer size mismatch");
        }
        buffer[0] = if *self { 1 } else { 0 };
    }

    fn decode_fixed(buffer: &[u8]) -> Result<Self, FixedLayoutError> {
        if buffer.len() != Self::LAYOUT_SIZE {
            return Err(FixedLayoutError::InvalidBufferSize {
                expected: Self::LAYOUT_SIZE,
                actual: buffer.len(),
            });
        }
        match buffer[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(FixedLayoutError::InvalidData(
                "Invalid bool value".to_string(),
            )),
        }
    }
}

impl FixedLayout for () {
    const LAYOUT_SIZE: usize = 0;

    fn encode_fixed(&self, buffer: &mut [u8]) {
        if !buffer.is_empty() {
            panic!("Buffer size mismatch for unit type");
        }
    }

    fn decode_fixed(buffer: &[u8]) -> Result<Self, FixedLayoutError> {
        if !buffer.is_empty() {
            return Err(FixedLayoutError::InvalidBufferSize {
                expected: 0,
                actual: buffer.len(),
            });
        }
        Ok(())
    }
}

// FixedLayout for fixed-size arrays
impl<T: FixedLayout, const N: usize> FixedLayout for [T; N] {
    const LAYOUT_SIZE: usize = N * T::LAYOUT_SIZE;

    fn encode_fixed(&self, buffer: &mut [u8]) {
        if buffer.len() != Self::LAYOUT_SIZE {
            panic!("Buffer size mismatch");
        }
        for (i, item) in self.iter().enumerate() {
            let start = i * T::LAYOUT_SIZE;
            let end = start + T::LAYOUT_SIZE;
            item.encode_fixed(&mut buffer[start..end]);
        }
    }

    fn decode_fixed(buffer: &[u8]) -> Result<Self, FixedLayoutError> {
        if buffer.len() != Self::LAYOUT_SIZE {
            return Err(FixedLayoutError::InvalidBufferSize {
                expected: Self::LAYOUT_SIZE,
                actual: buffer.len(),
            });
        }

        // For arrays, collect into a Vec first then try_into array
        let mut items = Vec::with_capacity(N);
        for i in 0..N {
            let start = i * T::LAYOUT_SIZE;
            let end = start + T::LAYOUT_SIZE;
            let item = T::decode_fixed(&buffer[start..end])?;
            items.push(item);
        }

        // Convert Vec to array
        items.try_into().map_err(|_| {
            FixedLayoutError::InvalidData("Failed to convert Vec to array".to_string())
        })
    }
}
