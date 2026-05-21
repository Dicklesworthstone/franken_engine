use franken_engine_deterministic_derive::Deterministic;
use franken_engine_deterministic_trait::Deterministic;

// Basic struct test
#[derive(Deterministic)]
struct SimpleStruct {
    x: i32,
    y: u64,
    name: String,
}

// Enum test
#[derive(Deterministic)]
enum SimpleEnum {
    Unit,
    Tuple(i32, String),
    Struct { x: i32, y: i32 },
}

// Nested struct test
#[derive(Deterministic)]
struct NestedStruct {
    inner: SimpleStruct,
    values: Vec<i32>,
}

// Generic struct test
#[derive(Deterministic)]
struct GenericStruct<T: Deterministic> {
    value: T,
    optional: Option<T>,
}

// Test with BTreeMap (deterministic collection)
#[derive(Deterministic)]
struct WithBTreeMap {
    map: std::collections::BTreeMap<String, i32>,
    set: std::collections::BTreeSet<i32>,
}

// Test with arrays and slices
#[derive(Deterministic)]
struct WithArrays {
    fixed_array: [i32; 10],
    boxed_slice: Box<[u8]>,
}

// Test with tuples
#[derive(Deterministic)]
struct WithTuples {
    unit: (),
    pair: (i32, String),
    triple: (i32, i32, i32),
}

#[test]
fn test_deterministic_trait_implemented() {
    // This test just verifies that the derive macro successfully generates
    // implementations of the Deterministic trait. If compilation succeeds,
    // the test passes.
    fn is_deterministic<T: Deterministic>() {}

    is_deterministic::<SimpleStruct>();
    is_deterministic::<SimpleEnum>();
    is_deterministic::<NestedStruct>();
    is_deterministic::<GenericStruct<i32>>();
    is_deterministic::<WithBTreeMap>();
    is_deterministic::<WithArrays>();
    is_deterministic::<WithTuples>();
}

#[test]
fn test_generic_deterministic() {
    fn is_deterministic<T: Deterministic>() {}

    // Test that generic types work correctly
    is_deterministic::<GenericStruct<i32>>();
    is_deterministic::<GenericStruct<String>>();
    is_deterministic::<GenericStruct<Vec<u8>>>();
}

#[test]
fn test_builtin_deterministic_types() {
    fn is_deterministic<T: Deterministic>() {}

    // Test built-in deterministic implementations
    is_deterministic::<i32>();
    is_deterministic::<u64>();
    is_deterministic::<String>();
    is_deterministic::<bool>();
    is_deterministic::<char>();
    is_deterministic::<Option<i32>>();
    is_deterministic::<Result<i32, String>>();
    is_deterministic::<Vec<i32>>();
    is_deterministic::<std::collections::BTreeMap<String, i32>>();
    is_deterministic::<std::collections::BTreeSet<i32>>();
}
