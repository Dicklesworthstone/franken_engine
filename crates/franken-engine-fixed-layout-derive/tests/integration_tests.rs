use franken_engine_deterministic_derive::Deterministic;
use franken_engine_deterministic_trait::{FixedLayout, FixedLayoutError};
use franken_engine_fixed_layout_derive::FixedLayout;

#[derive(Debug, Clone, PartialEq, Eq, Deterministic, FixedLayout)]
struct Point {
    x: i32,
    y: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deterministic, FixedLayout)]
struct UnitStruct;

#[derive(Debug, Clone, PartialEq, Eq, Deterministic, FixedLayout)]
struct NewtypeWrapper(u64);

#[derive(Debug, Clone, PartialEq, Eq, Deterministic, FixedLayout)]
enum Status {
    Active,
    Inactive,
    Code(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Deterministic, FixedLayout)]
struct Nested {
    point: Point,
    status: Status,
    flag: bool,
}

#[test]
fn test_point_fixed_layout() {
    let point = Point { x: 42, y: -17 };

    // Check layout size
    assert_eq!(Point::LAYOUT_SIZE, 8); // 4 + 4 bytes

    // Test encode/decode round trip
    let mut buffer = vec![0u8; Point::LAYOUT_SIZE];
    point.encode_fixed(&mut buffer);

    let decoded = Point::decode_fixed(&buffer).unwrap();
    assert_eq!(point, decoded);
}

#[test]
fn test_unit_struct_fixed_layout() {
    let unit = UnitStruct;

    // Check layout size
    assert_eq!(UnitStruct::LAYOUT_SIZE, 0);

    // Test encode/decode round trip
    let mut buffer = vec![0u8; UnitStruct::LAYOUT_SIZE];
    unit.encode_fixed(&mut buffer);

    let decoded = UnitStruct::decode_fixed(&buffer).unwrap();
    assert_eq!(unit, decoded);
}

#[test]
fn test_newtype_wrapper_fixed_layout() {
    let wrapper = NewtypeWrapper(12345678901234567890);

    // Check layout size
    assert_eq!(NewtypeWrapper::LAYOUT_SIZE, 8); // u64 size

    // Test encode/decode round trip
    let mut buffer = vec![0u8; NewtypeWrapper::LAYOUT_SIZE];
    wrapper.encode_fixed(&mut buffer);

    let decoded = NewtypeWrapper::decode_fixed(&buffer).unwrap();
    assert_eq!(wrapper, decoded);
}

#[test]
fn test_enum_fixed_layout() {
    // Test unit variant
    let status_active = Status::Active;
    assert_eq!(Status::LAYOUT_SIZE, 9); // 1 discriminant + 8 for max variant size (simplified)

    let mut buffer = vec![0u8; Status::LAYOUT_SIZE];
    status_active.encode_fixed(&mut buffer);
    let decoded_active = Status::decode_fixed(&buffer).unwrap();
    assert_eq!(status_active, decoded_active);

    // Test variant with data
    let status_code = Status::Code(404);
    let mut buffer = vec![0u8; Status::LAYOUT_SIZE];
    status_code.encode_fixed(&mut buffer);
    let decoded_code = Status::decode_fixed(&buffer).unwrap();
    assert_eq!(status_code, decoded_code);
}

#[test]
fn test_nested_struct_fixed_layout() {
    let nested = Nested {
        point: Point { x: 100, y: 200 },
        status: Status::Code(500),
        flag: true,
    };

    // Check layout size: Point (8) + Status (9) + bool (1) = 18
    assert_eq!(Nested::LAYOUT_SIZE, 18);

    // Test encode/decode round trip
    let mut buffer = vec![0u8; Nested::LAYOUT_SIZE];
    nested.encode_fixed(&mut buffer);

    let decoded = Nested::decode_fixed(&buffer).unwrap();
    assert_eq!(nested, decoded);
}

#[test]
fn test_fixed_layout_determinism() {
    let point1 = Point { x: 42, y: -17 };
    let point2 = Point { x: 42, y: -17 };

    let mut buffer1 = vec![0u8; Point::LAYOUT_SIZE];
    let mut buffer2 = vec![0u8; Point::LAYOUT_SIZE];

    point1.encode_fixed(&mut buffer1);
    point2.encode_fixed(&mut buffer2);

    // Same values should produce identical encodings
    assert_eq!(buffer1, buffer2);
}

#[test]
fn test_buffer_size_validation() {
    let point = Point { x: 1, y: 2 };

    // Test encode with wrong buffer size. The closure captures `&mut small_buffer`,
    // which is not `UnwindSafe`; `AssertUnwindSafe` is correct here because we discard
    // the buffer after the expected panic.
    let mut small_buffer = vec![0u8; 4]; // Too small
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        point.encode_fixed(&mut small_buffer);
    }))
    .expect_err("Should panic with wrong buffer size");

    // Test decode with wrong buffer size
    let wrong_size_buffer = vec![0u8; 4]; // Too small
    let result = Point::decode_fixed(&wrong_size_buffer);
    assert!(matches!(
        result,
        Err(FixedLayoutError::InvalidBufferSize { .. })
    ));
}

#[test]
fn test_enum_invalid_discriminant() {
    let mut buffer = vec![0u8; Status::LAYOUT_SIZE];
    buffer[0] = 99; // Invalid discriminant

    let result = Status::decode_fixed(&buffer);
    assert!(matches!(result, Err(FixedLayoutError::InvalidData(_))));
}

#[test]
fn test_bool_encoding() {
    // Test true
    let mut buffer = vec![0u8; bool::LAYOUT_SIZE];
    true.encode_fixed(&mut buffer);
    assert_eq!(buffer, vec![1]);
    assert!(bool::decode_fixed(&buffer).unwrap());

    // Test false
    let mut buffer = vec![0u8; bool::LAYOUT_SIZE];
    false.encode_fixed(&mut buffer);
    assert_eq!(buffer, vec![0]);
    assert!(!bool::decode_fixed(&buffer).unwrap());

    // Test invalid bool value
    let invalid_buffer = vec![2];
    let result = bool::decode_fixed(&invalid_buffer);
    assert!(matches!(result, Err(FixedLayoutError::InvalidData(_))));
}

#[test]
fn test_array_fixed_layout() {
    let array: [u32; 4] = [1, 2, 3, 4];
    assert_eq!(<[u32; 4]>::LAYOUT_SIZE, 16); // 4 * 4 bytes

    let mut buffer = vec![0u8; <[u32; 4]>::LAYOUT_SIZE];
    array.encode_fixed(&mut buffer);

    let decoded = <[u32; 4]>::decode_fixed(&buffer).unwrap();
    assert_eq!(array, decoded);
}

#[test]
fn test_empty_array() {
    let array: [u8; 0] = [];
    assert_eq!(<[u8; 0]>::LAYOUT_SIZE, 0);

    let mut buffer = vec![0u8; <[u8; 0]>::LAYOUT_SIZE];
    array.encode_fixed(&mut buffer);

    let decoded = <[u8; 0]>::decode_fixed(&buffer).unwrap();
    assert_eq!(array, decoded);
}

#[test]
fn test_primitive_encodings() {
    // Test u32 big-endian encoding
    let value = 0x12345678u32;
    let mut buffer = vec![0u8; u32::LAYOUT_SIZE];
    value.encode_fixed(&mut buffer);
    assert_eq!(buffer, vec![0x12, 0x34, 0x56, 0x78]);

    let decoded = u32::decode_fixed(&buffer).unwrap();
    assert_eq!(value, decoded);

    // Test i32 big-endian encoding
    let negative_value = -1i32;
    let mut buffer = vec![0u8; i32::LAYOUT_SIZE];
    negative_value.encode_fixed(&mut buffer);
    assert_eq!(buffer, vec![0xFF, 0xFF, 0xFF, 0xFF]);

    let decoded = i32::decode_fixed(&buffer).unwrap();
    assert_eq!(negative_value, decoded);
}
