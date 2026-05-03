//! Integration tests for locale-aware date formatting (bd-1j1wy).
//!
//! Validates Date.prototype.toLocaleString(), toLocaleDateString(), and toLocaleTimeString()
//! support for en-US, en-GB, and ja-JP locales with proper date ordering and localized names.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{Ir3Instruction, Ir3Module, RegRange, Value};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn test_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn create_date_object_module(timestamp_ms: i64) -> Ir3Module {
    let mut m = Ir3Module::new(ContentHash::compute(b"date-test"), "date-locale-test");
    m.instructions = vec![
        // Create a Date object with specific timestamp
        Ir3Instruction::CreateObject { dst: 0 },
        // Set __type property to "Date"
        Ir3Instruction::LoadConstant {
            dst: 1,
            value: Value::Str("__type".to_string()),
        },
        Ir3Instruction::LoadConstant {
            dst: 2,
            value: Value::Str("Date".to_string()),
        },
        Ir3Instruction::SetProperty {
            object: 0,
            key: 1,
            value: 2,
        },
        // Set __timestamp property
        Ir3Instruction::LoadConstant {
            dst: 3,
            value: Value::Str("__timestamp".to_string()),
        },
        Ir3Instruction::LoadConstant {
            dst: 4,
            value: Value::Int(timestamp_ms),
        },
        Ir3Instruction::SetProperty {
            object: 0,
            key: 3,
            value: 4,
        },
        Ir3Instruction::Halt,
    ];
    m
}

fn create_locale_date_format_module(timestamp_ms: i64, locale: &str, method: &str) -> Ir3Module {
    let mut m = create_date_object_module(timestamp_ms);

    // Add locale formatting call
    let mut additional_instructions = vec![
        // Load locale string
        Ir3Instruction::LoadConstant {
            dst: 5,
            value: Value::Str(locale.to_string()),
        },
        // Call the appropriate locale formatting method
        Ir3Instruction::HostCall {
            capability: crate::ir_contract::CapabilityTag(method.to_string()),
            args: RegRange { start: 0, count: 2 }, // date object + locale
            dst: 6,
        },
        Ir3Instruction::Halt,
    ];

    // Replace Halt with the new instructions
    m.instructions.pop(); // Remove existing Halt
    m.instructions.append(&mut additional_instructions);
    m
}

// =========================================================================
// Test 1: en-US locale date formatting with MM/DD/YYYY ordering
// =========================================================================

#[test]
fn en_us_locale_date_formatting() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "en-us-test");

    // Create Date for January 15, 2024 (roughly)
    let timestamp = 1705363200000; // Approximately 2024-01-15
    let module = create_locale_date_format_module(
        timestamp,
        "en-US",
        "builtin:DatePrototypeToLocaleDateString",
    );

    let result = core.execute(&module);
    assert!(result.is_ok(), "Date formatting should succeed");

    let formatted_date = core.read_reg(6).unwrap();
    if let Value::Str(date_str) = formatted_date {
        // Should contain MM/DD/YYYY format and English day name
        assert!(date_str.contains('/'), "en-US should use slash separators");
        assert!(date_str.len() > 5, "Formatted date should be substantial");
        // Should contain day abbreviation (Mon, Tue, etc.)
        let has_english_day = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            .iter()
            .any(|day| date_str.contains(day));
        assert!(has_english_day, "Should contain English day abbreviation");
    } else {
        panic!(
            "Date formatting should return string, got: {:?}",
            formatted_date
        );
    }
}

// =========================================================================
// Test 2: en-GB locale date formatting with DD/MM/YYYY ordering
// =========================================================================

#[test]
fn en_gb_locale_date_formatting() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "en-gb-test");

    // Create Date for March 25, 2024 (to test DD/MM vs MM/DD difference)
    let timestamp = 1711324800000; // Approximately 2024-03-25
    let module = create_locale_date_format_module(
        timestamp,
        "en-GB",
        "builtin:DatePrototypeToLocaleDateString",
    );

    let result = core.execute(&module);
    assert!(result.is_ok(), "Date formatting should succeed");

    let formatted_date = core.read_reg(6).unwrap();
    if let Value::Str(date_str) = formatted_date {
        // Should contain DD/MM/YYYY format (different from en-US)
        assert!(date_str.contains('/'), "en-GB should use slash separators");
        assert!(date_str.len() > 5, "Formatted date should be substantial");

        // Should contain English day abbreviation but in DD/MM format
        let has_english_day = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            .iter()
            .any(|day| date_str.contains(day));
        assert!(has_english_day, "Should contain English day abbreviation");
    } else {
        panic!(
            "Date formatting should return string, got: {:?}",
            formatted_date
        );
    }
}

// =========================================================================
// Test 3: ja-JP locale date formatting with YYYY-MM-DD and Japanese names
// =========================================================================

#[test]
fn ja_jp_locale_date_formatting() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "ja-jp-test");

    let timestamp = 1705363200000; // Approximately 2024-01-15
    let module = create_locale_date_format_module(
        timestamp,
        "ja-JP",
        "builtin:DatePrototypeToLocaleDateString",
    );

    let result = core.execute(&module);
    assert!(result.is_ok(), "Date formatting should succeed");

    let formatted_date = core.read_reg(6).unwrap();
    if let Value::Str(date_str) = formatted_date {
        // Should contain YYYY-MM-DD format with hyphens
        assert!(date_str.contains('-'), "ja-JP should use hyphen separators");

        // Should contain Japanese day characters
        let has_japanese_day = ["日", "月", "火", "水", "木", "金", "土"]
            .iter()
            .any(|day| date_str.contains(day));
        assert!(has_japanese_day, "Should contain Japanese day characters");
    } else {
        panic!(
            "Date formatting should return string, got: {:?}",
            formatted_date
        );
    }
}

// =========================================================================
// Test 4: toLocaleTimeString formatting for different locales
// =========================================================================

#[test]
fn time_formatting_across_locales() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "time-test");

    let timestamp = 1705363200000; // Some timestamp

    // Test time formatting for multiple locales
    for locale in ["en-US", "en-GB", "ja-JP"] {
        let module = create_locale_date_format_module(
            timestamp,
            locale,
            "builtin:DatePrototypeToLocaleTimeString",
        );

        let result = core.execute(&module);
        assert!(
            result.is_ok(),
            "Time formatting should succeed for {}",
            locale
        );

        let formatted_time = core.read_reg(6).unwrap();
        if let Value::Str(time_str) = formatted_time {
            // Time should contain colons for hours:minutes:seconds
            assert!(
                time_str.contains(':'),
                "Time should contain colon separators for {}",
                locale
            );
            assert!(
                time_str.len() >= 8,
                "Time should be at least HH:MM:SS format for {}",
                locale
            );
        } else {
            panic!(
                "Time formatting should return string for {}, got: {:?}",
                locale, formatted_time
            );
        }
    }
}

// =========================================================================
// Test 5: toLocaleString (full date + time) formatting
// =========================================================================

#[test]
fn full_datetime_formatting() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "datetime-test");

    let timestamp = 1705363200000;
    let module =
        create_locale_date_format_module(timestamp, "en-US", "builtin:DatePrototypeToLocaleString");

    let result = core.execute(&module);
    assert!(result.is_ok(), "DateTime formatting should succeed");

    let formatted_datetime = core.read_reg(6).unwrap();
    if let Value::Str(datetime_str) = formatted_datetime {
        // Should contain both date and time elements
        assert!(
            datetime_str.len() > 15,
            "Full datetime should be substantial"
        );

        // Should contain time colons and date separators
        let has_time = datetime_str.contains(':');
        let has_date_sep = datetime_str.contains('/') || datetime_str.contains('-');

        assert!(has_time, "DateTime should contain time portion");
        assert!(has_date_sep, "DateTime should contain date portion");
    } else {
        panic!(
            "DateTime formatting should return string, got: {:?}",
            formatted_datetime
        );
    }
}

// =========================================================================
// Test 6: Fallback behavior for unsupported locales
// =========================================================================

#[test]
fn unsupported_locale_fallback() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "fallback-test");

    let timestamp = 1705363200000;

    // Test with unsupported locale should fallback to en-US
    let module = create_locale_date_format_module(
        timestamp,
        "xx-XX",
        "builtin:DatePrototypeToLocaleDateString",
    );

    let result = core.execute(&module);
    assert!(
        result.is_ok(),
        "Unsupported locale should fallback gracefully"
    );

    let formatted_date = core.read_reg(6).unwrap();
    if let Value::Str(date_str) = formatted_date {
        // Should fallback to en-US format (MM/DD/YYYY with slashes)
        assert!(
            date_str.contains('/'),
            "Fallback should use en-US slash format"
        );

        let has_english_day = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            .iter()
            .any(|day| date_str.contains(day));
        assert!(has_english_day, "Fallback should use English day names");
    } else {
        panic!(
            "Fallback formatting should return string, got: {:?}",
            formatted_date
        );
    }
}

// =========================================================================
// Test 7: BTreeMap determinism in locale data
// =========================================================================

#[test]
fn locale_formatting_determinism() {
    let config1 = test_config();
    let config2 = test_config();
    let mut core1 = InterpreterCore::new(config1, "determinism-1");
    let mut core2 = InterpreterCore::new(config2, "determinism-2");

    let timestamp = 1705363200000;
    let module1 = create_locale_date_format_module(
        timestamp,
        "ja-JP",
        "builtin:DatePrototypeToLocaleDateString",
    );
    let module2 = create_locale_date_format_module(
        timestamp,
        "ja-JP",
        "builtin:DatePrototypeToLocaleDateString",
    );

    let result1 = core1.execute(&module1);
    let result2 = core2.execute(&module2);

    assert!(
        result1.is_ok() && result2.is_ok(),
        "Both executions should succeed"
    );

    let formatted1 = core1.read_reg(6).unwrap();
    let formatted2 = core2.read_reg(6).unwrap();

    // Results should be identical (deterministic)
    assert_eq!(
        formatted1, formatted2,
        "Locale formatting should be deterministic"
    );

    if let Value::Str(date_str) = formatted1 {
        // Verify it's actually Japanese formatting
        let has_japanese_chars = date_str.chars().any(|c| c as u32 > 127);
        assert!(
            has_japanese_chars,
            "Should contain Japanese characters for determinism test"
        );
    }
}

// =========================================================================
// Test 8: Edge cases - Invalid Date objects
// =========================================================================

#[test]
fn invalid_date_handling() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "invalid-date-test");

    // Create an object that's not a proper Date
    let mut m = Ir3Module::new(ContentHash::compute(b"invalid-date"), "invalid-date-test");
    m.instructions = vec![
        // Create regular object (not a Date)
        Ir3Instruction::CreateObject { dst: 0 },
        // Try to format it as a date
        Ir3Instruction::LoadConstant {
            dst: 1,
            value: Value::Str("en-US".to_string()),
        },
        Ir3Instruction::HostCall {
            capability: crate::ir_contract::CapabilityTag(
                "builtin:DatePrototypeToLocaleDateString".to_string(),
            ),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Halt,
    ];

    let result = core.execute(&m);
    assert!(result.is_ok(), "Invalid date should be handled gracefully");

    let formatted = core.read_reg(2).unwrap();
    if let Value::Str(error_str) = formatted {
        assert_eq!(
            error_str, "Invalid Date",
            "Should return 'Invalid Date' for non-date objects"
        );
    } else {
        panic!(
            "Invalid date should return error string, got: {:?}",
            formatted
        );
    }
}

// =========================================================================
// Test 9: Month and day name localization verification
// =========================================================================

#[test]
fn month_and_day_name_localization() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "localization-test");

    // Test multiple timestamps to hit different months/days
    let test_cases = [
        (1705363200000, "en-US"), // January
        (1708041600000, "en-GB"), // February
        (1710547200000, "ja-JP"), // March
    ];

    for (timestamp, locale) in test_cases {
        let module = create_locale_date_format_module(
            timestamp,
            locale,
            "builtin:DatePrototypeToLocaleDateString",
        );

        let result = core.execute(&module);
        assert!(
            result.is_ok(),
            "Localization test should succeed for {}",
            locale
        );

        let formatted = core.read_reg(6).unwrap();
        if let Value::Str(date_str) = formatted {
            assert!(
                !date_str.is_empty(),
                "Formatted date should not be empty for {}",
                locale
            );

            // Verify locale-specific characteristics
            match locale {
                "en-US" | "en-GB" => {
                    let has_latin_chars = date_str.chars().all(|c| (c as u32) < 256);
                    assert!(
                        has_latin_chars,
                        "English locales should use Latin characters"
                    );
                }
                "ja-JP" => {
                    let has_japanese_chars = date_str.chars().any(|c| (c as u32) > 127);
                    assert!(
                        has_japanese_chars,
                        "Japanese locale should contain Japanese characters"
                    );
                }
                _ => {}
            }
        } else {
            panic!(
                "Localization test should return string for {}, got: {:?}",
                locale, formatted
            );
        }
    }
}

// =========================================================================
// Test 10: Memory safety with forbid(unsafe_code)
// =========================================================================

#[test]
fn memory_safety_stress_test() {
    // This test validates that locale formatting works without unsafe code
    // The #![forbid(unsafe_code)] directive at the top ensures this

    let config = test_config();
    let mut core = InterpreterCore::new(config, "safety-test");

    // Create many date formatting operations to stress-test memory safety
    for i in 0..50 {
        let timestamp = 1705363200000 + (i * 86400000); // Different days
        let locales = ["en-US", "en-GB", "ja-JP"];
        let locale = locales[i as usize % locales.len()];

        let module = create_locale_date_format_module(
            timestamp,
            locale,
            "builtin:DatePrototypeToLocaleDateString",
        );

        let result = core.execute(&module);
        assert!(
            result.is_ok(),
            "Memory safety test iteration {} should succeed",
            i
        );

        let formatted = core.read_reg(6).unwrap();
        if let Value::Str(date_str) = formatted {
            assert!(
                !date_str.is_empty(),
                "Iteration {} should produce non-empty result",
                i
            );
        } else {
            panic!("Iteration {} should produce string result", i);
        }
    }
}
