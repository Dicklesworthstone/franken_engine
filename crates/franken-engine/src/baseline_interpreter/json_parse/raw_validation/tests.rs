use super::*;

fn core() -> InterpreterCore {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    InterpreterCore::new(config, "raw-json-lexical-validation")
}

fn scan(units: impl IntoIterator<Item = u16>) -> bool {
    let mut scanner = RawScanner::default();
    for unit in units {
        if !scanner.feed(unit) {
            return false;
        }
    }
    scanner.complete()
}

fn assert_released(core: &InterpreterCore, inherited: u64) {
    assert_eq!(core.json_parse_temporary_bytes, inherited);
    assert!(core.pending_exception.is_none());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn scanner_recognizes_only_complete_unpadded_primitive_tokens() {
    let accepted = [
        "null", "true", "false", "0", "-0", "1", "-123", "0.0", "-0.10",
        "12.3400e+005", "0E-0", "1e400", "1e999999999999999999999",
        r#""""#, r#""a\"b\\c\/d\b\f\n\r\t\u0000\uD800""#,
        "\"日😀\u{2028}\u{2029}\"",
    ];
    for text in accepted {
        assert!(scan(text.encode_utf16()), "{text:?}");
    }
    let rejected = [
        "", " ", " null", "null ", "true\n", "false\t", "0\r", "\u{feff}0",
        "[]", "{}", "[0]", "{\"x\":1}", "undefined", "NaN", "Infinity", "-Infinity",
        "+0", "00", "-01", ".5", "1.", "1.e0", "1e", "1e+", "1e-", "1e+-1",
        "1_000", "0x10", "0b1", "0o1", "tru", "TRUE", "nul", "nullnull",
        "true false", "1 2", "\"x\"\"y\"", "\"open", "\"x\\", "\"\n\"",
        r#""\x41""#, r#""\v""#, r#""\0""#, r#""\u123""#, r#""\u12xz""#,
    ];
    for text in rejected {
        assert!(!scan(text.encode_utf16()), "{text:?}");
    }
    let mut scanner = RawScanner::default();
    assert!(!scanner.feed(u16::from(b'[')));
    assert!(!scanner.feed(u16::from(b'0')));
    assert!(!scanner.complete(), "a rejected scanner must not restart");
}

#[test]
fn scanner_preserves_every_literal_unit_and_only_json_escapes() {
    for unit in 0..=u16::MAX {
        assert_eq!(
            scan([0x22, unit, 0x22]),
            unit >= 0x20 && unit != 0x22 && unit != 0x5c,
            "literal unit {unit:#x}"
        );
        assert_eq!(
            scan([0x22, 0x5c, unit, 0x22]),
            matches!(unit, 0x22 | 0x2f | 0x5c | 0x62 | 0x66 | 0x6e | 0x72 | 0x74),
            "escape unit {unit:#x}"
        );
        for position in 0..4 {
            let mut escaped = [0x22, 0x5c, 0x75, 0x30, 0x30, 0x30, 0x30, 0x22];
            escaped[3 + position] = unit;
            assert_eq!(
                scan(escaped),
                matches!(unit, 0x30..=0x39 | 0x41..=0x46 | 0x61..=0x66),
                "hex position {position}, unit {unit:#x}"
            );
        }
    }
}

#[test]
fn scanner_state_survives_every_split_of_literals_numbers_and_escapes() {
    for text in ["false", "-123.456E-078", r#""a\uD800\n\"b""#, "\"😀日\""] {
        let units: Vec<_> = text.encode_utf16().collect();
        for first in 0..=units.len() {
            for second in first..=units.len() {
                let mut scanner = RawScanner::default();
                for chunk in [&units[..first], &units[first..second], &units[second..]] {
                    for &unit in chunk {
                        assert!(scanner.feed(unit), "{text:?}, splits {first}/{second}");
                    }
                }
                assert!(scanner.complete());
            }
        }
    }
}

#[test]
fn scanner_number_acceptance_agrees_with_the_original_native_json_parser() {
    for sign in ["", "-", "+"] {
        for integer in ["0", "1", "01", "999"] {
            for fraction in ["", ".0", ".", "..5"] {
                for exponent in ["", "e0", "E-1", "e+"] {
                    let text = format!("{sign}{integer}{fraction}{exponent}");
                    let units: Vec<u16> = text.encode_utf16().collect();
                    let mut core = core();
                    let original = core.json_parse_document(&units);
                    assert_eq!(scan(units), original.is_ok(), "{text:?}");
                    if let Err(error) = original {
                        assert!(matches!(error, InterpreterError::UncaughtException { .. }));
                    }
                    assert_eq!(core.json_parse_temporary_bytes, 0);
                }
            }
        }
    }
}

#[test]
fn flat_and_exact_validation_need_no_temporary_memory_or_heap_objects() {
    let mut core = core();
    core.json_reserve_temporary(77).unwrap();
    core.config.max_total_memory_bytes = core.estimated_memory_bytes();
    let before = core.estimated_memory_bytes();
    let heap_len = core.heap.len();
    let inputs = [
        JsString::from(format!("1{}e999999999999999999", "0".repeat(65_536))),
        JsString::from(format!("\"{}\"", "aé日😀\\uD800".repeat(4096))),
        JsString::from_code_units(&[0x22, 0xd800, 0x61, 0xdc00, 0x22]),
    ];
    for input in inputs {
        assert!(input.unjoined_concat_children().is_none());
        assert!(core.json_raw_text_is_valid(&input).unwrap());
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(core.heap.len(), heap_len);
        assert_released(&core, 77);
    }
    core.json_release_temporary(77);
    assert_released(&core, 0);
}

#[test]
fn rope_validation_keeps_shared_backing_and_state_across_escape_boundaries() {
    let cases = [
        (format!("\"{}\\u", "a".repeat(1024)), "D800\"".to_string()),
        (format!("\"{}\\", "é日😀".repeat(256)), "\"tail\"".to_string()),
        (format!("1{}.", "0".repeat(1024)), "25e+9999".to_string()),
        (format!("1{}e-", "0".repeat(1024)), "123".to_string()),
        (format!("\"{}\\u", "a".repeat(1024)), "D80x\"".to_string()),
        (format!("1{}e-", "0".repeat(1024)), String::new()),
    ];
    let mut core = core();
    for (left, right) in cases {
        let expected = scan(format!("{left}{right}").encode_utf16());
        let text = JsString::from(left).concat(&JsString::from(right));
        // Empty concatenation is legitimately flat.
        let was_rope = text.unjoined_concat_children().is_some();
        assert_eq!(core.json_raw_text_is_valid(&text).unwrap(), expected);
        assert_eq!(text.unjoined_concat_children().is_some(), was_rope);
        assert_released(&core, 0);
        let _ = text.as_str();
        assert_eq!(core.json_raw_text_is_valid(&text).unwrap(), expected);
        assert_released(&core, 0);
    }
}

fn deep_text() -> JsString {
    let mut text = JsString::from(format!("\"{}", "x".repeat(1024)));
    let leaf = JsString::from("x".repeat(1024));
    for _ in 0..512 {
        text = text.concat(&leaf);
    }
    text.concat(&JsString::from("\""))
}

#[test]
fn deep_frontier_refusal_keeps_inherited_scratch_and_allows_retry() {
    let text = deep_text();
    for headroom in [0, 127, 128, 255, 256, 511, 512, 1024] {
        let mut core = core();
        core.json_reserve_temporary(77).unwrap();
        let max = core.config.max_total_memory_bytes;
        let before = core.estimated_memory_bytes();
        let heap_len = core.heap.len();
        core.config.max_total_memory_bytes = before + headroom;
        assert!(matches!(
            core.json_raw_text_is_valid(&text),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(text.unjoined_concat_children().is_some());
        assert_eq!(core.heap.len(), heap_len);
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_released(&core, 77);
        core.config.max_total_memory_bytes = max;
        assert!(core.json_raw_text_is_valid(&text).unwrap());
        assert!(text.unjoined_concat_children().is_some());
        core.json_release_temporary(77);
        assert_released(&core, 0);
    }
}

#[test]
fn cancellation_and_work_refusal_bound_both_leaf_and_deep_structural_scans() {
    for text in [deep_text(), JsString::from(format!("\"{}\"", "a".repeat(4096)))] {
        let mut core = core();
        core.json_reserve_temporary(77).unwrap();
        let before = core.estimated_memory_bytes();
        let token = CancellationToken::new();
        token.cancel();
        core.config.cancellation_token = Some(token);
        assert_eq!(
            core.json_raw_text_is_valid(&text),
            Err(InterpreterError::Cancelled)
        );
        assert_released(&core, 77);
        core.config.cancellation_token = None;
        core.config.instruction_budget = core.instructions_executed + 1;
        assert!(matches!(
            core.json_raw_text_is_valid(&text),
            Err(InterpreterError::BudgetExhausted { .. })
        ));
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_released(&core, 77);
        core.json_release_temporary(77);
        assert_released(&core, 0);
    }
}

#[test]
fn raw_builtin_keeps_original_spelling_brand_and_secret_provenance() {
    let text = JsString::from(format!("1{}", "2".repeat(2048)))
        .concat(&JsString::from(".3400e+99999"));
    assert!(text.unjoined_concat_children().is_some());
    let mut core = core();
    core.seed_register(0, Value::Str(text.clone())).unwrap();
    core.set_register_label(0, Label::Secret).unwrap();
    let Value::Object(object) = core
        .json_raw_json_builtin(None, RegRange { start: 0, count: 1 })
        .unwrap()
    else {
        panic!("raw JSON object expected");
    };
    assert!(core.is_raw_json_object(object));
    assert!(core.heap[object.0 as usize].is_frozen);
    assert!(core.heap[object.0 as usize].prototype.is_none());
    assert_eq!(
        core.heap[object.0 as usize].properties.get("rawJSON"),
        Some(&Value::Str(text.clone()))
    );
    assert_eq!(core.object_mutation_labels.get(&object), Some(&Label::Secret));
    assert!(text.unjoined_concat_children().is_some());
    assert_released(&core, 0);
}

#[test]
fn invalid_raw_text_keeps_the_original_parser_diagnostic() {
    for text in ["", " 0", "0 ", "[]", "{}", "-", "00", "1e+", "true false", r#""\u12xz""#, "\"open"] {
        let mut actual = core();
        let mut expected = core();
        for core in [&mut actual, &mut expected] {
            core.seed_register(0, Value::str(text)).unwrap();
        }
        let got = actual.json_raw_json_builtin(None, RegRange { start: 0, count: 1 });
        let units: Vec<u16> = text.encode_utf16().collect();
        let padded = |unit: Option<&u16>| {
            unit.is_none_or(|unit| matches!(unit, 0x09 | 0x0a | 0x0d | 0x20))
        };
        let want = if padded(units.first())
            || padded(units.last())
            || matches!(units.first(), Some(0x7b | 0x5b))
        {
            expected.json_syntax_error(0)
        } else {
            expected.json_parse_document(&units)
        };
        assert_eq!(got, want, "{text:?}");
        let Some(Value::Object(a)) = actual.pending_exception.as_ref() else {
            panic!("syntax error expected");
        };
        let Some(Value::Object(b)) = expected.pending_exception.as_ref() else {
            panic!("reference syntax error expected");
        };
        assert_eq!(
            actual.chain_data_property(*a, "name"),
            Some(&Value::str("SyntaxError"))
        );
        assert_eq!(
            actual.chain_data_property(*a, "message"),
            expected.chain_data_property(*b, "message")
        );
        assert_eq!(actual.json_parse_temporary_bytes, 0);
    }
}

#[test]
fn raw_validation_preserves_coercion_reentrancy_and_callback_exception_identity() {
    let source = r#"
        var count = 0;
        var spelling = '1' + '2'.repeat(2048) + '.3400e+99999';
        var raw = JSON.rawJSON({
            [Symbol.toPrimitive]: function (hint) {
                count++;
                if (hint !== 'string') throw 'hint';
                if (JSON.stringify(JSON.rawJSON('"nested"')) !== '"nested"') throw 'reentry';
                return spelling;
            }
        });
        var result = JSON.stringify({value: 1}, function (key, value) {
            if (key === 'value') { count++; return raw; }
            return value;
        });
        var marker = {};
        var same = false;
        try { JSON.rawJSON({toString: function () { throw marker; }}); }
        catch (error) { same = error === marker; }
        var symbol = false;
        try { JSON.rawJSON(Symbol('x')); } catch (error) { symbol = error instanceof TypeError; }
        var invalid = 0;
        for (var s of ['', ' 0', '0 ', '[]', '{}', '1e+', '"\\uZZZZ"']) {
            try { JSON.rawJSON(s); } catch (error) { if (error instanceof SyntaxError) invalid++; }
        }
        [count, result === '{"value":' + spelling + '}', raw.rawJSON === spelling,
         JSON.isRawJSON(raw), Object.isFrozen(raw), Object.getPrototypeOf(raw) === null,
         same, symbol, invalid, JSON.stringify(JSON.rawJSON('1.2300e+5'))].join('|');
    "#;
    let tree = crate::parser_api_stability::parse_script(source).unwrap();
    let lowered = crate::lowering_pipeline::lower_ir0_to_ir3(
        &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "raw-validation.js"),
        &crate::lowering_pipeline::LoweringContext::new("raw-validation", "callbacks", "builtin-only"),
    )
    .unwrap();
    let mut core = core();
    let result = core.execute(&lowered.ir3).unwrap();
    assert_eq!(
        result.value,
        Value::str("2|true|true|true|true|true|true|true|7|1.2300e+5")
    );
    assert_released(&core, 0);
}
