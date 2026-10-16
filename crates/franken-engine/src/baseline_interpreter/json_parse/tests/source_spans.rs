//! Source records retain offsets, not eagerly decoded strings. These tests
//! exercise the actual record builder, property publisher and JS evaluator.

use super::*;

#[test]
fn primitive_record_needs_only_fixed_metadata_even_for_large_source() {
    for text in [
        format!("1{}e+99999", "2".repeat(16_384)),
        format!("\"{}\"", "aé日😀\\uD800".repeat(1024)),
    ] {
        let units: Vec<u16> = text.encode_utf16().collect();
        let mut core = core();
        let value = core.json_parse_document(&units).unwrap();
        let baseline = core.estimated_memory_bytes();
        let bytes = std::mem::size_of::<JsonParseRecord>() as u64;
        core.config.max_total_memory_bytes = baseline + bytes;
        let mut charged = 0;
        let mut pos = 0;
        let record = core
            .json_parse_record(&units, &mut pos, value, &mut charged)
            .unwrap();
        assert_eq!(pos, units.len());
        assert_eq!(record.source, Some(0..units.len()));
        assert_eq!(record.source_units(&units).unwrap().as_ptr(), units.as_ptr());
        assert_eq!(charged, bytes, "source spelling must not be copied here");
        assert_eq!(core.json_parse_temporary_bytes, bytes);
        drop(record);
        core.json_release_temporary(charged);
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert!(core.pending_exception.is_none());
    }
}

#[test]
fn wide_records_borrow_distinct_original_spans_and_preserve_last_duplicate() {
    let mut core = core();
    let width = 1024;
    let text = format!("[{}]", vec!["1.2300e+005"; width].join(","));
    let (record, charged, units) = parse_record(&mut core, &text);
    assert_eq!(record.elements.len(), width);
    assert_eq!(
        charged,
        (width as u64 + 1) * std::mem::size_of::<JsonParseRecord>() as u64
    );
    for (index, child) in record.elements.iter().enumerate() {
        let child = child.as_ref().unwrap();
        let start = 1 + index * 12;
        assert_eq!(child.source, Some(start..start + 11));
        assert_eq!(child.source_units(&units).unwrap(), &units[start..start + 11]);
        assert_eq!(
            child.source_units(&units).unwrap().as_ptr(),
            units[start..].as_ptr()
        );
    }
    drop(record);
    core.json_release_temporary(charged);

    let text = r#"{"dup":{"discarded":"é😀"},"dup":6.00,"\ud800":7e0}"#;
    let (mut record, charged, units) = parse_record(&mut core, text);
    let child = record.take_entry(&JsString::from("dup")).unwrap();
    assert_eq!(
        child.source_units(&units).map(JsString::from_code_units),
        Some(JsString::from("6.00"))
    );
    assert!(child.entries.is_empty());
    let child = record
        .take_entry(&JsString::from_code_units(&[0xd800]))
        .unwrap();
    assert_eq!(
        child.source_units(&units).map(JsString::from_code_units),
        Some(JsString::from("7e0"))
    );
    drop(record);
    core.json_release_temporary(charged);
    assert_eq!(core.json_parse_temporary_bytes, 0);
}

#[test]
fn exact_source_spans_remain_code_unit_offsets_after_astral_text_and_escapes() {
    let units = [
        0x5b, 0x22, 0xd83d, 0xde00, 0x22, 0x2c, 0x22, 0xd800, 0x5c, 0x22,
        0xdc00, 0x22, 0x2c, 0x2d, 0x30, 0x5d,
    ];
    let mut core = core();
    let value = core.json_parse_document(&units).unwrap();
    let mut charged = 0;
    let mut pos = 0;
    let record = core
        .json_parse_record(&units, &mut pos, value, &mut charged)
        .unwrap();
    for (child, span) in record.elements.iter().zip([1..5, 6..12, 13..15]) {
        let child = child.as_ref().unwrap();
        assert_eq!(child.source, Some(span.clone()));
        assert_eq!(child.source_units(&units), Some(&units[span]));
    }
    assert!(record.source.is_none());
    drop(record);
    core.json_release_temporary(charged);
    assert_eq!(core.json_parse_temporary_bytes, 0);
}

#[test]
fn source_publication_admits_before_copying_and_releases_only_its_own_scratch() {
    let mut core = core();
    let object = core.alloc_object_with_prototype(None).unwrap();
    core.json_reserve_temporary(77).unwrap();
    let units: Vec<u16> = "\"é😀\\uD800\"".encode_utf16().collect();
    let baseline = core.estimated_memory_bytes();
    let original_limit = core.config.max_total_memory_bytes;
    let bytes = units.len() as u64 * 10 + 128;
    core.config.max_total_memory_bytes = baseline + bytes - 1;
    assert!(matches!(
        core.json_store_reviver_source(object, &units),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(!core.heap[object.0 as usize].properties.contains_key("source"));
    assert_eq!(core.json_parse_temporary_bytes, 77);
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert!(core.pending_exception.is_none());

    core.config.max_total_memory_bytes = original_limit;
    core.json_observe_label(Label::Secret).unwrap();
    core.json_store_reviver_source(object, &units).unwrap();
    let expected = JsString::from_code_units(&units);
    drop(units);
    assert_eq!(
        core.heap[object.0 as usize].properties.get("source"),
        Some(&Value::Str(expected))
    );
    assert_eq!(core.own_property_label(object, "source"), Label::Secret);
    assert_eq!(core.json_parse_temporary_bytes, 77);
    core.json_release_temporary(77);
    assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
}

#[test]
fn reviver_source_contexts_survive_reentrancy_replacement_and_input_lifetime() {
    assert_eq!(
        execute_reviver_source(
            r#"
            var saved = [], seen = [];
            JSON.parse('{"a":1.00,"b":2e0,"c":3e0,"d":{"x":3.00},"dup":0,"dup":6.00}',
                function (key, value, context) {
                    saved.push(context);
                    if (key === 'a') {
                        this.b = 7;
                        this.c = 9;
                        this.d = {x: 3};
                        JSON.parse('5.00', function (k, v, c) { saved.push(c); return v; });
                    }
                    seen.push(key + ':' + context.source);
                    return value;
                });
            JSON.parse('[9,8,7]');
            seen.join('|') + '/' + saved.map(function (c) { return c.source; }).join(',');
            "#,
        ),
        Value::str("a:1.00|b:undefined|c:undefined|x:undefined|d:undefined|dup:6.00|:undefined/1.00,5.00,,,,,6.00,")
    );
}

#[test]
fn reviver_source_keeps_samevalue_rules_holes_and_exact_source_spelling() {
    assert_eq!(
        execute_reviver_source(
            r#"
            var seen = [], saved = [];
            JSON.parse('[1.00,2e0,-0,9007199254740993,1e999,"\\ud800","😀"]',
                function (key, value, context) {
                    if (key === '0') {
                        this[1] = 2;
                        delete this[2];
                    }
                    seen.push(key + ':' + context.source);
                    saved.push(context);
                    return key === '1' ? undefined : value;
                });
            JSON.stringify(seen) + '/' + saved[5].source;
            "#,
        ),
        Value::str(r#"["0:1.00","1:2e0","2:undefined","3:9007199254740993","4:1e999","5:\"\\ud800\"","6:\"😀\"",":undefined"]/"\ud800""#)
    );
}

#[test]
fn abrupt_reviver_retains_escaped_context_and_does_not_poison_next_parse() {
    assert_eq!(
        execute_reviver_source(
            r#"
            var first, marker = {}, same = false;
            try {
                JSON.parse('[1.2300e+5,"later","unused"]', function (key, value, context) {
                    first = context;
                    throw marker;
                });
            } catch (error) { same = error === marker; }
            var next;
            JSON.parse('-0', function (key, value, context) { next = context; return value; });
            [same, first.source, next.source, Object.keys(first).join(',')].join('|');
            "#,
        ),
        Value::str("true|1.2300e+5|-0|source")
    );
}

#[test]
fn replaced_negative_zero_does_not_reuse_its_original_source_span() {
    // SameValue(-0, +0) is false. Node 22.16 retains '-0' in this case;
    // preserve the native/specification contract rather than that quirk.
    assert_eq!(
        execute_reviver_source(
            r#"
            var source;
            JSON.parse('{"a":1,"b":-0}', function (key, value, context) {
                if (key === 'a') this.b = 0;
                if (key === 'b') source = context.source;
                return value;
            });
            String(source);
            "#,
        ),
        Value::str("undefined")
    );
}
