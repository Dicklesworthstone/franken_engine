//! E4.T3 (`bd-fqlfw.4.3`): first family migrated onto the declarative
//! intrinsic table — `String.prototype.*` (26 methods).
//!
//! Two proof obligations, per
//! `docs/dueling_wizards/E4_INTRINSIC_TABLE_MIGRATION_PLAN.md` steps 3–4:
//!
//! 1. **Table shape** (public API): the family table validates, generates
//!    glue, verifies the cross-artifact invariant, and is uniform (String
//!    receiver, ToString coercion, no typed authority, conformance links,
//!    no escape hatches).
//! 2. **Non-breaking coexist** (end-to-end): the legacy seam still serves
//!    every family method through the full parser → lowering → interpreter
//!    pipeline. The route-level parity proof (legacy arms vs generated
//!    dispatch on shared impl fns) lives in the lib unit tests
//!    (`string_intrinsic_table_parity_tests` in `baseline_interpreter.rs`),
//!    where the private dispatch seam is reachable.
//!
//! The flip that retires the legacy arms is migration-plan step 5 and is
//! intentionally NOT part of this change.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::intrinsics_codegen::{DispatchTarget, generate_glue};
use frankenengine_engine::intrinsics_table::{
    Arity, GapStatus, IfcPropagation, ReceiverKind, ThisCoercion, string_prototype, validate_table,
};

use std::collections::BTreeSet;

fn ev(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(output) => output.value,
        Err(error) => format!("ERR:{error}"),
    }
}

// ---------------------------------------------------------------- table shape

#[test]
fn family_table_validates_and_generates_verified_glue() {
    validate_table(string_prototype::ROWS).expect("String.prototype family table must validate");
    let glue = generate_glue(string_prototype::ROWS)
        .expect("String.prototype family table must generate glue");
    glue.verify()
        .expect("String.prototype family glue must verify (cross-artifact invariant)");
    assert_eq!(glue.registry.len(), 26);
    assert_eq!(glue.dispatch.len(), 26);
    assert_eq!(glue.gap_entries.len(), 26);
}

#[test]
fn family_rows_are_uniform_and_fully_generated() {
    for row in string_prototype::ROWS {
        assert!(
            row.name.starts_with("String.prototype."),
            "{}: family rows must be String.prototype methods",
            row.name
        );
        assert_eq!(row.receiver, ReceiverKind::String, "{}", row.name);
        assert_eq!(row.this_coercion, ThisCoercion::ToString, "{}", row.name);
        assert!(row.capability.is_none(), "{}: pure builtin", row.name);
        assert!(!row.conformance.is_empty(), "{}", row.name);
        assert!(!row.is_escape_hatch(), "{}", row.name);
    }
}

#[test]
fn dispatch_plan_routes_every_method_to_a_named_impl_fn() {
    let glue = generate_glue(string_prototype::ROWS).expect("glue");
    for entry in &glue.dispatch {
        match &entry.target {
            DispatchTarget::Generated { impl_fn } => {
                // The impl-fn identifiers follow the family convention; the
                // binding-resolution proof (identifier -> fn pointer) is the
                // lib-side parity test where the binding is visible.
                assert!(
                    impl_fn.starts_with("string_") && impl_fn.ends_with("_impl"),
                    "{}: unexpected impl fn naming `{impl_fn}`",
                    entry.name
                );
            }
            DispatchTarget::Manual { site } => {
                panic!(
                    "{}: String family must be fully generated, found {site}",
                    entry.name
                )
            }
        }
    }
}

#[test]
fn family_covers_the_exact_legacy_method_set() {
    let mut names: Vec<&str> = string_prototype::ROWS
        .iter()
        .map(|row| {
            row.name
                .strip_prefix("String.prototype.")
                .expect("family-row name prefix")
        })
        .collect();
    names.sort_unstable();
    let mut expected = vec![
        "charAt",
        "charCodeAt",
        "at",
        "toUpperCase",
        "toLowerCase",
        "trim",
        "trimStart",
        "trimEnd",
        "replaceAll",
        "codePointAt",
        "localeCompare",
        "normalize",
        "split",
        "includes",
        "startsWith",
        "endsWith",
        "indexOf",
        "lastIndexOf",
        "slice",
        "substring",
        "replace",
        "match",
        "search",
        "repeat",
        "padStart",
        "padEnd",
    ];
    expected.sort_unstable();
    assert_eq!(names, expected);
}

#[test]
fn one_table_row_to_generated_glue_snapshot_is_stable() {
    let glue = generate_glue(string_prototype::ROWS).expect("glue");
    let row = glue
        .registry
        .get("String.prototype.charAt")
        .expect("charAt row");
    let dispatch = glue
        .dispatch
        .iter()
        .find(|entry| entry.name == row.name)
        .expect("charAt dispatch entry");
    let gap = glue
        .gap_entries
        .iter()
        .find(|entry| entry.name == row.name)
        .expect("charAt gap entry");
    let impl_fn = match &dispatch.target {
        DispatchTarget::Generated { impl_fn } => *impl_fn,
        other => panic!("charAt must route to generated glue, got {other:?}"),
    };

    let snapshot = format!(
        "name={};receiver={:?};this={:?};arity={:?};ifc={:?};dispatch={};gap={:?};conformance={}",
        row.name,
        row.receiver,
        row.this_coercion,
        row.arity,
        row.ifc,
        impl_fn,
        gap.status,
        gap.conformance
    );

    assert_eq!(
        snapshot,
        "name=String.prototype.charAt;receiver=String;this=ToString;arity=Range { min: 0, max: 1 };ifc=JoinReceiverAndArgs;dispatch=string_char_at_impl;gap=Resolved;conformance=test262:built-ins/String/prototype/charAt"
    );
}

#[test]
fn generated_glue_contains_identifiers_not_semantic_bodies() {
    let glue = generate_glue(string_prototype::ROWS).expect("glue");

    for entry in &glue.dispatch {
        let impl_fn = match &entry.target {
            DispatchTarget::Generated { impl_fn } => impl_fn,
            DispatchTarget::Manual { site } => {
                panic!(
                    "{}: String family must not use manual site {site}",
                    entry.name
                )
            }
        };

        assert!(
            impl_fn
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch == '_'),
            "{}: generated dispatch target must be a plain Rust identifier, got `{impl_fn}`",
            entry.name
        );
        for forbidden in ["fn ", "match ", "Value", "=>", "{", "}", ";"] {
            assert!(
                !impl_fn.contains(forbidden),
                "{}: generated dispatch target smuggles semantic text `{forbidden}` in `{impl_fn}`",
                entry.name
            );
        }
    }
}

#[test]
fn every_table_row_generates_gap_inventory_entry_without_drift() {
    let glue = generate_glue(string_prototype::ROWS).expect("glue");
    let row_names: BTreeSet<&str> = string_prototype::ROWS.iter().map(|row| row.name).collect();
    let gap_names: BTreeSet<&str> = glue.gap_entries.iter().map(|entry| entry.name).collect();

    assert_eq!(gap_names, row_names);
    for row in string_prototype::ROWS {
        let entry = glue
            .gap_entries
            .iter()
            .find(|entry| entry.name == row.name)
            .expect("every row yields a gap entry");
        assert_eq!(entry.status, row.gap_status, "{}", row.name);
        assert_eq!(entry.conformance, row.conformance, "{}", row.name);
        assert!(
            !entry.conformance.is_empty(),
            "{}: generated gap-inventory entry must carry a conformance anchor",
            row.name
        );
        assert!(
            !matches!(&entry.status, GapStatus::Planned),
            "{}: migrated String row must not remain planned",
            row.name
        );
    }
}

#[test]
fn string_rows_declare_secret_safe_ifc_policies_per_row() {
    for row in string_prototype::ROWS {
        match &row.arity {
            Arity::Exact(0) => assert_eq!(
                row.ifc,
                IfcPropagation::PropagateReceiverLabel,
                "{}: arg-free String method should propagate the receiver label",
                row.name
            ),
            _ => assert_eq!(
                row.ifc,
                IfcPropagation::JoinReceiverAndArgs,
                "{}: argument-reading String method must join receiver and argument labels",
                row.name
            ),
        }
    }
}

// ------------------------------------------------- end-to-end coexist proof

#[test]
fn e2e_char_index_family_still_serves() {
    assert_eq!(ev("'abc'.charAt(1)"), "b");
    assert_eq!(ev("'abc'.charCodeAt(0)"), "97");
    assert_eq!(ev("'abc'.at(-1)"), "c");
    assert_eq!(ev("'A'.codePointAt(0)"), "65");
}

#[test]
fn e2e_char_index_family_truncates_fractional_indices() {
    assert_eq!(ev("'abc'.charAt(1.9)"), "b");
    assert_eq!(ev("'abc'.charCodeAt(1.9)"), "98");
    assert_eq!(ev("'abc'.codePointAt(1.9)"), "98");
    assert_eq!(ev("'abc'.charAt('1.9')"), "b");
    assert_eq!(ev("'abc'.charCodeAt('1.9')"), "98");
    assert_eq!(ev("'abc'.codePointAt('1.9')"), "98");
}

#[test]
fn e2e_char_index_family_keeps_nan_indices_at_zero() {
    assert_eq!(ev("'abc'.charAt(0 / 0)"), "a");
    assert_eq!(ev("'abc'.charCodeAt(0 / 0)"), "97");
    assert_eq!(ev("'abc'.codePointAt(0 / 0)"), "97");
}

#[test]
fn e2e_case_and_trim_family_still_serves() {
    assert_eq!(ev("'aBc'.toUpperCase()"), "ABC");
    assert_eq!(ev("'AbC'.toLowerCase()"), "abc");
    assert_eq!(ev("'  hi  '.trim()"), "hi");
    assert_eq!(ev("'  hi  '.trimStart()"), "hi  ");
    assert_eq!(ev("'  hi  '.trimEnd()"), "  hi");
}

#[test]
fn e2e_search_family_still_serves() {
    assert_eq!(ev("'hello'.includes('ell')"), "true");
    assert_eq!(ev("'hello'.startsWith('he')"), "true");
    assert_eq!(ev("'hello'.endsWith('lo')"), "true");
    assert_eq!(ev("'hello'.indexOf('l')"), "2");
    assert_eq!(ev("'hello'.lastIndexOf('l')"), "3");
    assert_eq!(ev("'hello'.search('ll')"), "2");
}

#[test]
fn e2e_search_family_truncates_fractional_positions() {
    assert_eq!(ev("'abc'.includes('a', 1.9)"), "false");
    assert_eq!(ev("'abc'.includes('a', '1.9')"), "false");
    assert_eq!(ev("'abc'.startsWith('b', 1.9)"), "true");
    assert_eq!(ev("'abc'.startsWith('b', '1.9')"), "true");
    assert_eq!(ev("'abcd'.endsWith('bc', 3.9)"), "true");
    assert_eq!(ev("'abcd'.endsWith('bc', '3.9')"), "true");
    assert_eq!(ev("'abcabc'.indexOf('a', 1.9)"), "3");
    assert_eq!(ev("'abcabc'.indexOf('a', '1.9')"), "3");
    assert_eq!(ev("'ababa'.lastIndexOf('a', 1.9)"), "0");
    assert_eq!(ev("'ababa'.lastIndexOf('a', '1.9')"), "0");
}

#[test]
fn e2e_search_family_keeps_nan_positions_at_zero() {
    assert_eq!(ev("'abc'.includes('a', 0 / 0)"), "true");
    assert_eq!(ev("'abc'.startsWith('a', 0 / 0)"), "true");
    assert_eq!(ev("'abc'.endsWith('a', 0 / 0)"), "false");
    assert_eq!(ev("'abcabc'.indexOf('a', 0 / 0)"), "0");
    assert_eq!(ev("'ababa'.lastIndexOf('a', 0 / 0)"), "0");
}

#[test]
fn e2e_slice_family_still_serves() {
    assert_eq!(ev("'hello'.slice(1, 3)"), "el");
    assert_eq!(ev("'hello'.slice(-2)"), "lo");
    assert_eq!(ev("'hello'.substring(3, 1)"), "el");
}

#[test]
fn e2e_slice_family_truncates_fractional_bounds() {
    assert_eq!(ev("'abcd'.slice(1.9, 3.9)"), "bc");
    assert_eq!(ev("'abcd'.substring(1.9, 3.9)"), "bc");
    assert_eq!(ev("'abcd'.slice('1.9', '3.9')"), "bc");
    assert_eq!(ev("'abcd'.substring('1.9', '3.9')"), "bc");
}

#[test]
fn e2e_slice_family_keeps_nan_bounds_at_zero() {
    assert_eq!(ev("'abcd'.slice(0 / 0, 2)"), "ab");
    assert_eq!(ev("'abcd'.substring(0 / 0, 2)"), "ab");
}

#[test]
fn e2e_replace_split_family_still_serves() {
    assert_eq!(ev("'aba'.replace('a', '_')"), "_ba");
    assert_eq!(ev("'aba'.replaceAll('a', '_')"), "_b_");
    assert_eq!(ev("let p = 'a-b-c'.split('-'); p.length"), "3");
    assert_eq!(ev("let q = 'a-b-c'.split('-'); q[1]"), "b");
}

#[test]
fn e2e_repeat_pad_family_still_serves() {
    assert_eq!(ev("'ab'.repeat(3)"), "ababab");
    assert_eq!(ev("'7'.padStart(3, '0')"), "007");
    assert_eq!(ev("'7'.padEnd(3, '0')"), "700");
}

#[test]
fn e2e_repeat_pad_family_truncates_fractional_lengths() {
    assert_eq!(ev("'x'.repeat(2.9)"), "xx");
    assert_eq!(ev("'7'.padStart(2.9, '0')"), "07");
    assert_eq!(ev("'7'.padEnd(2.9, '0')"), "70");
    assert_eq!(ev("'x'.repeat('2.9')"), "xx");
    assert_eq!(ev("'7'.padStart('2.9', '0')"), "07");
    assert_eq!(ev("'7'.padEnd('2.9', '0')"), "70");
}

#[test]
fn e2e_repeat_pad_family_keeps_nan_lengths_at_zero() {
    assert_eq!(ev("'x'.repeat(0 / 0)"), "");
    assert_eq!(ev("'7'.padStart(0 / 0, '0')"), "7");
    assert_eq!(ev("'7'.padEnd(0 / 0, '0')"), "7");
}

#[test]
fn e2e_repeat_pad_family_rejects_huge_pad_lengths_before_allocation() {
    let pad_start = ev("'x'.padStart(1e300, '0')");
    assert!(
        pad_start.contains("string allocation size exceeded"),
        "unexpected padStart result: {pad_start}"
    );

    let pad_end = ev("'x'.padEnd(1e300, '0')");
    assert!(
        pad_end.contains("string allocation size exceeded"),
        "unexpected padEnd result: {pad_end}"
    );
}

#[test]
fn e2e_locale_normalize_match_still_serve() {
    assert_eq!(ev("'abc'.localeCompare('abd')"), "-1");
    assert_eq!(ev("'abc'.normalize()"), "abc");
    assert_eq!(ev("let m = 'hello'.match('ll'); m === null"), "false");
}
