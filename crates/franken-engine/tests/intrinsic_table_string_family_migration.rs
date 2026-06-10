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
    ReceiverKind, ThisCoercion, string_prototype, validate_table,
};

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

// ------------------------------------------------- end-to-end coexist proof

#[test]
fn e2e_char_index_family_still_serves() {
    assert_eq!(ev("'abc'.charAt(1)"), "b");
    assert_eq!(ev("'abc'.charCodeAt(0)"), "97");
    assert_eq!(ev("'abc'.at(-1)"), "c");
    assert_eq!(ev("'A'.codePointAt(0)"), "65");
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
fn e2e_slice_family_still_serves() {
    assert_eq!(ev("'hello'.slice(1, 3)"), "el");
    assert_eq!(ev("'hello'.slice(-2)"), "lo");
    assert_eq!(ev("'hello'.substring(3, 1)"), "el");
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
fn e2e_locale_normalize_match_still_serve() {
    assert_eq!(ev("'abc'.localeCompare('abd')"), "-1");
    assert_eq!(ev("'abc'.normalize()"), "abc");
    assert_eq!(ev("let m = 'hello'.match('ll'); m === null"), "false");
}
