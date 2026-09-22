//! BRIDGE-15.1/15.3 coexistence proof for the declarative Array family.
//!
//! The semantic bodies remain on the legacy receiver-aware interpreter seam for
//! this migration stage. These tests pin the table/glue invariants and prove a
//! representative cross-section still executes through the shipped HybridRouter.

use std::collections::BTreeSet;

use frankenengine_engine::HybridRouter;
use frankenengine_engine::intrinsics_codegen::{DispatchTarget, array_prototype, generate_glue};
use frankenengine_engine::intrinsics_table::{
    GapStatus, IfcPropagation, ReceiverKind, ThisCoercion, validate_table,
};

fn ev(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for {source:?}: {error}"))
        .value
}

#[test]
fn family_table_validates_and_generates_verified_glue() {
    validate_table(array_prototype::ROWS).expect("Array.prototype family table must validate");
    let glue = generate_glue(array_prototype::ROWS)
        .expect("Array.prototype family table must generate glue");
    glue.verify()
        .expect("Array.prototype generated glue must verify");
    assert_eq!(glue.registry.len(), 34);
    assert_eq!(glue.dispatch.len(), 34);
    assert_eq!(glue.gap_entries.len(), 34);
}

#[test]
fn family_rows_are_uniform_and_authority_free() {
    for row in array_prototype::ROWS {
        assert!(row.name.starts_with("Array.prototype."), "{}", row.name);
        assert_eq!(row.receiver, ReceiverKind::Array, "{}", row.name);
        assert_eq!(row.this_coercion, ThisCoercion::Passthrough, "{}", row.name);
        assert!(
            row.capability.is_none(),
            "{} must not gain ambient authority",
            row.name
        );
        assert!(
            !row.conformance.is_empty(),
            "{} needs a conformance anchor",
            row.name
        );
    }
}

#[test]
fn coexistence_dispatch_is_explicitly_manual_not_fake_generated_semantics() {
    let glue = generate_glue(array_prototype::ROWS).expect("glue");
    for entry in &glue.dispatch {
        match &entry.target {
            DispatchTarget::Manual { site } => assert!(
                site.contains("array_prototype_method/dispatch_builtin_function"),
                "{} points at unexpected manual site {site}",
                entry.name
            ),
            DispatchTarget::Generated { impl_fn } => panic!(
                "{} claims generated semantic binding {impl_fn} before extraction from the legacy interpreter",
                entry.name
            ),
        }
    }
}

#[test]
fn family_method_set_is_stable_and_unique() {
    let actual: BTreeSet<_> = array_prototype::property_names().collect();
    let expected = BTreeSet::from([
        "at",
        "concat",
        "copyWithin",
        "entries",
        "every",
        "fill",
        "filter",
        "find",
        "findIndex",
        "flat",
        "flatMap",
        "forEach",
        "includes",
        "indexOf",
        "join",
        "keys",
        "lastIndexOf",
        "map",
        "pop",
        "push",
        "reduce",
        "reduceRight",
        "reverse",
        "shift",
        "slice",
        "some",
        "sort",
        "splice",
        "toReversed",
        "toSorted",
        "toSpliced",
        "unshift",
        "values",
        "with",
    ]);
    assert_eq!(actual, expected);
}

#[test]
fn family_gap_ledger_matches_shipped_array_semantics() {
    let unresolved: Vec<_> = array_prototype::ROWS
        .iter()
        .filter(|row| !matches!(&row.gap_status, GapStatus::Resolved))
        .map(|row| row.name)
        .collect();
    assert!(
        unresolved.is_empty(),
        "unexpected Array semantic gaps: {unresolved:?}"
    );
}

#[test]
fn callback_methods_declare_callback_dependent_ifc() {
    for name in [
        "every",
        "filter",
        "find",
        "findIndex",
        "flatMap",
        "forEach",
        "map",
        "reduce",
        "reduceRight",
        "some",
        "sort",
        "toSorted",
    ] {
        let canonical = format!("Array.prototype.{name}");
        let row = array_prototype::ROWS
            .iter()
            .find(|row| row.name == canonical)
            .expect("callback row");
        assert!(
            matches!(&row.ifc, IfcPropagation::Custom(_)),
            "{}",
            row.name
        );
    }
}

#[test]
fn e2e_mutators_still_serve_receiver_aware_semantics() {
    assert_eq!(ev("let a=[1,2]; a.push(3); a.join(',');"), "1,2,3");
    assert_eq!(ev("let a=[1,2]; let x=a.pop(); x + ':' + a.length;"), "2:1");
    assert_eq!(ev("let a=[1,2]; let x=a.shift(); x + ':' + a[0];"), "1:2");
    assert_eq!(ev("let a=[2,3]; a.unshift(1); a.join(',');"), "1,2,3");
    assert_eq!(
        ev("let a=[1,2,3,4]; let r=a.splice(1,2,9); r.join(',') + ':' + a.join(',');"),
        "2,3:1,9,4"
    );
}

#[test]
fn e2e_queries_and_copying_methods_still_serve() {
    assert_eq!(ev("[1,2,3].includes(2);"), "true");
    assert_eq!(ev("[1,2,3].indexOf(3);"), "2");
    assert_eq!(ev("[1,2,1].lastIndexOf(1);"), "2");
    assert_eq!(ev("[1,2,3].at(-1);"), "3");
    assert_eq!(ev("[1,2].concat([3,4]).join(',');"), "1,2,3,4");
    assert_eq!(ev("[1,2,3,4].slice(1,3).join(',');"), "2,3");
}

#[test]
fn e2e_callback_and_reduce_methods_still_serve() {
    assert_eq!(ev("[1,2,3].map(x=>x*2).join(',');"), "2,4,6");
    assert_eq!(ev("[1,2,3,4].filter(x=>x%2===0).join(',');"), "2,4");
    assert_eq!(ev("[1,2,3].find(x=>x>1);"), "2");
    assert_eq!(ev("[1,2,3].findIndex(x=>x===3);"), "2");
    assert_eq!(ev("[1,2,3].some(x=>x===2);"), "true");
    assert_eq!(ev("[1,2,3].every(x=>x>0);"), "true");
    assert_eq!(ev("[1,2,3].reduce((a,b)=>a+b,0);"), "6");
    assert_eq!(ev("[1,2,3].reduceRight((a,b)=>a-b,0);"), "-6");
}

#[test]
fn e2e_array_iterator_methods_are_lazy_and_stateful() {
    assert_eq!(
        ev(
            "let a=[1,2]; let it=a.values(); a[0]=8; let x=it.next().value; a[1]=9; x + ':' + it.next().value + ':' + it.next().done;"
        ),
        "8:9:true"
    );
    assert_eq!(
        ev(
            "let calls=0,a=[1]; Object.defineProperty(a,'0',{get(){calls+=1;throw 7;}}); let it=a.keys(); it.next().value + ':' + it.next().done + ':' + calls;"
        ),
        "0:true:0"
    );
    assert_eq!(
        ev(
            "let a=[1,2]; let it=a.entries(); let first=it.next().value; a[1]=9; let second=it.next().value; first.join(':') + ':' + second.join(':') + ':' + (first===second);"
        ),
        "0:1:1:9:false"
    );
}

#[test]
fn e2e_array_iterator_reads_live_length_and_stays_done_after_exhaustion() {
    assert_eq!(
        ev(
            "let a=[1]; let it=a.values(); let first=it.next().value; a.push(2); first + ':' + it.next().value + ':' + it.next().done;"
        ),
        "1:2:true"
    );
    assert_eq!(
        ev(
            "let a=[]; let it=a.values(); let done=it.next().done; a.push(7); done + ':' + it.next().done;"
        ),
        "true:true"
    );
}
