//! Declarative `Array.prototype.*` migration table for BRIDGE-15.1/15.3.
//!
//! The production interpreter still owns the semantic bodies today.  This table
//! is the coexistence-stage source of truth for the Array family: names, receiver
//! contract, arity shape, IFC propagation, conformance anchors, and explicit
//! residual gaps all live in one reviewable place.  Rows intentionally use the
//! `Manual` binding until a semantic body has been extracted from the legacy
//! interpreter into a shared function; inventing generated binding names before
//! those functions exist would make the migration ledger lie.

use crate::intrinsics_table::{
    Arity, GapStatus, IfcPropagation, ImplBinding, IntrinsicRow, ReceiverKind, ThisCoercion,
};

const MANUAL_SITE: &str =
    "baseline_interpreter.rs:array_prototype_method/dispatch_builtin_function";
const MANUAL_REASON: &str =
    "coexistence migration: production Array semantics still live in the legacy receiver-aware interpreter seam";

macro_rules! array_row {
    ($name:literal, $arity:expr, $ifc:expr, $status:expr) => {
        IntrinsicRow {
            name: concat!("Array.prototype.", $name),
            receiver: ReceiverKind::Array,
            this_coercion: ThisCoercion::Passthrough,
            arity: $arity,
            capability: None,
            ifc: $ifc,
            impl_binding: ImplBinding::Manual {
                reason: MANUAL_REASON,
                site: MANUAL_SITE,
            },
            conformance: concat!("test262:built-ins/Array/prototype/", $name),
            gap_status: $status,
        }
    };
}

/// ES2020 Array prototype methods plus the post-ES2020 methods already exposed
/// by the production runtime.  Keeping the extensions here matters: the table
/// is a migration source of truth for the *shipped* seam, not merely a spec-era
/// checklist.
pub const ROWS: &[IntrinsicRow] = &[
    array_row!("at", Arity::Range { min: 0, max: 1 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("concat", Arity::Variadic { required: 0 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("copyWithin", Arity::Range { min: 2, max: 3 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("entries", Arity::Exact(0), IfcPropagation::PropagateReceiverLabel, GapStatus::Partial("stateful ArrayIterator object / .next() semantics remain to be unified with the live VM iterator store")),
    array_row!("every", Arity::Range { min: 1, max: 2 }, IfcPropagation::Custom("array_callback_ifc"), GapStatus::Resolved),
    array_row!("fill", Arity::Range { min: 1, max: 3 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("filter", Arity::Range { min: 1, max: 2 }, IfcPropagation::Custom("array_callback_ifc"), GapStatus::Resolved),
    array_row!("find", Arity::Range { min: 1, max: 2 }, IfcPropagation::Custom("array_callback_ifc"), GapStatus::Resolved),
    array_row!("findIndex", Arity::Range { min: 1, max: 2 }, IfcPropagation::Custom("array_callback_ifc"), GapStatus::Resolved),
    array_row!("flat", Arity::Range { min: 0, max: 1 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("flatMap", Arity::Range { min: 1, max: 2 }, IfcPropagation::Custom("array_callback_ifc"), GapStatus::Resolved),
    array_row!("forEach", Arity::Range { min: 1, max: 2 }, IfcPropagation::Custom("array_callback_ifc"), GapStatus::Resolved),
    array_row!("includes", Arity::Range { min: 1, max: 2 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("indexOf", Arity::Range { min: 1, max: 2 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("join", Arity::Range { min: 0, max: 1 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("keys", Arity::Exact(0), IfcPropagation::PropagateReceiverLabel, GapStatus::Partial("stateful ArrayIterator object / .next() semantics remain to be unified with the live VM iterator store")),
    array_row!("lastIndexOf", Arity::Range { min: 1, max: 2 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("map", Arity::Range { min: 1, max: 2 }, IfcPropagation::Custom("array_callback_ifc"), GapStatus::Resolved),
    array_row!("pop", Arity::Exact(0), IfcPropagation::PropagateReceiverLabel, GapStatus::Resolved),
    array_row!("push", Arity::Variadic { required: 0 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("reduce", Arity::Range { min: 1, max: 2 }, IfcPropagation::Custom("array_reduce_ifc"), GapStatus::Resolved),
    array_row!("reduceRight", Arity::Range { min: 1, max: 2 }, IfcPropagation::Custom("array_reduce_right_ifc"), GapStatus::Resolved),
    array_row!("reverse", Arity::Exact(0), IfcPropagation::PropagateReceiverLabel, GapStatus::Resolved),
    array_row!("shift", Arity::Exact(0), IfcPropagation::PropagateReceiverLabel, GapStatus::Resolved),
    array_row!("slice", Arity::Range { min: 0, max: 2 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("some", Arity::Range { min: 1, max: 2 }, IfcPropagation::Custom("array_callback_ifc"), GapStatus::Resolved),
    array_row!("sort", Arity::Range { min: 0, max: 1 }, IfcPropagation::Custom("array_sort_ifc"), GapStatus::Resolved),
    array_row!("splice", Arity::Variadic { required: 0 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("unshift", Arity::Variadic { required: 0 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("values", Arity::Exact(0), IfcPropagation::PropagateReceiverLabel, GapStatus::Partial("stateful ArrayIterator object / .next() semantics remain to be unified with the live VM iterator store")),
    array_row!("toReversed", Arity::Exact(0), IfcPropagation::PropagateReceiverLabel, GapStatus::Resolved),
    array_row!("toSorted", Arity::Range { min: 0, max: 1 }, IfcPropagation::Custom("array_sort_ifc"), GapStatus::Resolved),
    array_row!("toSpliced", Arity::Variadic { required: 0 }, IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
    array_row!("with", Arity::Exact(2), IfcPropagation::JoinReceiverAndArgs, GapStatus::Resolved),
];

/// Canonical property names in deterministic table order.
pub fn property_names() -> impl Iterator<Item = &'static str> {
    ROWS.iter().map(|row| {
        row.name
            .strip_prefix("Array.prototype.")
            .expect("Array family row must retain canonical prefix")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intrinsics_table::validate_table;
    use std::collections::BTreeSet;

    #[test]
    fn array_family_validates_and_has_unique_names() {
        validate_table(ROWS).expect("Array.prototype table must validate");
        assert_eq!(ROWS.len(), 34);
        let names: BTreeSet<_> = property_names().collect();
        assert_eq!(names.len(), ROWS.len());
    }

    #[test]
    fn every_row_is_array_receiver_without_ambient_authority() {
        for row in ROWS {
            assert_eq!(row.receiver, ReceiverKind::Array, "{}", row.name);
            assert_eq!(row.this_coercion, ThisCoercion::Passthrough, "{}", row.name);
            assert!(row.capability.is_none(), "{}", row.name);
            assert!(!row.conformance.is_empty(), "{}", row.name);
            assert!(row.is_escape_hatch(), "{} remains coexist/manual until semantic extraction", row.name);
        }
    }

    #[test]
    fn only_live_iterator_methods_remain_partial() {
        let partial: BTreeSet<_> = ROWS
            .iter()
            .filter(|row| matches!(&row.gap_status, GapStatus::Partial(_)))
            .map(|row| row.name)
            .collect();
        assert_eq!(
            partial,
            BTreeSet::from([
                "Array.prototype.entries",
                "Array.prototype.keys",
                "Array.prototype.values",
            ])
        );
    }

    #[test]
    fn callback_methods_never_claim_simple_ifc_propagation() {
        for name in [
            "every", "filter", "find", "findIndex", "flatMap", "forEach", "map", "reduce",
            "reduceRight", "some", "sort", "toSorted",
        ] {
            let row = ROWS
                .iter()
                .find(|row| row.name == format!("Array.prototype.{name}"))
                .expect("callback method row");
            assert!(matches!(&row.ifc, IfcPropagation::Custom(_)), "{}", row.name);
        }
    }
}