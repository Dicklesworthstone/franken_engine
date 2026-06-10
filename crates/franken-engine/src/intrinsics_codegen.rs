//! Declarative-codegen layer over the intrinsic table — Dueling-Wizards E4.T2 (`bd-fqlfw.4.2`).
//!
//! # What this does
//! [`intrinsics_table`](crate::intrinsics_table) (E4.T1) defines the *schema* — one
//! [`IntrinsicRow`] per builtin. This module is the **codegen** that expands those rows into
//! the mechanical glue the old hand-wired "5-seam assembly line" produced by hand:
//! * a name → row **registry** (replaces the scattered name/constructor mapping),
//! * a **dispatch plan** (name → the hand-written impl fn, or the documented escape-hatch site),
//! * generated **gap-inventory entries** (replaces the hand-maintained `lowering_gap_inventory`
//!   rows),
//!   all derived from the single source of truth so they cannot drift from each other.
//!
//! # Two surfaces
//! * [`define_intrinsics!`] — the declaration macro. `define_intrinsics! { row, row, ... }`
//!   collects [`IntrinsicRow`] literals into a `ROWS` const. This is the one place a
//!   contributor edits to add a builtin (E4.T3 then provides the hand-written impl fn).
//! * [`generate_glue`] — the codegen step. Given the rows, it derives the registry, dispatch
//!   plan, and gap-inventory entries, consistent by construction.
//!
//! # Glue only (load-bearing rule from the E4 epic)
//! The generated artifacts are **data**: names, capability/IFC metadata, impl-fn *identifiers*,
//! and gap statuses. No JS semantics live here — [`DispatchTarget::Generated`] names a
//! hand-written fn that E4.T3 (`bd-fqlfw.4.3`) wires into the interpreter; this module never
//! emits behavior. That keeps a reviewer's line of sight to where behavior comes from, which is
//! mandatory in a security runtime.

use std::collections::BTreeMap;

use crate::intrinsics_table::{GapStatus, ImplBinding, IntrinsicRow};

/// Declare an intrinsic table: collects [`IntrinsicRow`] literals into a `ROWS` const. The
/// single edit site for adding a builtin (the impl fn is hand-written separately, E4.T3).
///
/// ```ignore
/// define_intrinsics! {
///     IntrinsicRow { name: "String.prototype.trim", /* ... */ },
///     IntrinsicRow { name: "Date.now", /* ... */ },
/// }
/// // expands to: pub const ROWS: &[IntrinsicRow] = &[ /* the rows */ ];
/// ```
#[macro_export]
macro_rules! define_intrinsics {
    ($($row:expr),* $(,)?) => {
        /// Generated intrinsic table (one row per builtin). Source of truth for codegen.
        pub const ROWS: &[$crate::intrinsics_table::IntrinsicRow] = &[ $($row),* ];
    };
}

/// Where a dispatched intrinsic routes. Pure data (an identifier or a site string) — never code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchTarget {
    /// Routes to a hand-written semantic fn of this name (E4.T3 wires the call).
    Generated { impl_fn: &'static str },
    /// Routes to a documented manual escape-hatch site (irregular builtin).
    Manual { site: &'static str },
}

/// One generated dispatch-plan entry: a builtin name and where it routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedDispatch {
    pub name: &'static str,
    pub target: DispatchTarget,
}

/// One generated gap-inventory entry, derived from a row. Replaces the hand-maintained
/// `lowering_gap_inventory` row so the inventory cannot drift from the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedGapEntry {
    pub name: &'static str,
    pub status: GapStatus,
    pub conformance: &'static str,
}

/// All glue generated from a table: registry + dispatch plan + gap-inventory entries.
#[derive(Debug, Clone)]
pub struct GeneratedGlue<'a> {
    /// name → row, for O(log n) lookup (replaces the scattered name mapping).
    pub registry: BTreeMap<&'a str, &'a IntrinsicRow>,
    /// name → dispatch target, in table order.
    pub dispatch: Vec<GeneratedDispatch>,
    /// One gap-inventory entry per row, in table order.
    pub gap_entries: Vec<GeneratedGapEntry>,
}

/// Errors the codegen consistency check can fail closed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodegenError {
    /// A row failed its own schema validation.
    InvalidRow(String),
    /// Two rows share a name (the registry would be ambiguous).
    DuplicateName(&'static str),
    /// Derived-glue counts disagree with the row count (a derivation bug).
    GlueCountMismatch {
        rows: usize,
        dispatch: usize,
        gap: usize,
    },
}

impl std::fmt::Display for CodegenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodegenError::InvalidRow(m) => write!(f, "invalid row: {m}"),
            CodegenError::DuplicateName(n) => write!(f, "duplicate intrinsic name: {n}"),
            CodegenError::GlueCountMismatch {
                rows,
                dispatch,
                gap,
            } => write!(
                f,
                "glue count mismatch: rows={rows} dispatch={dispatch} gap={gap}"
            ),
        }
    }
}
impl std::error::Error for CodegenError {}

/// The codegen step: derive registry + dispatch plan + gap-inventory entries from the table.
/// Every row produces exactly one dispatch entry and one gap entry, and is inserted into the
/// registry — consistency by construction. Fails closed on an invalid or duplicate row.
pub fn generate_glue(rows: &[IntrinsicRow]) -> Result<GeneratedGlue<'_>, CodegenError> {
    let mut registry: BTreeMap<&str, &IntrinsicRow> = BTreeMap::new();
    let mut dispatch = Vec::with_capacity(rows.len());
    let mut gap_entries = Vec::with_capacity(rows.len());

    for row in rows {
        row.validate().map_err(CodegenError::InvalidRow)?;
        if registry.insert(row.name, row).is_some() {
            return Err(CodegenError::DuplicateName(row.name));
        }
        dispatch.push(GeneratedDispatch {
            name: row.name,
            target: match &row.impl_binding {
                ImplBinding::Generated { impl_fn } => DispatchTarget::Generated { impl_fn },
                ImplBinding::Manual { site, .. } => DispatchTarget::Manual { site },
            },
        });
        gap_entries.push(GeneratedGapEntry {
            name: row.name,
            status: row.gap_status.clone(),
            conformance: row.conformance,
        });
    }

    if dispatch.len() != rows.len() || gap_entries.len() != rows.len() {
        return Err(CodegenError::GlueCountMismatch {
            rows: rows.len(),
            dispatch: dispatch.len(),
            gap: gap_entries.len(),
        });
    }
    Ok(GeneratedGlue {
        registry,
        dispatch,
        gap_entries,
    })
}

impl GeneratedGlue<'_> {
    /// Re-assert the cross-artifact invariant: one dispatch entry and one gap entry per
    /// registry row, names aligned. (E4.T3 calls this before wiring the interpreter.)
    pub fn verify(&self) -> Result<(), CodegenError> {
        let n = self.registry.len();
        if self.dispatch.len() != n || self.gap_entries.len() != n {
            return Err(CodegenError::GlueCountMismatch {
                rows: n,
                dispatch: self.dispatch.len(),
                gap: self.gap_entries.len(),
            });
        }
        for d in &self.dispatch {
            if !self.registry.contains_key(d.name) {
                return Err(CodegenError::DuplicateName(d.name));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intrinsics_table::{Arity, IfcPropagation, ReceiverKind, SEED_ROWS, ThisCoercion};

    // Exercise the declaration macro itself (proves `define_intrinsics! { .. }` expands).
    mod macro_demo {
        use crate::flow_lattice::LabelClass;
        use crate::intrinsics_table::*;
        crate::define_intrinsics! {
            IntrinsicRow {
                name: "String.prototype.trim",
                receiver: ReceiverKind::String,
                this_coercion: ThisCoercion::ToString,
                arity: Arity::Exact(0),
                capability: None,
                ifc: IfcPropagation::PropagateReceiverLabel,
                impl_binding: ImplBinding::Generated { impl_fn: "string_trim_impl" },
                conformance: "test262:built-ins/String/prototype/trim",
                gap_status: GapStatus::Resolved,
            },
            IntrinsicRow {
                name: "Date.now",
                receiver: ReceiverKind::Global,
                this_coercion: ThisCoercion::None,
                arity: Arity::Exact(0),
                capability: None,
                ifc: IfcPropagation::Constant(LabelClass::Public),
                impl_binding: ImplBinding::Generated { impl_fn: "date_now_impl" },
                conformance: "test262:built-ins/Date/now",
                gap_status: GapStatus::Resolved,
            },
        }
    }

    #[test]
    fn macro_collected_rows_into_const() {
        assert_eq!(macro_demo::ROWS.len(), 2);
        assert_eq!(macro_demo::ROWS[0].name, "String.prototype.trim");
    }

    #[test]
    fn one_row_yields_all_glue_consistently() {
        let glue = generate_glue(SEED_ROWS).expect("seed table generates glue");
        // exactly one registry + dispatch + gap entry per row
        assert_eq!(glue.registry.len(), SEED_ROWS.len());
        assert_eq!(glue.dispatch.len(), SEED_ROWS.len());
        assert_eq!(glue.gap_entries.len(), SEED_ROWS.len());
        glue.verify().expect("glue is internally consistent");
    }

    #[test]
    fn escape_hatch_row_routes_to_manual_site() {
        let glue = generate_glue(SEED_ROWS).unwrap();
        let reduce = glue
            .dispatch
            .iter()
            .find(|d| d.name == "Array.prototype.reduce")
            .expect("reduce present");
        match &reduce.target {
            DispatchTarget::Manual { site } => {
                assert!(site.contains("invoke_simple_reduce_callback"))
            }
            other => panic!("reduce must route to a Manual site, got {other:?}"),
        }
    }

    #[test]
    fn generated_rows_route_to_named_impl_fns() {
        let glue = generate_glue(SEED_ROWS).unwrap();
        let now = glue.dispatch.iter().find(|d| d.name == "Date.now").unwrap();
        assert_eq!(
            now.target,
            DispatchTarget::Generated {
                impl_fn: "date_now_impl"
            }
        );
    }

    #[test]
    fn gap_entries_mirror_row_status_and_conformance() {
        let glue = generate_glue(SEED_ROWS).unwrap();
        for row in SEED_ROWS {
            let entry = glue
                .gap_entries
                .iter()
                .find(|e| e.name == row.name)
                .expect("every row yields a gap entry");
            assert_eq!(entry.status, row.gap_status);
            assert_eq!(entry.conformance, row.conformance);
        }
    }

    #[test]
    fn duplicate_name_fails_closed() {
        // two rows with the same name must be rejected (registry would be ambiguous)
        let dup = [SEED_ROWS[0].clone(), SEED_ROWS[0].clone()];
        assert!(matches!(
            generate_glue(&dup),
            Err(CodegenError::DuplicateName(_))
        ));
    }
}
