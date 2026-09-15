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
//! * deterministic **prototype installation plans** and a cross-family installation index,
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

use crate::capability::RuntimeCapability;
use crate::intrinsics_table::{
    Arity, GapStatus, IfcPropagation, ImplBinding, IntrinsicRow, ReceiverKind, ThisCoercion,
};

#[path = "intrinsics_array_table.rs"]
pub mod array_prototype;

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

impl DispatchTarget {
    fn from_row(row: &IntrinsicRow) -> Self {
        match &row.impl_binding {
            ImplBinding::Generated { impl_fn } => Self::Generated { impl_fn },
            ImplBinding::Manual { site, .. } => Self::Manual { site },
        }
    }
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

/// A prototype property installation derived entirely from one [`IntrinsicRow`].
///
/// These are deliberately data, not executable semantics. A family migration can install
/// methods from this plan and route the resulting function object through `dispatch_target`,
/// while the semantic body remains hand-written and independently testable. Ordinary builtin
/// methods use the ECMAScript method-property attributes writable=true, enumerable=false,
/// configurable=true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedPrototypeInstallation {
    pub canonical_name: &'static str,
    pub constructor: &'static str,
    pub property: &'static str,
    pub receiver: ReceiverKind,
    pub this_coercion: ThisCoercion,
    pub arity: Arity,
    pub capability: Option<RuntimeCapability>,
    pub ifc: IfcPropagation,
    pub dispatch_target: DispatchTarget,
    pub writable: bool,
    pub enumerable: bool,
    pub configurable: bool,
}

/// Canonical cross-family prototype installation index.
///
/// The key is `(constructor, property)`, so a family cannot silently shadow a method installed
/// by another source. This is the data structure the eventual production flip can query instead
/// of maintaining per-family name matches in the interpreter.
#[derive(Debug, Clone)]
pub struct PrototypeInstallationIndex {
    entries: BTreeMap<(&'static str, &'static str), GeneratedPrototypeInstallation>,
}

impl PrototypeInstallationIndex {
    pub fn get(
        &self,
        constructor: &str,
        property: &str,
    ) -> Option<&GeneratedPrototypeInstallation> {
        self.entries
            .iter()
            .find(|((candidate_constructor, candidate_property), _)| {
                *candidate_constructor == constructor && *candidate_property == property
            })
            .map(|(_, installation)| installation)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(
        &self,
    ) -> impl Iterator<
        Item = (
            (&'static str, &'static str),
            &GeneratedPrototypeInstallation,
        ),
    > {
        self.entries.iter().map(|(key, value)| (*key, value))
    }
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
    /// A prototype installer was requested for a non-prototype canonical name.
    NotPrototypeIntrinsic(&'static str),
    /// A prototype row's canonical constructor and typed receiver disagree.
    PrototypeReceiverMismatch {
        name: &'static str,
        expected_constructor: &'static str,
        actual_constructor: &'static str,
    },
    /// A canonical prototype name ended at `.prototype.` with no property key.
    EmptyPrototypeProperty(&'static str),
    /// Two family tables claim the same `(constructor, property)` installation target.
    DuplicatePrototypeProperty {
        constructor: &'static str,
        property: &'static str,
    },
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
            CodegenError::NotPrototypeIntrinsic(name) => {
                write!(f, "intrinsic {name} is not a prototype method")
            }
            CodegenError::PrototypeReceiverMismatch {
                name,
                expected_constructor,
                actual_constructor,
            } => write!(
                f,
                "prototype receiver mismatch for {name}: typed receiver expects {expected_constructor}, canonical name targets {actual_constructor}"
            ),
            CodegenError::EmptyPrototypeProperty(name) => {
                write!(f, "prototype intrinsic {name} has an empty property key")
            }
            CodegenError::DuplicatePrototypeProperty {
                constructor,
                property,
            } => write!(f, "duplicate prototype installation target {constructor}.prototype.{property}"),
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

fn prototype_constructor(receiver: &ReceiverKind) -> Option<&'static str> {
    match receiver {
        ReceiverKind::String => Some("String"),
        ReceiverKind::Array => Some("Array"),
        ReceiverKind::Object => Some("Object"),
        ReceiverKind::Number => Some("Number"),
        ReceiverKind::Collection(tag) => Some(tag),
        ReceiverKind::Global | ReceiverKind::Constructor(_) => None,
    }
}

/// Generate deterministic prototype-property installation records for a regular family.
///
/// This fails closed if a row is not a canonical `X.prototype.y` method or if its canonical
/// constructor disagrees with the typed [`ReceiverKind`]. Calling [`generate_glue`] first
/// also preserves row validation and duplicate-name refusal, so an installer never accepts a
/// table that the dispatch/gap generators would reject.
pub fn generate_prototype_installations(
    rows: &[IntrinsicRow],
) -> Result<Vec<GeneratedPrototypeInstallation>, CodegenError> {
    let _ = generate_glue(rows)?;
    let mut installations = Vec::with_capacity(rows.len());
    for row in rows {
        let (actual_constructor, property) = row
            .name
            .split_once(".prototype.")
            .ok_or(CodegenError::NotPrototypeIntrinsic(row.name))?;
        if property.is_empty() {
            return Err(CodegenError::EmptyPrototypeProperty(row.name));
        }
        let expected_constructor = prototype_constructor(&row.receiver)
            .ok_or(CodegenError::NotPrototypeIntrinsic(row.name))?;
        if actual_constructor != expected_constructor {
            return Err(CodegenError::PrototypeReceiverMismatch {
                name: row.name,
                expected_constructor,
                actual_constructor,
            });
        }
        installations.push(GeneratedPrototypeInstallation {
            canonical_name: row.name,
            constructor: expected_constructor,
            property,
            receiver: row.receiver.clone(),
            this_coercion: row.this_coercion.clone(),
            arity: row.arity.clone(),
            capability: row.capability,
            ifc: row.ifc.clone(),
            dispatch_target: DispatchTarget::from_row(row),
            writable: true,
            enumerable: false,
            configurable: true,
        });
    }
    Ok(installations)
}

/// Build one canonical prototype-property index from multiple migrated families.
///
/// Every family is validated independently before insertion. A duplicate target is refused even
/// when the canonical row names happen to differ, so generated installation can never depend on
/// family ordering.
pub fn build_prototype_installation_index(
    families: &[&[IntrinsicRow]],
) -> Result<PrototypeInstallationIndex, CodegenError> {
    let mut entries = BTreeMap::new();
    for family in families {
        for installation in generate_prototype_installations(family)? {
            let key = (installation.constructor, installation.property);
            if entries.insert(key, installation).is_some() {
                return Err(CodegenError::DuplicatePrototypeProperty {
                    constructor: key.0,
                    property: key.1,
                });
            }
        }
    }
    Ok(PrototypeInstallationIndex { entries })
}

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
            target: DispatchTarget::from_row(row),
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
    use crate::intrinsics_table::SEED_ROWS;

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
        assert_eq!(glue.registry.len(), SEED_ROWS.len());
        assert_eq!(glue.dispatch.len(), SEED_ROWS.len());
        assert_eq!(glue.gap_entries.len(), SEED_ROWS.len());
        glue.verify().expect("glue is internally consistent");
    }

    #[test]
    fn array_family_generates_verified_glue() {
        let glue = generate_glue(array_prototype::ROWS).expect("Array table generates glue");
        assert_eq!(glue.registry.len(), array_prototype::ROWS.len());
        assert_eq!(glue.dispatch.len(), array_prototype::ROWS.len());
        assert_eq!(glue.gap_entries.len(), array_prototype::ROWS.len());
        glue.verify().expect("Array glue is internally consistent");
    }

    #[test]
    fn array_family_generates_exact_prototype_targets_and_attributes() {
        let installations = generate_prototype_installations(array_prototype::ROWS)
            .expect("Array table must generate prototype installations");
        assert_eq!(installations.len(), array_prototype::ROWS.len());
        let push = installations
            .iter()
            .find(|entry| entry.property == "push")
            .expect("push installation");
        assert_eq!(push.constructor, "Array");
        assert_eq!(push.canonical_name, "Array.prototype.push");
        assert_eq!(push.receiver, ReceiverKind::Array);
        assert_eq!(push.this_coercion, ThisCoercion::Passthrough);
        assert_eq!(push.ifc, IfcPropagation::JoinReceiverAndArgs);
        assert!(push.capability.is_none());
        assert!(push.writable);
        assert!(!push.enumerable);
        assert!(push.configurable);
        assert!(matches!(&push.dispatch_target, DispatchTarget::Manual { .. }));
    }

    #[test]
    fn string_family_can_generate_prototype_installations_too() {
        let installations = generate_prototype_installations(
            crate::intrinsics_table::string_prototype::ROWS,
        )
        .expect("String table must generate prototype installations");
        assert_eq!(installations.len(), 26);
        assert!(installations.iter().all(|entry| entry.constructor == "String"));
        assert!(installations.iter().all(|entry| entry.writable));
        assert!(installations.iter().all(|entry| !entry.enumerable));
        assert!(installations.iter().all(|entry| entry.configurable));
    }

    #[test]
    fn migrated_families_share_one_collision_free_installation_index() {
        let index = build_prototype_installation_index(&[
            crate::intrinsics_table::string_prototype::ROWS,
            array_prototype::ROWS,
        ])
        .expect("String + Array installation index");
        assert_eq!(index.len(), 60);
        assert_eq!(
            index.get("String", "trim").map(|entry| entry.canonical_name),
            Some("String.prototype.trim")
        );
        assert_eq!(
            index.get("Array", "push").map(|entry| entry.canonical_name),
            Some("Array.prototype.push")
        );
    }

    #[test]
    fn duplicate_family_installation_is_refused() {
        assert!(matches!(
            build_prototype_installation_index(&[
                array_prototype::ROWS,
                array_prototype::ROWS,
            ]),
            Err(CodegenError::DuplicatePrototypeProperty {
                constructor: "Array",
                ..
            })
        ));
    }

    #[test]
    fn prototype_installation_rejects_receiver_name_mismatch() {
        let row = IntrinsicRow {
            name: "String.prototype.trim",
            receiver: ReceiverKind::Array,
            this_coercion: ThisCoercion::Passthrough,
            arity: Arity::Exact(0),
            capability: None,
            ifc: IfcPropagation::PropagateReceiverLabel,
            impl_binding: ImplBinding::Manual {
                reason: "test",
                site: "test",
            },
            conformance: "test",
            gap_status: GapStatus::Resolved,
        };
        assert!(matches!(
            generate_prototype_installations(&[row]),
            Err(CodegenError::PrototypeReceiverMismatch { .. })
        ));
    }

    #[test]
    fn prototype_installation_rejects_nonprototype_rows() {
        assert!(matches!(
            generate_prototype_installations(&[SEED_ROWS[3].clone()]),
            Err(CodegenError::NotPrototypeIntrinsic("Date.now"))
        ));
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
        let dup = [SEED_ROWS[0].clone(), SEED_ROWS[0].clone()];
        assert!(matches!(
            generate_glue(&dup),
            Err(CodegenError::DuplicateName(_))
        ));
    }
}
