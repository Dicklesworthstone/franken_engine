//! Declarative intrinsic-table schema — Dueling-Wizards E4.T1 (`bd-fqlfw.4.1`).
//!
//! # Why this exists
//! Language-surface completion is the codebase's dominant day-to-day cost. Today every
//! builtin/prototype method is added via a fragile "5-seam assembly line": a
//! [`BuiltinFunctionKind`](crate::baseline_interpreter) variant, a name/constructor mapping,
//! an exec arm in `dispatch_builtin_function`, prototype wiring in `string_property_value` /
//! `array_prototype_method` / `collection_prototype_method`, plus a `lowering_gap_inventory`
//! entry — all scattered across the 1.25 MB interpreter and constantly colliding between
//! agents. This module defines the **schema** for collapsing those five edit sites into ONE
//! declarative [`IntrinsicRow`]. Build-time codegen (E4.T2, `bd-fqlfw.4.2`) will expand each
//! row into the dispatch arm, capability tag, IFC-propagation glue, and gap-inventory entry —
//! all consistent by construction.
//!
//! # Load-bearing rules (from the E4 epic)
//! * **Glue only.** Codegen emits *only* boring glue (enum variants, dispatch arms, property
//!   installers, capability/IFC metadata, gap+conformance links). The SEMANTIC body of every
//!   intrinsic stays an ordinary, individually-tested Rust function referenced by
//!   [`ImplBinding::Generated`] — generated semantics would erode reviewers' grasp of where
//!   behavior comes from, which is unacceptable in a security runtime.
//! * **Escape hatch, not an over-narrow schema.** Irregular builtins that cannot be
//!   table-generated are expressed via [`ImplBinding::Manual`] with a documented reason +
//!   manual site, so the table never blocks an exotic case and never lies about coverage.
//! * **Uniform IFC propagation.** Label propagation is a *declared per-row policy*
//!   ([`IfcPropagation`]), not ad-hoc per-site code — this removes the class of under-tainting
//!   bugs that arose from hand-wiring propagation at each site (e.g. `bd-0zybl`).
//!
//! This module is the schema + a small illustrative seed + invariant validation. It references
//! the real [`RuntimeCapability`] and [`LabelClass`] enums directly so the schema cannot drift
//! from the authority/IFC algebras it must agree with.

use crate::capability::RuntimeCapability;
use crate::flow_lattice::LabelClass;

/// The receiver shape an intrinsic dispatches against. Mirrors the existing dispatch seams:
/// global builtins, `string_property_value` (String), `array_prototype_method` (Array), and
/// `collection_prototype_method(type_tag, ..)` (Map/Set/WeakMap/WeakSet/Date), plus object
/// statics, `Number`, and constructors (`new X(..)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiverKind {
    /// A bare global with no `this` (e.g. `require`, `console.log`, `Math.max`).
    Global,
    /// `String.prototype.*` — dispatched via `string_property_value`.
    String,
    /// `Array.prototype.*` — dispatched via `array_prototype_method`.
    Array,
    /// `Object.*` static or `Object.prototype.*`.
    Object,
    /// `Number.prototype.*` / `Number.*`.
    Number,
    /// A `__type`-tagged collection (`"Map"`, `"Set"`, `"WeakMap"`, `"WeakSet"`, `"Date"`),
    /// dispatched via `collection_prototype_method`.
    Collection(&'static str),
    /// A constructor invoked with `new` (the tag is the constructor name, e.g. `"Date"`).
    Constructor(&'static str),
}

/// Arity contract for the explicit argument list (the receiver/`this` is excluded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arity {
    /// Exactly `n` arguments.
    Exact(u8),
    /// At least `n` arguments (no upper bound).
    AtLeast(u8),
    /// Between `min` and `max` arguments inclusive (optional trailing args).
    Range { min: u8, max: u8 },
    /// `required` fixed leading args followed by a rest/variadic tail.
    Variadic { required: u8 },
}

/// How the receiver / `this` value is coerced before the semantic impl runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThisCoercion {
    /// No receiver (global function).
    None,
    /// `ToString(this)` boxing for `String.prototype.*`.
    ToString,
    /// Generic `ToObject(this)`.
    ToObject,
    /// Brand check: the receiver must carry `__type == tag` (e.g. `Map`/`Set`/`Date`),
    /// otherwise dispatch fails closed with a `TypeError`.
    RequireType(&'static str),
    /// Receiver used as-is (e.g. a real array for `Array.prototype.*`).
    Passthrough,
}

/// IFC label-propagation policy for an intrinsic's *result*. Declared once per row so the
/// generated label glue is uniform (no hand-wired per-site propagation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfcPropagation {
    /// Result label ≥ receiver label (the common case for prototype methods).
    PropagateReceiverLabel,
    /// Result label = join(receiver, all argument labels) (e.g. `Array.prototype.concat`).
    JoinReceiverAndArgs,
    /// Result label = join(argument labels) only (static fns with no meaningful receiver,
    /// e.g. `Math.max`).
    JoinArgs,
    /// Result carries a fixed label regardless of inputs (e.g. `Date.now` → `Public`).
    Constant(LabelClass),
    /// Escape hatch: a hand-written propagation fn (named) for irregular flows.
    Custom(&'static str),
}

/// Binding from a row to its hand-written semantic implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImplBinding {
    /// Codegen wires the dispatch seam to this hand-written fn; the fn holds the semantics.
    Generated {
        /// Name of the hand-written `fn` implementing the method's behavior.
        impl_fn: &'static str,
    },
    /// Escape hatch for builtins whose dispatch cannot be table-generated. The row records
    /// WHY and points at the manual site so coverage accounting stays honest.
    Manual {
        /// Why this intrinsic resists table generation.
        reason: &'static str,
        /// The manual dispatch site (file:symbol) that owns it.
        site: &'static str,
    },
}

/// Status the generated `lowering_gap_inventory` entry will carry for this construct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GapStatus {
    /// Fully implemented + conformance-backed.
    Resolved,
    /// Partially implemented; the note explains the residual gap.
    Partial(&'static str),
    /// Declared but not yet implemented.
    Planned,
}

/// One declarative intrinsic. Replaces the hand-wired five-seam edits with a single row that
/// codegen expands consistently. All fields are `&'static`/`Copy`-friendly so a complete table
/// can live in a `const`/`static` and be consumed by `build.rs` without allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrinsicRow {
    /// Canonical JS name, e.g. `"String.prototype.trim"` or `"Date.now"`.
    pub name: &'static str,
    /// Receiver shape / dispatch seam.
    pub receiver: ReceiverKind,
    /// Receiver/`this` coercion applied before the impl runs.
    pub this_coercion: ThisCoercion,
    /// Argument arity contract.
    pub arity: Arity,
    /// Typed authority this intrinsic requires, if any. Pure builtins are `None`.
    pub capability: Option<RuntimeCapability>,
    /// Declared IFC result-label propagation policy.
    pub ifc: IfcPropagation,
    /// Binding to the hand-written semantics (or the documented escape hatch).
    pub impl_binding: ImplBinding,
    /// Test262 path backing this intrinsic, or `""` if none is wired yet.
    pub conformance: &'static str,
    /// Gap-inventory status codegen will emit.
    pub gap_status: GapStatus,
}

impl IntrinsicRow {
    /// True when this row uses the manual escape hatch rather than generated dispatch.
    pub fn is_escape_hatch(&self) -> bool {
        matches!(self.impl_binding, ImplBinding::Manual { .. })
    }

    /// Validate basic structural invariants of a row. Returns `Err` with a human-readable
    /// reason on violation. (Codegen in E4.T2 runs this over the whole table and fails closed.)
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("intrinsic name must be non-empty".to_string());
        }
        // A global function must not declare a receiver coercion other than `None`.
        if matches!(self.receiver, ReceiverKind::Global)
            && !matches!(self.this_coercion, ThisCoercion::None)
        {
            return Err(format!(
                "{}: Global receiver requires ThisCoercion::None, found {:?}",
                self.name, self.this_coercion
            ));
        }
        // A non-global receiver must declare a real coercion (never `None`).
        if !matches!(self.receiver, ReceiverKind::Global)
            && matches!(self.this_coercion, ThisCoercion::None)
        {
            return Err(format!(
                "{}: non-Global receiver must declare a ThisCoercion",
                self.name
            ));
        }
        // A Range arity must be well-ordered.
        if let Arity::Range { min, max } = self.arity {
            if min > max {
                return Err(format!("{}: Range arity min {min} > max {max}", self.name));
            }
        }
        // Escape-hatch rows must document a reason and a site.
        if let ImplBinding::Manual { reason, site } = self.impl_binding {
            if reason.is_empty() || site.is_empty() {
                return Err(format!(
                    "{}: Manual escape-hatch rows must document both reason and site",
                    self.name
                ));
            }
        }
        Ok(())
    }
}

/// A small, illustrative seed proving the schema spans the real variety the dispatch seams
/// exhibit. This is NOT the full table — E4.T3 (`bd-fqlfw.4.3`) migrates a complete family
/// (String/Array) and E4.T2 generates code from rows shaped like these. The seed exists so the
/// schema is exercised + tested from day one.
pub const SEED_ROWS: &[IntrinsicRow] = &[
    // Simple, pure, receiver-aware prototype method.
    IntrinsicRow {
        name: "String.prototype.trim",
        receiver: ReceiverKind::String,
        this_coercion: ThisCoercion::ToString,
        arity: Arity::Exact(0),
        capability: None,
        ifc: IfcPropagation::PropagateReceiverLabel,
        impl_binding: ImplBinding::Generated {
            impl_fn: "string_trim_impl",
        },
        conformance: "test262:built-ins/String/prototype/trim",
        gap_status: GapStatus::Resolved,
    },
    // Variadic, joins receiver + all args (the IFC subtlety the schema must capture).
    IntrinsicRow {
        name: "Array.prototype.concat",
        receiver: ReceiverKind::Array,
        this_coercion: ThisCoercion::Passthrough,
        arity: Arity::Variadic { required: 0 },
        capability: None,
        ifc: IfcPropagation::JoinReceiverAndArgs,
        impl_binding: ImplBinding::Generated {
            impl_fn: "array_concat_impl",
        },
        conformance: "test262:built-ins/Array/prototype/concat",
        gap_status: GapStatus::Resolved,
    },
    // The hard case: a callback-driven method with `thisArg` + abrupt completion. Expressed via
    // the escape hatch rather than contorting the schema — proving the table never blocks an
    // exotic builtin.
    IntrinsicRow {
        name: "Array.prototype.reduce",
        receiver: ReceiverKind::Array,
        this_coercion: ThisCoercion::Passthrough,
        arity: Arity::Range { min: 1, max: 2 },
        capability: None,
        ifc: IfcPropagation::Custom("array_reduce_ifc"),
        impl_binding: ImplBinding::Manual {
            reason: "callback dispatch + thisArg + abrupt-completion unwinding cannot be \
                     table-generated; label propagation depends on the callback's return label",
            site: "baseline_interpreter.rs:invoke_simple_reduce_callback",
        },
        conformance: "test262:built-ins/Array/prototype/reduce",
        gap_status: GapStatus::Partial("callback-lane IFC labels pending (bd-ooaka.1)"),
    },
    // Constant-labelled static (Date.now reads the clock -> Public, never inherits a label).
    IntrinsicRow {
        name: "Date.now",
        receiver: ReceiverKind::Global,
        this_coercion: ThisCoercion::None,
        arity: Arity::Exact(0),
        capability: None,
        ifc: IfcPropagation::Constant(LabelClass::Public),
        impl_binding: ImplBinding::Generated {
            impl_fn: "date_now_impl",
        },
        conformance: "test262:built-ins/Date/now",
        gap_status: GapStatus::Resolved,
    },
    // Brand-checked collection method (must be invoked on a real Map).
    IntrinsicRow {
        name: "Map.prototype.get",
        receiver: ReceiverKind::Collection("Map"),
        this_coercion: ThisCoercion::RequireType("Map"),
        arity: Arity::Exact(1),
        capability: None,
        ifc: IfcPropagation::PropagateReceiverLabel,
        impl_binding: ImplBinding::Generated {
            impl_fn: "map_get_impl",
        },
        conformance: "test262:built-ins/Map/prototype/get",
        gap_status: GapStatus::Resolved,
    },
    // Effectful global requiring a typed capability (module loading).
    IntrinsicRow {
        name: "require",
        receiver: ReceiverKind::Global,
        this_coercion: ThisCoercion::None,
        arity: Arity::Exact(1),
        capability: Some(RuntimeCapability::ModuleLoad),
        ifc: IfcPropagation::JoinArgs,
        impl_binding: ImplBinding::Generated {
            impl_fn: "require_impl",
        },
        conformance: "",
        gap_status: GapStatus::Resolved,
    },
];

/// Validate the entire seed table and assert name-uniqueness. Codegen (E4.T2) will run this
/// shape over the full table and fail the build on any violation.
pub fn validate_table(rows: &[IntrinsicRow]) -> Result<(), String> {
    for row in rows {
        row.validate()?;
    }
    // name-uniqueness (sorted compare; LC_ALL-independent since names are ASCII)
    let mut names: Vec<&str> = rows.iter().map(|r| r.name).collect();
    names.sort_unstable();
    for pair in names.windows(2) {
        if pair[0] == pair[1] {
            return Err(format!("duplicate intrinsic name: {}", pair[0]));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_table_is_valid_and_unique() {
        validate_table(SEED_ROWS).expect("seed intrinsic table must validate");
    }

    #[test]
    fn schema_expresses_the_hard_callback_case_via_escape_hatch() {
        let reduce = SEED_ROWS
            .iter()
            .find(|r| r.name == "Array.prototype.reduce")
            .expect("reduce seed row present");
        assert!(
            reduce.is_escape_hatch(),
            "reduce must use the Manual escape hatch"
        );
        assert!(
            matches!(reduce.ifc, IfcPropagation::Custom(_)),
            "reduce result label is callback-dependent -> Custom propagation"
        );
    }

    #[test]
    fn schema_expresses_constant_labelled_static() {
        let now = SEED_ROWS.iter().find(|r| r.name == "Date.now").unwrap();
        assert_eq!(now.ifc, IfcPropagation::Constant(LabelClass::Public));
        assert!(matches!(now.receiver, ReceiverKind::Global));
    }

    #[test]
    fn schema_expresses_variadic_and_capability_rows() {
        let concat = SEED_ROWS
            .iter()
            .find(|r| r.name == "Array.prototype.concat")
            .unwrap();
        assert_eq!(concat.arity, Arity::Variadic { required: 0 });
        assert_eq!(concat.ifc, IfcPropagation::JoinReceiverAndArgs);

        let require_row = SEED_ROWS.iter().find(|r| r.name == "require").unwrap();
        assert_eq!(require_row.capability, Some(RuntimeCapability::ModuleLoad));
    }

    #[test]
    fn validate_rejects_global_with_receiver_coercion() {
        let bad = IntrinsicRow {
            name: "Bad.global",
            receiver: ReceiverKind::Global,
            this_coercion: ThisCoercion::ToString, // illegal for a Global
            arity: Arity::Exact(0),
            capability: None,
            ifc: IfcPropagation::JoinArgs,
            impl_binding: ImplBinding::Generated { impl_fn: "x" },
            conformance: "",
            gap_status: GapStatus::Planned,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn validate_rejects_nonglobal_without_coercion_and_bad_range() {
        let no_coercion = IntrinsicRow {
            name: "Bad.method",
            receiver: ReceiverKind::String,
            this_coercion: ThisCoercion::None, // illegal for non-Global
            arity: Arity::Exact(0),
            capability: None,
            ifc: IfcPropagation::PropagateReceiverLabel,
            impl_binding: ImplBinding::Generated { impl_fn: "x" },
            conformance: "",
            gap_status: GapStatus::Planned,
        };
        assert!(no_coercion.validate().is_err());

        let bad_range = IntrinsicRow {
            name: "Bad.range",
            receiver: ReceiverKind::Global,
            this_coercion: ThisCoercion::None,
            arity: Arity::Range { min: 3, max: 1 },
            capability: None,
            ifc: IfcPropagation::JoinArgs,
            impl_binding: ImplBinding::Generated { impl_fn: "x" },
            conformance: "",
            gap_status: GapStatus::Planned,
        };
        assert!(bad_range.validate().is_err());
    }

    #[test]
    fn escape_hatch_rows_must_document_reason_and_site() {
        let undocumented = IntrinsicRow {
            name: "Bad.manual",
            receiver: ReceiverKind::Array,
            this_coercion: ThisCoercion::Passthrough,
            arity: Arity::Exact(0),
            capability: None,
            ifc: IfcPropagation::PropagateReceiverLabel,
            impl_binding: ImplBinding::Manual {
                reason: "",
                site: "",
            },
            conformance: "",
            gap_status: GapStatus::Planned,
        };
        assert!(undocumented.validate().is_err());
    }
}
