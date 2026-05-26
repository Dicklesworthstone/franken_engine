#![forbid(unsafe_code)]

//! IFC label-propagation translation validation (G.6.F — bd-cixqu.7.9.6).
//!
//! Extends the G.4/G.5/G.6.A translation-validation programme to the
//! information-flow-control (IFC) label subset. The IFC lattice
//! `Public < Internal < Confidential < Secret < TopSecret`
//! (mirror of [`flow_lattice::LabelClass`]) propagates a security label
//! through every *join* on derived data: a value derived from several inputs
//! carries the **least upper bound** (lub) of their labels. Lowering this to
//! IR3 emits label markers — `AssignLabel`, `JoinLabels`, `Declassify`,
//! `SinkCheck` — and the runtime threads the label environment through them.
//!
//! A declassification (an explicit downgrade) is admitted **only** when backed
//! by a signed declassification receipt whose authorizer is trusted for the
//! governing decision contract — mirroring
//! [`flow_lattice::FlowLattice::use_declassification_with_receipt`] and the
//! [`ifc_artifacts::DeclassificationReceipt`] shape. Without a valid, trusted
//! receipt the downgrade is **refused** and the label stays high.
//!
//! G.6.F proves that the lowered IR3 propagates labels *identically* to the
//! source semantics. We do this with a small **differential abstract
//! interpreter**: one label evaluator is run over two views of the same
//! program —
//!
//!   * a **reference view**, whose label flow is dictated by the source
//!     structure (a join takes the lub of *all* its inputs; a declassification
//!     is admitted iff the source carries a valid trusted receipt); and
//!   * a **target view**, whose label flow is dictated by the IR3 markers
//!     *actually emitted* by the lowering (a join takes the lub of exactly the
//!     inputs the lowering listed, with whatever result the lowering forced; a
//!     declassification is admitted iff the lowering's emitted decision says
//!     so).
//!
//! Translation validation succeeds iff the two views produce **identical
//! observable label traces** (each event carries the resulting label and the
//! running taint high-water mark). A "preserving-looking" lowering that
//! silently drops a join input, weakens a join result, forges a
//! declassification without a valid receipt, or spuriously refuses an
//! authorized downgrade therefore diverges from the reference and is
//! **rejected** — this is the G.6.F / G.11 negative case.
//!
//! The recorded [`IfcTrace`] *is* the witness: every [`IfcEvent`] carries the
//! [`LabelState`] after it (resulting label + high-water), so the validation
//! witness includes the full label-propagation transition sequence (G.6.F
//! acceptance criterion #1). Declassification-receipt validity, refusal
//! without a receipt, and lattice ordering / join idempotence are all covered
//! lemmas (acceptance criterion #2/#3).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// IFC security lattice (mirror of flow_lattice::LabelClass)
// ---------------------------------------------------------------------------

/// A security label in the confidentiality lattice
/// `Public < Internal < Confidential < Secret < TopSecret`. Mirrors
/// [`flow_lattice::LabelClass`]; declared low-to-high so the variant order
/// equals the lattice order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityLabel {
    /// Public data — no restrictions (lattice bottom).
    Public,
    /// Internal engine state — limited access.
    Internal,
    /// Confidential data.
    Confidential,
    /// Secret data.
    Secret,
    /// Top-secret data (lattice top).
    TopSecret,
}

impl SecurityLabel {
    /// Every label, ascending. Used by the lattice-algebra lemmas.
    pub const ALL: [SecurityLabel; 5] = [
        SecurityLabel::Public,
        SecurityLabel::Internal,
        SecurityLabel::Confidential,
        SecurityLabel::Secret,
        SecurityLabel::TopSecret,
    ];

    /// Integer rank in the total order (0 = `Public`, 4 = `TopSecret`).
    pub fn level(self) -> u8 {
        match self {
            SecurityLabel::Public => 0,
            SecurityLabel::Internal => 1,
            SecurityLabel::Confidential => 2,
            SecurityLabel::Secret => 3,
            SecurityLabel::TopSecret => 4,
        }
    }

    /// Join (least upper bound) — the more sensitive of the two labels.
    pub fn join(self, other: SecurityLabel) -> SecurityLabel {
        if self.level() >= other.level() {
            self
        } else {
            other
        }
    }

    /// Meet (greatest lower bound) — the less sensitive of the two labels.
    pub fn meet(self, other: SecurityLabel) -> SecurityLabel {
        if self.level() <= other.level() {
            self
        } else {
            other
        }
    }

    /// Lattice ordering: `self` flows to `other` (is no more sensitive).
    pub fn leq(self, other: SecurityLabel) -> bool {
        self.level() <= other.level()
    }
}

// ---------------------------------------------------------------------------
// Declassification receipt (mirror of ifc_artifacts::DeclassificationReceipt)
// ---------------------------------------------------------------------------

/// A SSA-style variable / label slot identifier.
pub type VarId = u32;

/// A declassification receipt authorizing a downgrade. Self-contained mirror
/// of [`ifc_artifacts::DeclassificationReceipt`] keeping only the fields the
/// admission decision depends on; `signature_valid` abstracts the cryptographic
/// signature + validity-window checks of `DeclassificationReceipt::validate_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationReceipt {
    /// Decision contract that authorized this declassification
    /// (`decision_contract_id`).
    pub decision_contract_id: String,
    /// Verification key of the authorizer (`authorized_by`).
    pub authorized_by: String,
    /// Source label being declassified from (`source_label`).
    pub from: SecurityLabel,
    /// Target label being declassified to (`sink_clearance`).
    pub to: SecurityLabel,
    /// Whether the signature and validity window verify.
    pub signature_valid: bool,
}

/// The set of authorizer keys trusted for each decision contract — mirror of
/// `flow_lattice::FlowLattice::trusted_receipt_authorizers`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedAuthorizers {
    trusted: BTreeMap<String, BTreeSet<String>>,
}

impl TrustedAuthorizers {
    /// An empty trust set (no declassification is admissible).
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `authorizer` to authorize declassifications under `contract_id`.
    pub fn trust(&mut self, contract_id: impl Into<String>, authorizer: impl Into<String>) {
        self.trusted
            .entry(contract_id.into())
            .or_default()
            .insert(authorizer.into());
    }

    /// Whether `authorizer` is trusted for `contract_id`.
    pub fn trusts(&self, contract_id: &str, authorizer: &str) -> bool {
        self.trusted
            .get(contract_id)
            .is_some_and(|set| set.contains(authorizer))
    }
}

/// Decide whether a declassification of `actual_from` to `requested_to` is
/// admitted, mirroring `use_declassification_with_receipt`: the receipt must be
/// present, carry a verifying signature, be authorized by a trusted authorizer
/// for its decision contract, bind exactly the source label being declassified,
/// request exactly the target the program asks for, and move *down* the lattice
/// (declassification can only lower sensitivity).
pub fn declassification_admitted(
    receipt: Option<&DeclassificationReceipt>,
    actual_from: SecurityLabel,
    requested_to: SecurityLabel,
    trusted: &TrustedAuthorizers,
) -> bool {
    match receipt {
        None => false,
        Some(r) => {
            r.signature_valid
                && trusted.trusts(&r.decision_contract_id, &r.authorized_by)
                && r.from == actual_from
                && r.to == requested_to
                && requested_to.leq(actual_from)
        }
    }
}

// ---------------------------------------------------------------------------
// Source-level model of the IFC subset
// ---------------------------------------------------------------------------

/// A declassification request: lower the current label of a slot to `to`,
/// guarded by `receipt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Declassify {
    pub to: SecurityLabel,
    pub receipt: Option<DeclassificationReceipt>,
}

/// A source statement in the IFC subset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IfcStmt {
    /// Introduce a labeled value into slot `var`.
    Source { var: VarId, label: SecurityLabel },
    /// `dest := join(inputs)`, optionally declassified afterwards. The join
    /// takes the lub of every input's current label; a declassification (when
    /// present and admitted) then lowers `dest` to `declassify.to`.
    Derive {
        dest: VarId,
        inputs: Vec<VarId>,
        declassify: Option<Declassify>,
    },
    /// Observe slot `var` flowing to a sink of the given `clearance`.
    Sink {
        site: u32,
        var: VarId,
        clearance: SecurityLabel,
    },
}

// ---------------------------------------------------------------------------
// Observable label trace
// ---------------------------------------------------------------------------

/// Machine state recorded after each label event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelState {
    /// Label resulting from the operation that produced this event.
    pub result_label: SecurityLabel,
    /// Running least-upper-bound of every label assigned so far (the taint
    /// high-water mark). Non-decreasing across a faithful trace.
    pub high_water: SecurityLabel,
}

/// The kind of an observable label-propagation event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IfcEventKind {
    /// A source introduced `label` into `var`.
    Labeled { var: VarId, label: SecurityLabel },
    /// `dest` received the join of its inputs, yielding `result`.
    Joined { dest: VarId, result: SecurityLabel },
    /// A declassification of `dest` from `from` to `to` was admitted.
    Declassified {
        dest: VarId,
        from: SecurityLabel,
        to: SecurityLabel,
    },
    /// A declassification of `dest` was refused; the label stays at `retained`.
    DeclassifyRefused {
        dest: VarId,
        retained: SecurityLabel,
    },
    /// `var`'s label reached a sink; `allowed` = it flows to the clearance.
    SinkFlow {
        site: u32,
        label: SecurityLabel,
        clearance: SecurityLabel,
        allowed: bool,
    },
}

/// A single observable label event plus the machine state after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfcEvent {
    pub kind: IfcEventKind,
    pub state_after: LabelState,
}

/// An observable label-propagation trace.
pub type IfcTrace = Vec<IfcEvent>;

// ---------------------------------------------------------------------------
// Lowered IR3 label markers
// ---------------------------------------------------------------------------

/// A lowered IR3 label marker — the emit-phase output the validator checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoweredOp {
    /// `AssignLabel var <- label`.
    AssignLabel { var: VarId, label: SecurityLabel },
    /// `JoinLabels dest <- join(inputs)`. `inputs` is the set the lowering
    /// *actually* joins; `result_override` lets a (mis)lowering force a result
    /// instead of taking the lub.
    JoinLabels {
        dest: VarId,
        inputs: Vec<VarId>,
        result_override: Option<SecurityLabel>,
    },
    /// `Declassify dest -> to` guarded by `receipt`. `admit_override` forces the
    /// admission decision instead of recomputing it from the receipt + trust
    /// set; `None` = recompute faithfully.
    Declassify {
        dest: VarId,
        to: SecurityLabel,
        receipt: Option<DeclassificationReceipt>,
        admit_override: Option<bool>,
    },
    /// `SinkFlow` check of `var` against `clearance`.
    SinkCheck {
        site: u32,
        var: VarId,
        clearance: SecurityLabel,
    },
}

// ---------------------------------------------------------------------------
// Differential abstract interpreter
// ---------------------------------------------------------------------------

/// A unified evaluation op the single interpreter runs. Both the source
/// (reference) and lowered (target) views lower into this so divergence is a
/// pure trace comparison.
#[derive(Debug, Clone)]
enum EvalOp {
    Assign {
        var: VarId,
        label: SecurityLabel,
    },
    Join {
        dest: VarId,
        inputs: Vec<VarId>,
        result_override: Option<SecurityLabel>,
    },
    Declassify {
        dest: VarId,
        to: SecurityLabel,
        receipt: Option<DeclassificationReceipt>,
        admit_override: Option<bool>,
    },
    Sink {
        site: u32,
        var: VarId,
        clearance: SecurityLabel,
    },
}

fn to_reference_eval(program: &[IfcStmt]) -> Vec<EvalOp> {
    let mut out = Vec::new();
    for stmt in program {
        match stmt {
            IfcStmt::Source { var, label } => out.push(EvalOp::Assign {
                var: *var,
                label: *label,
            }),
            IfcStmt::Derive {
                dest,
                inputs,
                declassify,
            } => {
                // The reference join takes the lub of *all* declared inputs and
                // never overrides the result.
                out.push(EvalOp::Join {
                    dest: *dest,
                    inputs: inputs.clone(),
                    result_override: None,
                });
                if let Some(d) = declassify {
                    // The reference recomputes admission from the receipt.
                    out.push(EvalOp::Declassify {
                        dest: *dest,
                        to: d.to,
                        receipt: d.receipt.clone(),
                        admit_override: None,
                    });
                }
            }
            IfcStmt::Sink {
                site,
                var,
                clearance,
            } => out.push(EvalOp::Sink {
                site: *site,
                var: *var,
                clearance: *clearance,
            }),
        }
    }
    out
}

fn to_target_eval(lowered: &[LoweredOp]) -> Vec<EvalOp> {
    lowered
        .iter()
        .map(|op| match op {
            LoweredOp::AssignLabel { var, label } => EvalOp::Assign {
                var: *var,
                label: *label,
            },
            LoweredOp::JoinLabels {
                dest,
                inputs,
                result_override,
            } => EvalOp::Join {
                dest: *dest,
                inputs: inputs.clone(),
                result_override: *result_override,
            },
            LoweredOp::Declassify {
                dest,
                to,
                receipt,
                admit_override,
            } => EvalOp::Declassify {
                dest: *dest,
                to: *to,
                receipt: receipt.clone(),
                admit_override: *admit_override,
            },
            LoweredOp::SinkCheck {
                site,
                var,
                clearance,
            } => EvalOp::Sink {
                site: *site,
                var: *var,
                clearance: *clearance,
            },
        })
        .collect()
}

/// Run the unified ops, producing the observable label trace.
fn interpret(ops: &[EvalOp], trusted: &TrustedAuthorizers) -> IfcTrace {
    let mut env: BTreeMap<VarId, SecurityLabel> = BTreeMap::new();
    let mut high_water = SecurityLabel::Public;
    let mut trace = IfcTrace::new();

    let resolve = |env: &BTreeMap<VarId, SecurityLabel>, var: VarId| {
        env.get(&var).copied().unwrap_or(SecurityLabel::Public)
    };

    for op in ops {
        match op {
            EvalOp::Assign { var, label } => {
                env.insert(*var, *label);
                high_water = high_water.join(*label);
                trace.push(IfcEvent {
                    kind: IfcEventKind::Labeled {
                        var: *var,
                        label: *label,
                    },
                    state_after: LabelState {
                        result_label: *label,
                        high_water,
                    },
                });
            }
            EvalOp::Join {
                dest,
                inputs,
                result_override,
            } => {
                let lub = inputs
                    .iter()
                    .map(|v| resolve(&env, *v))
                    .fold(SecurityLabel::Public, SecurityLabel::join);
                let result = result_override.unwrap_or(lub);
                env.insert(*dest, result);
                high_water = high_water.join(result);
                trace.push(IfcEvent {
                    kind: IfcEventKind::Joined {
                        dest: *dest,
                        result,
                    },
                    state_after: LabelState {
                        result_label: result,
                        high_water,
                    },
                });
            }
            EvalOp::Declassify {
                dest,
                to,
                receipt,
                admit_override,
            } => {
                let actual_from = resolve(&env, *dest);
                let admitted = match admit_override {
                    Some(decision) => *decision,
                    None => declassification_admitted(receipt.as_ref(), actual_from, *to, trusted),
                };
                if admitted {
                    env.insert(*dest, *to);
                    trace.push(IfcEvent {
                        kind: IfcEventKind::Declassified {
                            dest: *dest,
                            from: actual_from,
                            to: *to,
                        },
                        // A declassification lowers the effective label but the
                        // high-water mark records what was *ever* observed.
                        state_after: LabelState {
                            result_label: *to,
                            high_water,
                        },
                    });
                } else {
                    trace.push(IfcEvent {
                        kind: IfcEventKind::DeclassifyRefused {
                            dest: *dest,
                            retained: actual_from,
                        },
                        state_after: LabelState {
                            result_label: actual_from,
                            high_water,
                        },
                    });
                }
            }
            EvalOp::Sink {
                site,
                var,
                clearance,
            } => {
                let label = resolve(&env, *var);
                let allowed = label.leq(*clearance);
                trace.push(IfcEvent {
                    kind: IfcEventKind::SinkFlow {
                        site: *site,
                        label,
                        clearance: *clearance,
                        allowed,
                    },
                    state_after: LabelState {
                        result_label: label,
                        high_water,
                    },
                });
            }
        }
    }

    trace
}

/// The source-dictated reference label trace.
pub fn reference_trace(program: &[IfcStmt], trusted: &TrustedAuthorizers) -> IfcTrace {
    interpret(&to_reference_eval(program), trusted)
}

/// The label trace dictated by the emitted IR3 markers.
pub fn target_trace(lowered: &[LoweredOp], trusted: &TrustedAuthorizers) -> IfcTrace {
    interpret(&to_target_eval(lowered), trusted)
}

/// The faithful lowering of an IFC source program: a join lowers to a
/// `JoinLabels` over *all* its inputs with no forced result, and a
/// declassification lowers to a `Declassify` that recomputes admission.
pub fn faithful_lower(program: &[IfcStmt]) -> Vec<LoweredOp> {
    let mut out = Vec::new();
    for stmt in program {
        match stmt {
            IfcStmt::Source { var, label } => out.push(LoweredOp::AssignLabel {
                var: *var,
                label: *label,
            }),
            IfcStmt::Derive {
                dest,
                inputs,
                declassify,
            } => {
                out.push(LoweredOp::JoinLabels {
                    dest: *dest,
                    inputs: inputs.clone(),
                    result_override: None,
                });
                if let Some(d) = declassify {
                    out.push(LoweredOp::Declassify {
                        dest: *dest,
                        to: d.to,
                        receipt: d.receipt.clone(),
                        admit_override: None,
                    });
                }
            }
            IfcStmt::Sink {
                site,
                var,
                clearance,
            } => out.push(LoweredOp::SinkCheck {
                site: *site,
                var: *var,
                clearance: *clearance,
            }),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Semantics-breaking transforms (negative-case generators)
// ---------------------------------------------------------------------------

/// A transformation that *looks* label-preserving but breaks IFC propagation.
/// Applying it to the first applicable op produces an IR3 stream the validator
/// must reject (whenever it actually changes the observable trace).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticsBreakingTransform {
    /// Drop one input from the first `JoinLabels`: the derived value is
    /// under-tainted when the dropped input was the most-sensitive one.
    DropJoinInput,
    /// Force the first join result to `Public`: an explicit downgrade with no
    /// declassification receipt.
    WeakenJoinResult,
    /// Force the first join result to `TopSecret`: over-classification (safe,
    /// but not label-identical to the source).
    OverclassifyJoinResult,
    /// Force-admit the first declassification regardless of its receipt: an
    /// illegal downgrade.
    ForgeDeclassification,
    /// Force-refuse the first declassification: drop an authorized downgrade.
    SpuriousDeclassifyRefusal,
}

/// Apply a semantics-breaking transform to the first op that admits it. Returns
/// `None` when no applicable op exists (so callers can skip).
pub fn apply_transform(
    lowered: &[LoweredOp],
    transform: SemanticsBreakingTransform,
) -> Option<Vec<LoweredOp>> {
    let mut out = lowered.to_vec();
    if mutate_first(&mut out, transform) {
        Some(out)
    } else {
        None
    }
}

fn mutate_first(ops: &mut [LoweredOp], transform: SemanticsBreakingTransform) -> bool {
    for op in ops.iter_mut() {
        match (transform, op) {
            (SemanticsBreakingTransform::DropJoinInput, LoweredOp::JoinLabels { inputs, .. })
                if !inputs.is_empty() =>
            {
                inputs.pop();
                return true;
            }
            (
                SemanticsBreakingTransform::WeakenJoinResult,
                LoweredOp::JoinLabels {
                    result_override, ..
                },
            ) => {
                *result_override = Some(SecurityLabel::Public);
                return true;
            }
            (
                SemanticsBreakingTransform::OverclassifyJoinResult,
                LoweredOp::JoinLabels {
                    result_override, ..
                },
            ) => {
                *result_override = Some(SecurityLabel::TopSecret);
                return true;
            }
            (
                SemanticsBreakingTransform::ForgeDeclassification,
                LoweredOp::Declassify { admit_override, .. },
            ) => {
                *admit_override = Some(true);
                return true;
            }
            (
                SemanticsBreakingTransform::SpuriousDeclassifyRefusal,
                LoweredOp::Declassify { admit_override, .. },
            ) => {
                *admit_override = Some(false);
                return true;
            }
            _ => {}
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Validation lemmas + result
// ---------------------------------------------------------------------------

/// IFC label-flow validation lemma classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IfcLemma {
    /// `join(a, b)` is the least upper bound of `a` and `b` across the lattice.
    JoinIsLeastUpperBound,
    /// `join(a, a) == a` for every label (idempotence).
    JoinIdempotent,
    /// Source and target label traces are flow-equivalent (identical event +
    /// label sequences).
    LabelFlowEquivalence,
    /// Every declassification decision agrees between source and target, and
    /// every admitted downgrade is backed by a valid trusted receipt.
    DeclassificationReceiptDiscipline,
    /// Every join result in the target equals the lub the source computes
    /// (catches dropped inputs, weakened results, and over-classification).
    JoinResultFidelity,
    /// Sink allow/deny decisions agree between source and target.
    SinkFlowAgreement,
}

/// A structured validation event (bd-cixqu.45 diagnostic discipline).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationEvent {
    pub lemma: IfcLemma,
    pub verified: bool,
    pub detail: String,
}

/// Result of IFC label-propagation translation validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfcValidationResult {
    pub validation_successful: bool,
    pub verified_lemmas: Vec<IfcLemma>,
    pub failed_lemmas: Vec<IfcLemma>,
    pub flow_equivalence_proven: bool,
    /// Index of the first divergent trace event, when equivalence fails.
    pub first_divergence: Option<usize>,
    pub events: Vec<ValidationEvent>,
}

impl IfcValidationResult {
    /// Render the event log as JSONL (one event per line) for the bd-cixqu.45
    /// diagnostic surface.
    pub fn events_jsonl(&self) -> String {
        self.events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Translation-validation context for the IFC label subset.
#[derive(Debug, Clone)]
pub struct IfcValidationContext {
    source: Vec<IfcStmt>,
    lowered: Vec<LoweredOp>,
    trusted: TrustedAuthorizers,
}

impl IfcValidationContext {
    /// Build a context from a source program, a candidate lowering, and the
    /// trusted-authorizer set.
    pub fn new(source: Vec<IfcStmt>, lowered: Vec<LoweredOp>, trusted: TrustedAuthorizers) -> Self {
        Self {
            source,
            lowered,
            trusted,
        }
    }

    /// Build a context whose lowering is the faithful lowering of the source
    /// (the positive / expected case).
    pub fn faithful(source: Vec<IfcStmt>, trusted: TrustedAuthorizers) -> Self {
        let lowered = faithful_lower(&source);
        Self {
            source,
            lowered,
            trusted,
        }
    }

    /// Run translation validation, proving label-flow equivalence between the
    /// source and the candidate lowering.
    pub fn validate(&self) -> IfcValidationResult {
        let reference = reference_trace(&self.source, &self.trusted);
        let target = target_trace(&self.lowered, &self.trusted);

        let mut verified = Vec::new();
        let mut failed = Vec::new();
        let mut events = Vec::new();

        // Lattice soundness: join is the lub the validator relies on.
        record(
            &mut events,
            &mut verified,
            &mut failed,
            IfcLemma::JoinIsLeastUpperBound,
            join_is_least_upper_bound(),
            "join(a,b) is the least upper bound of a and b across the lattice",
        );

        // Lattice soundness: join idempotence.
        record(
            &mut events,
            &mut verified,
            &mut failed,
            IfcLemma::JoinIdempotent,
            join_is_idempotent(),
            "join(a,a) == a for every label",
        );

        // Full label-flow equivalence — the event + label sequences match.
        let first_divergence = first_divergence(&reference, &target);
        let flow_ok = first_divergence.is_none();
        record(
            &mut events,
            &mut verified,
            &mut failed,
            IfcLemma::LabelFlowEquivalence,
            flow_ok,
            "source and target label traces are flow-equivalent",
        );

        // Declassification discipline — decisions agree and admitted downgrades
        // are backed by a valid trusted receipt in the reference semantics.
        let declassify_ok = declassify_decisions_match(&reference, &target)
            && admitted_declassifications_are_authorized(&self.source, &self.trusted);
        record(
            &mut events,
            &mut verified,
            &mut failed,
            IfcLemma::DeclassificationReceiptDiscipline,
            declassify_ok,
            "declassification decisions agree and every admitted downgrade has a valid trusted receipt",
        );

        // Join-result fidelity — every join result in the target equals the lub
        // the source computes (a precise diagnostic for under-tainting,
        // weakening, and over-classification).
        let join_ok = join_results_match(&reference, &target);
        record(
            &mut events,
            &mut verified,
            &mut failed,
            IfcLemma::JoinResultFidelity,
            join_ok,
            "every join result in the target equals the least-upper-bound the source computes",
        );

        // Sink-flow agreement — allow/deny decisions match.
        let sink_ok = sink_decisions_match(&reference, &target);
        record(
            &mut events,
            &mut verified,
            &mut failed,
            IfcLemma::SinkFlowAgreement,
            sink_ok,
            "sink allow/deny decisions agree between source and target",
        );

        IfcValidationResult {
            validation_successful: failed.is_empty(),
            verified_lemmas: verified,
            failed_lemmas: failed,
            flow_equivalence_proven: flow_ok,
            first_divergence,
            events,
        }
    }
}

fn record(
    events: &mut Vec<ValidationEvent>,
    verified: &mut Vec<IfcLemma>,
    failed: &mut Vec<IfcLemma>,
    lemma: IfcLemma,
    ok: bool,
    detail: &str,
) {
    events.push(ValidationEvent {
        lemma,
        verified: ok,
        detail: detail.to_string(),
    });
    if ok {
        verified.push(lemma);
    } else {
        failed.push(lemma);
    }
}

/// Verify `join` is the least upper bound across every pair: it dominates both
/// operands, equals one of them, and is commutative.
fn join_is_least_upper_bound() -> bool {
    for a in SecurityLabel::ALL {
        for b in SecurityLabel::ALL {
            let j = a.join(b);
            if !a.leq(j) || !b.leq(j) {
                return false;
            }
            if j != a && j != b {
                return false;
            }
            if a.join(b) != b.join(a) {
                return false;
            }
            // Least: no label strictly below `j` is an upper bound of both.
            for c in SecurityLabel::ALL {
                if a.leq(c) && b.leq(c) && c.leq(j) && c != j {
                    return false;
                }
            }
        }
    }
    true
}

fn join_is_idempotent() -> bool {
    SecurityLabel::ALL.iter().all(|a| a.join(*a) == *a)
}

fn first_divergence(reference: &IfcTrace, target: &IfcTrace) -> Option<usize> {
    let max = reference.len().max(target.len());
    for i in 0..max {
        match (reference.get(i), target.get(i)) {
            (Some(a), Some(b)) if a.kind == b.kind && a.state_after == b.state_after => continue,
            _ => return Some(i),
        }
    }
    None
}

/// The ordered sequence of declassification decisions in a trace.
fn declassify_decisions(trace: &IfcTrace) -> Vec<(VarId, bool, SecurityLabel)> {
    trace
        .iter()
        .filter_map(|e| match e.kind {
            IfcEventKind::Declassified { dest, to, .. } => Some((dest, true, to)),
            IfcEventKind::DeclassifyRefused { dest, retained } => Some((dest, false, retained)),
            _ => None,
        })
        .collect()
}

fn declassify_decisions_match(reference: &IfcTrace, target: &IfcTrace) -> bool {
    declassify_decisions(reference) == declassify_decisions(target)
}

/// Every declassification the *reference* admits must be backed by a valid,
/// trusted receipt under [`declassification_admitted`].
fn admitted_declassifications_are_authorized(
    program: &[IfcStmt],
    trusted: &TrustedAuthorizers,
) -> bool {
    let mut env: BTreeMap<VarId, SecurityLabel> = BTreeMap::new();
    for stmt in program {
        match stmt {
            IfcStmt::Source { var, label } => {
                env.insert(*var, *label);
            }
            IfcStmt::Derive {
                dest,
                inputs,
                declassify,
            } => {
                let lub = inputs
                    .iter()
                    .map(|v| env.get(v).copied().unwrap_or(SecurityLabel::Public))
                    .fold(SecurityLabel::Public, SecurityLabel::join);
                env.insert(*dest, lub);
                if let Some(d) = declassify {
                    let admitted =
                        declassification_admitted(d.receipt.as_ref(), lub, d.to, trusted);
                    if admitted {
                        // An admitted downgrade must carry a genuinely valid receipt.
                        if !matches!(d.receipt.as_ref(), Some(r) if r.signature_valid) {
                            return false;
                        }
                        env.insert(*dest, d.to);
                    }
                }
            }
            IfcStmt::Sink { .. } => {}
        }
    }
    true
}

/// The ordered sequence of join results in a trace.
fn join_results(trace: &IfcTrace) -> Vec<(VarId, SecurityLabel)> {
    trace
        .iter()
        .filter_map(|e| match e.kind {
            IfcEventKind::Joined { dest, result } => Some((dest, result)),
            _ => None,
        })
        .collect()
}

fn join_results_match(reference: &IfcTrace, target: &IfcTrace) -> bool {
    join_results(reference) == join_results(target)
}

fn sink_decisions(trace: &IfcTrace) -> Vec<(u32, bool)> {
    trace
        .iter()
        .filter_map(|e| match e.kind {
            IfcEventKind::SinkFlow { site, allowed, .. } => Some((site, allowed)),
            _ => None,
        })
        .collect()
}

fn sink_decisions_match(reference: &IfcTrace, target: &IfcTrace) -> bool {
    sink_decisions(reference) == sink_decisions(target)
}

// ---------------------------------------------------------------------------
// Test-program generator (>=50 programs across the required categories)
// ---------------------------------------------------------------------------

/// The IFC behaviour a generated program exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramCategory {
    LatticeOrdering,
    JoinIdempotence,
    JoinMultipleInputs,
    DeclassifyWithReceipt,
    DeclassifyRefusedNoReceipt,
    DeclassifyRefusedUntrusted,
    DeclassifyRefusedInvalidSignature,
    SinkFlowAllowed,
    SinkFlowViolation,
}

/// A generated IFC test program tagged with its category and trust set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfcTestProgram {
    pub name: String,
    pub category: ProgramCategory,
    pub program: Vec<IfcStmt>,
    pub trusted: TrustedAuthorizers,
}

fn src(var: VarId, label: SecurityLabel) -> IfcStmt {
    IfcStmt::Source { var, label }
}

fn sink(site: u32, var: VarId, clearance: SecurityLabel) -> IfcStmt {
    IfcStmt::Sink {
        site,
        var,
        clearance,
    }
}

fn receipt(
    contract: &str,
    authorizer: &str,
    from: SecurityLabel,
    to: SecurityLabel,
    signature_valid: bool,
) -> DeclassificationReceipt {
    DeclassificationReceipt {
        decision_contract_id: contract.to_string(),
        authorized_by: authorizer.to_string(),
        from,
        to,
        signature_valid,
    }
}

/// Generate >=50 IFC programs covering every required category: lattice
/// ordering, join idempotence, multi-input joins, declassification with a valid
/// receipt, declassification refused (no receipt / untrusted authorizer /
/// invalid signature), and sink flows (allowed and violating). Every program's
/// faithful lowering validates successfully.
pub fn generate_ifc_test_programs() -> Vec<IfcTestProgram> {
    let mut out = Vec::new();
    let labels = SecurityLabel::ALL;

    // LatticeOrdering: a single labeled source observed at top clearance.
    for (i, label) in labels.iter().enumerate() {
        let mut trusted = TrustedAuthorizers::new();
        let _ = &mut trusted;
        out.push(IfcTestProgram {
            name: format!("lattice_ordering_{}", label.level()),
            category: ProgramCategory::LatticeOrdering,
            program: vec![
                src(0, *label),
                sink(100 + i as u32, 0, SecurityLabel::TopSecret),
            ],
            trusted: TrustedAuthorizers::new(),
        });
    }

    // JoinIdempotence: derive join(a, a) == a.
    for (i, label) in labels.iter().enumerate() {
        out.push(IfcTestProgram {
            name: format!("join_idempotence_{}", label.level()),
            category: ProgramCategory::JoinIdempotence,
            program: vec![
                src(0, *label),
                IfcStmt::Derive {
                    dest: 1,
                    inputs: vec![0, 0],
                    declassify: None,
                },
                sink(200 + i as u32, 1, SecurityLabel::TopSecret),
            ],
            trusted: TrustedAuthorizers::new(),
        });
    }

    // JoinMultipleInputs: derive join of distinct labels; result = max.
    for (i, hi) in labels.iter().enumerate() {
        for (j, lo) in labels.iter().enumerate() {
            if lo.level() >= hi.level() {
                continue;
            }
            out.push(IfcTestProgram {
                name: format!("join_multi_{}_{}", hi.level(), lo.level()),
                category: ProgramCategory::JoinMultipleInputs,
                program: vec![
                    src(0, *lo),
                    src(1, *hi),
                    IfcStmt::Derive {
                        dest: 2,
                        inputs: vec![0, 1],
                        declassify: None,
                    },
                    sink(300 + (i * 5 + j) as u32, 2, SecurityLabel::TopSecret),
                ],
                trusted: TrustedAuthorizers::new(),
            });
        }
    }

    // JoinMultipleInputs: three-input joins; result = max of the three.
    for (a, b, c) in [
        (
            SecurityLabel::Public,
            SecurityLabel::Internal,
            SecurityLabel::Secret,
        ),
        (
            SecurityLabel::Public,
            SecurityLabel::Confidential,
            SecurityLabel::TopSecret,
        ),
        (
            SecurityLabel::Internal,
            SecurityLabel::Confidential,
            SecurityLabel::Secret,
        ),
        (
            SecurityLabel::Public,
            SecurityLabel::Internal,
            SecurityLabel::Confidential,
        ),
    ] {
        out.push(IfcTestProgram {
            name: format!("join_triple_{}_{}_{}", a.level(), b.level(), c.level()),
            category: ProgramCategory::JoinMultipleInputs,
            program: vec![
                src(0, a),
                src(1, b),
                src(2, c),
                IfcStmt::Derive {
                    dest: 3,
                    inputs: vec![0, 1, 2],
                    declassify: None,
                },
                sink(350 + a.level() as u32, 3, SecurityLabel::TopSecret),
            ],
            trusted: TrustedAuthorizers::new(),
        });
    }

    // DeclassifyWithReceipt: valid trusted receipt downgrades the label.
    for (i, from) in labels.iter().enumerate() {
        for to in labels.iter() {
            if to.level() >= from.level() {
                continue;
            }
            let mut trusted = TrustedAuthorizers::new();
            trusted.trust("contract.declassify.v1", "authority.alpha");
            out.push(IfcTestProgram {
                name: format!("declassify_ok_{}_{}", from.level(), to.level()),
                category: ProgramCategory::DeclassifyWithReceipt,
                program: vec![
                    src(0, *from),
                    IfcStmt::Derive {
                        dest: 1,
                        inputs: vec![0],
                        declassify: Some(Declassify {
                            to: *to,
                            receipt: Some(receipt(
                                "contract.declassify.v1",
                                "authority.alpha",
                                *from,
                                *to,
                                true,
                            )),
                        }),
                    },
                    sink(400 + i as u32, 1, *to),
                ],
                trusted,
            });
        }
    }

    // DeclassifyRefusedNoReceipt: downgrade requested without any receipt.
    for from in [
        SecurityLabel::Internal,
        SecurityLabel::Confidential,
        SecurityLabel::Secret,
        SecurityLabel::TopSecret,
    ] {
        out.push(IfcTestProgram {
            name: format!("declassify_no_receipt_{}", from.level()),
            category: ProgramCategory::DeclassifyRefusedNoReceipt,
            program: vec![
                src(0, from),
                IfcStmt::Derive {
                    dest: 1,
                    inputs: vec![0],
                    declassify: Some(Declassify {
                        to: SecurityLabel::Public,
                        receipt: None,
                    }),
                },
                sink(500 + from.level() as u32, 1, SecurityLabel::TopSecret),
            ],
            trusted: TrustedAuthorizers::new(),
        });
    }

    // DeclassifyRefusedUntrusted: receipt present but authorizer not trusted.
    for from in [
        SecurityLabel::Confidential,
        SecurityLabel::Secret,
        SecurityLabel::TopSecret,
    ] {
        // Trust set covers a *different* authorizer.
        let mut trusted = TrustedAuthorizers::new();
        trusted.trust("contract.declassify.v1", "authority.alpha");
        out.push(IfcTestProgram {
            name: format!("declassify_untrusted_{}", from.level()),
            category: ProgramCategory::DeclassifyRefusedUntrusted,
            program: vec![
                src(0, from),
                IfcStmt::Derive {
                    dest: 1,
                    inputs: vec![0],
                    declassify: Some(Declassify {
                        to: SecurityLabel::Public,
                        receipt: Some(receipt(
                            "contract.declassify.v1",
                            "authority.rogue",
                            from,
                            SecurityLabel::Public,
                            true,
                        )),
                    }),
                },
                sink(600 + from.level() as u32, 1, SecurityLabel::TopSecret),
            ],
            trusted,
        });
    }

    // DeclassifyRefusedInvalidSignature: trusted authorizer but bad signature.
    for from in [
        SecurityLabel::Confidential,
        SecurityLabel::Secret,
        SecurityLabel::TopSecret,
    ] {
        let mut trusted = TrustedAuthorizers::new();
        trusted.trust("contract.declassify.v1", "authority.alpha");
        out.push(IfcTestProgram {
            name: format!("declassify_bad_sig_{}", from.level()),
            category: ProgramCategory::DeclassifyRefusedInvalidSignature,
            program: vec![
                src(0, from),
                IfcStmt::Derive {
                    dest: 1,
                    inputs: vec![0],
                    declassify: Some(Declassify {
                        to: SecurityLabel::Public,
                        receipt: Some(receipt(
                            "contract.declassify.v1",
                            "authority.alpha",
                            from,
                            SecurityLabel::Public,
                            false,
                        )),
                    }),
                },
                sink(700 + from.level() as u32, 1, SecurityLabel::TopSecret),
            ],
            trusted,
        });
    }

    // SinkFlowAllowed: label flows to a clearance that dominates it.
    for label in labels {
        out.push(IfcTestProgram {
            name: format!("sink_allowed_{}", label.level()),
            category: ProgramCategory::SinkFlowAllowed,
            program: vec![src(0, label), sink(800 + label.level() as u32, 0, label)],
            trusted: TrustedAuthorizers::new(),
        });
    }

    // SinkFlowViolation: label exceeds the sink clearance (still faithfully
    // lowered, so translation validation must preserve the violation).
    for label in [
        SecurityLabel::Internal,
        SecurityLabel::Confidential,
        SecurityLabel::Secret,
        SecurityLabel::TopSecret,
    ] {
        out.push(IfcTestProgram {
            name: format!("sink_violation_{}", label.level()),
            category: ProgramCategory::SinkFlowViolation,
            program: vec![
                src(0, label),
                sink(900 + label.level() as u32, 0, SecurityLabel::Public),
            ],
            trusted: TrustedAuthorizers::new(),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- lattice algebra -------------------------------------------------

    #[test]
    fn join_is_lub_over_all_pairs() {
        assert!(join_is_least_upper_bound());
    }

    #[test]
    fn join_idempotent_over_all() {
        assert!(join_is_idempotent());
    }

    #[test]
    fn join_commutative_and_associative() {
        for a in SecurityLabel::ALL {
            for b in SecurityLabel::ALL {
                assert_eq!(a.join(b), b.join(a));
                for c in SecurityLabel::ALL {
                    assert_eq!(a.join(b).join(c), a.join(b.join(c)));
                }
            }
        }
    }

    #[test]
    fn meet_is_glb() {
        for a in SecurityLabel::ALL {
            for b in SecurityLabel::ALL {
                let m = a.meet(b);
                assert!(m.leq(a) && m.leq(b));
                assert!(m == a || m == b);
            }
        }
    }

    #[test]
    fn leq_is_total_order() {
        for a in SecurityLabel::ALL {
            for b in SecurityLabel::ALL {
                assert!(a.leq(b) || b.leq(a));
            }
        }
    }

    // ---- corpus ----------------------------------------------------------

    #[test]
    fn corpus_has_at_least_50_programs() {
        assert!(generate_ifc_test_programs().len() >= 50);
    }

    #[test]
    fn corpus_covers_all_categories() {
        use ProgramCategory::*;
        let programs = generate_ifc_test_programs();
        for cat in [
            LatticeOrdering,
            JoinIdempotence,
            JoinMultipleInputs,
            DeclassifyWithReceipt,
            DeclassifyRefusedNoReceipt,
            DeclassifyRefusedUntrusted,
            DeclassifyRefusedInvalidSignature,
            SinkFlowAllowed,
            SinkFlowViolation,
        ] {
            assert!(
                programs.iter().any(|p| p.category == cat),
                "missing category {cat:?}"
            );
        }
    }

    #[test]
    fn every_corpus_program_validates_faithfully() {
        for p in generate_ifc_test_programs() {
            let result =
                IfcValidationContext::faithful(p.program.clone(), p.trusted.clone()).validate();
            assert!(
                result.validation_successful,
                "program {} ({:?}) failed lemmas {:?}",
                p.name, p.category, result.failed_lemmas
            );
            assert!(result.flow_equivalence_proven);
            assert_eq!(result.events.len(), 6);
        }
    }

    #[test]
    fn faithful_reference_equals_target() {
        for p in generate_ifc_test_programs() {
            let reference = reference_trace(&p.program, &p.trusted);
            let target = target_trace(&faithful_lower(&p.program), &p.trusted);
            assert_eq!(reference, target, "{} diverged", p.name);
        }
    }

    // ---- declassification semantics --------------------------------------

    fn secret_source_declassify(
        to: SecurityLabel,
        receipt: Option<DeclassificationReceipt>,
    ) -> Vec<IfcStmt> {
        vec![
            src(0, SecurityLabel::Secret),
            IfcStmt::Derive {
                dest: 1,
                inputs: vec![0],
                declassify: Some(Declassify { to, receipt }),
            },
        ]
    }

    #[test]
    fn declassify_with_valid_receipt_is_admitted() {
        let mut trusted = TrustedAuthorizers::new();
        trusted.trust("c", "alice");
        let program = secret_source_declassify(
            SecurityLabel::Public,
            Some(receipt(
                "c",
                "alice",
                SecurityLabel::Secret,
                SecurityLabel::Public,
                true,
            )),
        );
        let trace = reference_trace(&program, &trusted);
        assert!(matches!(
            trace.last().unwrap().kind,
            IfcEventKind::Declassified {
                to: SecurityLabel::Public,
                ..
            }
        ));
    }

    #[test]
    fn declassify_without_receipt_is_refused() {
        let trusted = TrustedAuthorizers::new();
        let program = secret_source_declassify(SecurityLabel::Public, None);
        let trace = reference_trace(&program, &trusted);
        assert!(matches!(
            trace.last().unwrap().kind,
            IfcEventKind::DeclassifyRefused {
                retained: SecurityLabel::Secret,
                ..
            }
        ));
    }

    #[test]
    fn declassify_with_untrusted_authorizer_is_refused() {
        let mut trusted = TrustedAuthorizers::new();
        trusted.trust("c", "alice");
        let program = secret_source_declassify(
            SecurityLabel::Public,
            Some(receipt(
                "c",
                "mallory",
                SecurityLabel::Secret,
                SecurityLabel::Public,
                true,
            )),
        );
        let trace = reference_trace(&program, &trusted);
        assert!(matches!(
            trace.last().unwrap().kind,
            IfcEventKind::DeclassifyRefused { .. }
        ));
    }

    #[test]
    fn declassify_with_invalid_signature_is_refused() {
        let mut trusted = TrustedAuthorizers::new();
        trusted.trust("c", "alice");
        let program = secret_source_declassify(
            SecurityLabel::Public,
            Some(receipt(
                "c",
                "alice",
                SecurityLabel::Secret,
                SecurityLabel::Public,
                false,
            )),
        );
        let trace = reference_trace(&program, &trusted);
        assert!(matches!(
            trace.last().unwrap().kind,
            IfcEventKind::DeclassifyRefused { .. }
        ));
    }

    #[test]
    fn declassify_with_mismatched_target_is_refused() {
        // Receipt authorizes Secret->Confidential, but the program requests
        // Secret->Public: the binding does not match, so it is refused.
        let mut trusted = TrustedAuthorizers::new();
        trusted.trust("c", "alice");
        let program = secret_source_declassify(
            SecurityLabel::Public,
            Some(receipt(
                "c",
                "alice",
                SecurityLabel::Secret,
                SecurityLabel::Confidential,
                true,
            )),
        );
        let trace = reference_trace(&program, &trusted);
        assert!(matches!(
            trace.last().unwrap().kind,
            IfcEventKind::DeclassifyRefused { .. }
        ));
    }

    #[test]
    fn declassify_upgrade_attempt_is_refused() {
        // Requesting a *higher* target is not a declassification; refused.
        let mut trusted = TrustedAuthorizers::new();
        trusted.trust("c", "alice");
        let program = vec![
            src(0, SecurityLabel::Confidential),
            IfcStmt::Derive {
                dest: 1,
                inputs: vec![0],
                declassify: Some(Declassify {
                    to: SecurityLabel::Secret,
                    receipt: Some(receipt(
                        "c",
                        "alice",
                        SecurityLabel::Confidential,
                        SecurityLabel::Secret,
                        true,
                    )),
                }),
            },
        ];
        let trace = reference_trace(&program, &trusted);
        assert!(matches!(
            trace.last().unwrap().kind,
            IfcEventKind::DeclassifyRefused { .. }
        ));
    }

    // ---- semantics-breaking transforms are rejected ----------------------

    /// A program that joins Public + Secret then declassifies to Public with a
    /// valid trusted receipt — every transform breaks it.
    fn rich_program() -> (Vec<IfcStmt>, TrustedAuthorizers) {
        let mut trusted = TrustedAuthorizers::new();
        trusted.trust("c", "alice");
        let program = vec![
            src(0, SecurityLabel::Public),
            src(1, SecurityLabel::Secret),
            IfcStmt::Derive {
                dest: 2,
                inputs: vec![0, 1],
                declassify: Some(Declassify {
                    to: SecurityLabel::Public,
                    receipt: Some(receipt(
                        "c",
                        "alice",
                        SecurityLabel::Secret,
                        SecurityLabel::Public,
                        true,
                    )),
                }),
            },
            sink(10, 2, SecurityLabel::Public),
        ];
        (program, trusted)
    }

    /// A program whose faithful declassification is *refused* (no receipt):
    /// the source retains `Secret`. Forging an admission diverges.
    fn refused_program() -> (Vec<IfcStmt>, TrustedAuthorizers) {
        (
            secret_source_declassify(SecurityLabel::Public, None),
            TrustedAuthorizers::new(),
        )
    }

    fn assert_transform_rejected(
        transform: SemanticsBreakingTransform,
        program: Vec<IfcStmt>,
        trusted: TrustedAuthorizers,
    ) {
        let faithful = faithful_lower(&program);
        let mutated = apply_transform(&faithful, transform)
            .unwrap_or_else(|| panic!("{transform:?} not applicable"));
        // It must actually change the observable trace...
        let faithful_target = target_trace(&faithful, &trusted);
        let mutated_target = target_trace(&mutated, &trusted);
        assert_ne!(
            faithful_target, mutated_target,
            "{transform:?} did not change the trace"
        );
        // ...and the validator must reject the mutated lowering.
        let result = IfcValidationContext::new(program, mutated, trusted).validate();
        assert!(
            !result.validation_successful,
            "{transform:?} was not rejected (failed: {:?})",
            result.failed_lemmas
        );
    }

    #[test]
    fn drop_join_input_rejected() {
        let (p, t) = rich_program();
        assert_transform_rejected(SemanticsBreakingTransform::DropJoinInput, p, t);
    }

    #[test]
    fn weaken_join_result_rejected() {
        let (p, t) = rich_program();
        assert_transform_rejected(SemanticsBreakingTransform::WeakenJoinResult, p, t);
    }

    #[test]
    fn overclassify_join_result_rejected() {
        let (p, t) = rich_program();
        assert_transform_rejected(SemanticsBreakingTransform::OverclassifyJoinResult, p, t);
    }

    #[test]
    fn forge_declassification_rejected() {
        // Forging only changes behaviour when the faithful decision is refusal.
        let (p, t) = refused_program();
        assert_transform_rejected(SemanticsBreakingTransform::ForgeDeclassification, p, t);
    }

    #[test]
    fn spurious_declassify_refusal_rejected() {
        // Spuriously refusing only changes behaviour when faithful admits.
        let (p, t) = rich_program();
        assert_transform_rejected(SemanticsBreakingTransform::SpuriousDeclassifyRefusal, p, t);
    }

    #[test]
    fn forge_declassification_breaks_receipt_discipline() {
        // A program that refuses (no receipt); forging the admission turns a
        // DeclassifyRefused into a Declassified, so the declassification
        // decisions no longer agree.
        let (program, trusted) = refused_program();
        let faithful = faithful_lower(&program);
        let forged =
            apply_transform(&faithful, SemanticsBreakingTransform::ForgeDeclassification).unwrap();
        let result = IfcValidationContext::new(program, forged, trusted).validate();
        assert!(!result.validation_successful);
        assert!(
            result
                .failed_lemmas
                .contains(&IfcLemma::DeclassificationReceiptDiscipline)
        );
    }

    #[test]
    fn every_transform_breaks_some_corpus_program() {
        use SemanticsBreakingTransform::*;
        for transform in [
            DropJoinInput,
            WeakenJoinResult,
            OverclassifyJoinResult,
            ForgeDeclassification,
            SpuriousDeclassifyRefusal,
        ] {
            let mut observed_break = false;
            for p in generate_ifc_test_programs() {
                let faithful = faithful_lower(&p.program);
                if let Some(mutated) = apply_transform(&faithful, transform) {
                    let faithful_target = target_trace(&faithful, &p.trusted);
                    let mutated_target = target_trace(&mutated, &p.trusted);
                    if faithful_target != mutated_target {
                        let result = IfcValidationContext::new(
                            p.program.clone(),
                            mutated,
                            p.trusted.clone(),
                        )
                        .validate();
                        assert!(
                            !result.validation_successful,
                            "{transform:?} on {} not rejected",
                            p.name
                        );
                        observed_break = true;
                    }
                }
            }
            assert!(
                observed_break,
                "{transform:?} never broke any corpus program"
            );
        }
    }

    // ---- sink-flow preservation ------------------------------------------

    #[test]
    fn sink_flow_violation_is_preserved_not_repaired() {
        // A Secret value into a Public sink is a violation; the faithful
        // lowering preserves the violation (allowed == false in both views).
        let trusted = TrustedAuthorizers::new();
        let program = vec![
            src(0, SecurityLabel::Secret),
            sink(1, 0, SecurityLabel::Public),
        ];
        let result = IfcValidationContext::faithful(program.clone(), trusted.clone()).validate();
        assert!(result.validation_successful);
        let trace = reference_trace(&program, &trusted);
        assert!(matches!(
            trace.last().unwrap().kind,
            IfcEventKind::SinkFlow { allowed: false, .. }
        ));
    }

    // ---- diagnostics / serde ---------------------------------------------

    #[test]
    fn events_jsonl_has_line_per_lemma() {
        let (program, trusted) = rich_program();
        let result = IfcValidationContext::faithful(program, trusted).validate();
        assert_eq!(result.events_jsonl().lines().count(), 6);
    }

    #[test]
    fn first_divergence_index_is_reported() {
        let (program, trusted) = rich_program();
        let faithful = faithful_lower(&program);
        let mutated =
            apply_transform(&faithful, SemanticsBreakingTransform::WeakenJoinResult).unwrap();
        let result = IfcValidationContext::new(program, mutated, trusted).validate();
        assert!(result.first_divergence.is_some());
    }

    #[test]
    fn result_serde_roundtrip() {
        let (program, trusted) = rich_program();
        let result = IfcValidationContext::faithful(program, trusted).validate();
        let json = serde_json::to_string(&result).unwrap();
        let back: IfcValidationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn trace_serde_roundtrip() {
        let (program, trusted) = rich_program();
        let trace = reference_trace(&program, &trusted);
        let json = serde_json::to_string(&trace).unwrap();
        let back: IfcTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(trace, back);
    }
}
