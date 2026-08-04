//! Corpus promotion pipeline (Track U — bd-cixqu.21.2).
//!
//! Closes the red-team feedback loop: an attack that SUCCEEDS (achieves a
//! manifested containment-bypass) must not stay a one-off. It is
//!
//!   1. minimized to a minimal reproducer via [`hierarchical_delta_debug`], then
//!   2. gated by [`acquisition_experiment_oracle`] so only genuine, *reproduced*
//!      bypasses are admitted (a candidate that does not reliably re-trigger the
//!      bypass yields zero information gain and is rejected), and finally
//!   3. promoted into the red-team scenario corpus as a committed regression in
//!      the `franken-engine.red-team-scenario.v1` manifest-pair format.
//!
//! The pipeline mirrors the plan-versus-execute discipline of
//! [`crate::coverage_frontier_filing`]: [`build_promotion_plan`] is a
//! side-effect-free planner (it runs the caller-supplied bypass oracle but never
//! touches the filesystem), while [`execute_plan`] is the explicit, gated writer
//! that materializes admitted promotions and records them in a [`PromotedLedger`]
//! for idempotency. A [`PromotionPlan`] carries a `plan_digest` — a single
//! content hash over its canonical sequence — so two runs over identical inputs
//! are provably identical.
//!
//! The pipeline is deliberately generic over a bypass *oracle*
//! (`Fn(&str) -> StepOutcome`), exactly like the delta debugger it drives. The
//! oracle decides how a candidate program is executed and whether the bypass is
//! still present; wiring a real engine (parse -> lower -> observe the containment
//! verdict) is the caller's job. This keeps the module hermetic and unit-testable
//! without an engine, and lets the same pipeline gate any containment defect.
//!
//! Per bd-cixqu.45 the pipeline emits a structured [`MinimizationTrace`] and an
//! [`OracleVerdict`] for every candidate it considers, so each promotion (or
//! rejection) is auditable.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::acquisition_experiment_oracle::{
    AcquisitionSignal, ExperimentKind, ExperimentProposal, record_outcome,
};
use crate::hash_tiers::ContentHash;
use crate::hierarchical_delta_debug::{
    DefectClass, DeltaDebugger, MinimalRepro, ReductionConfig, StepOutcome,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema + policy constants
// ---------------------------------------------------------------------------

/// Greppable marker embedded in every promoted scenario program, binding it to
/// this pipeline for corpus reconstruction and provenance.
pub const CORPUS_PROMOTION_MARKER: &str = "franken-engine:corpus-promotion:v1";

/// Manifest schema id every promoted scenario conforms to. Must match the
/// curated corpus contract enforced by the red-team manifest validator.
pub const RED_TEAM_SCENARIO_SCHEMA_VERSION: &str = "franken-engine.red-team-scenario.v1";

/// Baseline id every promoted scenario declares. Must match the curated corpus.
pub const RED_TEAM_BASELINE_VERSION: &str = "node-bun-frankenengine-red-team-v1";

/// Schema id for a serialized [`PromotionPlan`].
pub const PROMOTION_PLAN_SCHEMA_VERSION: &str = "franken-engine.corpus-promotion-plan.v1";

/// Schema id for a serialized [`PromotedLedger`].
pub const PROMOTION_LEDGER_SCHEMA_VERSION: &str = "franken-engine.corpus-promotion-ledger.v1";

/// Schema id for a serialized [`MinimizationTrace`].
pub const MINIMIZATION_TRACE_SCHEMA_VERSION: &str = "franken-engine.corpus-promotion-trace.v1";

/// Default number of independent reproduction trials the oracle gate runs on a
/// minimized candidate. A candidate must re-trigger the bypass on *every* trial
/// to be admitted; a flaky (non-deterministic) attack fails this check.
pub const DEFAULT_REPRODUCTION_TRIALS: u32 = 5;

/// Expected information gain (millionths) claimed for a corpus-addition proposal
/// that documents a genuine bypass. The oracle gate compares the actual gain —
/// scaled by reproduction stability — against this expectation.
pub const EXPECTED_BYPASS_GAIN_MILLIONTHS: u64 = 1_000_000;

/// Signal strength (millionths) attached to the adversarial-opportunity signal.
pub const DEFAULT_SIGNAL_STRENGTH_MILLIONTHS: u64 = 1_000_000;

/// Estimated cost (millionths) of admitting a scenario into the corpus.
pub const PROMOTION_COST_MILLIONTHS: u64 = 100_000;

// ---------------------------------------------------------------------------
// Attack candidate (pipeline input)
// ---------------------------------------------------------------------------

/// A successful attack offered to the pipeline for promotion.
///
/// Carries the raw attack program plus the metadata needed to render a
/// corpus-conformant manifest. The program's *bypass* is decided by the oracle
/// the caller supplies to [`build_promotion_plan`] — this struct never runs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackCandidate {
    /// Corpus scenario name (also the promoted file stem). Lower-snake.
    pub name: String,
    /// Human-readable scenario title.
    pub title: String,
    /// Attack-vector key (unique per curated scenario).
    pub attack_vector: String,
    /// Associated CWE identifiers (e.g. `"CWE-470"`).
    pub cwe: Vec<String>,
    /// The attack program source (pre-minimization).
    pub source: String,
    /// Payload input description.
    pub input: String,
    /// What the attack achieves when it succeeds.
    pub success_criteria: String,
    /// Observable on Node when the attack succeeds.
    pub node_observable: String,
    /// Observable on Bun when the attack succeeds.
    pub bun_observable: String,
    /// Observable on FrankenEngine when the attack is contained.
    pub frankenengine_observable: String,
    /// Machine-readable containment/denial reason on FrankenEngine.
    pub denial_reason: String,
    /// Measurement failure signal (what FrankenEngine does to defeat the attack).
    pub failure_signal: String,
    /// Strength (millionths) of the adversarial-opportunity acquisition signal.
    pub signal_strength_millionths: u64,
}

impl AttackCandidate {
    /// Construct a candidate with the essential fields, deriving conventional
    /// defaults for the remaining manifest metadata (all overridable via the
    /// public fields).
    pub fn new(
        name: impl Into<String>,
        title: impl Into<String>,
        attack_vector: impl Into<String>,
        source: impl Into<String>,
        denial_reason: impl Into<String>,
    ) -> Self {
        let name = name.into();
        let attack_vector = attack_vector.into();
        Self {
            title: title.into(),
            input: format!("attack program `{name}`"),
            success_criteria: format!("{attack_vector} bypass reaches the protected authority"),
            node_observable: "attack program runs to completion and reaches the sink".to_string(),
            bun_observable: "attack program runs to completion and reaches the sink".to_string(),
            frankenengine_observable:
                "FrankenEngine fails closed and refuses the attack before the sink is reached"
                    .to_string(),
            denial_reason: denial_reason.into(),
            failure_signal: "containment refuses the attack".to_string(),
            signal_strength_millionths: DEFAULT_SIGNAL_STRENGTH_MILLIONTHS,
            cwe: Vec::new(),
            name,
            attack_vector,
            source: source.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Minimization trace (bd-cixqu.45 logging)
// ---------------------------------------------------------------------------

/// Structured, auditable record of a single minimization run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimizationTrace {
    /// Schema id (`MINIMIZATION_TRACE_SCHEMA_VERSION`).
    pub schema_version: String,
    /// Candidate scenario name.
    pub candidate_name: String,
    /// Content-addressed repro id from the delta debugger.
    pub repro_id: String,
    /// Original attack source size (bytes).
    pub original_size: u32,
    /// Minimized source size (bytes).
    pub reduced_size: u32,
    /// Reduction ratio (millionths, `1_000_000` == 100% removed).
    pub reduction_ratio_millionths: u64,
    /// Total reduction steps attempted.
    pub total_steps: u32,
    /// Steps that made progress (a fragment was removable).
    pub progress_steps: u32,
    /// The minimized program source.
    pub minimized_source: String,
}

impl MinimizationTrace {
    fn from_repro(candidate_name: &str, repro: &MinimalRepro) -> Self {
        Self {
            schema_version: MINIMIZATION_TRACE_SCHEMA_VERSION.to_string(),
            candidate_name: candidate_name.to_string(),
            repro_id: repro.repro_id.clone(),
            original_size: repro.original_size,
            reduced_size: repro.reduced_size,
            reduction_ratio_millionths: repro.reduction_ratio_millionths,
            total_steps: repro.total_steps,
            progress_steps: repro.progress_steps,
            minimized_source: repro.source.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Oracle verdict (bd-cixqu.45 logging + admission decision)
// ---------------------------------------------------------------------------

/// The acquisition-oracle verdict for one candidate: the reproduction evidence,
/// the derived information-gain accounting, and the admission decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleVerdict {
    /// The acquisition proposal id this verdict belongs to.
    pub proposal_id: String,
    /// Number of reproduction trials run.
    pub total_trials: u32,
    /// Number of trials on which the bypass reproduced.
    pub reproduced_trials: u32,
    /// Expected information gain (millionths) claimed by the proposal.
    pub expected_gain_millionths: u64,
    /// Actual information gain (millionths), scaled by reproduction stability.
    pub actual_gain_millionths: u64,
    /// Regret (millionths) = `max(0, expected - actual)`.
    pub regret_millionths: u64,
    /// Surprise (millionths) = `|expected - actual|`.
    pub surprise_millionths: u64,
    /// Whether the candidate was admitted (regret within threshold).
    pub admitted: bool,
    /// Content hash (hex) of the sealed acquisition outcome.
    pub outcome_hash: String,
}

// ---------------------------------------------------------------------------
// Promoted scenario (manifest-pair artifact)
// ---------------------------------------------------------------------------

/// The serialized manifest-pair for a promoted scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotedScenario {
    /// Scenario name / file stem.
    pub name: String,
    /// The promoted program (`<name>.js` contents): provenance header + the
    /// minimized attack source.
    pub program_js: String,
    /// The manifest (`<name>.manifest.json` contents), pretty-printed.
    pub manifest_json: String,
    /// Content hash (hex) over `(name, program_js, manifest_json)`.
    pub content_hash: String,
}

/// Typed red-team manifest (serialized in declaration order to match the
/// curated corpus and satisfy the `red-team-scenario.v1` validator).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RedTeamManifest {
    schema_version: String,
    name: String,
    title: String,
    baseline_version: String,
    attack_vector: String,
    cwe: Vec<String>,
    payload: ManifestPayload,
    expected_outcome: ManifestExpectedOutcome,
    measurement: ManifestMeasurement,
    reproduction: Vec<String>,
    provenance: ManifestProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestPayload {
    program: String,
    entrypoint: String,
    input: String,
    success_criteria: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestExpectedOutcome {
    node: ManifestRuntimeOutcome,
    bun: ManifestRuntimeOutcome,
    frankenengine: ManifestRuntimeOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestRuntimeOutcome {
    outcome: String,
    observable: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    denial_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestMeasurement {
    success_signal: String,
    failure_signal: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestProvenance {
    marker: String,
    repro_id: String,
    minimized_from_bytes: u32,
    minimized_to_bytes: u32,
    reproduced_trials: u32,
    total_trials: u32,
}

// ---------------------------------------------------------------------------
// Ledger (idempotent dedup)
// ---------------------------------------------------------------------------

/// One ledger entry: a scenario already promoted into the corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotedRecord {
    /// Scenario name (dedup key).
    pub name: String,
    /// Content-addressed repro id of the minimized attack.
    pub repro_id: String,
    /// Content hash (hex) of the promoted manifest-pair.
    pub content_hash: String,
    /// Human-readable provenance note.
    pub note: String,
}

/// The dedup ledger, keyed on scenario `name`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotedLedger {
    /// Schema id (`PROMOTION_LEDGER_SCHEMA_VERSION`).
    pub schema_version: String,
    /// `name -> record` for every already-promoted scenario.
    pub records: BTreeMap<String, PromotedRecord>,
}

impl Default for PromotedLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl PromotedLedger {
    /// An empty ledger (nothing promoted yet).
    pub fn new() -> Self {
        Self {
            schema_version: PROMOTION_LEDGER_SCHEMA_VERSION.to_string(),
            records: BTreeMap::new(),
        }
    }

    /// Build a ledger from records (later duplicates overwrite earlier ones).
    pub fn from_records(records: impl IntoIterator<Item = PromotedRecord>) -> Self {
        let mut ledger = Self::new();
        for record in records {
            ledger.records.insert(record.name.clone(), record);
        }
        ledger
    }

    /// True when this scenario has already been promoted.
    pub fn contains(&self, name: &str) -> bool {
        self.records.contains_key(name)
    }

    /// Record a freshly-promoted scenario, returning any prior record.
    pub fn record(
        &mut self,
        name: impl Into<String>,
        repro_id: impl Into<String>,
        content_hash: impl Into<String>,
        note: impl Into<String>,
    ) -> Option<PromotedRecord> {
        let name = name.into();
        self.records.insert(
            name.clone(),
            PromotedRecord {
                name,
                repro_id: repro_id.into(),
                content_hash: content_hash.into(),
                note: note.into(),
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Promotion plan (planner output)
// ---------------------------------------------------------------------------

/// An admitted promotion: the minimization trace, the oracle verdict, and the
/// materialized scenario artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionProposal {
    /// Candidate scenario name.
    pub candidate_name: String,
    /// The minimization trace.
    pub minimization: MinimizationTrace,
    /// The oracle verdict (admitted).
    pub verdict: OracleVerdict,
    /// The promoted manifest-pair.
    pub scenario: PromotedScenario,
}

/// A candidate that was not promoted, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedCandidate {
    /// Candidate scenario name.
    pub candidate_name: String,
    /// Why it was skipped.
    pub reason: String,
    /// The oracle verdict, when one was reached (absent for dedup skips).
    pub verdict: Option<OracleVerdict>,
}

/// The deterministic promotion plan: what would be promoted, and what was not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionPlan {
    /// Schema id (`PROMOTION_PLAN_SCHEMA_VERSION`).
    pub schema_version: String,
    /// Number of candidates considered.
    pub considered_count: usize,
    /// Number of admitted promotions.
    pub promoted_count: usize,
    /// Number of candidates skipped.
    pub skipped_count: usize,
    /// Admitted promotions, in candidate order.
    pub proposals: Vec<PromotionProposal>,
    /// Skipped candidates, in candidate order.
    pub skipped: Vec<SkippedCandidate>,
    /// Content hash (hex) over the canonical plan sequence.
    pub plan_digest: String,
}

/// One audit record from executing a plan (a file-pair written).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionAudit {
    /// Scenario name.
    pub name: String,
    /// Absolute path of the written program file.
    pub program_path: PathBuf,
    /// Absolute path of the written manifest file.
    pub manifest_path: PathBuf,
    /// Content hash (hex) of the promoted manifest-pair.
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// Marker + content-hash helpers
// ---------------------------------------------------------------------------

/// The provenance marker line embedded in every promoted program.
pub fn marker_line(name: &str, repro_id: &str) -> String {
    format!("{CORPUS_PROMOTION_MARKER} name={name} repro_id={repro_id}")
}

fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

fn content_hash_hex(parts: &[&[u8]]) -> String {
    let mut buf = Vec::new();
    for part in parts {
        push_field(&mut buf, part);
    }
    ContentHash::compute(&buf).to_hex()
}

// ---------------------------------------------------------------------------
// Minimization
// ---------------------------------------------------------------------------

/// Minimize an attack to a minimal reproducer, preserving the bypass under the
/// supplied `oracle`. Returns the delta-debugger repro and an auditable trace.
///
/// The oracle receives a reduced program and returns whether the bypass is still
/// present ([`StepOutcome::DefectPreserved`]) or lost. Minimization is
/// deterministic for a deterministic oracle: identical inputs yield an identical
/// [`MinimalRepro`] (content-addressed `repro_id`).
pub fn minimize_attack<F>(
    candidate: &AttackCandidate,
    oracle: F,
) -> (MinimalRepro, MinimizationTrace)
where
    F: Fn(&str) -> StepOutcome,
{
    let mut debugger = DeltaDebugger::new(
        candidate.source.clone(),
        DefectClass::IfcViolation,
        ReductionConfig::default(),
        SecurityEpoch::from_raw(1),
    );
    let repro = debugger.reduce(&oracle);
    let trace = MinimizationTrace::from_repro(&candidate.name, &repro);
    (repro, trace)
}

// ---------------------------------------------------------------------------
// Oracle gate
// ---------------------------------------------------------------------------

/// Count how many of `trials` independent oracle runs on `source` reproduce the
/// bypass ([`StepOutcome::DefectPreserved`]).
fn reproduction_count<F>(source: &str, trials: u32, oracle: &F) -> u32
where
    F: Fn(&str) -> StepOutcome,
{
    let mut reproduced = 0u32;
    for _ in 0..trials {
        if oracle(source) == StepOutcome::DefectPreserved {
            reproduced += 1;
        }
    }
    reproduced
}

/// Gate a minimized candidate through the acquisition-experiment oracle.
///
/// The minimized program is replayed `trials` times; the actual information gain
/// is the expected gain scaled by the fraction of trials on which the bypass
/// reproduced. A fully-reproduced bypass has zero regret and is admitted; any
/// shortfall (a flaky or non-reproducing candidate) produces positive regret and
/// is rejected. This is a faithful use of the oracle: `record_outcome` compares
/// realized gain against the proposal's expectation and the regret drives
/// admission.
pub fn gate_candidate<F>(
    candidate: &AttackCandidate,
    minimized_source: &str,
    trials: u32,
    oracle: &F,
) -> OracleVerdict
where
    F: Fn(&str) -> StepOutcome,
{
    let reproduced = reproduction_count(minimized_source, trials, oracle);

    let proposal = ExperimentProposal::new(
        format!("corpus-promo:{}", candidate.name),
        ExperimentKind::CorpusAddition,
        candidate.attack_vector.clone(),
        vec![(
            AcquisitionSignal::AdversarialOpportunity,
            candidate.signal_strength_millionths,
        )],
        EXPECTED_BYPASS_GAIN_MILLIONTHS,
        EXPECTED_BYPASS_GAIN_MILLIONTHS,
        PROMOTION_COST_MILLIONTHS,
        format!(
            "Promote reproduced containment-bypass `{}` into the regression corpus",
            candidate.name
        ),
    );

    // Actual gain is realized only in proportion to reproduction stability, and
    // only when the bypass reproduced at least once (a candidate that never
    // reproduces yields no information).
    let actual_gain = if trials == 0 {
        0
    } else {
        EXPECTED_BYPASS_GAIN_MILLIONTHS.saturating_mul(u64::from(reproduced)) / u64::from(trials)
    };

    let outcome = record_outcome(&proposal, actual_gain);
    // The acquisition oracle is the admission gate: a genuine, fully-reproduced
    // bypass realizes exactly the expected information gain, so its regret is
    // zero. Any reproduction shortfall — a flaky candidate (partial trials) or a
    // non-reproducing one (zero trials of gain) — leaves positive regret and is
    // rejected. No flaky admissions.
    let admitted = outcome.regret_millionths == 0;

    OracleVerdict {
        proposal_id: proposal.proposal_id.clone(),
        total_trials: trials,
        reproduced_trials: reproduced,
        expected_gain_millionths: proposal.expected_information_gain_millionths,
        actual_gain_millionths: outcome.actual_information_gain_millionths,
        regret_millionths: outcome.regret_millionths,
        surprise_millionths: outcome.surprise_millionths,
        admitted,
        outcome_hash: outcome.content_hash.to_hex(),
    }
}

// ---------------------------------------------------------------------------
// Scenario rendering
// ---------------------------------------------------------------------------

/// Render the promoted program (`<name>.js`): a shebang, strict mode, a
/// provenance header carrying the greppable marker, then the minimized source.
fn render_program(candidate: &AttackCandidate, repro: &MinimalRepro) -> String {
    format!(
        "#! /usr/bin/env node\n\
         \"use strict\";\n\
         // {marker}\n\
         // Promoted from a successful red-team attack: minimized via\n\
         // hierarchical_delta_debug and gated by acquisition_experiment_oracle.\n\
         // Regression contract: FrankenEngine must fail closed on this program.\n\
         {source}\n",
        marker = marker_line(&candidate.name, &repro.repro_id),
        source = repro.source,
    )
}

/// Build the corpus-conformant [`PromotedScenario`] for an admitted candidate.
pub fn build_scenario(
    candidate: &AttackCandidate,
    repro: &MinimalRepro,
    verdict: &OracleVerdict,
) -> PromotedScenario {
    let program_js = render_program(candidate, repro);
    let program_file = format!("{}.js", candidate.name);

    let manifest = RedTeamManifest {
        schema_version: RED_TEAM_SCENARIO_SCHEMA_VERSION.to_string(),
        name: candidate.name.clone(),
        title: candidate.title.clone(),
        baseline_version: RED_TEAM_BASELINE_VERSION.to_string(),
        attack_vector: candidate.attack_vector.clone(),
        cwe: candidate.cwe.clone(),
        payload: ManifestPayload {
            program: program_file.clone(),
            entrypoint: format!("node {program_file}"),
            input: candidate.input.clone(),
            success_criteria: candidate.success_criteria.clone(),
        },
        expected_outcome: ManifestExpectedOutcome {
            node: ManifestRuntimeOutcome {
                outcome: "succeeds".to_string(),
                observable: candidate.node_observable.clone(),
                denial_reason: None,
            },
            bun: ManifestRuntimeOutcome {
                outcome: "succeeds".to_string(),
                observable: candidate.bun_observable.clone(),
                denial_reason: None,
            },
            frankenengine: ManifestRuntimeOutcome {
                outcome: "fail_closed".to_string(),
                observable: candidate.frankenengine_observable.clone(),
                denial_reason: Some(candidate.denial_reason.clone()),
            },
        },
        measurement: ManifestMeasurement {
            success_signal: "attack_succeeded == true".to_string(),
            failure_signal: candidate.failure_signal.clone(),
        },
        reproduction: vec![format!(
            "node crates/franken-engine/tests/red_team_scenarios/promoted/{program_file}"
        )],
        provenance: ManifestProvenance {
            marker: CORPUS_PROMOTION_MARKER.to_string(),
            repro_id: repro.repro_id.clone(),
            minimized_from_bytes: repro.original_size,
            minimized_to_bytes: repro.reduced_size,
            reproduced_trials: verdict.reproduced_trials,
            total_trials: verdict.total_trials,
        },
    };

    // `to_string_pretty` over a typed struct is deterministic: fields serialize
    // in declaration order, so identical inputs yield byte-identical manifests.
    let manifest_json =
        serde_json::to_string_pretty(&manifest).expect("red-team manifest serializes to JSON");

    let content_hash = content_hash_hex(&[
        candidate.name.as_bytes(),
        program_js.as_bytes(),
        manifest_json.as_bytes(),
    ]);

    PromotedScenario {
        name: candidate.name.clone(),
        program_js,
        manifest_json,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// Plan builder (side-effect free)
// ---------------------------------------------------------------------------

fn compute_plan_digest(proposals: &[PromotionProposal], skipped: &[SkippedCandidate]) -> String {
    let mut buf = Vec::new();
    for proposal in proposals {
        buf.push(0x01); // promoted tag
        push_field(&mut buf, proposal.candidate_name.as_bytes());
        push_field(&mut buf, proposal.minimization.repro_id.as_bytes());
        push_field(&mut buf, proposal.scenario.content_hash.as_bytes());
    }
    for skip in skipped {
        buf.push(0x02); // skipped tag
        push_field(&mut buf, skip.candidate_name.as_bytes());
        push_field(&mut buf, skip.reason.as_bytes());
    }
    ContentHash::compute(&buf).to_hex()
}

/// Build a deterministic, side-effect-free [`PromotionPlan`] from a batch of
/// candidates.
///
/// For each candidate, in order: already-promoted candidates (present in
/// `ledger`) are skipped; the rest are minimized, gated by the oracle, and — if
/// admitted — rendered into a corpus-conformant [`PromotedScenario`]. Rejected
/// candidates are recorded as [`SkippedCandidate`]s carrying their verdict. The
/// oracle runs, but no filesystem or ledger mutation occurs here.
pub fn build_promotion_plan<F>(
    candidates: &[AttackCandidate],
    ledger: &PromotedLedger,
    trials: u32,
    oracle: F,
) -> PromotionPlan
where
    F: Fn(&str) -> StepOutcome,
{
    let mut proposals = Vec::new();
    let mut skipped = Vec::new();

    for candidate in candidates {
        if ledger.contains(&candidate.name) {
            skipped.push(SkippedCandidate {
                candidate_name: candidate.name.clone(),
                reason: format!("already promoted (ledger hit for `{}`)", candidate.name),
                verdict: None,
            });
            continue;
        }

        let (repro, minimization) = minimize_attack(candidate, &oracle);
        let verdict = gate_candidate(candidate, &repro.source, trials, &oracle);

        if !verdict.admitted {
            skipped.push(SkippedCandidate {
                candidate_name: candidate.name.clone(),
                reason: format!(
                    "oracle rejected: reproduced {}/{} trials, regret {} millionths",
                    verdict.reproduced_trials, verdict.total_trials, verdict.regret_millionths
                ),
                verdict: Some(verdict),
            });
            continue;
        }

        let scenario = build_scenario(candidate, &repro, &verdict);
        proposals.push(PromotionProposal {
            candidate_name: candidate.name.clone(),
            minimization,
            verdict,
            scenario,
        });
    }

    let plan_digest = compute_plan_digest(&proposals, &skipped);
    PromotionPlan {
        schema_version: PROMOTION_PLAN_SCHEMA_VERSION.to_string(),
        considered_count: candidates.len(),
        promoted_count: proposals.len(),
        skipped_count: skipped.len(),
        proposals,
        skipped,
        plan_digest,
    }
}

// ---------------------------------------------------------------------------
// Execute (explicit, gated side effects)
// ---------------------------------------------------------------------------

/// Materialize a plan's admitted promotions into `target_dir` and record them in
/// `ledger`.
///
/// Writes `<name>.js` and `<name>.manifest.json` for each admitted proposal that
/// is not already in the ledger, creating `target_dir` if needed. Idempotent:
/// re-running with a ledger that already contains a promotion skips it. Returns
/// one audit record per file-pair written.
pub fn execute_plan(
    plan: &PromotionPlan,
    target_dir: &Path,
    ledger: &mut PromotedLedger,
) -> io::Result<Vec<PromotionAudit>> {
    fs::create_dir_all(target_dir)?;
    let mut audits = Vec::new();

    for proposal in &plan.proposals {
        let scenario = &proposal.scenario;
        if ledger.contains(&scenario.name) {
            continue;
        }

        let program_path = target_dir.join(format!("{}.js", scenario.name));
        let manifest_path = target_dir.join(format!("{}.manifest.json", scenario.name));
        fs::write(&program_path, &scenario.program_js)?;
        fs::write(&manifest_path, &scenario.manifest_json)?;

        ledger.record(
            scenario.name.clone(),
            proposal.minimization.repro_id.clone(),
            scenario.content_hash.clone(),
            format!("promoted via {CORPUS_PROMOTION_MARKER}"),
        );

        audits.push(PromotionAudit {
            name: scenario.name.clone(),
            program_path,
            manifest_path,
            content_hash: scenario.content_hash.clone(),
        });
    }

    Ok(audits)
}
