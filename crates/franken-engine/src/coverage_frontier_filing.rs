//! Gated auto-bead filing + intrinsic-table scaffolding (`bd-fqlfw.7.5`, E7.T5).
//!
//! This is the final executable rung of the E7 Conformance Frontier
//! (`bd-fqlfw.7`). The earlier rungs measured the gap:
//!
//! - E7.T1 ([`crate::coverage_frontier`]) clustered Test262 + differential-oracle
//!   failures into content-addressed clusters.
//! - E7.T2 ([`crate::coverage_frontier_rank`]) ranked those clusters by a
//!   transparent impact score.
//! - E7.T3 ([`crate::coverage_frontier_xref`]) truth-gated them against the
//!   parser/lowering gap inventories.
//! - E7.T4 ([`crate::coverage_summary`]) published the weighted coverage figure.
//!
//! This module turns the *ranked* frontier into an **advisory worklist of beads**
//! — one per top-N cluster — each carrying its failing-case list and a scaffolded
//! E4 [`IntrinsicRow`](crate::intrinsics_table::IntrinsicRow) ready for a human to
//! fill in. Re-running `br ready` then surfaces impact-ranked, pre-scaffolded
//! language work instead of the probe-driven guesswork the E7 epic was created to
//! replace.
//!
//! ## Two hard rules from the E7 epic (both encoded here)
//!
//! 1. **Dedup, keyed on the content-hashed cluster id.** A cluster that has
//!    already been filed (whether the resulting bead is still open or already
//!    closed) is *never* re-filed. The dedup ledger ([`FiledLedger`]) is keyed on
//!    `cluster_id`, which E7.T1 derived purely from `(source, construct)` — so the
//!    same gap hashes to the same id every run and dedup is exact. Each filed bead
//!    body also carries a machine-greppable [`AUTOFILE_MARKER`] line so the ledger
//!    can be rebuilt from the tracker if it is ever lost.
//! 2. **Human-review path, not unprompted creation.** [`build_filing_plan`] is a
//!    *pure* function: it produces a deterministic [`BeadFilingPlan`] (the exact
//!    `br create` commands + scaffolds) and performs **no side effects**. Actually
//!    filing the beads is a separate, explicitly-opted-into step in the operator
//!    binary (`franken_coverage_frontier --file-beads --execute`); the default is
//!    plan-only so an operator reviews the worklist before anything is created.
//!
//! ## Honest scaffolding
//!
//! Not every gap is a builtin. A `built-ins/*` cluster scaffolds a real
//! `IntrinsicRow` (the E4 one-row-plus-one-impl-fn shape). A `language/*` cluster
//! is a parser/lowering gap, *not* an intrinsic, so its scaffold says so and
//! points at the gap inventories rather than fabricating an inapplicable row. A
//! differential-oracle cluster is a runtime divergence and points at the oracle
//! triage surface. The scaffold never lies about which kind of work a cluster is.
//!
//! ## Determinism
//!
//! The plan is built by walking the already-rank-ordered clusters, every map is a
//! `BTreeMap`, the impact score stays in fixed-point `u128` millionths (no float),
//! and the `plan_digest` mixes length-prefixed fields. Identical
//! `(ranked, frontier, ledger, top_n)` inputs therefore yield a byte-identical
//! plan and digest.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::coverage_frontier::CoverageFrontierReport;
use crate::coverage_frontier_rank::{RankedCluster, RankedFrontierReport};
use crate::hash_tiers::ContentHash;

/// Schema id stamped on every emitted filing plan and ledger.
pub const COVERAGE_FRONTIER_FILING_SCHEMA_VERSION: &str =
    "franken-engine.coverage-frontier-filing.v1";

/// Schema id stamped on the persisted dedup ledger.
pub const COVERAGE_FRONTIER_LEDGER_SCHEMA_VERSION: &str =
    "franken-engine.coverage-frontier-filed-ledger.v1";

/// Default number of top-ranked clusters considered for filing.
pub const DEFAULT_TOP_N: usize = 10;

/// Clusters ranked in this leading tier (1-based rank `<=` this) file at the
/// higher worklist priority; the rest file one tier lower. Conservative by
/// design: these are advisory worklist items, never P0/P1 release blockers.
pub const PRIORITY_TIER_RANK: usize = 3;

/// Stable marker embedded (with `cluster_id=<id>`) in every auto-filed bead body.
/// Greppable so the dedup ledger can be reconstructed from the tracker if lost.
pub const AUTOFILE_MARKER: &str = "franken-engine:coverage-frontier-autofile:v1";

/// Which kind of work a cluster represents — and therefore which scaffold shape is
/// honest for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScaffoldKind {
    /// A `built-ins/*` gap: scaffolds a real E4 [`IntrinsicRow`].
    Intrinsic,
    /// A `language/*` gap: a parser/lowering construct, not an intrinsic.
    LanguageGap,
    /// A differential-oracle divergence: a runtime behavior gap, not an intrinsic.
    RuntimeDivergence,
    /// Anything else (e.g. out-of-ES2020-scope Test262 trees): no row applies.
    Other,
}

impl ScaffoldKind {
    /// Stable lower-snake string for serialized output.
    pub fn as_str(self) -> &'static str {
        match self {
            ScaffoldKind::Intrinsic => "intrinsic",
            ScaffoldKind::LanguageGap => "language_gap",
            ScaffoldKind::RuntimeDivergence => "runtime_divergence",
            ScaffoldKind::Other => "other",
        }
    }
}

/// One ledger entry: a cluster that has already been filed as a bead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiledClusterRecord {
    /// Content-hashed cluster id from E7.T1 (the dedup key).
    pub cluster_id: String,
    /// The tracker id of the filed bead, or `""` if filed out-of-band.
    pub bead_id: String,
    /// Spec construct (provenance; not part of the dedup key).
    pub construct: String,
    /// Human-readable provenance note (e.g. when/how it was filed).
    pub note: String,
}

/// The dedup ledger: the set of cluster ids already filed, keyed on `cluster_id`.
///
/// Idempotency is exact because the key is E7.T1's content hash of
/// `(source, construct)` — independent of volatile counts or membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiledLedger {
    /// Schema id (`COVERAGE_FRONTIER_LEDGER_SCHEMA_VERSION`).
    pub schema_version: String,
    /// `cluster_id -> record` for every already-filed cluster.
    pub records: BTreeMap<String, FiledClusterRecord>,
}

impl Default for FiledLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl FiledLedger {
    /// An empty ledger (nothing filed yet).
    pub fn new() -> Self {
        Self {
            schema_version: COVERAGE_FRONTIER_LEDGER_SCHEMA_VERSION.to_string(),
            records: BTreeMap::new(),
        }
    }

    /// Build a ledger from a list of records (later duplicates overwrite earlier).
    pub fn from_records(records: impl IntoIterator<Item = FiledClusterRecord>) -> Self {
        let mut ledger = Self::new();
        for record in records {
            ledger.records.insert(record.cluster_id.clone(), record);
        }
        ledger
    }

    /// True when this cluster has already been filed (open *or* closed).
    pub fn contains(&self, cluster_id: &str) -> bool {
        self.records.contains_key(cluster_id)
    }

    /// Record a freshly-filed cluster, returning the previous record if the
    /// cluster was somehow already present (defensive; callers should `contains`
    /// first).
    pub fn record(
        &mut self,
        cluster_id: impl Into<String>,
        bead_id: impl Into<String>,
        construct: impl Into<String>,
        note: impl Into<String>,
    ) -> Option<FiledClusterRecord> {
        let cluster_id = cluster_id.into();
        self.records.insert(
            cluster_id.clone(),
            FiledClusterRecord {
                cluster_id,
                bead_id: bead_id.into(),
                construct: construct.into(),
                note: note.into(),
            },
        )
    }
}

/// One proposed bead for a not-yet-filed cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeadFilingProposal {
    /// Content-hashed cluster id (the dedup key).
    pub cluster_id: String,
    /// Failure stream (`test262` / `differential_oracle`).
    pub source: String,
    /// Spec-construct key.
    pub construct: String,
    /// 1-based impact rank from E7.T2.
    pub rank: usize,
    /// Raw failing count.
    pub failing_count: usize,
    /// Impact score (millionths) from E7.T2 (carried for provenance).
    pub impact_millionths: u128,
    /// The E7.T2 self-contained impact explanation.
    pub impact_explanation: String,
    /// Failing cases (the E7.T1 sample, already sorted/deduped/capped).
    pub sample_case_ids: Vec<String>,
    /// Worklist priority (`P2`/`P3`), derived from rank tier.
    pub priority: String,
    /// Bead title.
    pub title: String,
    /// Bead description body (failing cases + scaffold + dedup marker).
    pub body: String,
    /// Comma-separated labels for the bead.
    pub labels: String,
    /// What kind of work this cluster is (drives the scaffold shape).
    pub scaffold_kind: ScaffoldKind,
    /// The E4 `IntrinsicRow` scaffold (built-ins) or the honest "not an intrinsic"
    /// note (language / runtime gaps).
    pub scaffold: String,
    /// Exact, shell-safe `br create` command (plan-only; the module never runs it).
    pub br_create_command: String,
}

/// A cluster skipped because it is already in the dedup ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedCluster {
    /// Content-hashed cluster id.
    pub cluster_id: String,
    /// Spec-construct key.
    pub construct: String,
    /// 1-based impact rank.
    pub rank: usize,
    /// Why it was skipped (the matching ledger record's bead id / note).
    pub reason: String,
}

/// The deterministic filing plan: what would be filed, and what was deduped away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeadFilingPlan {
    /// Schema id (`COVERAGE_FRONTIER_FILING_SCHEMA_VERSION`).
    pub schema_version: String,
    /// The top-N cap requested.
    pub top_n: usize,
    /// Clusters actually considered = `min(top_n, ranked cluster count)`.
    pub considered_count: usize,
    /// Number of new proposals (`considered - skipped`).
    pub proposal_count: usize,
    /// Number of considered clusters skipped by dedup.
    pub skipped_count: usize,
    /// New beads to file, in impact-rank order.
    pub proposals: Vec<BeadFilingProposal>,
    /// Considered clusters skipped because already filed, in impact-rank order.
    pub skipped: Vec<SkippedCluster>,
    /// Content hash over the canonical plan sequence — a single integrity handle.
    pub plan_digest: String,
}

/// POSIX single-quote a string so it is safe to paste into a shell command.
/// Wraps in `'...'`, escaping any embedded single quote as `'\''`.
pub fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    let escaped = value.replace('\'', "'\\''");
    format!("'{escaped}'")
}

/// The marker line embedded in every auto-filed bead body, binding it to its
/// originating cluster for ledger reconstruction.
pub fn marker_line(cluster_id: &str) -> String {
    format!("{AUTOFILE_MARKER} cluster_id={cluster_id}")
}

/// Worklist priority for a 1-based rank: leading tier is `P2`, the rest `P3`.
fn priority_for_rank(rank: usize) -> &'static str {
    if rank <= PRIORITY_TIER_RANK {
        "P2"
    } else {
        "P3"
    }
}

/// Title-case-ish "is this a prototype (instance) method?" check.
fn is_prototype_construct(construct: &str) -> bool {
    construct.split('/').any(|seg| seg == "prototype")
}

/// Render an E4 `IntrinsicRow` scaffold for a `built-ins/<Builtin>/...` construct.
/// Heuristics pick a sensible default receiver/coercion; every field a human must
/// confirm carries a `// TODO` so the scaffold is honest about being a starting
/// point, not a finished row.
fn intrinsic_scaffold(construct: &str) -> String {
    let comps: Vec<&str> = construct.split('/').collect();
    let builtin = comps.get(1).copied().unwrap_or("Unknown");
    let is_proto = is_prototype_construct(construct);
    let name = if is_proto {
        format!("{builtin}.prototype.TODO_method")
    } else {
        format!("{builtin}.TODO_method")
    };

    // (receiver expr, this_coercion expr) heuristic from the builtin family.
    let (receiver, coercion) = match builtin {
        "String" => (
            "ReceiverKind::String".to_string(),
            "ThisCoercion::ToString".to_string(),
        ),
        "Array" => (
            "ReceiverKind::Array".to_string(),
            "ThisCoercion::Passthrough".to_string(),
        ),
        "Object" => (
            "ReceiverKind::Object".to_string(),
            "ThisCoercion::ToObject".to_string(),
        ),
        "Number" => (
            "ReceiverKind::Number".to_string(),
            "ThisCoercion::ToObject".to_string(),
        ),
        "Map" | "Set" | "WeakMap" | "WeakSet" | "Date" if is_proto => (
            format!("ReceiverKind::Collection({builtin:?})"),
            format!("ThisCoercion::RequireType({builtin:?})"),
        ),
        _ => (
            "ReceiverKind::Global".to_string(),
            "ThisCoercion::None".to_string(),
        ),
    };

    format!(
        "// E4 intrinsic-table scaffold for `{construct}`.\n\
         // Heuristic starting point — confirm EVERY field before adding to the table.\n\
         // Append to the matching family in `intrinsics_table.rs` and write the\n\
         // `*_impl` fn + its `*_intrinsic_impl_binding` entry in `baseline_interpreter.rs`.\n\
         IntrinsicRow {{\n\
         \x20   name: {name:?}, // TODO: exact JS method name (one row per method)\n\
         \x20   receiver: {receiver}, // TODO: confirm dispatch seam\n\
         \x20   this_coercion: {coercion}, // TODO: confirm receiver coercion\n\
         \x20   arity: Arity::Exact(0), // TODO: real arity (Exact/AtLeast/Range/Variadic)\n\
         \x20   capability: None, // TODO: Some(RuntimeCapability::..) if effectful, else None\n\
         \x20   ifc: IfcPropagation::PropagateReceiverLabel, // TODO: confirm IFC result-label policy\n\
         \x20   impl_binding: ImplBinding::Generated {{ impl_fn: \"TODO_impl_fn\" }}, // or Manual {{ reason, site }}\n\
         \x20   conformance: \"test262:{construct}\",\n\
         \x20   gap_status: GapStatus::Planned, // -> Partial(..)/Resolved as work lands\n\
         }},",
    )
}

/// Build the honest scaffold for a cluster, returning its kind + text.
fn build_scaffold(source: &str, construct: &str) -> (ScaffoldKind, String) {
    if source == crate::coverage_frontier::FrontierSource::DifferentialOracle.as_str() {
        let text = format!(
            "// Differential-oracle divergence cluster (class: `{construct}`).\n\
             // This is a runtime behavior gap, NOT an intrinsic — no E4 IntrinsicRow applies.\n\
             // Triage with `frankenctl oracle run <case> --engines franken,core` and minimize\n\
             // the repro; the fix lands in the parser/lowering/interpreter, not the table.\n\
             // See docs/DW_DIFFERENTIAL_ORACLE_V1.md."
        );
        return (ScaffoldKind::RuntimeDivergence, text);
    }

    match construct.split('/').next() {
        Some("built-ins") => (ScaffoldKind::Intrinsic, intrinsic_scaffold(construct)),
        Some("language") => {
            let text = format!(
                "// Language-surface cluster (`{construct}`).\n\
                 // This is a parser/lowering construct, NOT an intrinsic — no E4 IntrinsicRow applies.\n\
                 // Locate/extend the entry in `parser_gap_inventory.rs` and `lowering_gap_inventory.rs`\n\
                 // (the truth gate is `run_lowering_gap_truth_invariant.sh`); the fix lands in\n\
                 // `parser.rs` / `lowering_pipeline.rs`, not the intrinsic table."
            );
            (ScaffoldKind::LanguageGap, text)
        }
        _ => {
            let text = format!(
                "// Cluster `{construct}` is outside the built-ins/language ES2020 split\n\
                 // (e.g. intl402/annexB/proposals). No E4 IntrinsicRow scaffold applies;\n\
                 // confirm the construct is in scope before filing work for it."
            );
            (ScaffoldKind::Other, text)
        }
    }
}

/// Compose the bead title for a cluster.
fn build_title(source: &str, construct: &str, failing_count: usize) -> String {
    format!("[E7 frontier] {construct} conformance gap — {failing_count} failing ({source})")
}

/// Compose the bead description body, embedding the failing-case list, the E4 / gap
/// scaffold, the impact explanation, and the dedup marker. Reads the cluster
/// identity straight off the ranked cluster (keeping the arg count small).
fn build_body(
    cluster: &RankedCluster,
    sample_case_ids: &[String],
    scaffold_kind: ScaffoldKind,
    scaffold: &str,
) -> String {
    let mut body = String::new();
    body.push_str(
        "Auto-filed by the E7 Conformance Frontier worklist (E7.T5, bd-fqlfw.7.5).\n\
         This is an advisory, impact-ranked work item — review before starting.\n\n",
    );
    body.push_str(&format!("cluster_id: {}\n", cluster.cluster_id));
    body.push_str(&format!("source: {}\n", cluster.source));
    body.push_str(&format!("construct: {}\n", cluster.construct));
    body.push_str(&format!("impact_rank: {}\n", cluster.rank));
    body.push_str(&format!("failing_count: {}\n", cluster.failing_count));
    body.push_str(&format!("kind: {}\n", scaffold_kind.as_str()));
    body.push_str(&format!("impact: {}\n\n", cluster.score.explanation));

    body.push_str("Failing cases (E7.T1 sample, sorted/deduped/capped):\n");
    if sample_case_ids.is_empty() {
        body.push_str("- (no sample case ids recorded for this cluster)\n");
    } else {
        for case in sample_case_ids {
            body.push_str(&format!("- {case}\n"));
        }
    }
    body.push('\n');

    body.push_str("Scaffold:\n");
    body.push_str(scaffold);
    body.push_str("\n\n");

    body.push_str(
        "Done when: the failing cases above pass (or are correctly rejected), and the\n\
         filed-ledger entry for this cluster is recorded.\n\n",
    );
    body.push_str(&marker_line(&cluster.cluster_id));
    body.push('\n');
    body
}

/// Render the exact, shell-safe `br create` command for a proposal.
fn build_br_create_command(
    title: &str,
    priority: &str,
    labels: &str,
    parent: Option<&str>,
    body: &str,
) -> String {
    let mut cmd = format!(
        "br create {} -t task -p {} -l {}",
        shell_quote(title),
        priority,
        shell_quote(labels),
    );
    if let Some(parent) = parent {
        cmd.push_str(&format!(" --parent {}", shell_quote(parent)));
    }
    cmd.push_str(&format!(" -d {}", shell_quote(body)));
    cmd
}

/// Content hash over the canonical plan sequence (length-prefixed), giving the
/// plan a single integrity handle that is invariant to anything but the
/// decisions it encodes.
fn compute_plan_digest(
    top_n: usize,
    proposals: &[BeadFilingProposal],
    skipped: &[SkippedCluster],
) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(top_n as u64).to_be_bytes());
    let push_field = |buf: &mut Vec<u8>, field: &[u8]| {
        buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
        buf.extend_from_slice(field);
    };
    for proposal in proposals {
        buf.push(0x01); // proposal tag
        buf.extend_from_slice(&(proposal.rank as u64).to_be_bytes());
        push_field(&mut buf, proposal.cluster_id.as_bytes());
        buf.extend_from_slice(&proposal.impact_millionths.to_be_bytes());
        push_field(&mut buf, proposal.title.as_bytes());
        push_field(&mut buf, proposal.body.as_bytes());
    }
    for skip in skipped {
        buf.push(0x02); // skipped tag
        buf.extend_from_slice(&(skip.rank as u64).to_be_bytes());
        push_field(&mut buf, skip.cluster_id.as_bytes());
    }
    ContentHash::compute(&buf).to_hex()
}

/// Build a deterministic, side-effect-free [`BeadFilingPlan`] from the ranked
/// frontier.
///
/// `ranked` (E7.T2) supplies the impact ordering and per-cluster score; `frontier`
/// (E7.T1) supplies the failing-case samples (joined by `cluster_id`); `ledger`
/// supplies the dedup set; `top_n` caps how many leading clusters are considered.
///
/// Clusters already in `ledger` become [`SkippedCluster`]s; the rest become
/// [`BeadFilingProposal`]s carrying their failing cases, an E4 / gap scaffold, and
/// the exact (plan-only) `br create` command. `parent`, when set, is threaded into
/// each command as `--parent`.
pub fn build_filing_plan(
    ranked: &RankedFrontierReport,
    frontier: &CoverageFrontierReport,
    ledger: &FiledLedger,
    top_n: usize,
    parent: Option<&str>,
) -> BeadFilingPlan {
    // Join key: cluster_id -> failing-case sample from E7.T1.
    let samples: BTreeMap<&str, &Vec<String>> = frontier
        .clusters
        .iter()
        .map(|cluster| (cluster.cluster_id.as_str(), &cluster.sample_case_ids))
        .collect();

    let considered_count = top_n.min(ranked.ranked.len());
    let mut proposals = Vec::new();
    let mut skipped = Vec::new();

    for cluster in ranked.ranked.iter().take(top_n) {
        if let Some(existing) = ledger.records.get(&cluster.cluster_id) {
            let reason = if existing.bead_id.is_empty() {
                format!("already filed ({})", existing.note)
            } else {
                format!("already filed as {}", existing.bead_id)
            };
            skipped.push(SkippedCluster {
                cluster_id: cluster.cluster_id.clone(),
                construct: cluster.construct.clone(),
                rank: cluster.rank,
                reason,
            });
            continue;
        }

        let sample_case_ids = samples
            .get(cluster.cluster_id.as_str())
            .map(|s| (*s).clone())
            .unwrap_or_default();
        let (scaffold_kind, scaffold) = build_scaffold(&cluster.source, &cluster.construct);
        let title = build_title(&cluster.source, &cluster.construct, cluster.failing_count);
        let priority = priority_for_rank(cluster.rank).to_string();
        let labels = "coverage-frontier,conformance-gap".to_string();
        let body = build_body(cluster, &sample_case_ids, scaffold_kind, &scaffold);
        let br_create_command = build_br_create_command(&title, &priority, &labels, parent, &body);

        proposals.push(BeadFilingProposal {
            cluster_id: cluster.cluster_id.clone(),
            source: cluster.source.clone(),
            construct: cluster.construct.clone(),
            rank: cluster.rank,
            failing_count: cluster.failing_count,
            impact_millionths: cluster.score.impact_millionths,
            impact_explanation: cluster.score.explanation.clone(),
            sample_case_ids,
            priority,
            title,
            body,
            labels,
            scaffold_kind,
            scaffold,
            br_create_command,
        });
    }

    let plan_digest = compute_plan_digest(top_n, &proposals, &skipped);
    BeadFilingPlan {
        schema_version: COVERAGE_FRONTIER_FILING_SCHEMA_VERSION.to_string(),
        top_n,
        considered_count,
        proposal_count: proposals.len(),
        skipped_count: skipped.len(),
        proposals,
        skipped,
        plan_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage_frontier::{FailureObservation, FrontierSource, cluster_failures};
    use crate::coverage_frontier_rank::{ConstructCensus, rank_clusters};
    use std::collections::BTreeMap as Map;

    fn obs(source: FrontierSource, construct: &str, case: &str) -> FailureObservation {
        FailureObservation::new(source, construct, case, "fail")
    }

    /// Build a ranked frontier from `(source, construct, count)` gaps, neutral
    /// usage + locality (so impact == raw count and order is by count).
    fn ranked_from(
        gaps: &[(FrontierSource, &str, usize)],
    ) -> (CoverageFrontierReport, RankedFrontierReport) {
        let mut observations = Vec::new();
        for (source, construct, count) in gaps {
            for i in 0..*count {
                observations.push(obs(*source, construct, &format!("{construct}/case-{i}.js")));
            }
        }
        let frontier = cluster_failures(&observations, 3, 8);
        let ranked = rank_clusters(&frontier, &Map::new(), None);
        (frontier, ranked)
    }

    fn cid(source: FrontierSource, construct: &str) -> String {
        crate::coverage_frontier::cluster_id(source, construct)
    }

    // ---- plan shape + schema --------------------------------------------

    #[test]
    fn plan_stamps_schema_and_counts() {
        let (frontier, ranked) = ranked_from(&[(FrontierSource::Test262, "built-ins/Map", 3)]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        assert_eq!(plan.schema_version, COVERAGE_FRONTIER_FILING_SCHEMA_VERSION);
        assert_eq!(plan.top_n, DEFAULT_TOP_N);
        assert_eq!(plan.considered_count, 1);
        assert_eq!(plan.proposal_count, 1);
        assert_eq!(plan.skipped_count, 0);
    }

    #[test]
    fn top_n_caps_considered_clusters() {
        let (frontier, ranked) = ranked_from(&[
            (FrontierSource::Test262, "built-ins/A", 9),
            (FrontierSource::Test262, "built-ins/B", 8),
            (FrontierSource::Test262, "built-ins/C", 7),
            (FrontierSource::Test262, "built-ins/D", 6),
        ]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), 2, None);
        assert_eq!(plan.considered_count, 2);
        assert_eq!(plan.proposal_count, 2);
        // Highest-impact two clusters only.
        assert_eq!(plan.proposals[0].construct, "built-ins/A");
        assert_eq!(plan.proposals[1].construct, "built-ins/B");
    }

    #[test]
    fn considered_equals_proposals_plus_skipped() {
        let (frontier, ranked) = ranked_from(&[
            (FrontierSource::Test262, "built-ins/A", 5),
            (FrontierSource::Test262, "built-ins/B", 4),
            (FrontierSource::Test262, "built-ins/C", 3),
        ]);
        let ledger = FiledLedger::from_records([FiledClusterRecord {
            cluster_id: cid(FrontierSource::Test262, "built-ins/B"),
            bead_id: "bd-existing".into(),
            construct: "built-ins/B".into(),
            note: "prior run".into(),
        }]);
        let plan = build_filing_plan(&ranked, &frontier, &ledger, DEFAULT_TOP_N, None);
        assert_eq!(plan.considered_count, 3);
        assert_eq!(
            plan.proposal_count + plan.skipped_count,
            plan.considered_count
        );
        assert_eq!(plan.skipped_count, 1);
    }

    #[test]
    fn proposals_are_in_ascending_rank_order() {
        let (frontier, ranked) = ranked_from(&[
            (FrontierSource::Test262, "built-ins/A", 9),
            (FrontierSource::Test262, "built-ins/B", 5),
            (FrontierSource::Test262, "built-ins/C", 1),
        ]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let ranks: Vec<usize> = plan.proposals.iter().map(|p| p.rank).collect();
        assert_eq!(ranks, vec![1, 2, 3]);
    }

    // ---- dedup + idempotency (the core acceptance) ----------------------

    #[test]
    fn cluster_in_ledger_is_skipped_not_proposed() {
        let (frontier, ranked) = ranked_from(&[(FrontierSource::Test262, "built-ins/Map", 3)]);
        let ledger = FiledLedger::from_records([FiledClusterRecord {
            cluster_id: cid(FrontierSource::Test262, "built-ins/Map"),
            bead_id: "bd-zzz".into(),
            construct: "built-ins/Map".into(),
            note: "earlier".into(),
        }]);
        let plan = build_filing_plan(&ranked, &frontier, &ledger, DEFAULT_TOP_N, None);
        assert_eq!(plan.proposal_count, 0);
        assert_eq!(plan.skipped_count, 1);
        assert!(plan.skipped[0].reason.contains("bd-zzz"));
    }

    #[test]
    fn rerun_after_filing_does_not_duplicate() {
        // ACCEPTANCE: "re-running does not duplicate beads."
        let (frontier, ranked) = ranked_from(&[
            (FrontierSource::Test262, "built-ins/Map", 4),
            (FrontierSource::Test262, "built-ins/Set", 2),
        ]);
        // Run 1: empty ledger -> both proposed.
        let mut ledger = FiledLedger::new();
        let first = build_filing_plan(&ranked, &frontier, &ledger, DEFAULT_TOP_N, None);
        assert_eq!(first.proposal_count, 2);
        // Simulate the operator filing each proposal and recording it.
        for (i, p) in first.proposals.iter().enumerate() {
            ledger.record(
                p.cluster_id.clone(),
                format!("bd-new-{i}"),
                p.construct.clone(),
                "filed in run 1",
            );
        }
        // Run 2: same inputs, updated ledger -> nothing new, both skipped.
        let second = build_filing_plan(&ranked, &frontier, &ledger, DEFAULT_TOP_N, None);
        assert_eq!(second.proposal_count, 0, "no duplicate beads on re-run");
        assert_eq!(second.skipped_count, 2);
    }

    #[test]
    fn closed_cluster_in_ledger_still_skipped() {
        // A bead that was filed and later CLOSED must not be re-filed: the ledger
        // keys on cluster_id regardless of the bead's lifecycle state.
        let (frontier, ranked) = ranked_from(&[(FrontierSource::Test262, "built-ins/Date", 6)]);
        let ledger = FiledLedger::from_records([FiledClusterRecord {
            cluster_id: cid(FrontierSource::Test262, "built-ins/Date"),
            bead_id: "bd-closed".into(),
            construct: "built-ins/Date".into(),
            note: "closed: implemented".into(),
        }]);
        let plan = build_filing_plan(&ranked, &frontier, &ledger, DEFAULT_TOP_N, None);
        assert_eq!(plan.proposal_count, 0);
        assert_eq!(plan.skipped_count, 1);
    }

    // ---- proposals carry failing cases + scaffold (the other acceptance)

    #[test]
    fn proposal_carries_failing_cases_from_frontier() {
        let (frontier, ranked) = ranked_from(&[(FrontierSource::Test262, "built-ins/Map", 3)]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let p = &plan.proposals[0];
        assert_eq!(p.sample_case_ids.len(), 3);
        assert!(
            p.sample_case_ids
                .iter()
                .all(|c| c.starts_with("built-ins/Map/"))
        );
        // and the body lists them.
        assert!(p.body.contains(&p.sample_case_ids[0]));
    }

    #[test]
    fn builtins_proposal_carries_intrinsic_row_scaffold() {
        let (frontier, ranked) =
            ranked_from(&[(FrontierSource::Test262, "built-ins/Map/prototype", 3)]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let p = &plan.proposals[0];
        assert_eq!(p.scaffold_kind, ScaffoldKind::Intrinsic);
        assert!(p.scaffold.contains("IntrinsicRow {"));
        assert!(
            p.scaffold
                .contains("conformance: \"test262:built-ins/Map/prototype\"")
        );
        // prototype construct on a collection picks the brand-checked receiver.
        assert!(p.scaffold.contains("ReceiverKind::Collection(\"Map\")"));
        assert!(p.scaffold.contains("ThisCoercion::RequireType(\"Map\")"));
    }

    #[test]
    fn string_builtin_scaffold_uses_string_receiver() {
        let (frontier, ranked) =
            ranked_from(&[(FrontierSource::Test262, "built-ins/String/prototype", 2)]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let s = &plan.proposals[0].scaffold;
        assert!(s.contains("ReceiverKind::String"));
        assert!(s.contains("ThisCoercion::ToString"));
        assert!(s.contains("String.prototype.TODO_method"));
    }

    #[test]
    fn static_builtin_scaffold_uses_global_receiver_no_prototype() {
        let (frontier, ranked) = ranked_from(&[(FrontierSource::Test262, "built-ins/Math", 2)]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let s = &plan.proposals[0].scaffold;
        assert!(s.contains("ReceiverKind::Global"));
        assert!(s.contains("Math.TODO_method"));
        assert!(
            !s.contains(".prototype."),
            "static builtin is not a prototype method"
        );
    }

    #[test]
    fn language_cluster_is_not_an_intrinsic() {
        let (frontier, ranked) = ranked_from(&[(
            FrontierSource::Test262,
            "language/expressions/optional-chaining",
            5,
        )]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let p = &plan.proposals[0];
        assert_eq!(p.scaffold_kind, ScaffoldKind::LanguageGap);
        assert!(!p.scaffold.contains("IntrinsicRow {"));
        assert!(p.scaffold.contains("parser_gap_inventory.rs"));
        assert!(p.scaffold.contains("lowering_gap_inventory.rs"));
    }

    #[test]
    fn oracle_cluster_is_runtime_divergence() {
        let (frontier, ranked) = ranked_from(&[(FrontierSource::DifferentialOracle, "runtime", 4)]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let p = &plan.proposals[0];
        assert_eq!(p.scaffold_kind, ScaffoldKind::RuntimeDivergence);
        assert!(!p.scaffold.contains("IntrinsicRow {"));
        assert!(p.scaffold.contains("oracle"));
    }

    #[test]
    fn out_of_scope_cluster_is_other() {
        let (frontier, ranked) =
            ranked_from(&[(FrontierSource::Test262, "intl402/NumberFormat", 3)]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        assert_eq!(plan.proposals[0].scaffold_kind, ScaffoldKind::Other);
        assert!(!plan.proposals[0].scaffold.contains("IntrinsicRow {"));
    }

    // ---- bead metadata --------------------------------------------------

    #[test]
    fn body_carries_marker_and_cluster_id() {
        let (frontier, ranked) = ranked_from(&[(FrontierSource::Test262, "built-ins/Map", 3)]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let p = &plan.proposals[0];
        assert!(p.body.contains(AUTOFILE_MARKER));
        assert!(p.body.contains(&format!("cluster_id={}", p.cluster_id)));
        // The marker line is exactly reconstructable.
        assert!(p.body.contains(&marker_line(&p.cluster_id)));
    }

    #[test]
    fn title_names_construct_and_count() {
        let (frontier, ranked) = ranked_from(&[(FrontierSource::Test262, "built-ins/Map", 7)]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let t = &plan.proposals[0].title;
        assert!(t.contains("built-ins/Map"));
        assert!(t.contains("7 failing"));
        assert!(t.contains("test262"));
    }

    #[test]
    fn priority_follows_rank_tier() {
        let (frontier, ranked) = ranked_from(&[
            (FrontierSource::Test262, "built-ins/A", 9),
            (FrontierSource::Test262, "built-ins/B", 8),
            (FrontierSource::Test262, "built-ins/C", 7),
            (FrontierSource::Test262, "built-ins/D", 6),
        ]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        assert_eq!(plan.proposals[0].priority, "P2"); // rank 1
        assert_eq!(plan.proposals[2].priority, "P2"); // rank 3
        assert_eq!(plan.proposals[3].priority, "P3"); // rank 4
    }

    #[test]
    fn impact_explanation_is_propagated_from_ranking() {
        let (frontier, ranked) = ranked_from(&[(FrontierSource::Test262, "built-ins/Map", 4)]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let p = &plan.proposals[0];
        assert_eq!(p.impact_explanation, ranked.ranked[0].score.explanation);
        assert!(p.impact_explanation.contains("4 failing"));
        assert!(p.body.contains(&p.impact_explanation));
    }

    // ---- br create command ----------------------------------------------

    #[test]
    fn br_create_command_is_well_formed() {
        let (frontier, ranked) = ranked_from(&[(FrontierSource::Test262, "built-ins/Map", 3)]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let c = &plan.proposals[0].br_create_command;
        assert!(c.starts_with("br create "));
        assert!(c.contains("-t task"));
        assert!(c.contains("-p P2"));
        assert!(c.contains("-l 'coverage-frontier,conformance-gap'"));
        assert!(c.contains("-d "));
    }

    #[test]
    fn br_create_command_threads_parent_when_set() {
        let (frontier, ranked) = ranked_from(&[(FrontierSource::Test262, "built-ins/Map", 3)]);
        let plan = build_filing_plan(
            &ranked,
            &frontier,
            &FiledLedger::new(),
            DEFAULT_TOP_N,
            Some("bd-fqlfw.7"),
        );
        assert!(
            plan.proposals[0]
                .br_create_command
                .contains("--parent 'bd-fqlfw.7'")
        );
        // and absent when not set.
        let plan2 = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        assert!(!plan2.proposals[0].br_create_command.contains("--parent"));
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        // A body with a quote round-trips into a single quoted token.
        let q = shell_quote("it's a gap");
        assert!(q.starts_with('\'') && q.ends_with('\''));
        assert!(q.contains("'\\''"));
    }

    // ---- determinism ----------------------------------------------------

    #[test]
    fn plan_is_deterministic() {
        let (frontier, ranked) = ranked_from(&[
            (FrontierSource::Test262, "built-ins/Map", 5),
            (FrontierSource::Test262, "language/types", 4),
            (FrontierSource::DifferentialOracle, "runtime", 2),
        ]);
        let a = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let b = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        assert_eq!(a, b);
        assert_eq!(a.plan_digest, b.plan_digest);
    }

    #[test]
    fn digest_changes_when_a_cluster_is_deduped_away() {
        let (frontier, ranked) = ranked_from(&[
            (FrontierSource::Test262, "built-ins/Map", 5),
            (FrontierSource::Test262, "built-ins/Set", 3),
        ]);
        let open = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let ledger = FiledLedger::from_records([FiledClusterRecord {
            cluster_id: cid(FrontierSource::Test262, "built-ins/Set"),
            bead_id: "bd-x".into(),
            construct: "built-ins/Set".into(),
            note: "n".into(),
        }]);
        let deduped = build_filing_plan(&ranked, &frontier, &ledger, DEFAULT_TOP_N, None);
        assert_ne!(open.plan_digest, deduped.plan_digest);
    }

    #[test]
    fn empty_frontier_yields_empty_stable_plan() {
        let frontier = cluster_failures(&[], 3, 8);
        let ranked = rank_clusters(&frontier, &Map::new(), None);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        assert_eq!(plan.considered_count, 0);
        assert_eq!(plan.proposal_count, 0);
        assert!(plan.proposals.is_empty());
        let again = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        assert_eq!(plan.plan_digest, again.plan_digest);
    }

    // ---- locality can reorder, and filing follows the ranked order ------

    #[test]
    fn filing_follows_impact_not_raw_count() {
        // Two equal-count clusters; locality lifts the nearly-complete family.
        let mut observations = Vec::new();
        for i in 0..3 {
            observations.push(obs(
                FrontierSource::Test262,
                "built-ins/Almost",
                &format!("a{i}.js"),
            ));
            observations.push(obs(
                FrontierSource::Test262,
                "built-ins/Wall",
                &format!("w{i}.js"),
            ));
        }
        let frontier = cluster_failures(&observations, 3, 8);
        let mut census = Map::new();
        census.insert(
            "built-ins/Almost".to_string(),
            ConstructCensus {
                passing: 27,
                failing: 3,
            },
        );
        census.insert(
            "built-ins/Wall".to_string(),
            ConstructCensus {
                passing: 0,
                failing: 3,
            },
        );
        let ranked = rank_clusters(&frontier, &census, None);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        assert_eq!(
            plan.proposals[0].construct, "built-ins/Almost",
            "higher locality files first"
        );
        assert_eq!(plan.proposals[0].rank, 1);
    }

    // ---- ledger primitives ----------------------------------------------

    #[test]
    fn ledger_contains_and_record_roundtrip() {
        let mut ledger = FiledLedger::new();
        assert!(!ledger.contains("abc"));
        let prev = ledger.record("abc", "bd-1", "built-ins/Map", "first");
        assert!(prev.is_none());
        assert!(ledger.contains("abc"));
        // re-record returns the prior entry (defensive overwrite).
        let prev = ledger.record("abc", "bd-2", "built-ins/Map", "second");
        assert_eq!(prev.unwrap().bead_id, "bd-1");
        assert_eq!(ledger.records.get("abc").unwrap().bead_id, "bd-2");
    }

    #[test]
    fn ledger_schema_is_stamped() {
        assert_eq!(
            FiledLedger::new().schema_version,
            COVERAGE_FRONTIER_LEDGER_SCHEMA_VERSION
        );
    }

    #[test]
    fn scaffold_kind_strings_are_stable() {
        assert_eq!(ScaffoldKind::Intrinsic.as_str(), "intrinsic");
        assert_eq!(ScaffoldKind::LanguageGap.as_str(), "language_gap");
        assert_eq!(
            ScaffoldKind::RuntimeDivergence.as_str(),
            "runtime_divergence"
        );
        assert_eq!(ScaffoldKind::Other.as_str(), "other");
    }

    #[test]
    fn all_proposal_cluster_ids_are_unique() {
        let (frontier, ranked) = ranked_from(&[
            (FrontierSource::Test262, "built-ins/A", 5),
            (FrontierSource::Test262, "built-ins/B", 4),
            (FrontierSource::Test262, "built-ins/C", 3),
        ]);
        let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
        let mut ids: Vec<&str> = plan
            .proposals
            .iter()
            .map(|p| p.cluster_id.as_str())
            .collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "cluster ids are unique across proposals");
    }
}
