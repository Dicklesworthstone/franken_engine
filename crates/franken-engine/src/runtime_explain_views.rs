//! Human + machine VIEWS over the runtime explain index (E3.T4, `bd-fqlfw.3.4`).
//!
//! This module renders the six operator-facing explain artifacts —
//! `explain.md`, `evidence_graph.json`, `replay.json`, `counterfactuals.json`,
//! `commands.txt`, and `repro.lock` — as **pure projections** over a
//! [`RuntimeExplainBundle`] (the E3.T1 index). It owns no second truth model:
//! every node, link, hash, and source reference is read straight from the index,
//! which itself only references artifacts owned by their original stores
//! (ADR-0009). A wrong line here is a rendering bug, not an evidence forgery.
//!
//! All views are a pure function of the bundle (no wall-clock, no host facts
//! beyond what the index already carries), so the emitted bundle directory is
//! byte-deterministic and the `repro.lock` content-addresses it.
//!
//! ## The "why" story
//!
//! The runtime decision the operator cares about — allow / challenge / sandbox /
//! suspend / terminate / quarantine — is carried on the `ChosenAction` artifact
//! as deterministic display metadata (see the `EXPLAIN_META_*` keys). The
//! narrative reads those keys; it never re-derives or re-decides anything.
//! Per-decision **source links** are computed by walking the index's typed links
//! back to the `source` artifact, so every decision node points at the source it
//! was derived from. Span-precise links are surfaced when the index carries a
//! [`EXPLAIN_META_SOURCE_SPAN`] key; absent that, the file-level link is always
//! present and the boundary is stated rather than implied.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::runtime_explain_bundle::{
    RuntimeArtifactKind, RuntimeArtifactRef, RuntimeExplainBundle,
};

/// Schema id for the derived evidence-graph view (a projection, not a new
/// evidence schema).
pub const EXPLAIN_EVIDENCE_GRAPH_SCHEMA: &str = "franken-engine.explain.evidence-graph.v1";
/// Schema id for the derived replay view.
pub const EXPLAIN_REPLAY_VIEW_SCHEMA: &str = "franken-engine.explain.replay-view.v1";
/// Schema id for the derived counterfactual view.
pub const EXPLAIN_COUNTERFACTUAL_VIEW_SCHEMA: &str =
    "franken-engine.explain.counterfactual-view.v1";
/// Schema id for the derived (deterministic) reproducibility lock.
pub const EXPLAIN_REPRO_LOCK_SCHEMA: &str = "franken-engine.explain.repro-lock.v1";

/// On-thesis wording discipline: every view is an index projection, never an
/// authoritative claim. (E5.T4 wording discipline, shared across adoption
/// surfaces.) Worded to avoid absolute-superiority substrings so the over-claim
/// guard can scan the whole output, disclaimer included.
pub const EXPLAIN_VIEW_DISCLAIMER: &str = "derived index view over content-addressed runtime artifacts; \
it surfaces existing evidence and is not itself a second truth model.";

// Metadata keys the run-explain builder attaches to the ChosenAction artifact
// for narrative rendering. These are deterministic display metadata over the
// existing index (ADR-0009), not an authoritative schema.
/// Chosen containment action (allow/challenge/sandbox/suspend/terminate/quarantine).
pub const EXPLAIN_META_CHOSEN_ACTION: &str = "chosen_action";
/// Execution lane selected for the run.
pub const EXPLAIN_META_LANE: &str = "lane";
/// Human-readable reason the lane/action was chosen.
pub const EXPLAIN_META_LANE_REASON: &str = "lane_reason";
/// Expected loss (millionths) backing the action.
pub const EXPLAIN_META_EXPECTED_LOSS: &str = "expected_loss_millionths";
/// Optional source span (`L<line>:<col>`) of the construct that drove a decision.
pub const EXPLAIN_META_SOURCE_SPAN: &str = "source_span";

// Bundle-level metadata keys (written by build_run_explain_bundle).
const BUNDLE_META_COMMAND: &str = "command";
const BUNDLE_META_EXTENSION_ID: &str = "extension_id";
const BUNDLE_META_PARSE_GOAL: &str = "parse_goal";

// ---------------------------------------------------------------------------
// Category classification
// ---------------------------------------------------------------------------

/// Coarse category for an indexed artifact, used to group the evidence graph
/// and structure the narrative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCategory {
    Source,
    Ir,
    Decision,
    Receipt,
    Evidence,
    Replay,
    Counterfactual,
    Claim,
    Other,
}

impl EvidenceCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Ir => "ir",
            Self::Decision => "decision",
            Self::Receipt => "receipt",
            Self::Evidence => "evidence",
            Self::Replay => "replay",
            Self::Counterfactual => "counterfactual",
            Self::Claim => "claim",
            Self::Other => "other",
        }
    }
}

/// Classify an artifact into its evidence-graph category.
fn category_of(artifact: &RuntimeArtifactRef) -> EvidenceCategory {
    match &artifact.kind {
        RuntimeArtifactKind::ParseEventIrHash
        | RuntimeArtifactKind::Ir0Module
        | RuntimeArtifactKind::Ir1Module
        | RuntimeArtifactKind::Ir2Module
        | RuntimeArtifactKind::Ir3ExecIr => EvidenceCategory::Ir,
        RuntimeArtifactKind::CapabilityRequest
        | RuntimeArtifactKind::CapabilityGrant
        | RuntimeArtifactKind::IfcDecision
        | RuntimeArtifactKind::GuardplanePosterior
        | RuntimeArtifactKind::EProcessState
        | RuntimeArtifactKind::ExpectedLoss
        | RuntimeArtifactKind::ChosenAction => EvidenceCategory::Decision,
        RuntimeArtifactKind::ContainmentReceipt => EvidenceCategory::Receipt,
        RuntimeArtifactKind::EvidenceEntry => EvidenceCategory::Evidence,
        RuntimeArtifactKind::ReplayStatus => EvidenceCategory::Replay,
        RuntimeArtifactKind::CounterfactualStatus => EvidenceCategory::Counterfactual,
        RuntimeArtifactKind::Other { schema_id } => {
            let schema = schema_id.to_ascii_lowercase();
            if schema.contains("source") {
                EvidenceCategory::Source
            } else if schema.contains("claim") {
                EvidenceCategory::Claim
            } else {
                EvidenceCategory::Other
            }
        }
    }
}

// ---------------------------------------------------------------------------
// evidence_graph.json
// ---------------------------------------------------------------------------

/// A per-decision link back to the source the decision was derived from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLink {
    pub artifact_id: String,
    pub stable_ref: String,
    /// `L<line>:<col>` when the index carries a span; `None` for file-level links.
    pub span: Option<String>,
}

/// One node of the derived evidence graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceNode {
    pub id: String,
    pub category: EvidenceCategory,
    pub kind: String,
    pub schema_id: String,
    pub stable_ref: String,
    pub content_hash: String,
    pub roles: Vec<String>,
    /// Short display label (e.g. the chosen action), when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The source this node was (transitively) derived from, when reachable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_link: Option<SourceLink>,
}

/// One directed edge of the derived evidence graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
}

/// The derived evidence graph view (`evidence_graph.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceGraph {
    pub schema: String,
    pub run_id: String,
    pub bundle_content_hash: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub nodes: Vec<EvidenceNode>,
    pub edges: Vec<EvidenceEdge>,
    pub disclaimer: String,
}

/// Build undirected adjacency over the index links (for source reachability).
fn undirected_adjacency(bundle: &RuntimeExplainBundle) -> BTreeMap<&str, Vec<&str>> {
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for link in &bundle.links {
        adjacency
            .entry(link.from_artifact_id.as_str())
            .or_default()
            .push(link.to_artifact_id.as_str());
        adjacency
            .entry(link.to_artifact_id.as_str())
            .or_default()
            .push(link.from_artifact_id.as_str());
    }
    adjacency
}

/// Find the nearest source artifact reachable from `start` (undirected BFS over
/// the index links). Deterministic: neighbours are visited in sorted order.
fn nearest_source<'a>(
    bundle: &'a RuntimeExplainBundle,
    adjacency: &BTreeMap<&str, Vec<&'a str>>,
    start: &'a str,
) -> Option<&'a RuntimeArtifactRef> {
    let mut visited: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    queue.push_back(start);
    visited.insert(start);
    while let Some(current) = queue.pop_front() {
        if let Some(artifact) = bundle.artifacts.get(current)
            && category_of(artifact) == EvidenceCategory::Source
        {
            return Some(artifact);
        }
        if let Some(neighbours) = adjacency.get(current) {
            let mut sorted = neighbours.clone();
            sorted.sort_unstable();
            for next in sorted {
                if visited.insert(next) {
                    queue.push_back(next);
                }
            }
        }
    }
    None
}

/// Build the derived evidence graph from the index.
pub fn build_evidence_graph(bundle: &RuntimeExplainBundle) -> EvidenceGraph {
    let adjacency = undirected_adjacency(bundle);
    let mut nodes = Vec::with_capacity(bundle.artifacts.len());
    // bundle.artifacts is a BTreeMap → iteration is sorted by artifact_id.
    for (id, artifact) in &bundle.artifacts {
        let category = category_of(artifact);
        let label = artifact
            .metadata
            .get(EXPLAIN_META_CHOSEN_ACTION)
            .cloned()
            .filter(|_| category == EvidenceCategory::Decision);
        // Source links are meaningful for decisions/receipts/evidence, not for
        // the source node itself.
        let source_link = if category == EvidenceCategory::Source {
            None
        } else {
            nearest_source(bundle, &adjacency, id.as_str()).map(|source| SourceLink {
                artifact_id: source.artifact_id.clone(),
                stable_ref: source.stable_ref.to_string(),
                span: artifact.metadata.get(EXPLAIN_META_SOURCE_SPAN).cloned(),
            })
        };
        nodes.push(EvidenceNode {
            id: id.clone(),
            category,
            kind: artifact.kind.to_string(),
            schema_id: artifact.schema_id.clone(),
            stable_ref: artifact.stable_ref.to_string(),
            content_hash: artifact.content_hash.to_string(),
            roles: artifact.roles.iter().map(ToString::to_string).collect(),
            label,
            source_link,
        });
    }

    let mut edges: Vec<EvidenceEdge> = bundle
        .links
        .iter()
        .map(|link| EvidenceEdge {
            from: link.from_artifact_id.clone(),
            to: link.to_artifact_id.clone(),
            relation: link.relation.to_string(),
        })
        .collect();
    edges.sort_by(|a, b| {
        (a.from.as_str(), a.to.as_str(), a.relation.as_str()).cmp(&(
            b.from.as_str(),
            b.to.as_str(),
            b.relation.as_str(),
        ))
    });

    EvidenceGraph {
        schema: EXPLAIN_EVIDENCE_GRAPH_SCHEMA.to_string(),
        run_id: bundle.run_id.clone(),
        bundle_content_hash: bundle.content_hash().to_string(),
        node_count: nodes.len(),
        edge_count: edges.len(),
        nodes,
        edges,
        disclaimer: EXPLAIN_VIEW_DISCLAIMER.to_string(),
    }
}

// ---------------------------------------------------------------------------
// replay.json
// ---------------------------------------------------------------------------

/// A content-addressed pointer to an indexed artifact (used by replay/cf views).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactPointer {
    pub artifact_id: String,
    pub schema_id: String,
    pub stable_ref: String,
    pub content_hash: String,
}

fn pointers_for_category(
    bundle: &RuntimeExplainBundle,
    category: EvidenceCategory,
) -> Vec<ArtifactPointer> {
    bundle
        .artifacts
        .values()
        .filter(|artifact| category_of(artifact) == category)
        .map(|artifact| ArtifactPointer {
            artifact_id: artifact.artifact_id.clone(),
            schema_id: artifact.schema_id.clone(),
            stable_ref: artifact.stable_ref.to_string(),
            content_hash: artifact.content_hash.to_string(),
        })
        .collect()
}

/// One replay divergence class (mirrors `deterministic_replay` semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceClass {
    pub label: String,
    pub meaning: String,
}

/// The derived replay view (`replay.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayView {
    pub schema: String,
    pub run_id: String,
    pub modes: Vec<String>,
    pub indexed_replay_artifacts: Vec<ArtifactPointer>,
    pub divergence_classification: Vec<DivergenceClass>,
    pub note: String,
    pub disclaimer: String,
}

/// Build the derived replay view from the index.
pub fn build_replay_view(bundle: &RuntimeExplainBundle) -> ReplayView {
    let indexed = pointers_for_category(bundle, EvidenceCategory::Replay);
    let note = if indexed.is_empty() {
        "no replay-status artifacts are indexed in this run; regenerate one with \
         `frankenctl replay run --trace <trace.json> --mode strict` and re-index."
            .to_string()
    } else {
        format!(
            "{} replay-status artifact(s) indexed; re-verify with `frankenctl replay run ... --mode strict`.",
            indexed.len()
        )
    };
    ReplayView {
        schema: EXPLAIN_REPLAY_VIEW_SCHEMA.to_string(),
        run_id: bundle.run_id.clone(),
        modes: vec!["strict".to_string(), "validate".to_string()],
        indexed_replay_artifacts: indexed,
        divergence_classification: vec![
            DivergenceClass {
                label: "identical".to_string(),
                meaning: "replay reproduced every authoritative field byte-for-byte.".to_string(),
            },
            DivergenceClass {
                label: "benign_divergence".to_string(),
                meaning: "only non-authoritative display fields differ; the decision is unchanged."
                    .to_string(),
            },
            DivergenceClass {
                label: "critical_divergence".to_string(),
                meaning: "an authoritative decision/evidence field differs; strict replay aborts on first occurrence."
                    .to_string(),
            },
        ],
        note,
        disclaimer: EXPLAIN_VIEW_DISCLAIMER.to_string(),
    }
}

// ---------------------------------------------------------------------------
// counterfactuals.json
// ---------------------------------------------------------------------------

/// The derived counterfactual view (`counterfactuals.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualView {
    pub schema: String,
    pub run_id: String,
    pub indexed_counterfactual_artifacts: Vec<ArtifactPointer>,
    pub note: String,
    pub disclaimer: String,
}

/// Build the derived counterfactual view from the index.
pub fn build_counterfactual_view(bundle: &RuntimeExplainBundle) -> CounterfactualView {
    let indexed = pointers_for_category(bundle, EvidenceCategory::Counterfactual);
    let note = if indexed.is_empty() {
        "no counterfactual artifacts are indexed in this run; generate \"what would have happened\" \
         answers via the counterfactual_replay_engine / forensic_query_api surfaces and re-index."
            .to_string()
    } else {
        format!(
            "{} counterfactual artifact(s) indexed (owned by counterfactual_replay_engine / forensic_query_api).",
            indexed.len()
        )
    };
    CounterfactualView {
        schema: EXPLAIN_COUNTERFACTUAL_VIEW_SCHEMA.to_string(),
        run_id: bundle.run_id.clone(),
        indexed_counterfactual_artifacts: indexed,
        note,
        disclaimer: EXPLAIN_VIEW_DISCLAIMER.to_string(),
    }
}

// ---------------------------------------------------------------------------
// repro.lock
// ---------------------------------------------------------------------------

/// A content digest for one indexed artifact in the reproducibility lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproArtifactDigest {
    pub artifact_id: String,
    pub schema_id: String,
    pub stable_ref: String,
    pub content_hash: String,
}

/// The derived, deterministic reproducibility lock (`repro.lock`). Unlike the
/// benchmark repro lock it carries no wall-clock, so the explain bundle is
/// content-addressable across runs of `explain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainReproLock {
    pub schema: String,
    pub run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    pub bundle_schema_version: String,
    pub bundle_content_hash: String,
    pub artifacts: Vec<ReproArtifactDigest>,
    pub commands: Vec<String>,
    pub disclaimer: String,
}

/// Build the deterministic reproducibility lock from the index.
pub fn build_repro_lock(bundle: &RuntimeExplainBundle) -> ExplainReproLock {
    // bundle.artifacts is a BTreeMap → already sorted by artifact_id.
    let artifacts = bundle
        .artifacts
        .values()
        .map(|artifact| ReproArtifactDigest {
            artifact_id: artifact.artifact_id.clone(),
            schema_id: artifact.schema_id.clone(),
            stable_ref: artifact.stable_ref.to_string(),
            content_hash: artifact.content_hash.to_string(),
        })
        .collect();
    ExplainReproLock {
        schema: EXPLAIN_REPRO_LOCK_SCHEMA.to_string(),
        run_id: bundle.run_id.clone(),
        source_revision: bundle.source_revision.clone(),
        bundle_schema_version: bundle.schema_version.to_string(),
        bundle_content_hash: bundle.content_hash().to_string(),
        artifacts,
        commands: verification_commands(bundle),
        disclaimer: EXPLAIN_VIEW_DISCLAIMER.to_string(),
    }
}

// ---------------------------------------------------------------------------
// commands.txt
// ---------------------------------------------------------------------------

/// The source file path indexed by the bundle, when present.
fn source_path(bundle: &RuntimeExplainBundle) -> Option<String> {
    bundle
        .artifacts
        .values()
        .find(|artifact| category_of(artifact) == EvidenceCategory::Source)
        .map(|artifact| artifact.stable_ref.key.clone())
}

/// Operator-verification commands derived from the index metadata. Deterministic.
fn verification_commands(bundle: &RuntimeExplainBundle) -> Vec<String> {
    let mut commands = Vec::new();
    let goal = bundle.metadata.get(BUNDLE_META_PARSE_GOAL);
    let extension = bundle.metadata.get(BUNDLE_META_EXTENSION_ID);
    if let Some(source) = source_path(bundle) {
        let mut run = format!("frankenctl run --input {source}");
        if let Some(ext) = extension {
            run.push_str(&format!(" --extension-id {ext}"));
        }
        if let Some(goal) = goal {
            run.push_str(&format!(" --goal {goal}"));
        }
        run.push_str(" --explain run.explain.json");
        commands.push(run);
        commands.push(format!("frankenctl check {source} --format json"));
    }
    commands.push("frankenctl explain <bundle.json> --emit-bundle ./explain_bundle".to_string());
    if !pointers_for_category(bundle, EvidenceCategory::Replay).is_empty() {
        commands.push("frankenctl replay run --trace <trace.json> --mode strict".to_string());
    }
    commands
}

/// Render `commands.txt` (one operator-verification command per line).
pub fn render_commands_txt(bundle: &RuntimeExplainBundle) -> String {
    let mut text = String::from("# operator-verification commands (derived; deterministic)\n");
    for command in verification_commands(bundle) {
        text.push_str(&command);
        text.push('\n');
    }
    text
}

// ---------------------------------------------------------------------------
// explain.md
// ---------------------------------------------------------------------------

/// Find the single ChosenAction artifact (the decision the narrative explains).
fn chosen_action_artifact(bundle: &RuntimeExplainBundle) -> Option<&RuntimeArtifactRef> {
    bundle
        .artifacts
        .values()
        .find(|artifact| matches!(artifact.kind, RuntimeArtifactKind::ChosenAction))
}

/// Render the human-readable `explain.md` narrative from the index.
pub fn render_explain_markdown(bundle: &RuntimeExplainBundle) -> String {
    let graph = build_evidence_graph(bundle);
    let mut out = String::new();
    out.push_str(&format!("# Runtime explanation — {}\n\n", bundle.run_id));
    out.push_str(&format!("> {}\n\n", EXPLAIN_VIEW_DISCLAIMER));

    // Provenance header.
    out.push_str(&format!(
        "- bundle content hash: `{}`\n",
        bundle.content_hash()
    ));
    out.push_str(&format!(
        "- index schema version: `{}`\n",
        bundle.schema_version
    ));
    if let Some(revision) = &bundle.source_revision {
        out.push_str(&format!("- source revision: `{revision}`\n"));
    }
    if let Some(command) = bundle.metadata.get(BUNDLE_META_COMMAND) {
        out.push_str(&format!("- command: `{command}`\n"));
    }
    if let Some(extension) = bundle.metadata.get(BUNDLE_META_EXTENSION_ID) {
        out.push_str(&format!("- extension: `{extension}`\n"));
    }
    if let Some(source) = source_path(bundle) {
        out.push_str(&format!("- source: `{source}`\n"));
    }
    out.push('\n');

    // The decision "why" story.
    out.push_str("## Decision\n\n");
    match chosen_action_artifact(bundle) {
        Some(action) => {
            let chosen = action
                .metadata
                .get(EXPLAIN_META_CHOSEN_ACTION)
                .map(String::as_str)
                .unwrap_or("<not recorded>");
            out.push_str(&format!("The runtime chose **{chosen}**"));
            if let Some(lane) = action.metadata.get(EXPLAIN_META_LANE) {
                out.push_str(&format!(" on the `{lane}` lane"));
            }
            out.push_str(".\n");
            if let Some(reason) = action.metadata.get(EXPLAIN_META_LANE_REASON) {
                out.push_str(&format!("- why: {reason}\n"));
            }
            if let Some(loss) = action.metadata.get(EXPLAIN_META_EXPECTED_LOSS) {
                out.push_str(&format!("- expected loss (millionths): {loss}\n"));
            }
            out.push_str(&format!(
                "- decision artifact: `{}` (`{}`)\n",
                action.artifact_id, action.stable_ref
            ));
        }
        None => {
            out.push_str(
                "No `ChosenAction` artifact is indexed in this bundle; the decision could not be narrated.\n",
            );
        }
    }
    out.push('\n');

    // Per-decision source links — the load-bearing acceptance criterion.
    out.push_str("## Per-decision source links\n\n");
    let decision_nodes: Vec<&EvidenceNode> = graph
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                node.category,
                EvidenceCategory::Decision | EvidenceCategory::Receipt
            )
        })
        .collect();
    if decision_nodes.is_empty() {
        out.push_str("_No decision/receipt nodes were indexed._\n");
    } else {
        for node in decision_nodes {
            match &node.source_link {
                Some(link) => {
                    let span = link
                        .span
                        .as_deref()
                        .map(|span| format!(" @ {span}"))
                        .unwrap_or_default();
                    out.push_str(&format!(
                        "- `{}` ({}) ⟵ derived from `{}`{span}\n",
                        node.id, node.kind, link.stable_ref
                    ));
                }
                None => out.push_str(&format!(
                    "- `{}` ({}) ⟵ no source link reachable in the index\n",
                    node.id, node.kind
                )),
            }
        }
        out.push_str(
            "\n_Span-precise links are shown when the index carries a `source_span`; otherwise the file-level link is shown._\n",
        );
    }
    out.push('\n');

    // Evidence graph summary by category.
    out.push_str("## Evidence graph\n\n");
    out.push_str(&format!(
        "{} nodes, {} edges. By category:\n",
        graph.node_count, graph.edge_count
    ));
    let mut by_category: BTreeMap<&str, usize> = BTreeMap::new();
    for node in &graph.nodes {
        *by_category.entry(node.category.as_str()).or_default() += 1;
    }
    for (category, count) in &by_category {
        out.push_str(&format!("- {category}: {count}\n"));
    }
    out.push_str("\nSee `evidence_graph.json` for the full node/edge graph.\n\n");

    // Replay / counterfactual / verify pointers.
    out.push_str("## Replay & counterfactuals\n\n");
    out.push_str("- replay: see `replay.json` (modes: strict, validate).\n");
    out.push_str("- counterfactuals: see `counterfactuals.json`.\n\n");

    out.push_str("## Verify\n\n");
    out.push_str("Run the commands in `commands.txt`; `repro.lock` content-addresses every indexed artifact.\n");

    out
}

// ---------------------------------------------------------------------------
// Whole-bundle assembly
// ---------------------------------------------------------------------------

/// All six derived explain artifacts, ready to write to a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainBundleArtifacts {
    pub explain_md: String,
    pub evidence_graph: EvidenceGraph,
    pub replay: ReplayView,
    pub counterfactuals: CounterfactualView,
    pub commands_txt: String,
    pub repro_lock: ExplainReproLock,
}

/// Build all six derived explain views from the index in one pass.
pub fn build_explain_bundle(bundle: &RuntimeExplainBundle) -> ExplainBundleArtifacts {
    ExplainBundleArtifacts {
        explain_md: render_explain_markdown(bundle),
        evidence_graph: build_evidence_graph(bundle),
        replay: build_replay_view(bundle),
        counterfactuals: build_counterfactual_view(bundle),
        commands_txt: render_commands_txt(bundle),
        repro_lock: build_repro_lock(bundle),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_tiers::ContentHash;
    use crate::runtime_explain_bundle::{
        RuntimeArtifactRef, RuntimeExplainBundleBuilder, RuntimeExplainLink,
        RuntimeExplainRelation, RuntimeExplainRole, StableArtifactRef,
    };

    /// A small but representative index: source → action (DerivedFrom),
    /// posterior → action (SelectsAction), action → evidence (EmitsEvidence),
    /// action → containment (ProducesContainment). The action carries narrative
    /// metadata + a source span.
    fn sample_bundle() -> RuntimeExplainBundle {
        let source = RuntimeArtifactRef::new(
            "source",
            RuntimeArtifactKind::Other {
                schema_id: "franken-engine.frankenctl.run-source.v1".to_string(),
            },
            ContentHash::compute(b"const x = 1;\n"),
            StableArtifactRef::new("source_file", "demo.js"),
        )
        .with_schema_id("franken-engine.frankenctl.run-source.v1");

        let action = RuntimeArtifactRef::new(
            "action-decision",
            RuntimeArtifactKind::ChosenAction,
            ContentHash::compute(b"action"),
            StableArtifactRef::new("execution_orchestrator", "decision-1").with_revision("trace-1"),
        )
        .with_role(RuntimeExplainRole::ChosenAction)
        .with_metadata(EXPLAIN_META_CHOSEN_ACTION, "allow")
        .with_metadata(EXPLAIN_META_LANE, "baseline_deterministic")
        .with_metadata(EXPLAIN_META_LANE_REASON, "no risk threshold crossed")
        .with_metadata(EXPLAIN_META_EXPECTED_LOSS, "1200")
        .with_metadata(EXPLAIN_META_SOURCE_SPAN, "L1:1");

        let posterior = RuntimeArtifactRef::new(
            "guardplane-posterior",
            RuntimeArtifactKind::GuardplanePosterior,
            ContentHash::compute(b"posterior"),
            StableArtifactRef::new("guardplane_adapter", "decision-1"),
        )
        .with_role(RuntimeExplainRole::GuardplanePosterior);

        let evidence = RuntimeArtifactRef::new(
            "evidence-0",
            RuntimeArtifactKind::EvidenceEntry,
            ContentHash::compute(b"evidence"),
            StableArtifactRef::new("evidence_ledger", "entry-0"),
        )
        .with_role(RuntimeExplainRole::EvidenceEntry);

        let containment = RuntimeArtifactRef::new(
            "containment-receipt",
            RuntimeArtifactKind::ContainmentReceipt,
            ContentHash::compute(b"containment"),
            StableArtifactRef::new("containment_executor", "decision-1"),
        )
        .with_role(RuntimeExplainRole::ContainmentReceipt);

        RuntimeExplainBundleBuilder::new("trace-1")
            .with_source_revision("0.1.0")
            .with_metadata("command", "frankenctl run")
            .with_metadata("extension_id", "demo-ext")
            .with_metadata("parse_goal", "script")
            .add_artifact(source)
            .unwrap()
            .add_artifact(action)
            .unwrap()
            .add_artifact(posterior)
            .unwrap()
            .add_artifact(evidence)
            .unwrap()
            .add_artifact(containment)
            .unwrap()
            .add_link(RuntimeExplainLink::new(
                "source-to-action",
                "source",
                "action-decision",
                RuntimeExplainRelation::DerivedFrom,
            ))
            .add_link(RuntimeExplainLink::new(
                "posterior-to-action",
                "guardplane-posterior",
                "action-decision",
                RuntimeExplainRelation::SelectsAction,
            ))
            .add_link(RuntimeExplainLink::new(
                "action-to-evidence-0",
                "action-decision",
                "evidence-0",
                RuntimeExplainRelation::EmitsEvidence,
            ))
            .add_link(RuntimeExplainLink::new(
                "action-to-containment",
                "action-decision",
                "containment-receipt",
                RuntimeExplainRelation::ProducesContainment,
            ))
            .build()
    }

    #[test]
    fn evidence_graph_categorizes_nodes_and_links_decisions_to_source() {
        let bundle = sample_bundle();
        let graph = build_evidence_graph(&bundle);
        assert_eq!(graph.node_count, 5);
        assert_eq!(graph.edge_count, 4);

        let categories: BTreeMap<&str, &EvidenceCategory> = graph
            .nodes
            .iter()
            .map(|n| (n.id.as_str(), &n.category))
            .collect();
        assert_eq!(categories["source"], &EvidenceCategory::Source);
        assert_eq!(categories["action-decision"], &EvidenceCategory::Decision);
        assert_eq!(
            categories["guardplane-posterior"],
            &EvidenceCategory::Decision
        );
        assert_eq!(categories["evidence-0"], &EvidenceCategory::Evidence);
        assert_eq!(
            categories["containment-receipt"],
            &EvidenceCategory::Receipt
        );

        // Every decision links back to the source — the acceptance criterion.
        let action = graph
            .nodes
            .iter()
            .find(|n| n.id == "action-decision")
            .unwrap();
        let link = action.source_link.as_ref().expect("action has source link");
        assert_eq!(link.artifact_id, "source");
        assert_eq!(link.stable_ref, "source_file:demo.js");
        assert_eq!(link.span.as_deref(), Some("L1:1"));
        assert_eq!(action.label.as_deref(), Some("allow"));

        // The posterior (transitively connected to source via the action) also
        // resolves a source link.
        let posterior = graph
            .nodes
            .iter()
            .find(|n| n.id == "guardplane-posterior")
            .unwrap();
        assert_eq!(
            posterior
                .source_link
                .as_ref()
                .map(|l| l.artifact_id.as_str()),
            Some("source")
        );

        // The source node itself has no source_link (it IS the source).
        let source = graph.nodes.iter().find(|n| n.id == "source").unwrap();
        assert!(source.source_link.is_none());
    }

    #[test]
    fn explain_markdown_tells_the_why_story_with_source_links() {
        let bundle = sample_bundle();
        let md = render_explain_markdown(&bundle);
        assert!(md.contains("# Runtime explanation — trace-1"));
        assert!(md.contains("chose **allow**"));
        assert!(md.contains("baseline_deterministic"));
        assert!(md.contains("no risk threshold crossed"));
        // Per-decision source link present.
        assert!(md.contains("source_file:demo.js"));
        assert!(md.contains("@ L1:1"));
        assert!(md.contains("## Per-decision source links"));
    }

    #[test]
    fn replay_and_counterfactual_views_are_honest_when_absent() {
        let bundle = sample_bundle();
        let replay = build_replay_view(&bundle);
        assert_eq!(replay.modes, vec!["strict", "validate"]);
        assert!(replay.indexed_replay_artifacts.is_empty());
        assert!(replay.note.contains("no replay-status artifacts"));
        assert_eq!(replay.divergence_classification.len(), 3);

        let cf = build_counterfactual_view(&bundle);
        assert!(cf.indexed_counterfactual_artifacts.is_empty());
        assert!(cf.note.contains("no counterfactual artifacts"));
    }

    #[test]
    fn repro_lock_is_deterministic_and_covers_every_artifact() {
        let bundle = sample_bundle();
        let first = build_repro_lock(&bundle);
        let second = build_repro_lock(&bundle);
        // No wall-clock → byte-identical.
        let first_json = serde_json::to_string(&first).unwrap();
        let second_json = serde_json::to_string(&second).unwrap();
        assert_eq!(first_json, second_json);
        // Every indexed artifact is digested, sorted by id.
        assert_eq!(first.artifacts.len(), bundle.artifacts.len());
        let ids: Vec<&str> = first
            .artifacts
            .iter()
            .map(|a| a.artifact_id.as_str())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "artifacts sorted by id");
        assert_eq!(first.bundle_content_hash, bundle.content_hash().to_string());
    }

    #[test]
    fn commands_txt_references_the_indexed_source() {
        let bundle = sample_bundle();
        let commands = render_commands_txt(&bundle);
        assert!(commands.contains("frankenctl run --input demo.js"));
        assert!(commands.contains("--extension-id demo-ext"));
        assert!(commands.contains("frankenctl check demo.js"));
    }

    #[test]
    fn whole_bundle_builds_all_six_views_deterministically() {
        let bundle = sample_bundle();
        let first = build_explain_bundle(&bundle);
        let second = build_explain_bundle(&bundle);
        assert_eq!(
            first, second,
            "the derived bundle is a pure function of the index"
        );
        assert!(!first.explain_md.is_empty());
        assert_eq!(first.evidence_graph.node_count, 5);
    }

    #[test]
    fn no_view_overclaims_a_proof() {
        let bundle = sample_bundle();
        let artifacts = build_explain_bundle(&bundle);
        let mut blobs = vec![artifacts.explain_md.clone(), artifacts.commands_txt.clone()];
        blobs.push(serde_json::to_string(&artifacts.evidence_graph).unwrap());
        blobs.push(serde_json::to_string(&artifacts.replay).unwrap());
        blobs.push(serde_json::to_string(&artifacts.counterfactuals).unwrap());
        blobs.push(serde_json::to_string(&artifacts.repro_lock).unwrap());
        let forbidden = [
            "proof of correctness",
            "guarantees",
            "guaranteed",
            "provably",
            "unbreakable",
            "category-defining",
        ];
        for blob in &blobs {
            let lower = blob.to_ascii_lowercase();
            for phrase in &forbidden {
                assert!(!lower.contains(phrase), "over-claim `{phrase}` in: {blob}");
            }
        }
    }
}
