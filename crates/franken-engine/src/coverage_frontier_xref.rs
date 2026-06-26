//! Coverage-Frontier Cross-Reference (`bd-fqlfw.7.3`, E7.T3) — join the
//! [`crate::coverage_frontier`] clusters against the
//! [`crate::parser_gap_inventory`] and [`crate::lowering_gap_inventory`]
//! truth inventories and surface drift as a **truth-gate** result.
//!
//! Each failing cluster either:
//! - **reconciles** — it maps to a documented inventory entry (we report which
//!   inventory, site, construct family, and remediation status), or
//! - is an **undocumented gap** — it maps to no inventory entry, which means the
//!   hand-maintained inventory has drifted from the observed frontier. Any
//!   undocumented gap fails the truth gate ([`XrefReport::truth_gate_pass`]).
//!
//! This is the forcing function the E7 plan calls for: the inventory cannot
//! silently fall behind reality, and the surfaced undocumented gaps are exactly
//! the worklist `bd-fqlfw.7.5`'s (gated) auto-bead-filing consumes. The gate is
//! a TOOL with its own exit code — it is deliberately *not* wired into the
//! always-green CI lane, because as ES coverage grows it is *expected* to
//! surface genuinely-undocumented gaps that a human must triage or file.
//!
//! ## Matching (precise, build-tuning-free)
//!
//! A cluster's construct key (a Test262 path like `language/statements/for-in`,
//! or a differential-oracle divergence class) and an inventory entry's construct
//! family (`feature_family` / `ast_node_family`, e.g. `for_in_statement` /
//! `statement.for_in`) are each reduced to a normalized token set: split on
//! non-alphanumerics, lowercased, generic path words dropped (`language`,
//! `statements`, `built`, `ins`, …), and stemmed (one trailing `s`). A cluster
//! matches an entry iff one token set is a non-empty subset of the other
//! (either direction). That makes `try` ⊆ `try_catch_finally` and
//! `template-literals` ≈ `template_literal` match, while keeping `for-in` and
//! `for-of` distinct and never matching `built-ins/*` to `for_in` (`ins` is a
//! dropped word, so it cannot collapse to `in`).
//!
//! ## Determinism
//!
//! Inventory entries are sorted `(inventory, site_id)`; token sets are
//! `BTreeSet`; findings are sorted `(outcome, construct, cluster_id)`; the
//! `report_digest` is a content hash over the canonical `(cluster_id, outcome)`
//! sequence. Identical input yields a byte-identical report.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::coverage_frontier::CoverageFrontierReport;
use crate::hash_tiers::ContentHash;

/// Schema id stamped on every emitted cross-reference report.
pub const COVERAGE_FRONTIER_XREF_SCHEMA_VERSION: &str = "franken-engine.coverage-frontier-xref.v1";

/// Generic path/grammar words dropped before matching (checked against the raw
/// lowercased token, before stemming). `ins` is here so `built-ins` cannot
/// collapse to the `in` of `for-in`.
const STOPWORDS: &[&str] = &[
    "language",
    "statements",
    "statement",
    "expressions",
    "expression",
    "built",
    "ins",
    "prototype",
    "annexb",
    "annex",
    "intl",
    "harness",
    "staging",
    "test",
    "tests",
    "misc",
];

/// One documented gap, flattened from either inventory, with its construct
/// tokens precomputed for matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryEntry {
    /// Which inventory this came from.
    pub inventory: String,
    /// Inventory site id (stable identifier).
    pub site_id: String,
    /// Construct family string as the inventory states it.
    pub family: String,
    /// Remediation status (`resolved` / `fail_closed` / `open_placeholder`).
    pub status: String,
    /// Normalized construct tokens used for matching.
    pub tokens: BTreeSet<String>,
}

/// A per-cluster cross-reference finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrefFinding {
    /// Cluster content-hash id (from E7.T1).
    pub cluster_id: String,
    /// Failure stream (`test262` / `differential_oracle`).
    pub source: String,
    /// Spec-construct key.
    pub construct: String,
    /// Raw failing count.
    pub failing_count: usize,
    /// `reconciled` or `undocumented`.
    pub outcome: String,
    /// Number of inventory entries that matched (0 ⇒ undocumented).
    pub matched_count: usize,
    /// The representative matched inventory (first in sorted order), if any.
    pub matched_inventory: Option<String>,
    /// Matched site id, if any.
    pub matched_site_id: Option<String>,
    /// Matched construct family, if any.
    pub matched_family: Option<String>,
    /// Matched remediation status, if any.
    pub matched_status: Option<String>,
    /// Human-readable explanation.
    pub detail: String,
}

/// The cross-reference / truth-gate report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrefReport {
    /// Schema id (`COVERAGE_FRONTIER_XREF_SCHEMA_VERSION`).
    pub schema_version: String,
    /// Number of clusters cross-referenced.
    pub total_clusters: usize,
    /// Clusters that mapped to a documented inventory entry.
    pub reconciled_count: usize,
    /// Clusters that mapped to no inventory entry (truth-gate failures).
    pub undocumented_count: usize,
    /// `true` iff there are zero undocumented gaps.
    pub truth_gate_pass: bool,
    /// Per-cluster findings, sorted `(outcome, construct, cluster_id)`.
    pub findings: Vec<XrefFinding>,
    /// Content hash over the canonical `(cluster_id, outcome)` sequence.
    pub report_digest: String,
}

const OUTCOME_RECONCILED: &str = "reconciled";
const OUTCOME_UNDOCUMENTED: &str = "undocumented";

/// Reduce a construct string to its normalized matching tokens.
pub fn normalize_tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|raw| !raw.is_empty())
        .map(|raw| raw.to_ascii_lowercase())
        .filter(|tok| !STOPWORDS.contains(&tok.as_str()))
        .map(|tok| stem(&tok))
        .filter(|tok| !tok.is_empty())
        .collect()
}

/// Strip a single trailing `s` (length-preserving for 1-char tokens), so
/// `literals → literal`, `keys → key`, while leaving `as`/`is` untouched enough
/// for our purposes (`s`-only tokens are dropped as empty upstream anyway).
fn stem(token: &str) -> String {
    if token.len() > 2 && token.ends_with('s') {
        token[..token.len() - 1].to_string()
    } else {
        token.to_string()
    }
}

/// Whether a cluster's tokens match an inventory entry's tokens: one set is a
/// non-empty subset of the other (either direction).
fn tokens_match(cluster: &BTreeSet<String>, entry: &BTreeSet<String>) -> bool {
    if cluster.is_empty() || entry.is_empty() {
        return false;
    }
    cluster.is_subset(entry) || entry.is_subset(cluster)
}

/// Flatten both real inventories into matchable entries, sorted
/// `(inventory, site_id)` for deterministic first-match selection.
pub fn default_inventory_entries() -> Vec<InventoryEntry> {
    let mut entries = Vec::new();

    for site in crate::lowering_gap_inventory::lowering_gap_inventory().sites {
        let tokens = normalize_tokens(&site.ast_node_family);
        entries.push(InventoryEntry {
            inventory: "lowering_gap_inventory".to_string(),
            site_id: site.site_id,
            family: site.ast_node_family,
            status: site.status.as_str().to_string(),
            tokens,
        });
    }
    for site in crate::parser_gap_inventory::parser_gap_inventory().sites {
        let tokens = normalize_tokens(&site.feature_family);
        entries.push(InventoryEntry {
            inventory: "parser_gap_inventory".to_string(),
            site_id: site.site_id,
            family: site.feature_family,
            status: site.remediation_status.as_str().to_string(),
            tokens,
        });
    }

    entries.sort_by(|a, b| {
        a.inventory
            .cmp(&b.inventory)
            .then_with(|| a.site_id.cmp(&b.site_id))
    });
    entries
}

/// Content hash over the canonical `(cluster_id, outcome)` sequence.
fn compute_xref_digest(findings: &[XrefFinding]) -> String {
    let mut buf = Vec::new();
    for finding in findings {
        for field in [finding.cluster_id.as_bytes(), finding.outcome.as_bytes()] {
            buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
            buf.extend_from_slice(field);
        }
    }
    ContentHash::compute(&buf).to_hex()
}

/// Cross-reference the frontier clusters against inventory entries, producing a
/// truth-gate report (`truth_gate_pass == false` ⇒ undocumented gaps exist).
pub fn cross_reference(report: &CoverageFrontierReport, entries: &[InventoryEntry]) -> XrefReport {
    let mut findings: Vec<XrefFinding> = report
        .clusters
        .iter()
        .map(|cluster| {
            let cluster_tokens = normalize_tokens(&cluster.construct);
            let matched: Vec<&InventoryEntry> = entries
                .iter()
                .filter(|entry| tokens_match(&cluster_tokens, &entry.tokens))
                .collect();
            if let Some(first) = matched.first() {
                XrefFinding {
                    cluster_id: cluster.cluster_id.clone(),
                    source: cluster.source.clone(),
                    construct: cluster.construct.clone(),
                    failing_count: cluster.failing_count,
                    outcome: OUTCOME_RECONCILED.to_string(),
                    matched_count: matched.len(),
                    matched_inventory: Some(first.inventory.clone()),
                    matched_site_id: Some(first.site_id.clone()),
                    matched_family: Some(first.family.clone()),
                    matched_status: Some(first.status.clone()),
                    detail: format!(
                        "{} failing in `{}` reconciles with {} entr{} (e.g. {}::{} family `{}` status `{}`)",
                        cluster.failing_count,
                        cluster.construct,
                        matched.len(),
                        if matched.len() == 1 { "y" } else { "ies" },
                        first.inventory,
                        first.site_id,
                        first.family,
                        first.status,
                    ),
                }
            } else {
                XrefFinding {
                    cluster_id: cluster.cluster_id.clone(),
                    source: cluster.source.clone(),
                    construct: cluster.construct.clone(),
                    failing_count: cluster.failing_count,
                    outcome: OUTCOME_UNDOCUMENTED.to_string(),
                    matched_count: 0,
                    matched_inventory: None,
                    matched_site_id: None,
                    matched_family: None,
                    matched_status: None,
                    detail: format!(
                        "{} failing in `{}` ({}) maps to NO parser/lowering inventory entry — undocumented gap (inventory drifted from reality)",
                        cluster.failing_count, cluster.construct, cluster.source,
                    ),
                }
            }
        })
        .collect();

    // Deterministic order: undocumented (the gate failures) before reconciled,
    // then by construct, then by the stable content-hash cluster id.
    fn outcome_rank(outcome: &str) -> u8 {
        if outcome == OUTCOME_UNDOCUMENTED {
            0
        } else {
            1
        }
    }
    findings.sort_by(|a, b| {
        outcome_rank(&a.outcome)
            .cmp(&outcome_rank(&b.outcome))
            .then_with(|| a.construct.cmp(&b.construct))
            .then_with(|| a.cluster_id.cmp(&b.cluster_id))
    });

    let undocumented_count = findings
        .iter()
        .filter(|f| f.outcome == OUTCOME_UNDOCUMENTED)
        .count();
    let reconciled_count = findings.len() - undocumented_count;
    let report_digest = compute_xref_digest(&findings);

    XrefReport {
        schema_version: COVERAGE_FRONTIER_XREF_SCHEMA_VERSION.to_string(),
        total_clusters: report.clusters.len(),
        reconciled_count,
        undocumented_count,
        truth_gate_pass: undocumented_count == 0,
        findings,
        report_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage_frontier::{FailureObservation, FrontierSource, cluster_failures};

    fn frontier(gaps: &[(FrontierSource, &str, usize)]) -> CoverageFrontierReport {
        let mut observations = Vec::new();
        for (source, construct, count) in gaps {
            for i in 0..*count {
                observations.push(FailureObservation::new(
                    *source,
                    *construct,
                    format!("{construct}/{i}"),
                    "fail",
                ));
            }
        }
        cluster_failures(&observations, 3, 8)
    }

    // ---- token normalization --------------------------------------------

    #[test]
    fn normalize_drops_path_words_and_stems() {
        assert_eq!(
            normalize_tokens("language/statements/for-in"),
            BTreeSet::from(["for".to_string(), "in".to_string()])
        );
        assert_eq!(
            normalize_tokens("language/expressions/template-literals"),
            BTreeSet::from(["template".to_string(), "literal".to_string()])
        );
    }

    #[test]
    fn builtins_does_not_collapse_to_for_in() {
        // `built-ins` must not yield an `in` token (would falsely match for-in).
        let toks = normalize_tokens("built-ins/Proxy/ownKeys");
        assert!(!toks.contains("in"), "ins must be dropped, got {toks:?}");
        assert!(toks.contains("proxy"));
    }

    #[test]
    fn inventory_family_tokens_normalize_as_expected() {
        assert_eq!(
            normalize_tokens("for_in_statement"),
            BTreeSet::from(["for".to_string(), "in".to_string()])
        );
        assert_eq!(
            normalize_tokens("statement.for_of"),
            BTreeSet::from(["for".to_string(), "of".to_string()])
        );
        assert_eq!(
            normalize_tokens("try_catch_finally"),
            BTreeSet::from([
                "try".to_string(),
                "catch".to_string(),
                "finally".to_string()
            ])
        );
    }

    // ---- match precision -------------------------------------------------

    #[test]
    fn for_in_matches_for_in_not_for_of() {
        let for_in = normalize_tokens("for_in_statement");
        let cluster_in = normalize_tokens("language/statements/for-in");
        let cluster_of = normalize_tokens("language/statements/for-of");
        assert!(tokens_match(&cluster_in, &for_in));
        assert!(!tokens_match(&cluster_of, &for_in));
    }

    #[test]
    fn try_cluster_is_subset_of_try_catch_finally() {
        let entry = normalize_tokens("try_catch_finally");
        let cluster = normalize_tokens("language/statements/try");
        assert!(tokens_match(&cluster, &entry), "try ⊆ try/catch/finally");
    }

    #[test]
    fn empty_tokens_never_match() {
        let empty = BTreeSet::new();
        let some = normalize_tokens("for_in_statement");
        assert!(!tokens_match(&empty, &some));
        assert!(!tokens_match(&some, &empty));
    }

    // ---- inventory flattening -------------------------------------------

    #[test]
    fn default_entries_cover_both_inventories() {
        let entries = default_inventory_entries();
        assert_eq!(entries.len(), 14, "7 parser + 7 lowering sites");
        assert!(
            entries
                .iter()
                .any(|e| e.inventory == "parser_gap_inventory")
        );
        assert!(
            entries
                .iter()
                .any(|e| e.inventory == "lowering_gap_inventory")
        );
        // Sorted: lowering before parser.
        assert_eq!(entries[0].inventory, "lowering_gap_inventory");
        // Every flattened entry carries a status string.
        assert!(entries.iter().all(|e| !e.status.is_empty()));
    }

    // ---- the two acceptance directions ----------------------------------

    #[test]
    fn documented_construct_reconciles_and_passes_gate() {
        // for-in is tracked by BOTH inventories (and marked resolved).
        let report = frontier(&[(FrontierSource::Test262, "language/statements/for-in", 4)]);
        let xref = cross_reference(&report, &default_inventory_entries());
        assert_eq!(xref.total_clusters, 1);
        assert_eq!(xref.reconciled_count, 1);
        assert_eq!(xref.undocumented_count, 0);
        assert!(xref.truth_gate_pass, "documented gap reconciles");
        let f = &xref.findings[0];
        assert_eq!(f.outcome, "reconciled");
        assert_eq!(f.matched_count, 2, "parser + lowering both track for-in");
        assert!(f.matched_family.is_some());
        assert!(f.matched_status.is_some());
    }

    #[test]
    fn undocumented_construct_fails_truth_gate() {
        // Proxy traps are not in the parser/lowering inventories.
        let report = frontier(&[(FrontierSource::Test262, "built-ins/Proxy/ownKeys", 9)]);
        let xref = cross_reference(&report, &default_inventory_entries());
        assert_eq!(xref.undocumented_count, 1);
        assert!(
            !xref.truth_gate_pass,
            "undocumented gap fails the truth gate"
        );
        assert_eq!(xref.findings[0].outcome, "undocumented");
        assert_eq!(xref.findings[0].matched_count, 0);
        assert!(xref.findings[0].matched_inventory.is_none());
    }

    #[test]
    fn oracle_runtime_cluster_is_undocumented() {
        let report = frontier(&[(FrontierSource::DifferentialOracle, "runtime", 2)]);
        let xref = cross_reference(&report, &default_inventory_entries());
        assert!(!xref.truth_gate_pass);
        assert_eq!(xref.findings[0].source, "differential_oracle");
        assert_eq!(xref.findings[0].outcome, "undocumented");
    }

    #[test]
    fn mixed_documented_and_undocumented_counts_and_gate() {
        let report = frontier(&[
            (FrontierSource::Test262, "language/statements/for-of", 3),
            (FrontierSource::Test262, "built-ins/Map/iterator", 5),
            (
                FrontierSource::Test262,
                "language/expressions/template-literals",
                2,
            ),
        ]);
        let xref = cross_reference(&report, &default_inventory_entries());
        assert_eq!(xref.total_clusters, 3);
        assert_eq!(
            xref.reconciled_count, 2,
            "for-of + template-literal documented"
        );
        assert_eq!(xref.undocumented_count, 1, "Map/iterator undocumented");
        assert!(!xref.truth_gate_pass);
        // Undocumented findings sort first.
        assert_eq!(xref.findings[0].outcome, "undocumented");
        assert_eq!(xref.findings[0].construct, "built-ins/Map/iterator");
    }

    // ---- determinism -----------------------------------------------------

    #[test]
    fn cross_reference_is_deterministic_and_content_hashed() {
        let report = frontier(&[
            (FrontierSource::Test262, "language/statements/for-in", 4),
            (FrontierSource::Test262, "built-ins/Proxy/ownKeys", 9),
            (FrontierSource::DifferentialOracle, "runtime", 2),
        ]);
        let entries = default_inventory_entries();
        let a = cross_reference(&report, &entries);
        let b = cross_reference(&report, &entries);
        assert_eq!(a, b);
        assert_eq!(a.report_digest, b.report_digest);
    }

    #[test]
    fn all_documented_passes_gate() {
        let report = frontier(&[
            (FrontierSource::Test262, "language/statements/for-in", 1),
            (FrontierSource::Test262, "language/statements/for-of", 1),
            (FrontierSource::Test262, "language/statements/try", 1),
        ]);
        let xref = cross_reference(&report, &default_inventory_entries());
        assert_eq!(xref.undocumented_count, 0);
        assert!(
            xref.truth_gate_pass,
            "all-documented frontier passes the gate"
        );
    }

    #[test]
    fn empty_frontier_passes_gate() {
        let report = cluster_failures(&[], 3, 8);
        let xref = cross_reference(&report, &default_inventory_entries());
        assert_eq!(xref.total_clusters, 0);
        assert!(xref.truth_gate_pass);
        assert_eq!(xref.schema_version, COVERAGE_FRONTIER_XREF_SCHEMA_VERSION);
    }
}
