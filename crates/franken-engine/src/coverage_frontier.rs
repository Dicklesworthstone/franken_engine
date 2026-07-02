//! Coverage Frontier (`bd-fqlfw.7.1`, E7.T1) — cluster Test262 and
//! differential-oracle FAILURES by spec construct, with deterministic,
//! content-hashed cluster ids.
//!
//! This is the **report-first** foundation of the E7 Conformance Frontier
//! (`bd-fqlfw.7`): it turns the project's probe-driven coverage guesswork into a
//! measured, deduplicable failure map. It deliberately does *one* thing —
//! group failing observations into stable clusters keyed by spec construct and
//! address each cluster by a content hash of its identity. Two follow-ups build
//! on these clusters:
//!
//! - `bd-fqlfw.7.2` ranks clusters by a transparent impact score (one parser
//!   gap can mask thousands of failures; one semantic bug scatters across
//!   unrelated tests), so this module intentionally orders only by raw failing
//!   count — *not* impact.
//! - `bd-fqlfw.7.3` cross-references the parser/lowering gap inventories, so
//!   this module does *not* consult them.
//!
//! ## Why content-hashed cluster ids
//!
//! The cluster id is a pure function of the cluster's *identity*
//! (`source` + `construct`) — never of its volatile membership or counts. So
//! the same construct hashes to the same id on every run, which is exactly what
//! lets the gated auto-bead-filing step (`bd-fqlfw.7`'s DONE-WHEN) dedup against
//! already-filed work instead of re-filing the same gap each run.
//!
//! ## Determinism
//!
//! Clusters are keyed in a `BTreeMap`, bucket breakdowns are `BTreeMap`, sample
//! case ids are sorted+deduped+capped, the cluster vector is sorted by
//! (failing-count desc, id asc), and every hash mixes length-prefixed fields.
//! Identical input therefore yields a byte-identical report.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::differential_oracle::EngineCoreDifferentialReport;
use crate::hash_tiers::ContentHash;
use crate::test262_conformance_runner::{ConformanceReport, TestResult};

/// Schema id stamped on every emitted report.
pub const COVERAGE_FRONTIER_SCHEMA_VERSION: &str = "franken-engine.coverage-frontier.v1";

/// Default number of leading directory components (under the `test/<category>`
/// root) used to derive a spec-construct key. Depth 3 groups, e.g.,
/// `built-ins/Proxy/ownKeys` (per-trap) and `language/expressions/optional-chaining`.
pub const DEFAULT_CONSTRUCT_DEPTH: usize = 3;

/// Default cap on the number of sample case ids retained per cluster, keeping
/// the report bounded regardless of corpus size.
pub const DEFAULT_SAMPLE_LIMIT: usize = 8;

/// Which failure stream a clustered observation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FrontierSource {
    /// A Test262 conformance failure (`TestResult::Fail` / `TestResult::Error`).
    Test262,
    /// A franken-engine ↔ franken-core differential-oracle defect.
    DifferentialOracle,
}

impl FrontierSource {
    /// Stable lower-snake string used in hashes and serialized output.
    pub fn as_str(self) -> &'static str {
        match self {
            FrontierSource::Test262 => "test262",
            FrontierSource::DifferentialOracle => "differential_oracle",
        }
    }
}

/// A single normalized failing observation feeding the clusterer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureObservation {
    /// Originating failure stream.
    pub source: FrontierSource,
    /// Deterministic spec-construct key (the clustering dimension).
    pub construct: String,
    /// Case identity within the construct (Test262 path or oracle case id).
    pub case_id: String,
    /// Sub-bucket within the cluster: the Test262 result class
    /// (`fail`/`error`) or the oracle divergence comparison mode.
    pub bucket: String,
}

impl FailureObservation {
    /// Construct an observation from already-derived parts.
    pub fn new(
        source: FrontierSource,
        construct: impl Into<String>,
        case_id: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Self {
        Self {
            source,
            construct: construct.into(),
            case_id: case_id.into(),
            bucket: bucket.into(),
        }
    }
}

/// One content-addressed cluster of failures sharing a `(source, construct)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageCluster {
    /// Content hash (hex) of `(source, construct)` — stable across runs.
    pub cluster_id: String,
    /// Failure stream this cluster belongs to.
    pub source: String,
    /// Spec-construct key.
    pub construct: String,
    /// Number of failing observations in this cluster.
    pub failing_count: usize,
    /// Breakdown of failing observations by sub-bucket.
    pub buckets: BTreeMap<String, usize>,
    /// Sorted, deduplicated, capped sample of case ids in this cluster.
    pub sample_case_ids: Vec<String>,
}

/// The clustered coverage-frontier report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageFrontierReport {
    /// Schema id (`COVERAGE_FRONTIER_SCHEMA_VERSION`).
    pub schema_version: String,
    /// Total failing observations clustered.
    pub total_failures: usize,
    /// Number of distinct clusters.
    pub cluster_count: usize,
    /// Construct depth used to derive Test262 construct keys (provenance).
    pub construct_depth: usize,
    /// Per-cluster sample cap used (provenance).
    pub sample_limit: usize,
    /// Clusters, sorted by failing-count desc then `cluster_id` asc.
    pub clusters: Vec<CoverageCluster>,
    /// Content hash (hex) over the canonical `(cluster_id, failing_count)`
    /// sequence — a single integrity handle for the whole report.
    pub report_digest: String,
}

/// Derive a deterministic spec-construct key from a Test262 test path.
///
/// Drops a leading `test/` segment (tc39 layout is `test/<category>/...`) and
/// the trailing test filename, then joins the first `depth` directory
/// components with `/`. Examples (depth 3):
/// `test/built-ins/Proxy/ownKeys/return.js` → `built-ins/Proxy/ownKeys`;
/// `language/types/boolean.js` → `language/types`.
pub fn test262_construct_key(path: &Path, depth: usize) -> String {
    let depth = depth.max(1);
    let comps: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(segment) => Some(segment.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();

    // Anchor under the tc39 `test/` root if present, so callers can pass either
    // a corpus-relative (`test/...`) or category-relative (`language/...`) path.
    let start = usize::from(comps.first().map(String::as_str) == Some("test"));
    let dirs = &comps[start..];

    // The final component is the test file itself; cluster by its directory.
    let dir_count = dirs.len().saturating_sub(1);
    if dir_count == 0 {
        return dirs
            .first()
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
    }
    let take = depth.min(dir_count);
    dirs[..take].join("/")
}

/// Canonical, length-prefixed byte encoding of a cluster's identity. The
/// length prefixes prevent `(source="a", construct="bc")` colliding with
/// `(source="ab", construct="c")`.
fn canonical_cluster_key(source: FrontierSource, construct: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for field in [source.as_str().as_bytes(), construct.as_bytes()] {
        buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
        buf.extend_from_slice(field);
    }
    buf
}

/// Stable content-hash id (hex) for a cluster identity.
pub fn cluster_id(source: FrontierSource, construct: &str) -> String {
    ContentHash::compute(&canonical_cluster_key(source, construct)).to_hex()
}

/// Content hash over the canonical `(cluster_id, failing_count)` sequence.
fn compute_report_digest(clusters: &[CoverageCluster]) -> String {
    let mut buf = Vec::new();
    for cluster in clusters {
        let id = cluster.cluster_id.as_bytes();
        buf.extend_from_slice(&(id.len() as u64).to_be_bytes());
        buf.extend_from_slice(id);
        buf.extend_from_slice(&(cluster.failing_count as u64).to_be_bytes());
    }
    ContentHash::compute(&buf).to_hex()
}

/// Cluster failing observations into a deterministic, content-addressed report.
///
/// `construct_depth` and `sample_limit` are recorded for provenance;
/// observations are expected to already carry their derived `construct` (use
/// [`observations_from_conformance`] / [`observations_from_engine_core_report`]).
pub fn cluster_failures(
    observations: &[FailureObservation],
    construct_depth: usize,
    sample_limit: usize,
) -> CoverageFrontierReport {
    let mut groups: BTreeMap<(FrontierSource, String), Vec<&FailureObservation>> = BTreeMap::new();
    for observation in observations {
        groups
            .entry((observation.source, observation.construct.clone()))
            .or_default()
            .push(observation);
    }

    let mut clusters: Vec<CoverageCluster> = groups
        .into_iter()
        .map(|((source, construct), members)| {
            let mut buckets: BTreeMap<String, usize> = BTreeMap::new();
            let mut case_ids: Vec<String> = Vec::with_capacity(members.len());
            for member in &members {
                *buckets.entry(member.bucket.clone()).or_insert(0) += 1;
                case_ids.push(member.case_id.clone());
            }
            case_ids.sort();
            case_ids.dedup();
            let sample_case_ids = case_ids.into_iter().take(sample_limit).collect();
            CoverageCluster {
                cluster_id: cluster_id(source, &construct),
                source: source.as_str().to_string(),
                construct,
                failing_count: members.len(),
                buckets,
                sample_case_ids,
            }
        })
        .collect();

    // Largest gaps first; ties broken by the stable content-hash id so the
    // ordering is total and deterministic.
    clusters.sort_by(|a, b| {
        b.failing_count
            .cmp(&a.failing_count)
            .then_with(|| a.cluster_id.cmp(&b.cluster_id))
    });

    let report_digest = compute_report_digest(&clusters);
    CoverageFrontierReport {
        schema_version: COVERAGE_FRONTIER_SCHEMA_VERSION.to_string(),
        total_failures: observations.len(),
        cluster_count: clusters.len(),
        construct_depth,
        sample_limit,
        clusters,
        report_digest,
    }
}

/// Extract failing observations from a Test262 conformance report.
///
/// Only `TestResult::Fail` and `TestResult::Error` records are failures; `Pass`
/// (including a negative test that correctly threw) and `Skip` are not. The
/// runner's `result` field is taken as authoritative for negativity.
pub fn observations_from_conformance(
    report: &ConformanceReport,
    construct_depth: usize,
) -> Vec<FailureObservation> {
    report
        .test_records
        .iter()
        .filter(|record| matches!(record.result, TestResult::Fail | TestResult::Error))
        .map(|record| {
            FailureObservation::new(
                FrontierSource::Test262,
                test262_construct_key(&record.path, construct_depth),
                record.path.to_string_lossy().replace('\\', "/"),
                record.result.as_str(),
            )
        })
        .collect()
}

/// Extract failing observations from an engine ↔ core differential-oracle
/// report. Each defect contributes one observation, clustered by its dominant
/// divergence class (the first classified finding); the comparison mode of that
/// finding is the sub-bucket. A defect whose signature carries no classified
/// finding is clustered under `unclassified`.
pub fn observations_from_engine_core_report(
    report: &EngineCoreDifferentialReport,
) -> Vec<FailureObservation> {
    report
        .defects
        .iter()
        .map(|defect| {
            let dominant = defect.signature.findings.first();
            let construct = dominant
                .map(|finding| finding.class.clone())
                .unwrap_or_else(|| "unclassified".to_string());
            let bucket = dominant
                .map(|finding| finding.comparison_mode.clone())
                .unwrap_or_else(|| "unclassified".to_string());
            FailureObservation::new(
                FrontierSource::DifferentialOracle,
                construct,
                defect.case_id.clone(),
                bucket,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn obs(
        source: FrontierSource,
        construct: &str,
        case: &str,
        bucket: &str,
    ) -> FailureObservation {
        FailureObservation::new(source, construct, case, bucket)
    }

    // ---- construct-key derivation ----------------------------------------

    #[test]
    fn construct_key_drops_test_prefix_and_filename() {
        let p = PathBuf::from("test/built-ins/Proxy/ownKeys/return-type.js");
        assert_eq!(test262_construct_key(&p, 3), "built-ins/Proxy/ownKeys");
    }

    #[test]
    fn construct_key_accepts_category_relative_paths() {
        let p = PathBuf::from("language/expressions/optional-chaining/member-expr.js");
        assert_eq!(
            test262_construct_key(&p, 3),
            "language/expressions/optional-chaining"
        );
    }

    #[test]
    fn construct_key_depth_is_capped_to_available_dirs() {
        let p = PathBuf::from("language/types/boolean.js");
        assert_eq!(test262_construct_key(&p, 3), "language/types");
        assert_eq!(test262_construct_key(&p, 1), "language");
    }

    #[test]
    fn construct_key_depth_zero_is_treated_as_one() {
        let p = PathBuf::from("language/expressions/addition/x.js");
        assert_eq!(test262_construct_key(&p, 0), "language");
    }

    #[test]
    fn construct_key_handles_bare_filename() {
        let p = PathBuf::from("solo.js");
        assert_eq!(test262_construct_key(&p, 3), "solo.js");
    }

    #[test]
    fn construct_key_coarser_depth_merges_subtrees() {
        let a = PathBuf::from("built-ins/Proxy/get/x.js");
        let b = PathBuf::from("built-ins/Proxy/set/y.js");
        assert_eq!(test262_construct_key(&a, 2), test262_construct_key(&b, 2));
        assert_ne!(test262_construct_key(&a, 3), test262_construct_key(&b, 3));
    }

    // ---- cluster-id stability + content addressing -----------------------

    #[test]
    fn cluster_id_is_stable_for_same_identity() {
        assert_eq!(
            cluster_id(FrontierSource::Test262, "built-ins/Proxy"),
            cluster_id(FrontierSource::Test262, "built-ins/Proxy")
        );
    }

    #[test]
    fn cluster_id_differs_by_construct() {
        assert_ne!(
            cluster_id(FrontierSource::Test262, "built-ins/Proxy"),
            cluster_id(FrontierSource::Test262, "built-ins/Reflect")
        );
    }

    #[test]
    fn cluster_id_differs_by_source() {
        assert_ne!(
            cluster_id(FrontierSource::Test262, "runtime"),
            cluster_id(FrontierSource::DifferentialOracle, "runtime")
        );
    }

    #[test]
    fn cluster_id_is_64_char_hex() {
        let id = cluster_id(FrontierSource::Test262, "language/types");
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn cluster_key_length_prefix_prevents_field_boundary_collision() {
        // ("a","bc") and ("ab","c") must not hash equal.
        assert_ne!(
            ContentHash::compute(&canonical_cluster_key(FrontierSource::Test262, "x")).to_hex(),
            ContentHash::compute(&canonical_cluster_key(FrontierSource::Test262, "")).to_hex()
        );
        // Distinct construct boundaries differ.
        let k1 = canonical_cluster_key(FrontierSource::Test262, "ab/c");
        let k2 = canonical_cluster_key(FrontierSource::Test262, "a/bc");
        assert_ne!(k1, k2);
    }

    // ---- clustering ------------------------------------------------------

    #[test]
    fn clusters_group_by_source_and_construct() {
        let observations = vec![
            obs(FrontierSource::Test262, "built-ins/Proxy", "a.js", "fail"),
            obs(FrontierSource::Test262, "built-ins/Proxy", "b.js", "error"),
            obs(FrontierSource::Test262, "language/types", "c.js", "fail"),
        ];
        let report = cluster_failures(&observations, 3, 8);
        assert_eq!(report.total_failures, 3);
        assert_eq!(report.cluster_count, 2);
        let proxy = report
            .clusters
            .iter()
            .find(|c| c.construct == "built-ins/Proxy")
            .expect("proxy cluster");
        assert_eq!(proxy.failing_count, 2);
        assert_eq!(proxy.buckets.get("fail"), Some(&1));
        assert_eq!(proxy.buckets.get("error"), Some(&1));
        assert_eq!(proxy.sample_case_ids, vec!["a.js", "b.js"]);
    }

    #[test]
    fn clusters_sorted_by_failing_count_desc() {
        let mut observations = vec![obs(FrontierSource::Test262, "small", "s.js", "fail")];
        for i in 0..5 {
            observations.push(obs(
                FrontierSource::Test262,
                "big",
                &format!("b{i}.js"),
                "fail",
            ));
        }
        let report = cluster_failures(&observations, 3, 8);
        assert_eq!(report.clusters[0].construct, "big");
        assert_eq!(report.clusters[0].failing_count, 5);
        assert_eq!(report.clusters[1].construct, "small");
    }

    #[test]
    fn sample_case_ids_are_sorted_deduped_and_capped() {
        let observations = vec![
            obs(FrontierSource::Test262, "c", "z.js", "fail"),
            obs(FrontierSource::Test262, "c", "a.js", "fail"),
            obs(FrontierSource::Test262, "c", "a.js", "fail"), // duplicate
            obs(FrontierSource::Test262, "c", "m.js", "fail"),
        ];
        let report = cluster_failures(&observations, 3, 2);
        let c = &report.clusters[0];
        assert_eq!(c.failing_count, 4, "raw observation count is retained");
        assert_eq!(
            c.sample_case_ids,
            vec!["a.js", "m.js"],
            "sorted+deduped+capped"
        );
    }

    #[test]
    fn identical_input_yields_identical_report() {
        let observations = vec![
            obs(FrontierSource::Test262, "built-ins/Array", "a.js", "fail"),
            obs(
                FrontierSource::DifferentialOracle,
                "runtime",
                "loop",
                "structured_value",
            ),
            obs(FrontierSource::Test262, "language/types", "b.js", "error"),
        ];
        let a = cluster_failures(&observations, 3, 8);
        let b = cluster_failures(&observations, 3, 8);
        assert_eq!(a, b);
        assert_eq!(a.report_digest, b.report_digest);
    }

    #[test]
    fn input_order_does_not_change_report() {
        let forward = vec![
            obs(FrontierSource::Test262, "x", "1.js", "fail"),
            obs(FrontierSource::Test262, "y", "2.js", "fail"),
            obs(FrontierSource::Test262, "x", "3.js", "error"),
        ];
        let mut reversed = forward.clone();
        reversed.reverse();
        let a = cluster_failures(&forward, 3, 8);
        let b = cluster_failures(&reversed, 3, 8);
        assert_eq!(a.clusters, b.clusters);
        assert_eq!(a.report_digest, b.report_digest);
    }

    #[test]
    fn report_digest_changes_when_counts_change() {
        let one = vec![obs(FrontierSource::Test262, "x", "1.js", "fail")];
        let two = vec![
            obs(FrontierSource::Test262, "x", "1.js", "fail"),
            obs(FrontierSource::Test262, "x", "2.js", "fail"),
        ];
        assert_ne!(
            cluster_failures(&one, 3, 8).report_digest,
            cluster_failures(&two, 3, 8).report_digest
        );
    }

    #[test]
    fn empty_input_produces_empty_report() {
        let report = cluster_failures(&[], 3, 8);
        assert_eq!(report.total_failures, 0);
        assert_eq!(report.cluster_count, 0);
        assert!(report.clusters.is_empty());
        // A stable digest even when empty.
        assert_eq!(
            report.report_digest,
            cluster_failures(&[], 3, 8).report_digest
        );
    }

    #[test]
    fn schema_version_is_stamped() {
        let report = cluster_failures(&[], 3, 8);
        assert_eq!(report.schema_version, COVERAGE_FRONTIER_SCHEMA_VERSION);
        assert_eq!(report.construct_depth, 3);
        assert_eq!(report.sample_limit, 8);
    }

    #[test]
    fn cluster_ids_in_report_match_standalone_helper() {
        let observations = vec![obs(
            FrontierSource::Test262,
            "built-ins/Map",
            "m.js",
            "fail",
        )];
        let report = cluster_failures(&observations, 3, 8);
        assert_eq!(
            report.clusters[0].cluster_id,
            cluster_id(FrontierSource::Test262, "built-ins/Map")
        );
    }

    // ---- adapters --------------------------------------------------------

    #[test]
    fn conformance_adapter_keeps_only_failures() {
        use crate::test262_conformance_runner::TestRecord;
        let records = vec![
            TestRecord::new(
                PathBuf::from("test/built-ins/Proxy/get/x.js"),
                TestResult::Fail,
                10,
                Some("assertion".into()),
                false,
            ),
            TestRecord::new(
                PathBuf::from("test/built-ins/Proxy/get/y.js"),
                TestResult::Error,
                10,
                Some("threw".into()),
                false,
            ),
            TestRecord::new(
                PathBuf::from("test/built-ins/Proxy/get/z.js"),
                TestResult::Pass,
                10,
                None,
                false,
            ),
            TestRecord::new(
                PathBuf::from("test/built-ins/Proxy/get/s.js"),
                TestResult::Skip,
                10,
                None,
                false,
            ),
        ];
        let report = ConformanceReport::new(
            crate::security_epoch::SecurityEpoch::from_raw(1),
            "deadbeef".into(),
            records,
            4,
            true,
        );
        let observations = observations_from_conformance(&report, 3);
        assert_eq!(observations.len(), 2, "only Fail + Error are failures");
        assert!(
            observations
                .iter()
                .all(|o| o.source == FrontierSource::Test262)
        );
        assert!(
            observations
                .iter()
                .all(|o| o.construct == "built-ins/Proxy/get")
        );
        let clustered = cluster_failures(&observations, 3, 8);
        assert_eq!(clustered.cluster_count, 1);
        assert_eq!(clustered.clusters[0].failing_count, 2);
    }

    #[test]
    fn engine_core_adapter_clusters_by_divergence_class() {
        use crate::differential_oracle::{
            EngineCoreCorpusCase, run_engine_core_differential_oracle,
        };
        // A corpus carrying at least one genuine divergence so the adapter and
        // clustering are exercised on a real defect (not vacuously). The array/
        // object (bd-rkmpj) and consumed-postfix (bd-xi3bk) cases are at parity
        // now, so we seed a stable architectural divergence: `typeof console` is
        // "object" in the engine (runtime globals injected) but "undefined" in
        // franken-core (no runtime globals).
        let corpus = vec![
            EngineCoreCorpusCase::new("ok_add", "1 + 1;"),
            EngineCoreCorpusCase::new("divergent_typeof_global", "typeof console;"),
        ];
        let report = run_engine_core_differential_oracle(&corpus, 64);
        let observations = observations_from_engine_core_report(&report);
        // Each defect becomes exactly one observation.
        assert_eq!(observations.len(), report.defects.len());
        assert!(!report.defects.is_empty(), "corpus must seed a real defect");
        assert!(
            observations
                .iter()
                .all(|o| o.source == FrontierSource::DifferentialOracle)
        );
        // Clustering is deterministic and content-addressed.
        let a = cluster_failures(&observations, 3, 8);
        let b = cluster_failures(&observations, 3, 8);
        assert_eq!(a, b);
        for cluster in &a.clusters {
            assert_eq!(
                cluster.cluster_id,
                cluster_id(FrontierSource::DifferentialOracle, &cluster.construct)
            );
        }
    }

    #[test]
    fn mixed_sources_do_not_cross_contaminate() {
        let observations = vec![
            obs(FrontierSource::Test262, "runtime", "t.js", "fail"),
            obs(
                FrontierSource::DifferentialOracle,
                "runtime",
                "o",
                "structured_value",
            ),
        ];
        let report = cluster_failures(&observations, 3, 8);
        // Same construct string "runtime" but different sources => two clusters.
        assert_eq!(report.cluster_count, 2);
        assert_ne!(report.clusters[0].cluster_id, report.clusters[1].cluster_id);
    }

    #[test]
    fn frontier_source_strings_are_stable() {
        assert_eq!(FrontierSource::Test262.as_str(), "test262");
        assert_eq!(
            FrontierSource::DifferentialOracle.as_str(),
            "differential_oracle"
        );
    }
}
