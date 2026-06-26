//! Coverage-Frontier Ranking (`bd-fqlfw.7.2`, E7.T2) — rank the
//! [`crate::coverage_frontier`] clusters by a **transparent, reproducible,
//! per-cluster-explainable** impact score.
//!
//! E7.T1 ([`crate::coverage_frontier`]) deliberately ordered clusters by raw
//! failing count alone. This module adds the impact score the E7 plan calls
//! for: `failing-count × real-package-usage-frequency × proximity-to-already-
//! passing`. The output is an **advisory worklist** (the bead's stated RISK),
//! never an automated merge.
//!
//! ## The formula (every factor is stored on the cluster, in millionths)
//!
//! ```text
//! impact = failing_count × usage_weight × locality_weight
//! ```
//!
//! - **`failing_count`** — the raw cluster size (one parser gap can mask
//!   thousands of failures, so magnitude matters and is kept linear).
//! - **`usage_weight`** ∈ `[0, ∞)`, default `1.0` — a *real, external* usage
//!   signal mapping construct → relative weight, loaded from an auditable npm
//!   pure-JS corpus scan ([`UsageSignal`]). When no signal is supplied the
//!   weight is the neutral `1.0` and the cluster is flagged
//!   `usage_signal_present = false`. **No usage numbers are ever fabricated** —
//!   absent data degrades transparently to neutral rather than inventing a
//!   frequency.
//! - **`locality_weight`** ∈ `[LOCALITY_FLOOR, 1.0]` — proximity to already
//!   passing. A construct family that is *almost* fully green is high-leverage
//!   (a few fixes complete it), so the weight rises with the family pass
//!   fraction. A floor keeps a 0%-passing foundational gap from collapsing to
//!   impact zero (its magnitude still ranks via `failing_count`). Derived from
//!   a [`ConstructCensus`] built off the same Test262 report; differential-
//!   oracle clusters have no family census and use the neutral `1.0`.
//!
//! ## Determinism / reproducibility
//!
//! All weights and the score are fixed-point **millionths** (`u64`/`u128`) —
//! there is no floating point anywhere in the report or its digest, so the
//! ranked list is byte-identical across runs and platforms. Clusters are
//! ranked by `(impact desc, cluster_id asc)` (a total order), and the
//! `report_digest` is a content hash over the canonical
//! `(rank, cluster_id, impact)` sequence.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::coverage_frontier::{CoverageFrontierReport, FrontierSource};
use crate::hash_tiers::ContentHash;
use crate::test262_conformance_runner::{ConformanceReport, TestResult};

/// Schema id stamped on every emitted ranked report.
pub const COVERAGE_FRONTIER_RANK_SCHEMA_VERSION: &str = "franken-engine.coverage-frontier-rank.v1";

/// Fixed-point scale: `1_000_000` millionths == `1.0`. All weights and the
/// impact score use this scale so the report carries no floating point.
pub const SCALE: u64 = 1_000_000;

/// Lower bound (millionths) on the locality multiplier, so a fully-failing
/// (0%-passing) construct family is down-weighted but never annihilated to an
/// impact of zero — its magnitude still ranks through `failing_count`.
pub const LOCALITY_FLOOR: u64 = 100_000; // 0.1

/// Per-construct pass/fail tally used to derive the locality factor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConstructCensus {
    /// Tests in this construct that passed (`TestResult::Pass`).
    pub passing: usize,
    /// Tests in this construct that failed (`Fail` or `Error`).
    pub failing: usize,
}

impl ConstructCensus {
    /// Total classified (pass + fail) tests; `Skip` is excluded upstream.
    pub fn total(&self) -> usize {
        self.passing + self.failing
    }
}

/// A real, external construct usage signal: `construct → relative weight`
/// (millionths, where `1_000_000` is neutral). Loaded from an auditable npm
/// pure-JS corpus scan and supplied by the operator; it is **never synthesized**
/// by this module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageSignal {
    /// Provenance string for the signal (how/when the corpus was scanned).
    pub source: String,
    /// `construct → usage weight` in millionths. Missing constructs are neutral.
    pub weights: BTreeMap<String, u64>,
}

impl UsageSignal {
    /// Weight (millionths) for a construct, or the neutral `SCALE` if absent.
    pub fn weight_for(&self, construct: &str) -> u64 {
        self.weights.get(construct).copied().unwrap_or(SCALE)
    }
}

/// The three transparent factors and the resulting impact, all in millionths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactScore {
    /// Raw cluster size (magnitude factor).
    pub failing_count: usize,
    /// Usage weight applied (millionths; `1_000_000` == neutral).
    pub usage_weight_millionths: u64,
    /// Whether a usage signal supplied a weight for *this* construct.
    pub usage_signal_present: bool,
    /// Locality weight applied (millionths; family pass-fraction, floored).
    pub locality_weight_millionths: u64,
    /// How the locality weight was derived (provenance, human-readable).
    pub locality_basis: String,
    /// `failing_count × usage × locality`, in millionths (`u128` headroom).
    pub impact_millionths: u128,
    /// Self-contained, inspectable explanation of the score for this cluster.
    pub explanation: String,
}

/// One ranked cluster: its identity, its score, and its 1-based rank.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RankedCluster {
    /// Content-hash id from E7.T1 (stable across runs).
    pub cluster_id: String,
    /// Failure stream (`test262` / `differential_oracle`).
    pub source: String,
    /// Spec-construct key.
    pub construct: String,
    /// Raw failing count (mirrors `score.failing_count` for convenience).
    pub failing_count: usize,
    /// The transparent impact score.
    pub score: ImpactScore,
    /// 1-based rank after sorting by `(impact desc, cluster_id asc)`.
    pub rank: usize,
}

/// The ranked coverage-frontier report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RankedFrontierReport {
    /// Schema id (`COVERAGE_FRONTIER_RANK_SCHEMA_VERSION`).
    pub schema_version: String,
    /// Provenance of the usage signal, or `None` when ranked neutral.
    pub usage_signal_source: Option<String>,
    /// Locality floor used (millionths, provenance).
    pub locality_floor_millionths: u64,
    /// Number of ranked clusters.
    pub cluster_count: usize,
    /// Clusters in descending impact order (ties broken by `cluster_id` asc).
    pub ranked: Vec<RankedCluster>,
    /// Content hash over the canonical `(rank, cluster_id, impact)` sequence.
    pub report_digest: String,
}

/// Render a millionths value as a fixed 6-decimal string (no floating point),
/// e.g. `910_000 → "0.910000"`, `2_500_000 → "2.500000"`.
fn fmt_millionths(value: u128) -> String {
    let scale = SCALE as u128;
    format!("{}.{:06}", value / scale, value % scale)
}

/// Build a per-construct pass/fail census from a Test262 conformance report,
/// keyed by the same construct key E7.T1 clusters by (so census keys and
/// cluster constructs line up). `Pass` counts as passing, `Fail`/`Error` as
/// failing; `Skip` is ignored.
pub fn construct_census_from_conformance(
    report: &ConformanceReport,
    construct_depth: usize,
) -> BTreeMap<String, ConstructCensus> {
    let mut census: BTreeMap<String, ConstructCensus> = BTreeMap::new();
    for record in &report.test_records {
        let key = crate::coverage_frontier::test262_construct_key(&record.path, construct_depth);
        let entry = census.entry(key).or_default();
        match record.result {
            TestResult::Pass => entry.passing += 1,
            TestResult::Fail | TestResult::Error => entry.failing += 1,
            TestResult::Skip => {}
        }
    }
    census
}

/// Merge two construct censuses (summing pass/fail per construct), e.g. across
/// several `--report` inputs.
pub fn merge_censuses(
    mut into: BTreeMap<String, ConstructCensus>,
    other: &BTreeMap<String, ConstructCensus>,
) -> BTreeMap<String, ConstructCensus> {
    for (key, value) in other {
        let entry = into.entry(key.clone()).or_default();
        entry.passing += value.passing;
        entry.failing += value.failing;
    }
    into
}

/// Locality weight (millionths) for a construct family: `FLOOR + (SCALE-FLOOR)
/// × passing / (passing+failing)`, mapping a 0%-passing family to `FLOOR` and a
/// fully-passing one to `SCALE`. Returns `(weight, basis)`.
fn locality_weight(
    source: &str,
    construct: &str,
    census: &BTreeMap<String, ConstructCensus>,
) -> (u64, String) {
    // Only Test262 clusters have a spec-family census; oracle clusters do not.
    if source != FrontierSource::Test262.as_str() {
        return (SCALE, "neutral-non-test262-source".to_string());
    }
    match census.get(construct) {
        Some(c) if c.total() > 0 => {
            // FLOOR + (SCALE-FLOOR) * passing/total, computed in u128.
            let span = (SCALE - LOCALITY_FLOOR) as u128;
            let frac = span * c.passing as u128 / c.total() as u128;
            let weight = LOCALITY_FLOOR as u128 + frac;
            (
                weight as u64,
                format!(
                    "test262-family-pass-fraction {}/{} (floored at {})",
                    c.passing,
                    c.total(),
                    fmt_millionths(LOCALITY_FLOOR as u128)
                ),
            )
        }
        _ => (SCALE, "neutral-no-census".to_string()),
    }
}

/// Score a single cluster's `(source, construct, failing_count)` against the
/// census and optional usage signal.
fn score_cluster(
    source: &str,
    construct: &str,
    failing_count: usize,
    census: &BTreeMap<String, ConstructCensus>,
    usage: Option<&UsageSignal>,
) -> ImpactScore {
    let usage_signal_present = usage
        .map(|signal| signal.weights.contains_key(construct))
        .unwrap_or(false);
    let usage_weight_millionths = usage
        .map(|signal| signal.weight_for(construct))
        .unwrap_or(SCALE);
    let (locality_weight_millionths, locality_basis) = locality_weight(source, construct, census);

    // impact_millionths = failing_count * usage * locality / SCALE  (u128).
    let impact_millionths = failing_count as u128
        * usage_weight_millionths as u128
        * locality_weight_millionths as u128
        / SCALE as u128;

    let usage_note = if usage.is_none() {
        "neutral, no signal".to_string()
    } else if usage_signal_present {
        "from usage signal".to_string()
    } else {
        "neutral, construct absent from signal".to_string()
    };

    let explanation = format!(
        "impact {} = {} failing × usage {} ({}) × locality {} ({})",
        fmt_millionths(impact_millionths),
        failing_count,
        fmt_millionths(usage_weight_millionths as u128),
        usage_note,
        fmt_millionths(locality_weight_millionths as u128),
        locality_basis,
    );

    ImpactScore {
        failing_count,
        usage_weight_millionths,
        usage_signal_present,
        locality_weight_millionths,
        locality_basis,
        impact_millionths,
        explanation,
    }
}

/// Content hash over the canonical `(rank, cluster_id, impact_millionths)`
/// sequence — a single integrity handle for the ranked report.
fn compute_rank_digest(ranked: &[RankedCluster]) -> String {
    let mut buf = Vec::new();
    for cluster in ranked {
        buf.extend_from_slice(&(cluster.rank as u64).to_be_bytes());
        let id = cluster.cluster_id.as_bytes();
        buf.extend_from_slice(&(id.len() as u64).to_be_bytes());
        buf.extend_from_slice(id);
        buf.extend_from_slice(&cluster.score.impact_millionths.to_be_bytes());
    }
    ContentHash::compute(&buf).to_hex()
}

/// Rank a coverage-frontier report's clusters by transparent impact score.
///
/// `census` supplies the locality factor (build it with
/// [`construct_census_from_conformance`]); pass an empty map to rank with
/// neutral locality. `usage` supplies the real usage signal; pass `None` to
/// rank with neutral usage.
pub fn rank_clusters(
    report: &CoverageFrontierReport,
    census: &BTreeMap<String, ConstructCensus>,
    usage: Option<&UsageSignal>,
) -> RankedFrontierReport {
    let mut ranked: Vec<RankedCluster> = report
        .clusters
        .iter()
        .map(|cluster| {
            let score = score_cluster(
                &cluster.source,
                &cluster.construct,
                cluster.failing_count,
                census,
                usage,
            );
            RankedCluster {
                cluster_id: cluster.cluster_id.clone(),
                source: cluster.source.clone(),
                construct: cluster.construct.clone(),
                failing_count: cluster.failing_count,
                score,
                rank: 0, // assigned after the sort
            }
        })
        .collect();

    // Highest impact first; ties broken by the stable content-hash id so the
    // order is total and deterministic.
    ranked.sort_by(|a, b| {
        b.score
            .impact_millionths
            .cmp(&a.score.impact_millionths)
            .then_with(|| a.cluster_id.cmp(&b.cluster_id))
    });
    for (index, cluster) in ranked.iter_mut().enumerate() {
        cluster.rank = index + 1;
    }

    let report_digest = compute_rank_digest(&ranked);
    RankedFrontierReport {
        schema_version: COVERAGE_FRONTIER_RANK_SCHEMA_VERSION.to_string(),
        usage_signal_source: usage.map(|signal| signal.source.clone()),
        locality_floor_millionths: LOCALITY_FLOOR,
        cluster_count: ranked.len(),
        ranked,
        report_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage_frontier::{FailureObservation, cluster_failures};

    fn obs(
        source: FrontierSource,
        construct: &str,
        case: &str,
        bucket: &str,
    ) -> FailureObservation {
        FailureObservation::new(source, construct, case, bucket)
    }

    /// Build a frontier report from a list of (construct, count) test262 gaps.
    fn frontier(gaps: &[(&str, usize)]) -> CoverageFrontierReport {
        let mut observations = Vec::new();
        for (construct, count) in gaps {
            for i in 0..*count {
                observations.push(obs(
                    FrontierSource::Test262,
                    construct,
                    &format!("{construct}/{i}.js"),
                    "fail",
                ));
            }
        }
        cluster_failures(&observations, 3, 8)
    }

    // ---- fixed-point formatting -----------------------------------------

    #[test]
    fn fmt_millionths_is_six_decimals() {
        assert_eq!(fmt_millionths(0), "0.000000");
        assert_eq!(fmt_millionths(SCALE as u128), "1.000000");
        assert_eq!(fmt_millionths(910_000), "0.910000");
        assert_eq!(fmt_millionths(2_500_000), "2.500000");
        assert_eq!(fmt_millionths(123), "0.000123");
    }

    // ---- locality factor -------------------------------------------------

    #[test]
    fn locality_rises_with_pass_fraction() {
        let mut census = BTreeMap::new();
        census.insert(
            "almost".to_string(),
            ConstructCensus {
                passing: 9,
                failing: 1,
            },
        );
        census.insert(
            "barely".to_string(),
            ConstructCensus {
                passing: 1,
                failing: 9,
            },
        );
        let (hi, _) = locality_weight("test262", "almost", &census);
        let (lo, _) = locality_weight("test262", "barely", &census);
        assert!(hi > lo, "more-passing family must out-weight");
        // 9/10 -> FLOOR + 0.9*(SCALE-FLOOR) = 100000 + 0.9*900000 = 910000.
        assert_eq!(hi, 910_000);
        // 1/10 -> 100000 + 0.1*900000 = 190000.
        assert_eq!(lo, 190_000);
    }

    #[test]
    fn locality_floor_prevents_zero_for_fully_failing_family() {
        let mut census = BTreeMap::new();
        census.insert(
            "wall".to_string(),
            ConstructCensus {
                passing: 0,
                failing: 50,
            },
        );
        let (w, basis) = locality_weight("test262", "wall", &census);
        assert_eq!(w, LOCALITY_FLOOR, "0%-passing family floors, not zero");
        assert!(basis.contains("0/50"));
    }

    #[test]
    fn locality_neutral_for_oracle_source() {
        let census = BTreeMap::new();
        let (w, basis) = locality_weight("differential_oracle", "runtime", &census);
        assert_eq!(w, SCALE);
        assert_eq!(basis, "neutral-non-test262-source");
    }

    #[test]
    fn locality_neutral_when_construct_absent_from_census() {
        let census = BTreeMap::new();
        let (w, basis) = locality_weight("test262", "unknown", &census);
        assert_eq!(w, SCALE);
        assert_eq!(basis, "neutral-no-census");
    }

    // ---- usage factor ----------------------------------------------------

    #[test]
    fn usage_weight_applied_from_signal_else_neutral() {
        let mut weights = BTreeMap::new();
        weights.insert("hot".to_string(), 3_000_000); // 3x
        let signal = UsageSignal {
            source: "test-corpus".to_string(),
            weights,
        };
        assert_eq!(signal.weight_for("hot"), 3_000_000);
        assert_eq!(signal.weight_for("cold"), SCALE, "absent => neutral");
    }

    #[test]
    fn usage_signal_lifts_a_smaller_but_hotter_cluster_above_a_bigger_cold_one() {
        // cold: 10 failing, neutral usage. hot: 5 failing, 3x usage.
        let report = frontier(&[("cold", 10), ("hot", 5)]);
        let mut weights = BTreeMap::new();
        weights.insert("hot".to_string(), 3_000_000);
        let signal = UsageSignal {
            source: "npm-pure-js-vTEST".to_string(),
            weights,
        };
        // Neutral locality (no census) so usage is the deciding factor.
        let ranked = rank_clusters(&report, &BTreeMap::new(), Some(&signal));
        assert_eq!(ranked.ranked[0].construct, "hot", "5×3=15 > 10×1=10");
        assert_eq!(ranked.ranked[0].rank, 1);
        assert_eq!(ranked.ranked[1].construct, "cold");
        assert_eq!(
            ranked.usage_signal_source.as_deref(),
            Some("npm-pure-js-vTEST")
        );
        // hot impact = 5 * 3.0 * 1.0 = 15.0 in millionths.
        assert_eq!(ranked.ranked[0].score.impact_millionths, 15_000_000);
        assert!(ranked.ranked[0].score.usage_signal_present);
        assert!(!ranked.ranked[1].score.usage_signal_present);
    }

    // ---- neutral ranking reproduces raw count ----------------------------

    #[test]
    fn neutral_factors_make_impact_equal_raw_count() {
        let report = frontier(&[("a", 7)]);
        let ranked = rank_clusters(&report, &BTreeMap::new(), None);
        // 7 failing * 1.0 * 1.0 = 7.0 -> 7_000_000 millionths.
        assert_eq!(ranked.ranked[0].score.impact_millionths, 7_000_000);
        assert_eq!(ranked.ranked[0].score.usage_weight_millionths, SCALE);
        assert_eq!(ranked.ranked[0].score.locality_weight_millionths, SCALE);
        assert!(!ranked.ranked[0].score.usage_signal_present);
        assert_eq!(ranked.usage_signal_source, None);
    }

    #[test]
    fn locality_reorders_equal_count_clusters() {
        // Two clusters, same failing count, different family completeness.
        let report = frontier(&[("almost", 3), ("wall", 3)]);
        let mut census = BTreeMap::new();
        census.insert(
            "almost".to_string(),
            ConstructCensus {
                passing: 27,
                failing: 3,
            }, // 90% passing
        );
        census.insert(
            "wall".to_string(),
            ConstructCensus {
                passing: 0,
                failing: 3,
            }, // 0% passing
        );
        let ranked = rank_clusters(&report, &census, None);
        assert_eq!(
            ranked.ranked[0].construct, "almost",
            "nearly-done ranks first"
        );
        assert_eq!(ranked.ranked[1].construct, "wall");
        assert!(
            ranked.ranked[0].score.impact_millionths > ranked.ranked[1].score.impact_millionths
        );
    }

    // ---- explainability --------------------------------------------------

    #[test]
    fn every_cluster_carries_a_self_contained_explanation() {
        let report = frontier(&[("language/types", 4)]);
        let mut census = BTreeMap::new();
        census.insert(
            "language/types".to_string(),
            ConstructCensus {
                passing: 6,
                failing: 4,
            },
        );
        let ranked = rank_clusters(&report, &census, None);
        let exp = &ranked.ranked[0].score.explanation;
        assert!(
            exp.contains("4 failing"),
            "explanation names the count: {exp}"
        );
        assert!(exp.contains("usage"), "explanation names usage: {exp}");
        assert!(
            exp.contains("locality"),
            "explanation names locality: {exp}"
        );
        assert!(
            exp.contains("6/10"),
            "explanation shows the family census: {exp}"
        );
    }

    // ---- determinism -----------------------------------------------------

    #[test]
    fn ranking_is_deterministic_and_content_hashed() {
        let report = frontier(&[("a", 5), ("b", 5), ("c", 2)]);
        let mut census = BTreeMap::new();
        census.insert(
            "a".to_string(),
            ConstructCensus {
                passing: 5,
                failing: 5,
            },
        );
        census.insert(
            "b".to_string(),
            ConstructCensus {
                passing: 1,
                failing: 5,
            },
        );
        let one = rank_clusters(&report, &census, None);
        let two = rank_clusters(&report, &census, None);
        assert_eq!(one, two);
        assert_eq!(one.report_digest, two.report_digest);
        // Ranks are a dense 1..=N.
        let ranks: Vec<usize> = one.ranked.iter().map(|c| c.rank).collect();
        assert_eq!(ranks, vec![1, 2, 3]);
    }

    #[test]
    fn equal_impact_ties_break_by_cluster_id() {
        // Same count, neutral factors => identical impact; order must be by id.
        let report = frontier(&[("a", 4), ("b", 4)]);
        let ranked = rank_clusters(&report, &BTreeMap::new(), None);
        assert_eq!(
            ranked.ranked[0].score.impact_millionths,
            ranked.ranked[1].score.impact_millionths
        );
        assert!(
            ranked.ranked[0].cluster_id < ranked.ranked[1].cluster_id,
            "tie broken by ascending cluster id"
        );
    }

    #[test]
    fn digest_changes_when_an_impact_changes() {
        let report = frontier(&[("a", 5)]);
        let neutral = rank_clusters(&report, &BTreeMap::new(), None);
        let mut weights = BTreeMap::new();
        weights.insert("a".to_string(), 2_000_000);
        let signal = UsageSignal {
            source: "s".to_string(),
            weights,
        };
        let lifted = rank_clusters(&report, &BTreeMap::new(), Some(&signal));
        assert_ne!(neutral.report_digest, lifted.report_digest);
    }

    #[test]
    fn empty_report_ranks_empty() {
        let report = cluster_failures(&[], 3, 8);
        let ranked = rank_clusters(&report, &BTreeMap::new(), None);
        assert_eq!(ranked.cluster_count, 0);
        assert!(ranked.ranked.is_empty());
        assert_eq!(
            ranked.report_digest,
            rank_clusters(&cluster_failures(&[], 3, 8), &BTreeMap::new(), None).report_digest
        );
    }

    #[test]
    fn schema_and_floor_are_stamped() {
        let ranked = rank_clusters(&cluster_failures(&[], 3, 8), &BTreeMap::new(), None);
        assert_eq!(ranked.schema_version, COVERAGE_FRONTIER_RANK_SCHEMA_VERSION);
        assert_eq!(ranked.locality_floor_millionths, LOCALITY_FLOOR);
    }

    // ---- census builder --------------------------------------------------

    #[test]
    fn census_counts_pass_fail_error_and_ignores_skip() {
        use crate::test262_conformance_runner::TestRecord;
        use std::path::PathBuf;
        let records = vec![
            TestRecord::new(
                PathBuf::from("test/built-ins/Map/a.js"),
                TestResult::Pass,
                1,
                None,
                false,
            ),
            TestRecord::new(
                PathBuf::from("test/built-ins/Map/b.js"),
                TestResult::Pass,
                1,
                None,
                false,
            ),
            TestRecord::new(
                PathBuf::from("test/built-ins/Map/c.js"),
                TestResult::Fail,
                1,
                Some("x".into()),
                false,
            ),
            TestRecord::new(
                PathBuf::from("test/built-ins/Map/d.js"),
                TestResult::Error,
                1,
                Some("y".into()),
                false,
            ),
            TestRecord::new(
                PathBuf::from("test/built-ins/Map/e.js"),
                TestResult::Skip,
                1,
                None,
                false,
            ),
        ];
        let report = ConformanceReport::new(
            crate::security_epoch::SecurityEpoch::from_raw(1),
            "deadbeef".into(),
            records,
            5,
            true,
        );
        let census = construct_census_from_conformance(&report, 3);
        let map = census.get("built-ins/Map").expect("Map census");
        assert_eq!(map.passing, 2);
        assert_eq!(map.failing, 2, "Fail + Error both count as failing");
        assert_eq!(map.total(), 4, "Skip excluded");
    }

    #[test]
    fn merge_censuses_sums_per_construct() {
        let mut a = BTreeMap::new();
        a.insert(
            "x".to_string(),
            ConstructCensus {
                passing: 1,
                failing: 2,
            },
        );
        let mut b = BTreeMap::new();
        b.insert(
            "x".to_string(),
            ConstructCensus {
                passing: 3,
                failing: 0,
            },
        );
        b.insert(
            "y".to_string(),
            ConstructCensus {
                passing: 5,
                failing: 5,
            },
        );
        let merged = merge_censuses(a, &b);
        assert_eq!(
            merged.get("x"),
            Some(&ConstructCensus {
                passing: 4,
                failing: 2
            })
        );
        assert_eq!(
            merged.get("y"),
            Some(&ConstructCensus {
                passing: 5,
                failing: 5
            })
        );
    }
}
