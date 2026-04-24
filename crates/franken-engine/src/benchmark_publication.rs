//! Deterministic benchmark publication summaries for external adoption artifacts.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt::{self, Write};

use serde::{Deserialize, Serialize};

/// Stable schema marker for benchmark publication records.
pub const BENCHMARK_PUBLICATION_SCHEMA_VERSION: &str = "franken-engine.benchmark-publication.v1";

/// Benchmark metric families exposed in publication summaries.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkMetric {
    /// Higher values indicate better operation throughput.
    Throughput,
    /// Lower values indicate better response latency.
    Latency,
    /// Lower values indicate better memory footprint.
    Memory,
}

impl BenchmarkMetric {
    /// Return the stable publication spelling for the metric.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Throughput => "throughput",
            Self::Latency => "latency",
            Self::Memory => "memory",
        }
    }
}

impl fmt::Display for BenchmarkMetric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Publication-ready result for a single benchmark.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Hash)]
pub struct BenchmarkResult {
    /// Stable benchmark identifier.
    pub bench_id: String,
    /// Metric family represented by this value.
    pub metric: BenchmarkMetric,
    /// Fixed-point metric value where 1_000_000 represents 1.0.
    pub value_millionths: u64,
    /// Number of samples used to compute the published value.
    pub samples: u64,
}

impl BenchmarkResult {
    /// Build a benchmark result with explicit fixed-point value and sample count.
    #[must_use]
    pub fn new(
        bench_id: impl Into<String>,
        metric: BenchmarkMetric,
        value_millionths: u64,
        samples: u64,
    ) -> Self {
        Self {
            bench_id: bench_id.into(),
            metric,
            value_millionths,
            samples,
        }
    }
}

/// Deterministic benchmark publication payload.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Hash)]
pub struct BenchmarkPublication {
    /// Human-readable publication title.
    pub title: String,
    /// Benchmark results keyed by stable benchmark identifier.
    pub results: BTreeMap<String, BenchmarkResult>,
    /// Source commit used for the benchmark publication.
    pub commit_sha: String,
}

impl BenchmarkPublication {
    /// Render a deterministic Markdown summary sorted by benchmark id.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut markdown = String::new();
        let title = markdown_line(&self.title);
        let commit_sha = inline_code(&self.commit_sha);
        writeln!(markdown, "# {title}").expect("writing to String should not fail");
        writeln!(markdown).expect("writing to String should not fail");
        writeln!(markdown, "Schema: `{BENCHMARK_PUBLICATION_SCHEMA_VERSION}`")
            .expect("writing to String should not fail");
        writeln!(markdown, "Commit: `{commit_sha}`").expect("writing to String should not fail");
        writeln!(markdown).expect("writing to String should not fail");
        writeln!(
            markdown,
            "| Benchmark ID | Metric | Value (millionths) | Samples |"
        )
        .expect("writing to String should not fail");
        writeln!(markdown, "|---|---|---:|---:|").expect("writing to String should not fail");

        let mut ordered_results = self.results.iter().collect::<Vec<_>>();
        ordered_results.sort_by(|(left_key, left), (right_key, right)| {
            left.bench_id
                .cmp(&right.bench_id)
                .then_with(|| left_key.cmp(right_key))
        });

        for (_storage_key, result) in ordered_results {
            let bench_id = table_cell(&result.bench_id);
            let metric = &result.metric;
            let value_millionths = result.value_millionths;
            let samples = result.samples;
            writeln!(
                markdown,
                "| {bench_id} | {metric} | {value_millionths} | {samples} |"
            )
            .expect("writing to String should not fail");
        }

        markdown
    }

    /// Return the total number of samples across all benchmark results.
    #[must_use]
    pub fn total_samples(&self) -> u64 {
        self.results
            .values()
            .fold(0_u64, |total, result| total.saturating_add(result.samples))
    }
}

fn markdown_line(value: &str) -> String {
    value.replace(['\r', '\n'], " ").trim().to_string()
}

fn inline_code(value: &str) -> String {
    value.replace(['\r', '\n', '`'], "")
}

fn table_cell(value: &str) -> String {
    value
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn result(bench_id: &str, metric: BenchmarkMetric, value_millionths: u64) -> BenchmarkResult {
        BenchmarkResult::new(bench_id, metric, value_millionths, 5)
    }

    fn publication() -> BenchmarkPublication {
        BenchmarkPublication {
            title: "Extension-heavy benchmark suite".to_string(),
            results: BTreeMap::from([
                (
                    "zeta".to_string(),
                    BenchmarkResult::new("zeta", BenchmarkMetric::Throughput, 2_500_000, 11),
                ),
                (
                    "alpha".to_string(),
                    BenchmarkResult::new("alpha", BenchmarkMetric::Latency, 750_000, 7),
                ),
            ]),
            commit_sha: "abc123".to_string(),
        }
    }

    #[test]
    fn metric_as_str_is_stable() {
        assert_eq!(BenchmarkMetric::Throughput.as_str(), "throughput");
        assert_eq!(BenchmarkMetric::Latency.as_str(), "latency");
        assert_eq!(BenchmarkMetric::Memory.as_str(), "memory");
    }

    #[test]
    fn metric_display_matches_stable_spelling() {
        assert_eq!(BenchmarkMetric::Throughput.to_string(), "throughput");
    }

    #[test]
    fn metric_serde_uses_snake_case() {
        let json = serde_json::to_string(&BenchmarkMetric::Latency).expect("serialize metric");
        assert_eq!(json, "\"latency\"");
    }

    #[test]
    fn metric_serde_round_trip_preserves_variant() {
        let metric: BenchmarkMetric =
            serde_json::from_str("\"memory\"").expect("deserialize metric");
        assert_eq!(metric, BenchmarkMetric::Memory);
    }

    #[test]
    fn metric_sort_order_is_deterministic() {
        let mut metrics = vec![
            BenchmarkMetric::Memory,
            BenchmarkMetric::Throughput,
            BenchmarkMetric::Latency,
        ];
        metrics.sort();
        assert_eq!(
            metrics,
            vec![
                BenchmarkMetric::Throughput,
                BenchmarkMetric::Latency,
                BenchmarkMetric::Memory
            ]
        );
    }

    #[test]
    fn benchmark_result_new_sets_fields() {
        let result = BenchmarkResult::new("bench-a", BenchmarkMetric::Throughput, 1_250_000, 9);
        assert_eq!(result.bench_id, "bench-a");
        assert_eq!(result.metric, BenchmarkMetric::Throughput);
        assert_eq!(result.value_millionths, 1_250_000);
        assert_eq!(result.samples, 9);
    }

    #[test]
    fn benchmark_result_clone_preserves_equality() {
        let result = result("bench-a", BenchmarkMetric::Latency, 42);
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    #[test]
    fn benchmark_result_hash_is_stable_for_equal_values() {
        let left = result("bench-a", BenchmarkMetric::Latency, 42);
        let right = left.clone();
        assert_eq!(hash_of(&left), hash_of(&right));
    }

    #[test]
    fn benchmark_result_serde_round_trip_preserves_state() {
        let result = BenchmarkResult::new("bench-a", BenchmarkMetric::Memory, 64_000, 3);
        let json = serde_json::to_string(&result).expect("serialize result");
        let restored: BenchmarkResult = serde_json::from_str(&json).expect("deserialize result");
        assert_eq!(result, restored);
    }

    #[test]
    fn publication_total_samples_sums_all_results() {
        assert_eq!(publication().total_samples(), 18);
    }

    #[test]
    fn publication_total_samples_is_zero_for_empty_results() {
        let publication = BenchmarkPublication {
            title: "Empty".to_string(),
            results: BTreeMap::new(),
            commit_sha: "abc123".to_string(),
        };
        assert_eq!(publication.total_samples(), 0);
    }

    #[test]
    fn publication_total_samples_saturates_on_overflow() {
        let publication = BenchmarkPublication {
            title: "Overflow".to_string(),
            results: BTreeMap::from([
                (
                    "a".to_string(),
                    BenchmarkResult::new("a", BenchmarkMetric::Throughput, 1, u64::MAX),
                ),
                (
                    "b".to_string(),
                    BenchmarkResult::new("b", BenchmarkMetric::Throughput, 1, 1),
                ),
            ]),
            commit_sha: "abc123".to_string(),
        };
        assert_eq!(publication.total_samples(), u64::MAX);
    }

    #[test]
    fn render_markdown_includes_title() {
        assert!(
            publication()
                .render_markdown()
                .starts_with("# Extension-heavy benchmark suite\n")
        );
    }

    #[test]
    fn render_markdown_includes_schema_version() {
        assert!(
            publication()
                .render_markdown()
                .contains(BENCHMARK_PUBLICATION_SCHEMA_VERSION)
        );
    }

    #[test]
    fn render_markdown_includes_commit_sha() {
        assert!(publication().render_markdown().contains("Commit: `abc123`"));
    }

    #[test]
    fn render_markdown_includes_table_header() {
        assert!(publication().render_markdown().contains(
            "| Benchmark ID | Metric | Value (millionths) | Samples |\n|---|---|---:|---:|"
        ));
    }

    #[test]
    fn render_markdown_sorts_results_by_bench_id() {
        let markdown = publication().render_markdown();
        let alpha = markdown.find("| alpha |").expect("alpha row");
        let zeta = markdown.find("| zeta |").expect("zeta row");
        assert!(alpha < zeta);
    }

    #[test]
    fn render_markdown_uses_result_benchmark_id() {
        let publication = BenchmarkPublication {
            title: "Result IDs".to_string(),
            results: BTreeMap::from([(
                "storage-key".to_string(),
                BenchmarkResult::new("internal-id", BenchmarkMetric::Memory, 100, 1),
            )]),
            commit_sha: "abc123".to_string(),
        };
        let markdown = publication.render_markdown();
        assert!(markdown.contains("| internal-id | memory | 100 | 1 |"));
        assert!(!markdown.contains("| storage-key | memory | 100 | 1 |"));
    }

    #[test]
    fn render_markdown_sorts_by_result_benchmark_id() {
        let publication = BenchmarkPublication {
            title: "Result ID order".to_string(),
            results: BTreeMap::from([
                (
                    "a-storage-key".to_string(),
                    BenchmarkResult::new("zeta", BenchmarkMetric::Throughput, 10, 1),
                ),
                (
                    "z-storage-key".to_string(),
                    BenchmarkResult::new("alpha", BenchmarkMetric::Latency, 20, 1),
                ),
            ]),
            commit_sha: "abc123".to_string(),
        };
        let markdown = publication.render_markdown();
        let alpha = markdown.find("| alpha |").expect("alpha row");
        let zeta = markdown.find("| zeta |").expect("zeta row");
        assert!(alpha < zeta);
    }

    #[test]
    fn render_markdown_is_byte_identical_across_runs() {
        let publication = publication();
        assert_eq!(publication.render_markdown(), publication.render_markdown());
    }

    #[test]
    fn render_markdown_escapes_table_pipes() {
        let publication = BenchmarkPublication {
            title: "Escapes".to_string(),
            results: BTreeMap::from([(
                "bench|pipe".to_string(),
                BenchmarkResult::new("bench|pipe", BenchmarkMetric::Throughput, 10, 2),
            )]),
            commit_sha: "abc123".to_string(),
        };
        assert!(publication.render_markdown().contains("bench\\|pipe"));
    }

    #[test]
    fn render_markdown_collapses_title_newlines() {
        let publication = BenchmarkPublication {
            title: "Open\nTool".to_string(),
            results: BTreeMap::new(),
            commit_sha: "abc123".to_string(),
        };
        assert!(publication.render_markdown().starts_with("# Open Tool\n"));
    }

    #[test]
    fn render_markdown_strips_commit_backticks_and_newlines() {
        let publication = BenchmarkPublication {
            title: "Commit".to_string(),
            results: BTreeMap::new(),
            commit_sha: "`abc\n123`".to_string(),
        };
        assert!(publication.render_markdown().contains("Commit: `abc123`"));
    }

    #[test]
    fn publication_serde_round_trip_preserves_results() {
        let publication = publication();
        let json = serde_json::to_string(&publication).expect("serialize publication");
        let restored: BenchmarkPublication =
            serde_json::from_str(&json).expect("deserialize publication");
        assert_eq!(publication, restored);
    }

    #[test]
    fn publication_hash_is_stable_for_equal_values() {
        let publication = publication();
        let cloned = publication.clone();
        assert_eq!(hash_of(&publication), hash_of(&cloned));
    }

    fn hash_of<T: Hash>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }
}
