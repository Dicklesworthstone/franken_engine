#![forbid(unsafe_code)]

//! Deterministic technical report rendering support.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Machine-readable artifact attached to a technical report.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TechnicalReportArtifact {
    /// Human-facing artifact title.
    pub title: String,
    /// Stable artifact type, such as `dataset`, `benchmark`, or `proof`.
    pub artifact_type: String,
    /// Repository-relative or bundle-relative artifact path.
    pub path: String,
    /// Stable content digest or external reference digest.
    pub digest: String,
}

/// Reproducible technical report with deterministic Markdown rendering.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TechnicalReport {
    /// Stable report identifier.
    pub report_id: String,
    /// Report title.
    pub title: String,
    /// Report version.
    pub version: String,
    /// Report authors in deterministic display order.
    pub authors: Vec<String>,
    /// Short report abstract.
    pub abstract_text: String,
    /// Deterministic section bodies keyed by section heading.
    pub sections: BTreeMap<String, String>,
    /// Deterministic artifact index keyed by artifact ID.
    pub artifacts: BTreeMap<String, TechnicalReportArtifact>,
}

impl TechnicalReport {
    /// Render a deterministic Markdown representation of the report.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = String::new();
        push_line(&mut out, &format!("# {}", self.title));
        out.push('\n');
        push_line(&mut out, &format!("- Report ID: `{}`", self.report_id));
        push_line(&mut out, &format!("- Version: `{}`", self.version));
        push_line(
            &mut out,
            &format!("- Artifact Count: `{}`", self.artifact_count()),
        );
        push_line(&mut out, "- Authors:");
        if self.authors.is_empty() {
            push_line(&mut out, "  - None");
        } else {
            for author in &self.authors {
                push_line(&mut out, &format!("  - {author}"));
            }
        }

        out.push('\n');
        push_line(&mut out, "## Abstract");
        out.push('\n');
        push_line(&mut out, &self.abstract_text);

        for (heading, body) in &self.sections {
            out.push('\n');
            push_line(&mut out, &format!("## {heading}"));
            out.push('\n');
            push_line(&mut out, body);
        }

        out.push('\n');
        push_line(&mut out, "## Artifacts");
        out.push('\n');
        if self.artifacts.is_empty() {
            push_line(&mut out, "No artifacts.");
        } else {
            push_line(&mut out, "| Key | Title | Type | Path | Digest |");
            push_line(&mut out, "| --- | --- | --- | --- | --- |");
            for (key, artifact) in &self.artifacts {
                push_line(
                    &mut out,
                    &format!(
                        "| `{}` | {} | `{}` | `{}` | `{}` |",
                        escape_table_cell(key),
                        escape_table_cell(&artifact.title),
                        escape_table_cell(&artifact.artifact_type),
                        escape_table_cell(&artifact.path),
                        escape_table_cell(&artifact.digest)
                    ),
                );
            }
        }

        out
    }

    /// Count artifacts attached to this report.
    #[must_use]
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn escape_table_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(title: &str, artifact_type: &str, path: &str) -> TechnicalReportArtifact {
        TechnicalReportArtifact {
            title: title.to_string(),
            artifact_type: artifact_type.to_string(),
            path: path.to_string(),
            digest: format!("sha256:{title}:{artifact_type}"),
        }
    }

    fn sample_report() -> TechnicalReport {
        let mut sections = BTreeMap::new();
        sections.insert(
            "Method".to_string(),
            "Run deterministic replay and compare receipts.".to_string(),
        );
        sections.insert(
            "Results".to_string(),
            "All artifacts reproduced byte-identically.".to_string(),
        );

        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "z-receipt".to_string(),
            artifact("Replay Receipt", "receipt", "artifacts/replay.json"),
        );
        artifacts.insert(
            "a-dataset".to_string(),
            artifact("Corpus Dataset", "dataset", "artifacts/corpus.jsonl"),
        );

        TechnicalReport {
            report_id: "tr-0001".to_string(),
            title: "Deterministic Replay Technical Report".to_string(),
            version: "1.0.0".to_string(),
            authors: vec!["FrankenEngine Research Team".to_string()],
            abstract_text: "A deterministic report for reproducibility review.".to_string(),
            sections,
            artifacts,
        }
    }

    #[test]
    fn artifact_count_reports_number_of_artifacts() {
        assert_eq!(sample_report().artifact_count(), 2);
    }

    #[test]
    fn empty_report_has_zero_artifacts() {
        let mut report = sample_report();
        report.artifacts.clear();
        assert_eq!(report.artifact_count(), 0);
    }

    #[test]
    fn markdown_starts_with_title() {
        assert!(
            sample_report()
                .render_markdown()
                .starts_with("# Deterministic Replay Technical Report\n")
        );
    }

    #[test]
    fn markdown_includes_report_id() {
        assert!(
            sample_report()
                .render_markdown()
                .contains("- Report ID: `tr-0001`")
        );
    }

    #[test]
    fn markdown_includes_version() {
        assert!(
            sample_report()
                .render_markdown()
                .contains("- Version: `1.0.0`")
        );
    }

    #[test]
    fn markdown_includes_artifact_count() {
        assert!(
            sample_report()
                .render_markdown()
                .contains("- Artifact Count: `2`")
        );
    }

    #[test]
    fn markdown_includes_authors() {
        assert!(
            sample_report()
                .render_markdown()
                .contains("  - FrankenEngine Research Team")
        );
    }

    #[test]
    fn markdown_handles_empty_authors() {
        let mut report = sample_report();
        report.authors.clear();
        assert!(report.render_markdown().contains("  - None"));
    }

    #[test]
    fn markdown_includes_abstract_heading() {
        assert!(sample_report().render_markdown().contains("## Abstract\n"));
    }

    #[test]
    fn markdown_includes_abstract_text() {
        assert!(
            sample_report()
                .render_markdown()
                .contains("A deterministic report for reproducibility review.")
        );
    }

    #[test]
    fn markdown_sorts_sections_by_key() {
        let rendered = sample_report().render_markdown();
        let method = rendered.find("## Method").expect("method section");
        let results = rendered.find("## Results").expect("results section");
        assert!(method < results);
    }

    #[test]
    fn markdown_includes_artifact_heading() {
        assert!(sample_report().render_markdown().contains("## Artifacts\n"));
    }

    #[test]
    fn markdown_includes_artifact_table_header() {
        assert!(
            sample_report()
                .render_markdown()
                .contains("| Key | Title | Type | Path | Digest |")
        );
    }

    #[test]
    fn markdown_sorts_artifacts_by_key() {
        let rendered = sample_report().render_markdown();
        let dataset = rendered.find("`a-dataset`").expect("dataset artifact");
        let receipt = rendered.find("`z-receipt`").expect("receipt artifact");
        assert!(dataset < receipt);
    }

    #[test]
    fn markdown_includes_artifact_path() {
        assert!(
            sample_report()
                .render_markdown()
                .contains("`artifacts/corpus.jsonl`")
        );
    }

    #[test]
    fn markdown_includes_artifact_digest() {
        assert!(
            sample_report()
                .render_markdown()
                .contains("`sha256:Corpus Dataset:dataset`")
        );
    }

    #[test]
    fn empty_artifacts_render_explicit_message() {
        let mut report = sample_report();
        report.artifacts.clear();
        assert!(report.render_markdown().contains("No artifacts."));
    }

    #[test]
    fn render_markdown_is_byte_identical_across_two_calls() {
        let report = sample_report();
        assert_eq!(report.render_markdown(), report.render_markdown());
    }

    #[test]
    fn serde_round_trip_preserves_report() {
        let report = sample_report();
        let json = serde_json::to_string(&report).expect("serialize technical report");
        let restored: TechnicalReport =
            serde_json::from_str(&json).expect("deserialize technical report");
        assert_eq!(report, restored);
    }

    #[test]
    fn clone_preserves_report() {
        let report = sample_report();
        assert_eq!(report.clone(), report);
    }

    #[test]
    fn debug_mentions_type_name() {
        assert!(format!("{:?}", sample_report()).contains("TechnicalReport"));
    }

    #[test]
    fn table_cells_escape_pipes() {
        let mut report = sample_report();
        report.artifacts.insert(
            "pipe".to_string(),
            artifact("A | B", "proof", "artifacts/a|b.md"),
        );
        let rendered = report.render_markdown();
        assert!(rendered.contains("A \\| B"));
        assert!(rendered.contains("artifacts/a\\|b.md"));
    }

    #[test]
    fn table_cells_replace_newlines() {
        let mut report = sample_report();
        report.artifacts.insert(
            "newline".to_string(),
            artifact("Line\nBreak", "dataset", "artifacts/newline.json"),
        );
        assert!(report.render_markdown().contains("Line Break"));
    }
}
