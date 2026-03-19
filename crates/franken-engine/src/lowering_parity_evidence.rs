//! Fail-closed lowering diagnostics and parser-to-lowering parity evidence.
//!
//! This module enforces the contract: every syntax family that the parser accepts
//! must have a matching lowering path that either (a) produces typed IR, or (b)
//! rejects the input with a structured `UnsupportedSyntaxDiagnostic`. No silent
//! acceptance is permitted — the lowering pipeline must fail closed on any
//! syntax it cannot lower with full semantic fidelity.
//!
//! The parity evidence bundle records which parser families have lowering
//! coverage, which reject fail-closed, and proves there are zero unaccounted
//! gaps between parser and lowering surfaces.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::lowering_gap_inventory::{LoweringGapStatus, lowering_gap_inventory};
use crate::parser_gap_inventory::{ParserGapRemediationStatus, parser_gap_inventory};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const PARITY_EVIDENCE_SCHEMA_VERSION: &str =
    "franken-engine.lowering-parity-evidence.inventory.v1";
pub const PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.lowering-parity-evidence.run-manifest.v1";
pub const PARITY_EVIDENCE_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.lowering-parity-evidence.event.v1";
pub const PARITY_EVIDENCE_COMPONENT: &str = "lowering_parity_evidence";
pub const PARITY_EVIDENCE_POLICY_ID: &str = "franken-engine.lowering-parity-evidence.policy.v1";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The parity verdict for a single syntax family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityVerdict {
    /// Both parser and lowering agree on Resolved status.
    Covered,
    /// Both agree on fail-closed rejection.
    FailClosedAgreed,
    /// Parser accepts but lowering has no coverage (parity violation).
    ParserLeadsLowering,
    /// Lowering claims coverage but parser doesn't accept (unusual but safe).
    LoweringLeadsParser,
    /// Both are in an open-placeholder state (in-progress gap).
    OpenGap,
}

impl ParityVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::FailClosedAgreed => "fail_closed_agreed",
            Self::ParserLeadsLowering => "parser_leads_lowering",
            Self::LoweringLeadsParser => "lowering_leads_parser",
            Self::OpenGap => "open_gap",
        }
    }

    pub const fn is_parity_violation(self) -> bool {
        matches!(self, Self::ParserLeadsLowering)
    }
}

/// A single parity finding for one syntax family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityFinding {
    pub site_id: String,
    pub feature_family: String,
    pub parser_status: String,
    pub lowering_status: String,
    pub verdict: ParityVerdict,
    pub diagnostic_code: String,
}

/// The complete parity evidence inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub findings: Vec<ParityFinding>,
}

impl ParityEvidenceInventory {
    pub fn covered_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.verdict == ParityVerdict::Covered)
            .count()
    }

    pub fn fail_closed_agreed_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.verdict == ParityVerdict::FailClosedAgreed)
            .count()
    }

    pub fn parity_violation_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.verdict.is_parity_violation())
            .count()
    }

    pub fn open_gap_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.verdict == ParityVerdict::OpenGap)
            .count()
    }

    /// Returns true if the parity contract is satisfied:
    /// no parser-leads-lowering violations exist.
    pub fn contract_satisfied(&self) -> bool {
        self.parity_violation_count() == 0
    }
}

/// Run manifest for a parity evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityEvidenceRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub finding_count: u64,
    pub covered_count: u64,
    pub fail_closed_agreed_count: u64,
    pub parity_violation_count: u64,
    pub open_gap_count: u64,
    pub contract_satisfied: bool,
    pub artifact_paths: ParityEvidenceArtifactPaths,
}

/// Paths to parity evidence artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityEvidenceArtifactPaths {
    pub parity_evidence_inventory: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

/// An event emitted during parity evidence collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityEvidenceEvent {
    pub schema_version: String,
    pub component: String,
    pub event: String,
    pub policy_id: String,
    pub site_id: Option<String>,
    pub verdict: Option<String>,
    pub detail: Option<String>,
}

/// Bundle artifacts written to disk.
#[derive(Debug, Clone)]
pub struct ParityEvidenceBundleArtifacts {
    pub inventory_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub inventory_hash: String,
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Compute the parity verdict for a parser/lowering site pair.
fn compute_verdict(
    parser_status: ParserGapRemediationStatus,
    lowering_status: LoweringGapStatus,
) -> ParityVerdict {
    match (parser_status, lowering_status) {
        (ParserGapRemediationStatus::Resolved, LoweringGapStatus::Resolved) => {
            ParityVerdict::Covered
        }
        (ParserGapRemediationStatus::FailClosed, LoweringGapStatus::FailClosed) => {
            ParityVerdict::FailClosedAgreed
        }
        (ParserGapRemediationStatus::Resolved, LoweringGapStatus::FailClosed)
        | (ParserGapRemediationStatus::Resolved, LoweringGapStatus::OpenPlaceholder) => {
            ParityVerdict::ParserLeadsLowering
        }
        (ParserGapRemediationStatus::FailClosed, LoweringGapStatus::Resolved)
        | (ParserGapRemediationStatus::OpenPlaceholder, LoweringGapStatus::Resolved) => {
            ParityVerdict::LoweringLeadsParser
        }
        (ParserGapRemediationStatus::OpenPlaceholder, LoweringGapStatus::OpenPlaceholder) => {
            ParityVerdict::OpenGap
        }
        (ParserGapRemediationStatus::FailClosed, LoweringGapStatus::OpenPlaceholder)
        | (ParserGapRemediationStatus::OpenPlaceholder, LoweringGapStatus::FailClosed) => {
            ParityVerdict::OpenGap
        }
    }
}

/// Build the parity evidence inventory by cross-referencing parser and lowering inventories.
pub fn parity_evidence_inventory() -> ParityEvidenceInventory {
    let parser_inv = parser_gap_inventory();
    let lowering_inv = lowering_gap_inventory();

    let parser_map: BTreeMap<String, &crate::parser_gap_inventory::ParserGapSiteDescriptor> =
        parser_inv
            .sites
            .iter()
            .map(|site| (site.site_id.clone(), site))
            .collect();

    let lowering_map: BTreeMap<String, &crate::lowering_gap_inventory::LoweringGapSiteDescriptor> =
        lowering_inv
            .sites
            .iter()
            .map(|site| (site.site_id.clone(), site))
            .collect();

    let mut findings = Vec::new();

    // Match parser sites to lowering sites by site_id.
    for parser_site in &parser_inv.sites {
        let lowering_site = lowering_map.get(&parser_site.site_id);

        let (lowering_status, lowering_status_str) = if let Some(ls) = lowering_site {
            (ls.status, ls.status.as_str().to_string())
        } else {
            // No matching lowering site => parser leads lowering
            (LoweringGapStatus::OpenPlaceholder, "missing".to_string())
        };

        let verdict = compute_verdict(parser_site.remediation_status, lowering_status);

        findings.push(ParityFinding {
            site_id: parser_site.site_id.clone(),
            feature_family: parser_site.feature_family.clone(),
            parser_status: parser_site.remediation_status.as_str().to_string(),
            lowering_status: lowering_status_str,
            verdict,
            diagnostic_code: parser_site.desired_diagnostic_code.clone(),
        });
    }

    // Check for lowering sites without matching parser sites.
    for lowering_site in &lowering_inv.sites {
        if !parser_map.contains_key(&lowering_site.site_id) {
            findings.push(ParityFinding {
                site_id: lowering_site.site_id.clone(),
                feature_family: lowering_site.ast_node_family.clone(),
                parser_status: "missing".to_string(),
                lowering_status: lowering_site.status.as_str().to_string(),
                verdict: ParityVerdict::LoweringLeadsParser,
                diagnostic_code: lowering_site.diagnostic_code.clone(),
            });
        }
    }

    findings.sort_by(|a, b| a.site_id.cmp(&b.site_id));

    ParityEvidenceInventory {
        schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        findings,
    }
}

/// Generate events for a parity evidence collection run.
fn generate_events(inventory: &ParityEvidenceInventory) -> Vec<ParityEvidenceEvent> {
    let mut events = Vec::new();

    events.push(ParityEvidenceEvent {
        schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        event: "parity_evidence_run_started".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        site_id: None,
        verdict: None,
        detail: Some(format!(
            "starting parity evidence collection for {} findings",
            inventory.findings.len()
        )),
    });

    for finding in &inventory.findings {
        events.push(ParityEvidenceEvent {
            schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            event: "parity_finding_recorded".to_string(),
            policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
            site_id: Some(finding.site_id.clone()),
            verdict: Some(finding.verdict.as_str().to_string()),
            detail: Some(format!(
                "parser={}, lowering={}, verdict={}",
                finding.parser_status,
                finding.lowering_status,
                finding.verdict.as_str()
            )),
        });
    }

    events.push(ParityEvidenceEvent {
        schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        event: "parity_evidence_run_completed".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        site_id: None,
        verdict: None,
        detail: Some(format!(
            "{} findings: {} covered, {} fail-closed-agreed, {} violations, {} open gaps. Contract: {}",
            inventory.findings.len(),
            inventory.covered_count(),
            inventory.fail_closed_agreed_count(),
            inventory.parity_violation_count(),
            inventory.open_gap_count(),
            if inventory.contract_satisfied() {
                "SATISFIED"
            } else {
                "VIOLATED"
            }
        )),
    });

    events
}

/// Write the full parity evidence bundle to disk.
pub fn write_parity_evidence_bundle(
    out_dir: &Path,
    commands: &[String],
) -> Result<ParityEvidenceBundleArtifacts, std::io::Error> {
    fs::create_dir_all(out_dir)?;

    let inventory = parity_evidence_inventory();
    let inventory_json = serde_json::to_string_pretty(&inventory)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let inventory_hash =
        crate::hash_tiers::ContentHash::compute(inventory_json.as_bytes()).to_hex();

    let inventory_path = out_dir.join("parity_evidence_inventory.json");
    fs::write(&inventory_path, &inventory_json)?;

    let trace_id = format!(
        "parity-evidence-{}",
        inventory_hash.chars().take(12).collect::<String>()
    );
    let decision_id = format!("decision-{}", trace_id);

    let manifest = ParityEvidenceRunManifest {
        schema_version: PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        inventory_hash: inventory_hash.clone(),
        finding_count: inventory.findings.len() as u64,
        covered_count: inventory.covered_count() as u64,
        fail_closed_agreed_count: inventory.fail_closed_agreed_count() as u64,
        parity_violation_count: inventory.parity_violation_count() as u64,
        open_gap_count: inventory.open_gap_count() as u64,
        contract_satisfied: inventory.contract_satisfied(),
        artifact_paths: ParityEvidenceArtifactPaths {
            parity_evidence_inventory: "parity_evidence_inventory.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        },
    };

    let manifest_path = out_dir.join("run_manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    fs::write(&manifest_path, &manifest_json)?;

    let events = generate_events(&inventory);
    let events_path = out_dir.join("events.jsonl");
    let events_jsonl: String = events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap_or_else(|_| "{}".to_string()))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&events_path, &events_jsonl)?;

    let commands_path = out_dir.join("commands.txt");
    fs::write(&commands_path, commands.join("\n"))?;

    Ok(ParityEvidenceBundleArtifacts {
        inventory_path,
        run_manifest_path: manifest_path,
        events_path,
        commands_path,
        inventory_hash,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{}-{}", prefix, ts))
    }

    #[test]
    fn schema_version_constants_are_non_empty() {
        assert!(!PARITY_EVIDENCE_SCHEMA_VERSION.is_empty());
        assert!(!PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!PARITY_EVIDENCE_COMPONENT.is_empty());
        assert!(!PARITY_EVIDENCE_POLICY_ID.is_empty());
    }

    #[test]
    fn parity_verdict_serde_round_trip() {
        for verdict in [
            ParityVerdict::Covered,
            ParityVerdict::FailClosedAgreed,
            ParityVerdict::ParserLeadsLowering,
            ParityVerdict::LoweringLeadsParser,
            ParityVerdict::OpenGap,
        ] {
            let json = serde_json::to_string(&verdict).unwrap();
            let back: ParityVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(back, verdict);
        }
    }

    #[test]
    fn parity_finding_serde_round_trip() {
        let finding = ParityFinding {
            site_id: "test.site".to_string(),
            feature_family: "test_family".to_string(),
            parser_status: "resolved".to_string(),
            lowering_status: "resolved".to_string(),
            verdict: ParityVerdict::Covered,
            diagnostic_code: "FE-TEST-0001".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: ParityFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, finding);
    }

    #[test]
    fn parity_evidence_event_serde_round_trip() {
        let event = ParityEvidenceEvent {
            schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            event: "finding_recorded".to_string(),
            policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
            site_id: Some("test.site".to_string()),
            verdict: Some("covered".to_string()),
            detail: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ParityEvidenceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn parity_evidence_inventory_has_findings() {
        let inventory = parity_evidence_inventory();
        assert!(
            !inventory.findings.is_empty(),
            "inventory should have findings"
        );
    }

    #[test]
    fn all_current_sites_are_covered() {
        let inventory = parity_evidence_inventory();
        // Since all parser and lowering gap sites are Resolved,
        // every matched finding should be Covered.
        assert_eq!(inventory.covered_count(), inventory.findings.len());
    }

    #[test]
    fn parity_contract_is_satisfied() {
        let inventory = parity_evidence_inventory();
        assert!(
            inventory.contract_satisfied(),
            "parity contract should be satisfied: {} violations found",
            inventory.parity_violation_count()
        );
    }

    #[test]
    fn zero_parity_violations() {
        let inventory = parity_evidence_inventory();
        assert_eq!(
            inventory.parity_violation_count(),
            0,
            "no parser-leads-lowering violations should exist"
        );
    }

    #[test]
    fn zero_open_gaps() {
        let inventory = parity_evidence_inventory();
        assert_eq!(inventory.open_gap_count(), 0, "no open gaps should exist");
    }

    #[test]
    fn findings_have_valid_structure() {
        let inventory = parity_evidence_inventory();
        for finding in &inventory.findings {
            assert!(!finding.site_id.is_empty());
            assert!(!finding.feature_family.is_empty());
            assert!(!finding.parser_status.is_empty());
            assert!(!finding.lowering_status.is_empty());
            assert!(!finding.diagnostic_code.is_empty());
        }
    }

    #[test]
    fn findings_are_sorted_by_site_id() {
        let inventory = parity_evidence_inventory();
        let site_ids: Vec<&str> = inventory
            .findings
            .iter()
            .map(|f| f.site_id.as_str())
            .collect();
        let mut sorted = site_ids.clone();
        sorted.sort();
        assert_eq!(site_ids, sorted, "findings should be sorted by site_id");
    }

    #[test]
    fn parity_verdict_as_str_roundtrip() {
        let verdicts = [
            ParityVerdict::Covered,
            ParityVerdict::FailClosedAgreed,
            ParityVerdict::ParserLeadsLowering,
            ParityVerdict::LoweringLeadsParser,
            ParityVerdict::OpenGap,
        ];
        for verdict in verdicts {
            let s = verdict.as_str();
            assert!(!s.is_empty());
            assert!(!s.contains(' '));
        }
    }

    #[test]
    fn parity_verdict_is_parity_violation_only_for_parser_leads() {
        assert!(!ParityVerdict::Covered.is_parity_violation());
        assert!(!ParityVerdict::FailClosedAgreed.is_parity_violation());
        assert!(ParityVerdict::ParserLeadsLowering.is_parity_violation());
        assert!(!ParityVerdict::LoweringLeadsParser.is_parity_violation());
        assert!(!ParityVerdict::OpenGap.is_parity_violation());
    }

    #[test]
    fn compute_verdict_resolved_resolved_is_covered() {
        assert_eq!(
            compute_verdict(
                ParserGapRemediationStatus::Resolved,
                LoweringGapStatus::Resolved,
            ),
            ParityVerdict::Covered
        );
    }

    #[test]
    fn compute_verdict_fail_closed_fail_closed_is_agreed() {
        assert_eq!(
            compute_verdict(
                ParserGapRemediationStatus::FailClosed,
                LoweringGapStatus::FailClosed,
            ),
            ParityVerdict::FailClosedAgreed
        );
    }

    #[test]
    fn compute_verdict_parser_resolved_lowering_fail_closed_is_violation() {
        assert_eq!(
            compute_verdict(
                ParserGapRemediationStatus::Resolved,
                LoweringGapStatus::FailClosed,
            ),
            ParityVerdict::ParserLeadsLowering
        );
    }

    #[test]
    fn compute_verdict_parser_resolved_lowering_open_is_violation() {
        assert_eq!(
            compute_verdict(
                ParserGapRemediationStatus::Resolved,
                LoweringGapStatus::OpenPlaceholder,
            ),
            ParityVerdict::ParserLeadsLowering
        );
    }

    #[test]
    fn compute_verdict_open_open_is_open_gap() {
        assert_eq!(
            compute_verdict(
                ParserGapRemediationStatus::OpenPlaceholder,
                LoweringGapStatus::OpenPlaceholder,
            ),
            ParityVerdict::OpenGap
        );
    }

    #[test]
    fn inventory_serde_roundtrip() {
        let inventory = parity_evidence_inventory();
        let json = serde_json::to_string(&inventory).expect("serialize");
        let deserialized: ParityEvidenceInventory =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(inventory, deserialized);
    }

    #[test]
    fn write_parity_evidence_bundle_emits_expected_artifacts() {
        let out_dir = unique_temp_dir("parity-evidence");
        let commands = vec![
            "franken_parity_evidence".to_string(),
            "--out-dir".to_string(),
            out_dir.display().to_string(),
        ];
        let artifacts = write_parity_evidence_bundle(&out_dir, &commands).expect("write artifacts");
        assert!(artifacts.inventory_path.exists());
        assert!(artifacts.run_manifest_path.exists());
        assert!(artifacts.events_path.exists());
        assert!(artifacts.commands_path.exists());

        let inventory: ParityEvidenceInventory =
            serde_json::from_slice(&fs::read(&artifacts.inventory_path).expect("read"))
                .expect("parse inventory");
        assert!(!inventory.findings.is_empty());

        let manifest: ParityEvidenceRunManifest =
            serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read"))
                .expect("parse manifest");
        assert_eq!(manifest.finding_count, inventory.findings.len() as u64);
        assert!(manifest.contract_satisfied);
        assert_eq!(manifest.parity_violation_count, 0);
        assert_eq!(
            manifest.covered_count
                + manifest.fail_closed_agreed_count
                + manifest.parity_violation_count
                + manifest.open_gap_count,
            manifest.finding_count
        );

        let events = fs::read_to_string(&artifacts.events_path).expect("read events");
        assert_eq!(
            events.lines().count(),
            inventory.findings.len() + 2 // start + per-finding + end
        );
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let out1 = unique_temp_dir("parity-det-1");
        let out2 = unique_temp_dir("parity-det-2");
        let commands = vec!["test".to_string()];
        let a1 = write_parity_evidence_bundle(&out1, &commands).expect("write");
        let a2 = write_parity_evidence_bundle(&out2, &commands).expect("write");
        assert_eq!(a1.inventory_hash, a2.inventory_hash);
    }

    #[test]
    fn schema_version_constants_are_all_distinct() {
        let versions = [
            PARITY_EVIDENCE_SCHEMA_VERSION,
            PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION,
            PARITY_EVIDENCE_EVENT_SCHEMA_VERSION,
            PARITY_EVIDENCE_POLICY_ID,
        ];
        for (i, a) in versions.iter().enumerate() {
            for (j, b) in versions.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "constants at index {} and {} must differ", i, j);
                }
            }
        }
        for v in &versions {
            assert_ne!(
                *v, PARITY_EVIDENCE_COMPONENT,
                "component constant must differ from version/policy constants"
            );
        }
    }

    #[test]
    fn compute_verdict_remaining_lowering_leads_parser_cases() {
        assert_eq!(
            compute_verdict(
                ParserGapRemediationStatus::FailClosed,
                LoweringGapStatus::Resolved,
            ),
            ParityVerdict::LoweringLeadsParser
        );
        assert_eq!(
            compute_verdict(
                ParserGapRemediationStatus::OpenPlaceholder,
                LoweringGapStatus::Resolved,
            ),
            ParityVerdict::LoweringLeadsParser
        );
    }

    #[test]
    fn compute_verdict_mixed_non_resolved_yields_open_gap() {
        assert_eq!(
            compute_verdict(
                ParserGapRemediationStatus::FailClosed,
                LoweringGapStatus::OpenPlaceholder,
            ),
            ParityVerdict::OpenGap
        );
        assert_eq!(
            compute_verdict(
                ParserGapRemediationStatus::OpenPlaceholder,
                LoweringGapStatus::FailClosed,
            ),
            ParityVerdict::OpenGap
        );
    }

    #[test]
    fn empty_inventory_counts_and_contract() {
        let inv = ParityEvidenceInventory {
            schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            findings: Vec::new(),
        };
        assert_eq!(inv.covered_count(), 0);
        assert_eq!(inv.fail_closed_agreed_count(), 0);
        assert_eq!(inv.parity_violation_count(), 0);
        assert_eq!(inv.open_gap_count(), 0);
        assert!(inv.contract_satisfied());
    }

    #[test]
    fn inventory_with_violation_fails_contract() {
        let inv = ParityEvidenceInventory {
            schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            findings: vec![
                ParityFinding {
                    site_id: "site.a".to_string(),
                    feature_family: "family_a".to_string(),
                    parser_status: "resolved".to_string(),
                    lowering_status: "resolved".to_string(),
                    verdict: ParityVerdict::Covered,
                    diagnostic_code: "FE-A".to_string(),
                },
                ParityFinding {
                    site_id: "site.b".to_string(),
                    feature_family: "family_b".to_string(),
                    parser_status: "resolved".to_string(),
                    lowering_status: "open_placeholder".to_string(),
                    verdict: ParityVerdict::ParserLeadsLowering,
                    diagnostic_code: "FE-B".to_string(),
                },
            ],
        };
        assert_eq!(inv.covered_count(), 1);
        assert_eq!(inv.parity_violation_count(), 1);
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn parity_verdict_ordering_is_deterministic() {
        let mut verdicts = [
            ParityVerdict::OpenGap,
            ParityVerdict::LoweringLeadsParser,
            ParityVerdict::Covered,
            ParityVerdict::ParserLeadsLowering,
            ParityVerdict::FailClosedAgreed,
        ];
        verdicts.sort();
        assert_eq!(verdicts[0], ParityVerdict::Covered);
        assert_eq!(verdicts[1], ParityVerdict::FailClosedAgreed);
        assert_eq!(verdicts[4], ParityVerdict::OpenGap);
    }

    #[test]
    fn run_manifest_serde_roundtrip() {
        let manifest = ParityEvidenceRunManifest {
            schema_version: PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            trace_id: "trace-abc".to_string(),
            decision_id: "decision-trace-abc".to_string(),
            policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
            inventory_hash: "deadbeef".to_string(),
            finding_count: 5,
            covered_count: 3,
            fail_closed_agreed_count: 1,
            parity_violation_count: 0,
            open_gap_count: 1,
            contract_satisfied: true,
            artifact_paths: ParityEvidenceArtifactPaths {
                parity_evidence_inventory: "inv.json".to_string(),
                run_manifest: "manifest.json".to_string(),
                events_jsonl: "events.jsonl".to_string(),
                commands_txt: "commands.txt".to_string(),
            },
        };
        let json = serde_json::to_string_pretty(&manifest).expect("serialize manifest");
        let back: ParityEvidenceRunManifest =
            serde_json::from_str(&json).expect("deserialize manifest");
        assert_eq!(back.schema_version, manifest.schema_version);
        assert_eq!(back.finding_count, manifest.finding_count);
        assert_eq!(back.contract_satisfied, manifest.contract_satisfied);
        assert_eq!(
            back.artifact_paths.parity_evidence_inventory,
            manifest.artifact_paths.parity_evidence_inventory
        );
    }

    // ── enrichment tests (PearlTower 2026-03-16) ──────────────────

    #[test]
    fn parity_verdict_serde_roundtrip_all_variants() {
        for verdict in [
            ParityVerdict::Covered,
            ParityVerdict::FailClosedAgreed,
            ParityVerdict::ParserLeadsLowering,
            ParityVerdict::LoweringLeadsParser,
            ParityVerdict::OpenGap,
        ] {
            let json = serde_json::to_string(&verdict).unwrap();
            let back: ParityVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(verdict, back);
        }
    }

    #[test]
    fn parity_verdict_as_str_matches_serde() {
        for verdict in [
            ParityVerdict::Covered,
            ParityVerdict::FailClosedAgreed,
            ParityVerdict::ParserLeadsLowering,
            ParityVerdict::LoweringLeadsParser,
            ParityVerdict::OpenGap,
        ] {
            let json: String =
                serde_json::from_str(&serde_json::to_string(&verdict).unwrap()).unwrap();
            assert_eq!(json, verdict.as_str());
        }
    }

    #[test]
    fn parity_verdict_as_str_distinct() {
        let strs: std::collections::BTreeSet<&str> = [
            ParityVerdict::Covered,
            ParityVerdict::FailClosedAgreed,
            ParityVerdict::ParserLeadsLowering,
            ParityVerdict::LoweringLeadsParser,
            ParityVerdict::OpenGap,
        ]
        .iter()
        .map(|v| v.as_str())
        .collect();
        assert_eq!(strs.len(), 5);
    }

    #[test]
    fn only_parser_leads_lowering_is_violation() {
        assert!(!ParityVerdict::Covered.is_parity_violation());
        assert!(!ParityVerdict::FailClosedAgreed.is_parity_violation());
        assert!(ParityVerdict::ParserLeadsLowering.is_parity_violation());
        assert!(!ParityVerdict::LoweringLeadsParser.is_parity_violation());
        assert!(!ParityVerdict::OpenGap.is_parity_violation());
    }

    #[test]
    fn parity_evidence_inventory_has_correct_schema() {
        let inv = parity_evidence_inventory();
        assert_eq!(inv.schema_version, PARITY_EVIDENCE_SCHEMA_VERSION);
        assert_eq!(inv.component, PARITY_EVIDENCE_COMPONENT);
    }

    #[test]
    fn parity_evidence_inventory_counts_are_consistent() {
        let inv = parity_evidence_inventory();
        let total = inv.covered_count()
            + inv.fail_closed_agreed_count()
            + inv.parity_violation_count()
            + inv.open_gap_count();
        assert_eq!(
            total,
            inv.findings.len(),
            "verdict counts must sum to total findings"
        );
    }

    #[test]
    fn parity_evidence_inventory_findings_non_empty() {
        let inv = parity_evidence_inventory();
        assert!(!inv.findings.is_empty());
    }

    #[test]
    fn parity_evidence_event_serde_roundtrip() {
        let event = ParityEvidenceEvent {
            schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            event: "finding_recorded".to_string(),
            policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
            site_id: Some("test_family".to_string()),
            verdict: Some("covered".to_string()),
            detail: Some("test detail".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ParityEvidenceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn parity_finding_serde_roundtrip() {
        let finding = ParityFinding {
            site_id: "test_family".to_string(),
            feature_family: "expression".to_string(),
            diagnostic_code: "FE-TEST-0001".to_string(),
            parser_status: "resolved".to_string(),
            lowering_status: "resolved".to_string(),
            verdict: ParityVerdict::Covered,
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: ParityFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
    }

    #[test]
    fn schema_constants_are_non_empty() {
        assert!(!PARITY_EVIDENCE_SCHEMA_VERSION.is_empty());
        assert!(!PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!PARITY_EVIDENCE_COMPONENT.is_empty());
        assert!(!PARITY_EVIDENCE_POLICY_ID.is_empty());
    }

    #[test]
    fn schema_versions_all_distinct() {
        let versions = [
            PARITY_EVIDENCE_SCHEMA_VERSION,
            PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION,
            PARITY_EVIDENCE_EVENT_SCHEMA_VERSION,
        ];
        let set: std::collections::BTreeSet<&str> = versions.iter().copied().collect();
        assert_eq!(set.len(), versions.len());
    }

    #[test]
    fn parity_artifact_paths_serde_roundtrip() {
        let paths = ParityEvidenceArtifactPaths {
            parity_evidence_inventory: "inventory.json".to_string(),
            run_manifest: "manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        };
        let json = serde_json::to_string(&paths).unwrap();
        let back: ParityEvidenceArtifactPaths = serde_json::from_str(&json).unwrap();
        assert_eq!(paths, back);
    }

    // ── additional enrichment tests (PearlTower 2026-03-18) ──────────

    #[test]
    fn compute_verdict_exhaustive_3x3_matrix() {
        // Verify all 9 combinations of 3 parser statuses x 3 lowering statuses.
        let cases = [
            (ParserGapRemediationStatus::Resolved, LoweringGapStatus::Resolved, ParityVerdict::Covered),
            (ParserGapRemediationStatus::Resolved, LoweringGapStatus::FailClosed, ParityVerdict::ParserLeadsLowering),
            (ParserGapRemediationStatus::Resolved, LoweringGapStatus::OpenPlaceholder, ParityVerdict::ParserLeadsLowering),
            (ParserGapRemediationStatus::FailClosed, LoweringGapStatus::Resolved, ParityVerdict::LoweringLeadsParser),
            (ParserGapRemediationStatus::FailClosed, LoweringGapStatus::FailClosed, ParityVerdict::FailClosedAgreed),
            (ParserGapRemediationStatus::FailClosed, LoweringGapStatus::OpenPlaceholder, ParityVerdict::OpenGap),
            (ParserGapRemediationStatus::OpenPlaceholder, LoweringGapStatus::Resolved, ParityVerdict::LoweringLeadsParser),
            (ParserGapRemediationStatus::OpenPlaceholder, LoweringGapStatus::FailClosed, ParityVerdict::OpenGap),
            (ParserGapRemediationStatus::OpenPlaceholder, LoweringGapStatus::OpenPlaceholder, ParityVerdict::OpenGap),
        ];
        for (i, (parser, lowering, expected)) in cases.iter().enumerate() {
            let actual = compute_verdict(*parser, *lowering);
            assert_eq!(
                actual, *expected,
                "case {}: compute_verdict({:?}, {:?}) expected {:?}, got {:?}",
                i, parser, lowering, expected, actual
            );
        }
    }

    #[test]
    fn inventory_with_all_verdict_types_counts_correctly() {
        let findings = vec![
            ParityFinding {
                site_id: "a".to_string(),
                feature_family: "fa".to_string(),
                parser_status: "resolved".to_string(),
                lowering_status: "resolved".to_string(),
                verdict: ParityVerdict::Covered,
                diagnostic_code: "FE-A".to_string(),
            },
            ParityFinding {
                site_id: "b".to_string(),
                feature_family: "fb".to_string(),
                parser_status: "fail_closed".to_string(),
                lowering_status: "fail_closed".to_string(),
                verdict: ParityVerdict::FailClosedAgreed,
                diagnostic_code: "FE-B".to_string(),
            },
            ParityFinding {
                site_id: "c".to_string(),
                feature_family: "fc".to_string(),
                parser_status: "resolved".to_string(),
                lowering_status: "open_placeholder".to_string(),
                verdict: ParityVerdict::ParserLeadsLowering,
                diagnostic_code: "FE-C".to_string(),
            },
            ParityFinding {
                site_id: "d".to_string(),
                feature_family: "fd".to_string(),
                parser_status: "open_placeholder".to_string(),
                lowering_status: "resolved".to_string(),
                verdict: ParityVerdict::LoweringLeadsParser,
                diagnostic_code: "FE-D".to_string(),
            },
            ParityFinding {
                site_id: "e".to_string(),
                feature_family: "fe".to_string(),
                parser_status: "open_placeholder".to_string(),
                lowering_status: "open_placeholder".to_string(),
                verdict: ParityVerdict::OpenGap,
                diagnostic_code: "FE-E".to_string(),
            },
        ];
        let inv = ParityEvidenceInventory {
            schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            findings,
        };
        assert_eq!(inv.covered_count(), 1);
        assert_eq!(inv.fail_closed_agreed_count(), 1);
        assert_eq!(inv.parity_violation_count(), 1);
        assert_eq!(inv.open_gap_count(), 1);
        // LoweringLeadsParser is not counted by any of the 4 named counters
        // except as part of total findings
        let sum = inv.covered_count()
            + inv.fail_closed_agreed_count()
            + inv.parity_violation_count()
            + inv.open_gap_count();
        assert_eq!(sum, 4);
        assert_eq!(inv.findings.len(), 5);
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn inventory_lowering_leads_parser_only_satisfies_contract() {
        // LoweringLeadsParser is unusual but safe -- contract should be satisfied.
        let inv = ParityEvidenceInventory {
            schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            findings: vec![ParityFinding {
                site_id: "x".to_string(),
                feature_family: "fx".to_string(),
                parser_status: "fail_closed".to_string(),
                lowering_status: "resolved".to_string(),
                verdict: ParityVerdict::LoweringLeadsParser,
                diagnostic_code: "FE-X".to_string(),
            }],
        };
        assert!(inv.contract_satisfied());
        assert_eq!(inv.parity_violation_count(), 0);
    }

    #[test]
    fn inventory_open_gaps_only_satisfies_contract() {
        // Open gaps are in-progress work, not violations.
        let inv = ParityEvidenceInventory {
            schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            findings: vec![
                ParityFinding {
                    site_id: "g1".to_string(),
                    feature_family: "fg1".to_string(),
                    parser_status: "open_placeholder".to_string(),
                    lowering_status: "open_placeholder".to_string(),
                    verdict: ParityVerdict::OpenGap,
                    diagnostic_code: "FE-G1".to_string(),
                },
                ParityFinding {
                    site_id: "g2".to_string(),
                    feature_family: "fg2".to_string(),
                    parser_status: "fail_closed".to_string(),
                    lowering_status: "open_placeholder".to_string(),
                    verdict: ParityVerdict::OpenGap,
                    diagnostic_code: "FE-G2".to_string(),
                },
            ],
        };
        assert!(inv.contract_satisfied());
        assert_eq!(inv.open_gap_count(), 2);
    }

    #[test]
    fn generate_events_start_and_end_bookend() {
        let inv = ParityEvidenceInventory {
            schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            findings: vec![ParityFinding {
                site_id: "s1".to_string(),
                feature_family: "f1".to_string(),
                parser_status: "resolved".to_string(),
                lowering_status: "resolved".to_string(),
                verdict: ParityVerdict::Covered,
                diagnostic_code: "FE-1".to_string(),
            }],
        };
        let events = generate_events(&inv);
        assert_eq!(events.len(), 3); // start + 1 finding + end
        assert_eq!(events[0].event, "parity_evidence_run_started");
        assert_eq!(events[1].event, "parity_finding_recorded");
        assert_eq!(events[2].event, "parity_evidence_run_completed");
    }

    #[test]
    fn generate_events_empty_inventory() {
        let inv = ParityEvidenceInventory {
            schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            findings: Vec::new(),
        };
        let events = generate_events(&inv);
        assert_eq!(events.len(), 2); // start + end, no per-finding events
        assert_eq!(events[0].event, "parity_evidence_run_started");
        assert_eq!(events[1].event, "parity_evidence_run_completed");
    }

    #[test]
    fn generate_events_finding_events_carry_site_id_and_verdict() {
        let finding = ParityFinding {
            site_id: "my.site.id".to_string(),
            feature_family: "expr".to_string(),
            parser_status: "resolved".to_string(),
            lowering_status: "resolved".to_string(),
            verdict: ParityVerdict::Covered,
            diagnostic_code: "FE-MY".to_string(),
        };
        let inv = ParityEvidenceInventory {
            schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            findings: vec![finding],
        };
        let events = generate_events(&inv);
        let finding_event = &events[1];
        assert_eq!(finding_event.site_id.as_deref(), Some("my.site.id"));
        assert_eq!(finding_event.verdict.as_deref(), Some("covered"));
        assert!(finding_event.detail.as_ref().unwrap().contains("parser=resolved"));
        assert!(finding_event.detail.as_ref().unwrap().contains("lowering=resolved"));
        assert!(finding_event.detail.as_ref().unwrap().contains("verdict=covered"));
    }

    #[test]
    fn generate_events_start_event_has_no_site_or_verdict() {
        let inv = parity_evidence_inventory();
        let events = generate_events(&inv);
        let start = &events[0];
        assert!(start.site_id.is_none());
        assert!(start.verdict.is_none());
    }

    #[test]
    fn generate_events_end_event_detail_contains_contract_status() {
        let inv = parity_evidence_inventory();
        let events = generate_events(&inv);
        let end = events.last().unwrap();
        assert!(end.detail.as_ref().unwrap().contains("Contract:"));
        // Current inventory should be SATISFIED
        assert!(end.detail.as_ref().unwrap().contains("SATISFIED"));
    }

    #[test]
    fn generate_events_violated_contract_detail() {
        let inv = ParityEvidenceInventory {
            schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            findings: vec![ParityFinding {
                site_id: "v1".to_string(),
                feature_family: "fv".to_string(),
                parser_status: "resolved".to_string(),
                lowering_status: "open_placeholder".to_string(),
                verdict: ParityVerdict::ParserLeadsLowering,
                diagnostic_code: "FE-V".to_string(),
            }],
        };
        let events = generate_events(&inv);
        let end = events.last().unwrap();
        assert!(end.detail.as_ref().unwrap().contains("VIOLATED"));
        assert!(end.detail.as_ref().unwrap().contains("1 violations"));
    }

    #[test]
    fn generate_events_all_events_have_correct_schema_and_component() {
        let inv = parity_evidence_inventory();
        let events = generate_events(&inv);
        for event in &events {
            assert_eq!(event.schema_version, PARITY_EVIDENCE_EVENT_SCHEMA_VERSION);
            assert_eq!(event.component, PARITY_EVIDENCE_COMPONENT);
            assert_eq!(event.policy_id, PARITY_EVIDENCE_POLICY_ID);
        }
    }

    #[test]
    fn generate_events_each_event_is_valid_json() {
        let inv = parity_evidence_inventory();
        let events = generate_events(&inv);
        for event in &events {
            let json = serde_json::to_string(event).unwrap();
            let _parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn parity_verdict_clone_is_independent() {
        let original = ParityVerdict::ParserLeadsLowering;
        let cloned = original;
        assert_eq!(original, cloned);
        // Both are Copy, so both remain valid
        assert!(original.is_parity_violation());
        assert!(cloned.is_parity_violation());
    }

    #[test]
    fn parity_finding_clone_is_independent() {
        let original = ParityFinding {
            site_id: "clone.test".to_string(),
            feature_family: "clone_fam".to_string(),
            parser_status: "resolved".to_string(),
            lowering_status: "resolved".to_string(),
            verdict: ParityVerdict::Covered,
            diagnostic_code: "FE-CLN".to_string(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn parity_evidence_inventory_clone_is_independent() {
        let inv = parity_evidence_inventory();
        let cloned = inv.clone();
        assert_eq!(inv, cloned);
        assert_eq!(inv.findings.len(), cloned.findings.len());
    }

    #[test]
    fn parity_verdict_debug_format_contains_variant_name() {
        let dbg = format!("{:?}", ParityVerdict::Covered);
        assert!(dbg.contains("Covered"));
        let dbg2 = format!("{:?}", ParityVerdict::ParserLeadsLowering);
        assert!(dbg2.contains("ParserLeadsLowering"));
    }

    #[test]
    fn parity_finding_debug_format_contains_fields() {
        let finding = ParityFinding {
            site_id: "debug.site".to_string(),
            feature_family: "debug_fam".to_string(),
            parser_status: "resolved".to_string(),
            lowering_status: "resolved".to_string(),
            verdict: ParityVerdict::Covered,
            diagnostic_code: "FE-DBG".to_string(),
        };
        let dbg = format!("{:?}", finding);
        assert!(dbg.contains("debug.site"));
        assert!(dbg.contains("FE-DBG"));
        assert!(dbg.contains("Covered"));
    }

    #[test]
    fn parity_verdict_serde_snake_case_encoding() {
        assert_eq!(
            serde_json::to_string(&ParityVerdict::Covered).unwrap(),
            "\"covered\""
        );
        assert_eq!(
            serde_json::to_string(&ParityVerdict::FailClosedAgreed).unwrap(),
            "\"fail_closed_agreed\""
        );
        assert_eq!(
            serde_json::to_string(&ParityVerdict::ParserLeadsLowering).unwrap(),
            "\"parser_leads_lowering\""
        );
        assert_eq!(
            serde_json::to_string(&ParityVerdict::LoweringLeadsParser).unwrap(),
            "\"lowering_leads_parser\""
        );
        assert_eq!(
            serde_json::to_string(&ParityVerdict::OpenGap).unwrap(),
            "\"open_gap\""
        );
    }

    #[test]
    fn parity_verdict_rejects_invalid_serde_input() {
        let result: Result<ParityVerdict, _> = serde_json::from_str("\"nonexistent_verdict\"");
        assert!(result.is_err());
    }

    #[test]
    fn parity_verdict_rejects_numeric_serde_input() {
        let result: Result<ParityVerdict, _> = serde_json::from_str("42");
        assert!(result.is_err());
    }

    #[test]
    fn parity_verdict_rejects_null_serde_input() {
        let result: Result<ParityVerdict, _> = serde_json::from_str("null");
        assert!(result.is_err());
    }

    #[test]
    fn parity_finding_rejects_missing_fields() {
        let json = r#"{"site_id":"s","feature_family":"f"}"#;
        let result: Result<ParityFinding, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn parity_event_optional_fields_serialize_as_null() {
        let event = ParityEvidenceEvent {
            schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            event: "test".to_string(),
            policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
            site_id: None,
            verdict: None,
            detail: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(val["site_id"].is_null());
        assert!(val["verdict"].is_null());
        assert!(val["detail"].is_null());
    }

    #[test]
    fn write_bundle_commands_file_content() {
        let out_dir = unique_temp_dir("parity-cmds");
        let commands = vec![
            "cmd_alpha".to_string(),
            "cmd_beta".to_string(),
            "cmd_gamma".to_string(),
        ];
        let artifacts = write_parity_evidence_bundle(&out_dir, &commands).unwrap();
        let content = fs::read_to_string(&artifacts.commands_path).unwrap();
        assert_eq!(content, "cmd_alpha\ncmd_beta\ncmd_gamma");
    }

    #[test]
    fn write_bundle_empty_commands() {
        let out_dir = unique_temp_dir("parity-empty-cmds");
        let commands: Vec<String> = Vec::new();
        let artifacts = write_parity_evidence_bundle(&out_dir, &commands).unwrap();
        let content = fs::read_to_string(&artifacts.commands_path).unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn write_bundle_events_jsonl_each_line_is_valid_json() {
        let out_dir = unique_temp_dir("parity-jsonl");
        let artifacts =
            write_parity_evidence_bundle(&out_dir, &["test".to_string()]).unwrap();
        let content = fs::read_to_string(&artifacts.events_path).unwrap();
        for line in content.lines() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "invalid JSON line: {}", line);
        }
    }

    #[test]
    fn write_bundle_manifest_trace_id_derived_from_hash() {
        let out_dir = unique_temp_dir("parity-trace");
        let artifacts =
            write_parity_evidence_bundle(&out_dir, &["test".to_string()]).unwrap();
        let manifest_json = fs::read_to_string(&artifacts.run_manifest_path).unwrap();
        let manifest: ParityEvidenceRunManifest =
            serde_json::from_str(&manifest_json).unwrap();
        assert!(manifest.trace_id.starts_with("parity-evidence-"));
        assert!(manifest.decision_id.starts_with("decision-parity-evidence-"));
        // Trace ID should embed 12 chars of the inventory hash
        let hash_prefix: String = artifacts.inventory_hash.chars().take(12).collect();
        assert!(manifest.trace_id.contains(&hash_prefix));
    }

    #[test]
    fn write_bundle_manifest_artifact_paths_are_filenames_only() {
        let out_dir = unique_temp_dir("parity-paths");
        let artifacts =
            write_parity_evidence_bundle(&out_dir, &["test".to_string()]).unwrap();
        let manifest_json = fs::read_to_string(&artifacts.run_manifest_path).unwrap();
        let manifest: ParityEvidenceRunManifest =
            serde_json::from_str(&manifest_json).unwrap();
        // Paths should be relative filenames, not absolute paths
        assert!(!manifest.artifact_paths.parity_evidence_inventory.contains('/'));
        assert!(!manifest.artifact_paths.run_manifest.contains('/'));
        assert!(!manifest.artifact_paths.events_jsonl.contains('/'));
        assert!(!manifest.artifact_paths.commands_txt.contains('/'));
    }

    #[test]
    fn write_bundle_creates_output_directory() {
        let out_dir = unique_temp_dir("parity-mkdir")
            .join("nested")
            .join("deep");
        assert!(!out_dir.exists());
        let _artifacts =
            write_parity_evidence_bundle(&out_dir, &["test".to_string()]).unwrap();
        assert!(out_dir.exists());
    }

    #[test]
    fn inventory_hash_is_hex_string() {
        let out_dir = unique_temp_dir("parity-hex");
        let artifacts =
            write_parity_evidence_bundle(&out_dir, &["test".to_string()]).unwrap();
        assert!(!artifacts.inventory_hash.is_empty());
        assert!(
            artifacts
                .inventory_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
            "hash should be hex: {}",
            artifacts.inventory_hash
        );
    }

    #[test]
    fn inventory_unique_site_ids() {
        let inv = parity_evidence_inventory();
        let mut seen = std::collections::BTreeSet::new();
        for finding in &inv.findings {
            assert!(
                seen.insert(&finding.site_id),
                "duplicate site_id: {}",
                finding.site_id
            );
        }
    }

    #[test]
    fn parity_verdict_copy_semantics() {
        let v = ParityVerdict::Covered;
        let v2 = v; // Copy
        let v3 = v; // Still valid since Copy
        assert_eq!(v2, v3);
        assert_eq!(v, v2);
    }

    #[test]
    fn run_manifest_serde_full_equality_roundtrip() {
        let manifest = ParityEvidenceRunManifest {
            schema_version: PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            trace_id: "trace-full-rt".to_string(),
            decision_id: "decision-trace-full-rt".to_string(),
            policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
            inventory_hash: "abcdef0123456789".to_string(),
            finding_count: 10,
            covered_count: 7,
            fail_closed_agreed_count: 2,
            parity_violation_count: 0,
            open_gap_count: 1,
            contract_satisfied: true,
            artifact_paths: ParityEvidenceArtifactPaths {
                parity_evidence_inventory: "inv.json".to_string(),
                run_manifest: "manifest.json".to_string(),
                events_jsonl: "events.jsonl".to_string(),
                commands_txt: "commands.txt".to_string(),
            },
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: ParityEvidenceRunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn multiple_violations_tracked_correctly() {
        let findings = vec![
            ParityFinding {
                site_id: "v1".to_string(),
                feature_family: "f1".to_string(),
                parser_status: "resolved".to_string(),
                lowering_status: "fail_closed".to_string(),
                verdict: ParityVerdict::ParserLeadsLowering,
                diagnostic_code: "FE-V1".to_string(),
            },
            ParityFinding {
                site_id: "v2".to_string(),
                feature_family: "f2".to_string(),
                parser_status: "resolved".to_string(),
                lowering_status: "open_placeholder".to_string(),
                verdict: ParityVerdict::ParserLeadsLowering,
                diagnostic_code: "FE-V2".to_string(),
            },
            ParityFinding {
                site_id: "v3".to_string(),
                feature_family: "f3".to_string(),
                parser_status: "resolved".to_string(),
                lowering_status: "resolved".to_string(),
                verdict: ParityVerdict::Covered,
                diagnostic_code: "FE-V3".to_string(),
            },
        ];
        let inv = ParityEvidenceInventory {
            schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            findings,
        };
        assert_eq!(inv.parity_violation_count(), 2);
        assert_eq!(inv.covered_count(), 1);
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn parity_verdict_partial_ord_consistent_with_ord() {
        let a = ParityVerdict::Covered;
        let b = ParityVerdict::OpenGap;
        assert_eq!(a.partial_cmp(&b), Some(a.cmp(&b)));
    }
}
