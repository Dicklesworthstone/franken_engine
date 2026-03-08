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

use crate::lowering_gap_inventory::{
    lowering_gap_inventory, LoweringGapStatus,
};
use crate::parser_gap_inventory::{
    parser_gap_inventory, ParserGapRemediationStatus,
};

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
pub const PARITY_EVIDENCE_POLICY_ID: &str =
    "franken-engine.lowering-parity-evidence.policy.v1";

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
            (
                LoweringGapStatus::OpenPlaceholder,
                "missing".to_string(),
            )
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
                finding.parser_status, finding.lowering_status, finding.verdict.as_str()
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
    let inventory_json =
        serde_json::to_string_pretty(&inventory).map_err(|e| {
            std::io::Error::other(e.to_string())
        })?;
    let inventory_hash = crate::hash_tiers::ContentHash::compute(inventory_json.as_bytes()).to_hex();

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
        .map(|e| {
            serde_json::to_string(e)
                .unwrap_or_else(|_| "{}".to_string())
        })
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
        assert_eq!(
            inventory.open_gap_count(),
            0,
            "no open gaps should exist"
        );
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
        let artifacts =
            write_parity_evidence_bundle(&out_dir, &commands).expect("write artifacts");
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
}
