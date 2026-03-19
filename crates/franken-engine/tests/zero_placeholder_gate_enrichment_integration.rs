//! Enrichment integration tests for `zero_placeholder_gate`.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::zero_placeholder_gate::*;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn make_placeholder(
    subsystem: Subsystem,
    kind: PlaceholderKind,
    severity: PlaceholderSeverity,
) -> PlaceholderEntry {
    PlaceholderEntry::new(
        subsystem,
        kind,
        "test_file.rs",
        42,
        "test placeholder",
        severity,
    )
}

fn make_scan(subsystem: Subsystem, entries: Vec<PlaceholderEntry>) -> ScanResult {
    ScanResult::new(subsystem, entries, epoch())
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_non_empty() {
    assert!(!SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_component_non_empty() {
    assert!(!COMPONENT.is_empty());
}

#[test]
fn enrichment_bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_policy_id_non_empty() {
    assert!(!POLICY_ID.is_empty());
}

#[test]
fn enrichment_millionths_value() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// Subsystem
// ---------------------------------------------------------------------------

#[test]
fn enrichment_subsystem_all_count() {
    assert!(Subsystem::ALL.len() >= 4);
}

#[test]
fn enrichment_subsystem_as_str_unique() {
    let mut strs = std::collections::BTreeSet::new();
    for s in Subsystem::ALL {
        assert!(strs.insert(s.as_str()));
    }
}

#[test]
fn enrichment_subsystem_serde_roundtrip() {
    for s in Subsystem::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: Subsystem = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// PlaceholderKind
// ---------------------------------------------------------------------------

#[test]
fn enrichment_placeholder_kind_all_count() {
    assert!(PlaceholderKind::ALL.len() >= 4);
}

#[test]
fn enrichment_placeholder_kind_as_str_unique() {
    let mut strs = std::collections::BTreeSet::new();
    for k in PlaceholderKind::ALL {
        assert!(strs.insert(k.as_str()));
    }
}

#[test]
fn enrichment_placeholder_kind_serde_roundtrip() {
    for k in PlaceholderKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: PlaceholderKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// PlaceholderSeverity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_severity_all_count() {
    assert_eq!(PlaceholderSeverity::ALL.len(), 4);
}

#[test]
fn enrichment_severity_as_str_unique() {
    let mut strs = std::collections::BTreeSet::new();
    for s in PlaceholderSeverity::ALL {
        assert!(strs.insert(s.as_str()));
    }
}

#[test]
fn enrichment_severity_serde_roundtrip() {
    for s in PlaceholderSeverity::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: PlaceholderSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// PlaceholderEntry
// ---------------------------------------------------------------------------

#[test]
fn enrichment_placeholder_entry_hash_deterministic() {
    let p1 = make_placeholder(
        Subsystem::Parser,
        PlaceholderKind::TodoMacro,
        PlaceholderSeverity::Medium,
    );
    let p2 = make_placeholder(
        Subsystem::Parser,
        PlaceholderKind::TodoMacro,
        PlaceholderSeverity::Medium,
    );
    assert_eq!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_placeholder_entry_serde_roundtrip() {
    let p = make_placeholder(
        Subsystem::Runtime,
        PlaceholderKind::StubReturn,
        PlaceholderSeverity::High,
    );
    let json = serde_json::to_string(&p).unwrap();
    let back: PlaceholderEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(p.subsystem, back.subsystem);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_config_default_blocking_blocks() {
    let cfg = GateConfig::default_config();
    assert_eq!(
        cfg.action_for(PlaceholderSeverity::Blocking),
        GateAction::Block
    );
}

#[test]
fn enrichment_gate_config_strict_blocks_all() {
    let cfg = GateConfig::strict();
    for s in PlaceholderSeverity::ALL {
        assert_eq!(cfg.action_for(*s), GateAction::Block);
    }
}

#[test]
fn enrichment_gate_config_permissive_low_allows() {
    let cfg = GateConfig::permissive();
    assert_eq!(cfg.action_for(PlaceholderSeverity::Low), GateAction::Allow);
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let cfg = GateConfig::default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scan_result_clean() {
    let scan = make_scan(Subsystem::Parser, vec![]);
    assert!(scan.is_clean());
    assert_eq!(scan.placeholder_count(), 0);
}

#[test]
fn enrichment_scan_result_with_entries() {
    let entries = vec![make_placeholder(
        Subsystem::Parser,
        PlaceholderKind::TodoMacro,
        PlaceholderSeverity::Medium,
    )];
    let scan = make_scan(Subsystem::Parser, entries);
    assert!(!scan.is_clean());
    assert_eq!(scan.placeholder_count(), 1);
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_verdict_pass_is_pass() {
    assert!(GateVerdict::Pass.is_pass());
    assert!(!GateVerdict::Pass.is_block());
}

#[test]
fn enrichment_gate_verdict_block_is_block() {
    assert!(GateVerdict::Block.is_block());
    assert!(!GateVerdict::Block.is_pass());
}

#[test]
fn enrichment_gate_verdict_warn_neither() {
    assert!(!GateVerdict::Warn.is_pass());
    assert!(!GateVerdict::Warn.is_block());
}

#[test]
fn enrichment_gate_verdict_serde_roundtrip() {
    for v in [GateVerdict::Pass, GateVerdict::Warn, GateVerdict::Block] {
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// WaiverStatus
// ---------------------------------------------------------------------------

#[test]
fn enrichment_waiver_status_serde_roundtrip() {
    for s in [
        WaiverStatus::Active,
        WaiverStatus::Expired,
        WaiverStatus::Revoked,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: WaiverStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ---------------------------------------------------------------------------
// evaluate_gate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_gate_clean_pass() {
    let cfg = GateConfig::default_config();
    let scans = vec![make_scan(Subsystem::Parser, vec![])];
    let report = evaluate_gate(&scans, &[], &cfg, &epoch(), 1000).unwrap();
    assert!(report.is_pass());
    assert_eq!(report.total_placeholders(), 0);
}

#[test]
fn enrichment_evaluate_gate_blocking_placeholder_blocks() {
    let cfg = GateConfig::default_config();
    let entries = vec![make_placeholder(
        Subsystem::Runtime,
        PlaceholderKind::StubReturn,
        PlaceholderSeverity::Blocking,
    )];
    let scans = vec![make_scan(Subsystem::Runtime, entries)];
    let report = evaluate_gate(&scans, &[], &cfg, &epoch(), 1000).unwrap();
    assert!(report.is_block());
    assert!(report.blocked_count() > 0);
}

#[test]
fn enrichment_evaluate_gate_high_warns() {
    let cfg = GateConfig::default_config();
    let entries = vec![make_placeholder(
        Subsystem::Lowering,
        PlaceholderKind::TodoMacro,
        PlaceholderSeverity::High,
    )];
    let scans = vec![make_scan(Subsystem::Lowering, entries)];
    let report = evaluate_gate(&scans, &[], &cfg, &epoch(), 1000).unwrap();
    assert!(!report.is_block());
    assert!(report.warned_count() > 0);
}

// ---------------------------------------------------------------------------
// validate_waiver
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_waiver_active() {
    let waiver = Waiver {
        waiver_id: "w1".to_string(),
        placeholder_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
        subsystem: Subsystem::Parser,
        justification: "needed for now".to_string(),
        owner: "team-a".to_string(),
        expires_epoch: 100,
        status: WaiverStatus::Active,
        created_epoch: 1,
    };
    assert_eq!(validate_waiver(&waiver, 50), WaiverStatus::Active);
}

#[test]
fn enrichment_validate_waiver_expired() {
    let waiver = Waiver {
        waiver_id: "w2".to_string(),
        placeholder_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
        subsystem: Subsystem::Runtime,
        justification: "reason".to_string(),
        owner: "owner".to_string(),
        expires_epoch: 10,
        status: WaiverStatus::Active,
        created_epoch: 1,
    };
    assert_eq!(validate_waiver(&waiver, 50), WaiverStatus::Expired);
}

// ---------------------------------------------------------------------------
// GateAction
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_action_as_str_unique() {
    let mut strs = std::collections::BTreeSet::new();
    for a in [GateAction::Block, GateAction::Warn, GateAction::Allow] {
        assert!(strs.insert(a.as_str()));
    }
}

// ---------------------------------------------------------------------------
// summarize_report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summarize_report_non_empty() {
    let cfg = GateConfig::default_config();
    let scans = vec![make_scan(Subsystem::Parser, vec![])];
    let report = evaluate_gate(&scans, &[], &cfg, &epoch(), 1000).unwrap();
    let summary = summarize_report(&report);
    assert!(!summary.is_empty());
}
