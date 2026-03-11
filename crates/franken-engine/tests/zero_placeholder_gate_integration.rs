//! Integration tests for `zero_placeholder_gate` module.
//!
//! Validates public API, serde contracts, determinism, gate evaluation logic,
//! waiver mechanics, summarization, error handling, and receipt auditing.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeMap;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::zero_placeholder_gate::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn blocking_entry(sub: Subsystem) -> PlaceholderEntry {
    PlaceholderEntry::new(
        sub,
        PlaceholderKind::UnimplementedPanic,
        "src/lib.rs",
        42,
        "unimplemented!() in hot path",
        PlaceholderSeverity::Blocking,
    )
}

fn high_entry(sub: Subsystem) -> PlaceholderEntry {
    PlaceholderEntry::new(
        sub,
        PlaceholderKind::TodoMacro,
        "src/parser.rs",
        100,
        "todo!() in error recovery",
        PlaceholderSeverity::High,
    )
}

fn medium_entry(sub: Subsystem) -> PlaceholderEntry {
    PlaceholderEntry::new(
        sub,
        PlaceholderKind::StubReturn,
        "src/lowering.rs",
        200,
        "stub return value",
        PlaceholderSeverity::Medium,
    )
}

fn low_entry(sub: Subsystem) -> PlaceholderEntry {
    PlaceholderEntry::new(
        sub,
        PlaceholderKind::HardcodedFallback,
        "src/runtime.rs",
        300,
        "hardcoded fallback",
        PlaceholderSeverity::Low,
    )
}

fn empty_handler_entry(sub: Subsystem) -> PlaceholderEntry {
    PlaceholderEntry::new(
        sub,
        PlaceholderKind::EmptyHandler,
        "src/mod_loader.rs",
        50,
        "empty catch handler",
        PlaceholderSeverity::High,
    )
}

fn unsupported_entry(sub: Subsystem) -> PlaceholderEntry {
    PlaceholderEntry::new(
        sub,
        PlaceholderKind::UnsupportedError,
        "src/optimizer.rs",
        75,
        "unsupported error fallback",
        PlaceholderSeverity::Medium,
    )
}

fn make_waiver(entry: &PlaceholderEntry, sub: Subsystem) -> Waiver {
    Waiver {
        waiver_id: format!("waiver-{}-{}", sub.as_str(), entry.location_line),
        placeholder_hash: entry.content_hash.clone(),
        subsystem: sub,
        justification: "deferred to next sprint".to_string(),
        owner: "team-alpha".to_string(),
        expires_epoch: 200,
        status: WaiverStatus::Active,
        created_epoch: 50,
    }
}

fn clean_scan(sub: Subsystem) -> ScanResult {
    ScanResult::new(sub, Vec::new(), epoch(100))
}

fn scan_with(sub: Subsystem, entries: Vec<PlaceholderEntry>) -> ScanResult {
    ScanResult::new(sub, entries, epoch(100))
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn schema_version_prefix() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("zero-placeholder-gate"));
}

#[test]
fn component_name_matches() {
    assert_eq!(COMPONENT, "zero_placeholder_gate");
}

#[test]
fn bead_id_starts_with_bd() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn policy_id_starts_with_rgc() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn millionths_constant() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

#[test]
fn default_max_active_waivers_positive() {
    assert!(DEFAULT_MAX_ACTIVE_WAIVERS > 0);
}

#[test]
fn default_waiver_max_duration_positive() {
    assert!(DEFAULT_WAIVER_MAX_DURATION_EPOCHS > 0);
}

// ===========================================================================
// Subsystem
// ===========================================================================

#[test]
fn subsystem_all_has_eight() {
    assert_eq!(Subsystem::ALL.len(), 8);
}

#[test]
fn subsystem_names_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for s in Subsystem::ALL {
        assert!(seen.insert(s.as_str()), "duplicate: {}", s.as_str());
    }
}

#[test]
fn subsystem_display_matches_as_str() {
    for s in Subsystem::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn subsystem_serde_json_roundtrip() {
    for s in Subsystem::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: Subsystem = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn subsystem_copy_semantics() {
    let a = Subsystem::Parser;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn subsystem_ord() {
    assert!(Subsystem::Parser < Subsystem::Cli);
}

// ===========================================================================
// PlaceholderKind
// ===========================================================================

#[test]
fn kind_all_has_six() {
    assert_eq!(PlaceholderKind::ALL.len(), 6);
}

#[test]
fn kind_names_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for k in PlaceholderKind::ALL {
        assert!(seen.insert(k.as_str()));
    }
}

#[test]
fn kind_display_matches_as_str() {
    for k in PlaceholderKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn kind_serde_json_roundtrip() {
    for k in PlaceholderKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: PlaceholderKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ===========================================================================
// PlaceholderSeverity
// ===========================================================================

#[test]
fn severity_all_has_four() {
    assert_eq!(PlaceholderSeverity::ALL.len(), 4);
}

#[test]
fn severity_ordering_blocking_is_lowest() {
    assert!(PlaceholderSeverity::Blocking < PlaceholderSeverity::High);
    assert!(PlaceholderSeverity::High < PlaceholderSeverity::Medium);
    assert!(PlaceholderSeverity::Medium < PlaceholderSeverity::Low);
}

#[test]
fn severity_display_matches_as_str() {
    for s in PlaceholderSeverity::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn severity_serde_json_roundtrip() {
    for s in PlaceholderSeverity::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: PlaceholderSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ===========================================================================
// PlaceholderEntry
// ===========================================================================

#[test]
fn entry_hash_deterministic() {
    let e1 = blocking_entry(Subsystem::Parser);
    let e2 = blocking_entry(Subsystem::Parser);
    assert_eq!(e1.content_hash, e2.content_hash);
}

#[test]
fn entry_different_subsystem_different_hash() {
    let e1 = blocking_entry(Subsystem::Parser);
    let e2 = blocking_entry(Subsystem::Lowering);
    assert_ne!(e1.content_hash, e2.content_hash);
}

#[test]
fn entry_different_kind_different_hash() {
    let a = PlaceholderEntry::new(
        Subsystem::Parser,
        PlaceholderKind::TodoMacro,
        "f.rs",
        1,
        "d",
        PlaceholderSeverity::High,
    );
    let b = PlaceholderEntry::new(
        Subsystem::Parser,
        PlaceholderKind::StubReturn,
        "f.rs",
        1,
        "d",
        PlaceholderSeverity::High,
    );
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn entry_different_line_different_hash() {
    let a = PlaceholderEntry::new(
        Subsystem::Parser,
        PlaceholderKind::TodoMacro,
        "f.rs",
        1,
        "d",
        PlaceholderSeverity::High,
    );
    let b = PlaceholderEntry::new(
        Subsystem::Parser,
        PlaceholderKind::TodoMacro,
        "f.rs",
        2,
        "d",
        PlaceholderSeverity::High,
    );
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn entry_serde_roundtrip() {
    let e = blocking_entry(Subsystem::Interpreter);
    let json = serde_json::to_string(&e).unwrap();
    let back: PlaceholderEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn entry_fields_correct() {
    let e = blocking_entry(Subsystem::Parser);
    assert_eq!(e.subsystem, Subsystem::Parser);
    assert_eq!(e.kind, PlaceholderKind::UnimplementedPanic);
    assert_eq!(e.location_file, "src/lib.rs");
    assert_eq!(e.location_line, 42);
    assert_eq!(e.severity, PlaceholderSeverity::Blocking);
}

// ===========================================================================
// WaiverStatus
// ===========================================================================

#[test]
fn waiver_status_display_active() {
    assert_eq!(WaiverStatus::Active.to_string(), "active");
}

#[test]
fn waiver_status_display_expired() {
    assert_eq!(WaiverStatus::Expired.to_string(), "expired");
}

#[test]
fn waiver_status_display_revoked() {
    assert_eq!(WaiverStatus::Revoked.to_string(), "revoked");
}

#[test]
fn waiver_status_serde_roundtrip() {
    for st in [
        WaiverStatus::Active,
        WaiverStatus::Expired,
        WaiverStatus::Revoked,
    ] {
        let json = serde_json::to_string(&st).unwrap();
        let back: WaiverStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(st, back);
    }
}

// ===========================================================================
// validate_waiver
// ===========================================================================

#[test]
fn validate_waiver_active_within_epoch() {
    let e = blocking_entry(Subsystem::Parser);
    let w = make_waiver(&e, Subsystem::Parser);
    assert_eq!(validate_waiver(&w, 100), WaiverStatus::Active);
}

#[test]
fn validate_waiver_active_at_boundary() {
    let e = blocking_entry(Subsystem::Parser);
    let w = make_waiver(&e, Subsystem::Parser);
    assert_eq!(validate_waiver(&w, 200), WaiverStatus::Active);
}

#[test]
fn validate_waiver_expired_past_boundary() {
    let e = blocking_entry(Subsystem::Parser);
    let w = make_waiver(&e, Subsystem::Parser);
    assert_eq!(validate_waiver(&w, 201), WaiverStatus::Expired);
}

#[test]
fn validate_waiver_revoked_ignores_epoch() {
    let e = blocking_entry(Subsystem::Parser);
    let mut w = make_waiver(&e, Subsystem::Parser);
    w.status = WaiverStatus::Revoked;
    assert_eq!(validate_waiver(&w, 0), WaiverStatus::Revoked);
}

#[test]
fn validate_waiver_already_expired_status() {
    let e = blocking_entry(Subsystem::Parser);
    let mut w = make_waiver(&e, Subsystem::Parser);
    w.status = WaiverStatus::Expired;
    assert_eq!(validate_waiver(&w, 0), WaiverStatus::Expired);
}

// ===========================================================================
// GateAction
// ===========================================================================

#[test]
fn gate_action_display_values() {
    assert_eq!(GateAction::Block.to_string(), "block");
    assert_eq!(GateAction::Warn.to_string(), "warn");
    assert_eq!(GateAction::Allow.to_string(), "allow");
}

#[test]
fn gate_action_serde_roundtrip() {
    for a in [GateAction::Block, GateAction::Warn, GateAction::Allow] {
        let json = serde_json::to_string(&a).unwrap();
        let back: GateAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}

// ===========================================================================
// GateConfig
// ===========================================================================

#[test]
fn config_default_blocking_blocks() {
    let cfg = GateConfig::default_config();
    assert_eq!(
        cfg.action_for(PlaceholderSeverity::Blocking),
        GateAction::Block
    );
}

#[test]
fn config_default_high_warns() {
    let cfg = GateConfig::default_config();
    assert_eq!(cfg.action_for(PlaceholderSeverity::High), GateAction::Warn);
}

#[test]
fn config_default_medium_allows() {
    let cfg = GateConfig::default_config();
    assert_eq!(
        cfg.action_for(PlaceholderSeverity::Medium),
        GateAction::Allow
    );
}

#[test]
fn config_default_low_allows() {
    let cfg = GateConfig::default_config();
    assert_eq!(cfg.action_for(PlaceholderSeverity::Low), GateAction::Allow);
}

#[test]
fn config_strict_all_block() {
    let cfg = GateConfig::strict();
    for sev in PlaceholderSeverity::ALL {
        assert_eq!(cfg.action_for(*sev), GateAction::Block);
    }
}

#[test]
fn config_permissive_all_allow() {
    let cfg = GateConfig::permissive();
    for sev in PlaceholderSeverity::ALL {
        assert_eq!(cfg.action_for(*sev), GateAction::Allow);
    }
}

#[test]
fn config_default_trait_equals_default_config() {
    assert_eq!(GateConfig::default(), GateConfig::default_config());
}

#[test]
fn config_missing_severity_defaults_to_block() {
    let cfg = GateConfig {
        severity_actions: BTreeMap::new(),
        max_active_waivers: 10,
        waiver_max_duration_epochs: 50,
        require_justification: false,
        require_owner: false,
    };
    assert_eq!(
        cfg.action_for(PlaceholderSeverity::Medium),
        GateAction::Block
    );
}

#[test]
fn config_serde_roundtrip() {
    let cfg = GateConfig::default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn config_strict_serde_roundtrip() {
    let cfg = GateConfig::strict();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// ScanResult
// ===========================================================================

#[test]
fn scan_clean_is_clean() {
    let s = clean_scan(Subsystem::Parser);
    assert!(s.is_clean());
    assert_eq!(s.placeholder_count(), 0);
}

#[test]
fn scan_with_entries_not_clean() {
    let s = scan_with(Subsystem::Parser, vec![blocking_entry(Subsystem::Parser)]);
    assert!(!s.is_clean());
    assert_eq!(s.placeholder_count(), 1);
}

#[test]
fn scan_hash_deterministic() {
    let entries = vec![blocking_entry(Subsystem::Parser)];
    let s1 = ScanResult::new(Subsystem::Parser, entries.clone(), epoch(100));
    let s2 = ScanResult::new(Subsystem::Parser, entries, epoch(100));
    assert_eq!(s1.scan_content_hash, s2.scan_content_hash);
}

#[test]
fn scan_different_epoch_different_hash() {
    let entries = vec![blocking_entry(Subsystem::Parser)];
    let s1 = ScanResult::new(Subsystem::Parser, entries.clone(), epoch(100));
    let s2 = ScanResult::new(Subsystem::Parser, entries, epoch(101));
    assert_ne!(s1.scan_content_hash, s2.scan_content_hash);
}

#[test]
fn scan_serde_roundtrip() {
    let s = scan_with(Subsystem::Lowering, vec![medium_entry(Subsystem::Lowering)]);
    let json = serde_json::to_string(&s).unwrap();
    let back: ScanResult = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ===========================================================================
// GateVerdict
// ===========================================================================

#[test]
fn verdict_pass_display() {
    assert_eq!(GateVerdict::Pass.to_string(), "pass");
}

#[test]
fn verdict_warn_display() {
    assert_eq!(GateVerdict::Warn.to_string(), "warn");
}

#[test]
fn verdict_block_display() {
    assert_eq!(GateVerdict::Block.to_string(), "block");
}

#[test]
fn verdict_is_pass_true() {
    assert!(GateVerdict::Pass.is_pass());
}

#[test]
fn verdict_is_pass_false_for_block() {
    assert!(!GateVerdict::Block.is_pass());
}

#[test]
fn verdict_is_block_true() {
    assert!(GateVerdict::Block.is_block());
}

#[test]
fn verdict_is_block_false_for_pass() {
    assert!(!GateVerdict::Pass.is_block());
}

#[test]
fn verdict_serde_roundtrip() {
    for v in [GateVerdict::Pass, GateVerdict::Warn, GateVerdict::Block] {
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ===========================================================================
// DecisionReceipt
// ===========================================================================

#[test]
fn receipt_has_correct_constants() {
    let r = DecisionReceipt::new(
        epoch(10),
        ContentHash::compute(b"i"),
        GateVerdict::Pass,
        500,
    );
    assert_eq!(r.schema_version, SCHEMA_VERSION);
    assert_eq!(r.component, COMPONENT);
    assert_eq!(r.bead_id, BEAD_ID);
    assert_eq!(r.policy_id, POLICY_ID);
}

#[test]
fn receipt_epoch_matches() {
    let r = DecisionReceipt::new(
        epoch(42),
        ContentHash::compute(b"i"),
        GateVerdict::Pass,
        500,
    );
    assert_eq!(r.epoch, epoch(42));
}

#[test]
fn receipt_timestamp_matches() {
    let r = DecisionReceipt::new(
        epoch(1),
        ContentHash::compute(b"i"),
        GateVerdict::Pass,
        12345,
    );
    assert_eq!(r.timestamp_micros, 12345);
}

#[test]
fn receipt_deterministic_hash() {
    let ih = ContentHash::compute(b"x");
    let r1 = DecisionReceipt::new(epoch(1), ih.clone(), GateVerdict::Pass, 100);
    let r2 = DecisionReceipt::new(epoch(1), ih, GateVerdict::Pass, 100);
    assert_eq!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_different_verdict_different_hash() {
    let ih = ContentHash::compute(b"x");
    let r1 = DecisionReceipt::new(epoch(1), ih.clone(), GateVerdict::Pass, 100);
    let r2 = DecisionReceipt::new(epoch(1), ih, GateVerdict::Block, 100);
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_different_epoch_different_hash() {
    let ih = ContentHash::compute(b"x");
    let r1 = DecisionReceipt::new(epoch(1), ih.clone(), GateVerdict::Pass, 100);
    let r2 = DecisionReceipt::new(epoch(2), ih, GateVerdict::Pass, 100);
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_serde_roundtrip() {
    let r = DecisionReceipt::new(epoch(5), ContentHash::compute(b"y"), GateVerdict::Warn, 999);
    let json = serde_json::to_string(&r).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// evaluate_gate — clean paths
// ===========================================================================

#[test]
fn gate_single_clean_scan_passes() {
    let scans = vec![clean_scan(Subsystem::Parser)];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_pass());
    assert_eq!(r.blocked_count(), 0);
    assert_eq!(r.warned_count(), 0);
    assert_eq!(r.waived_count(), 0);
}

#[test]
fn gate_multiple_clean_scans_pass() {
    let scans = vec![
        clean_scan(Subsystem::Parser),
        clean_scan(Subsystem::Lowering),
        clean_scan(Subsystem::Runtime),
    ];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_pass());
    assert_eq!(r.total_placeholders(), 0);
}

// ===========================================================================
// evaluate_gate — blocking paths
// ===========================================================================

#[test]
fn gate_blocking_without_waiver_blocks() {
    let scans = vec![scan_with(
        Subsystem::Parser,
        vec![blocking_entry(Subsystem::Parser)],
    )];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_block());
    assert_eq!(r.blocked_count(), 1);
}

#[test]
fn gate_blocking_with_valid_waiver_passes() {
    let e = blocking_entry(Subsystem::Parser);
    let w = make_waiver(&e, Subsystem::Parser);
    let scans = vec![scan_with(Subsystem::Parser, vec![e])];
    let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_pass());
    assert_eq!(r.waived_count(), 1);
    assert_eq!(r.blocked_count(), 0);
}

#[test]
fn gate_blocking_with_expired_waiver_blocks() {
    let e = blocking_entry(Subsystem::Parser);
    let mut w = make_waiver(&e, Subsystem::Parser);
    w.expires_epoch = 50;
    w.created_epoch = 40;
    let scans = vec![scan_with(Subsystem::Parser, vec![e])];
    let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_block());
    assert_eq!(r.waived_count(), 0);
}

#[test]
fn gate_blocking_with_revoked_waiver_blocks() {
    let e = blocking_entry(Subsystem::Parser);
    let mut w = make_waiver(&e, Subsystem::Parser);
    w.status = WaiverStatus::Revoked;
    let scans = vec![scan_with(Subsystem::Parser, vec![e])];
    let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_block());
}

// ===========================================================================
// evaluate_gate — warning paths
// ===========================================================================

#[test]
fn gate_high_severity_warns() {
    let scans = vec![scan_with(
        Subsystem::Parser,
        vec![high_entry(Subsystem::Parser)],
    )];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert_eq!(r.verdict, GateVerdict::Warn);
    assert_eq!(r.warned_count(), 1);
}

#[test]
fn gate_high_with_waiver_passes() {
    let e = high_entry(Subsystem::Parser);
    let w = make_waiver(&e, Subsystem::Parser);
    let scans = vec![scan_with(Subsystem::Parser, vec![e])];
    let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_pass());
    assert_eq!(r.waived_count(), 1);
}

// ===========================================================================
// evaluate_gate — allow paths
// ===========================================================================

#[test]
fn gate_medium_allowed_by_default() {
    let scans = vec![scan_with(
        Subsystem::Runtime,
        vec![medium_entry(Subsystem::Runtime)],
    )];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_pass());
}

#[test]
fn gate_low_allowed_by_default() {
    let scans = vec![scan_with(Subsystem::Cli, vec![low_entry(Subsystem::Cli)])];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_pass());
}

// ===========================================================================
// evaluate_gate — mixed severities
// ===========================================================================

#[test]
fn gate_block_dominates_warn() {
    let scans = vec![scan_with(
        Subsystem::Parser,
        vec![
            blocking_entry(Subsystem::Parser),
            high_entry(Subsystem::Parser),
        ],
    )];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_block());
    assert_eq!(r.blocked_count(), 1);
    assert_eq!(r.warned_count(), 1);
}

#[test]
fn gate_all_severities_mixed() {
    let scans = vec![scan_with(
        Subsystem::Parser,
        vec![
            blocking_entry(Subsystem::Parser),
            high_entry(Subsystem::Parser),
            medium_entry(Subsystem::Parser),
            low_entry(Subsystem::Parser),
        ],
    )];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_block());
    assert_eq!(r.total_placeholders(), 4);
    assert_eq!(r.blocked_count(), 1);
    assert_eq!(r.warned_count(), 1);
}

#[test]
fn gate_waiver_only_covers_matching_hash() {
    let e1 = blocking_entry(Subsystem::Parser);
    let e2 = PlaceholderEntry::new(
        Subsystem::Parser,
        PlaceholderKind::UnimplementedPanic,
        "src/other.rs",
        99,
        "different spot",
        PlaceholderSeverity::Blocking,
    );
    let w = make_waiver(&e1, Subsystem::Parser);
    let scans = vec![scan_with(Subsystem::Parser, vec![e1, e2])];
    let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_block());
    assert_eq!(r.waived_count(), 1);
    assert_eq!(r.blocked_count(), 1);
}

// ===========================================================================
// evaluate_gate — multiple subsystems
// ===========================================================================

#[test]
fn gate_multi_subsystem_all_clean() {
    let scans = vec![
        clean_scan(Subsystem::Parser),
        clean_scan(Subsystem::Lowering),
        clean_scan(Subsystem::Interpreter),
        clean_scan(Subsystem::Runtime),
    ];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_pass());
}

#[test]
fn gate_multi_subsystem_one_blocked() {
    let scans = vec![
        clean_scan(Subsystem::Parser),
        scan_with(
            Subsystem::Lowering,
            vec![blocking_entry(Subsystem::Lowering)],
        ),
        clean_scan(Subsystem::Runtime),
    ];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_block());
}

#[test]
fn gate_multi_subsystem_waiver_crosses_subsystem() {
    let b = blocking_entry(Subsystem::Parser);
    let h = high_entry(Subsystem::Lowering);
    let w = make_waiver(&b, Subsystem::Parser);
    let scans = vec![
        scan_with(Subsystem::Parser, vec![b]),
        scan_with(Subsystem::Lowering, vec![h]),
    ];
    let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert_eq!(r.verdict, GateVerdict::Warn);
    assert_eq!(r.waived_count(), 1);
    assert_eq!(r.warned_count(), 1);
}

// ===========================================================================
// evaluate_gate — strict/permissive configs
// ===========================================================================

#[test]
fn gate_strict_blocks_low() {
    let scans = vec![scan_with(Subsystem::Cli, vec![low_entry(Subsystem::Cli)])];
    let r = evaluate_gate(&scans, &[], &GateConfig::strict(), &epoch(100), 1).unwrap();
    assert!(r.is_block());
}

#[test]
fn gate_strict_blocks_medium() {
    let scans = vec![scan_with(
        Subsystem::Optimizer,
        vec![medium_entry(Subsystem::Optimizer)],
    )];
    let r = evaluate_gate(&scans, &[], &GateConfig::strict(), &epoch(100), 1).unwrap();
    assert!(r.is_block());
}

#[test]
fn gate_permissive_allows_blocking() {
    let scans = vec![scan_with(
        Subsystem::Parser,
        vec![blocking_entry(Subsystem::Parser)],
    )];
    let r = evaluate_gate(&scans, &[], &GateConfig::permissive(), &epoch(100), 1).unwrap();
    assert!(r.is_pass());
}

// ===========================================================================
// evaluate_gate — errors
// ===========================================================================

#[test]
fn gate_empty_scans_error() {
    let r = evaluate_gate(&[], &[], &GateConfig::default(), &epoch(100), 1);
    assert!(matches!(r, Err(GateError::EmptyScans)));
}

#[test]
fn gate_duplicate_subsystem_error() {
    let scans = vec![clean_scan(Subsystem::Parser), clean_scan(Subsystem::Parser)];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1);
    assert!(matches!(r, Err(GateError::DuplicateSubsystem { .. })));
}

#[test]
fn gate_too_many_waivers_error() {
    let mut cfg = GateConfig::default();
    cfg.max_active_waivers = 0;
    let e = blocking_entry(Subsystem::Parser);
    let w = make_waiver(&e, Subsystem::Parser);
    let scans = vec![scan_with(Subsystem::Parser, vec![e])];
    let r = evaluate_gate(&scans, &[w], &cfg, &epoch(100), 1);
    assert!(matches!(r, Err(GateError::TooManyWaivers { .. })));
}

#[test]
fn gate_missing_justification_error() {
    let e = blocking_entry(Subsystem::Parser);
    let mut w = make_waiver(&e, Subsystem::Parser);
    w.justification = String::new();
    let scans = vec![scan_with(Subsystem::Parser, vec![e])];
    let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &epoch(100), 1);
    assert!(matches!(r, Err(GateError::MissingJustification { .. })));
}

#[test]
fn gate_missing_owner_error() {
    let e = blocking_entry(Subsystem::Parser);
    let mut w = make_waiver(&e, Subsystem::Parser);
    w.owner = String::new();
    let scans = vec![scan_with(Subsystem::Parser, vec![e])];
    let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &epoch(100), 1);
    assert!(matches!(r, Err(GateError::MissingOwner { .. })));
}

#[test]
fn gate_waiver_duration_exceeded_error() {
    let mut cfg = GateConfig::default();
    cfg.waiver_max_duration_epochs = 10;
    let e = blocking_entry(Subsystem::Parser);
    let w = make_waiver(&e, Subsystem::Parser); // duration = 200 - 50 = 150
    let scans = vec![scan_with(Subsystem::Parser, vec![e])];
    let r = evaluate_gate(&scans, &[w], &cfg, &epoch(100), 1);
    assert!(matches!(r, Err(GateError::WaiverDurationExceeded { .. })));
}

// ===========================================================================
// GateError display
// ===========================================================================

#[test]
fn error_display_too_many_waivers() {
    let e = GateError::TooManyWaivers {
        active: 5,
        limit: 3,
    };
    let msg = e.to_string();
    assert!(msg.contains("5"));
    assert!(msg.contains("3"));
}

#[test]
fn error_display_missing_justification() {
    let e = GateError::MissingJustification {
        waiver_id: "w-1".into(),
    };
    assert!(e.to_string().contains("w-1"));
}

#[test]
fn error_display_missing_owner() {
    let e = GateError::MissingOwner {
        waiver_id: "w-2".into(),
    };
    assert!(e.to_string().contains("w-2"));
}

#[test]
fn error_display_duration_exceeded() {
    let e = GateError::WaiverDurationExceeded {
        waiver_id: "w-3".into(),
        duration: 500,
        max_duration: 100,
    };
    let msg = e.to_string();
    assert!(msg.contains("500"));
    assert!(msg.contains("100"));
}

#[test]
fn error_display_empty_scans() {
    assert!(
        GateError::EmptyScans
            .to_string()
            .contains("no scan results")
    );
}

#[test]
fn error_display_duplicate_subsystem() {
    let e = GateError::DuplicateSubsystem {
        subsystem: "parser".into(),
    };
    assert!(e.to_string().contains("parser"));
}

#[test]
fn error_serde_roundtrip() {
    let e = GateError::EmptyScans;
    let json = serde_json::to_string(&e).unwrap();
    let back: GateError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ===========================================================================
// GateReport
// ===========================================================================

#[test]
fn report_total_placeholders_across_scans() {
    let scans = vec![
        scan_with(Subsystem::Parser, vec![blocking_entry(Subsystem::Parser)]),
        scan_with(
            Subsystem::Lowering,
            vec![
                high_entry(Subsystem::Lowering),
                medium_entry(Subsystem::Lowering),
            ],
        ),
    ];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert_eq!(r.total_placeholders(), 3);
}

#[test]
fn report_receipt_epoch() {
    let scans = vec![clean_scan(Subsystem::Parser)];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(42), 999).unwrap();
    assert_eq!(r.receipt.epoch, epoch(42));
    assert_eq!(r.receipt.timestamp_micros, 999);
}

#[test]
fn report_serde_roundtrip() {
    let e = blocking_entry(Subsystem::Parser);
    let w = make_waiver(&e, Subsystem::Parser);
    let scans = vec![scan_with(Subsystem::Parser, vec![e])];
    let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &epoch(100), 1).unwrap();
    let json = serde_json::to_string(&r).unwrap();
    let back: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// summarize_report
// ===========================================================================

#[test]
fn summarize_contains_verdict_pass() {
    let scans = vec![clean_scan(Subsystem::Parser)];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(summarize_report(&r).contains("pass"));
}

#[test]
fn summarize_contains_verdict_block() {
    let scans = vec![scan_with(
        Subsystem::Parser,
        vec![blocking_entry(Subsystem::Parser)],
    )];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    let s = summarize_report(&r);
    assert!(s.contains("block"));
    assert!(s.contains("blocked entries:"));
}

#[test]
fn summarize_blocked_entry_details() {
    let scans = vec![scan_with(
        Subsystem::Parser,
        vec![blocking_entry(Subsystem::Parser)],
    )];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    let s = summarize_report(&r);
    assert!(s.contains("src/lib.rs:42"));
    assert!(s.contains("parser"));
}

#[test]
fn summarize_warned_entry_section() {
    let scans = vec![scan_with(
        Subsystem::Parser,
        vec![high_entry(Subsystem::Parser)],
    )];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    let s = summarize_report(&r);
    assert!(s.contains("warned entries:"));
}

#[test]
fn summarize_waived_entry_section() {
    let e = blocking_entry(Subsystem::Parser);
    let w = make_waiver(&e, Subsystem::Parser);
    let scans = vec![scan_with(Subsystem::Parser, vec![e])];
    let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &epoch(100), 1).unwrap();
    let s = summarize_report(&r);
    assert!(s.contains("waived entries:"));
}

#[test]
fn summarize_receipt_epoch() {
    let scans = vec![clean_scan(Subsystem::Parser)];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(77), 1).unwrap();
    let s = summarize_report(&r);
    assert!(s.contains("epoch:77"));
}

// ===========================================================================
// Waiver serde
// ===========================================================================

#[test]
fn waiver_serde_roundtrip() {
    let e = blocking_entry(Subsystem::Interpreter);
    let w = make_waiver(&e, Subsystem::Interpreter);
    let json = serde_json::to_string(&w).unwrap();
    let back: Waiver = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

// ===========================================================================
// All PlaceholderKind variants in entries
// ===========================================================================

#[test]
fn all_placeholder_kinds_produce_unique_hashes() {
    let hashes: std::collections::BTreeSet<_> = PlaceholderKind::ALL
        .iter()
        .map(|k| {
            PlaceholderEntry::new(
                Subsystem::Parser,
                *k,
                "f.rs",
                1,
                "d",
                PlaceholderSeverity::High,
            )
            .content_hash
        })
        .collect();
    assert_eq!(hashes.len(), PlaceholderKind::ALL.len());
}

// ===========================================================================
// Edge cases
// ===========================================================================

#[test]
fn gate_with_all_subsystems_clean() {
    let scans: Vec<ScanResult> = Subsystem::ALL.iter().map(|s| clean_scan(*s)).collect();
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_pass());
}

#[test]
fn gate_permissive_no_justification_no_owner_ok() {
    let e = blocking_entry(Subsystem::Parser);
    let mut w = make_waiver(&e, Subsystem::Parser);
    w.justification = String::new();
    w.owner = String::new();
    let scans = vec![scan_with(Subsystem::Parser, vec![e])];
    let cfg = GateConfig::permissive();
    let r = evaluate_gate(&scans, &[w], &cfg, &epoch(100), 1).unwrap();
    assert!(r.is_pass());
}

#[test]
fn gate_empty_handler_high_warns() {
    let scans = vec![scan_with(
        Subsystem::ModuleLoader,
        vec![empty_handler_entry(Subsystem::ModuleLoader)],
    )];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert_eq!(r.verdict, GateVerdict::Warn);
}

#[test]
fn gate_unsupported_error_medium_passes() {
    let scans = vec![scan_with(
        Subsystem::Optimizer,
        vec![unsupported_entry(Subsystem::Optimizer)],
    )];
    let r = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_pass());
}

#[test]
fn gate_report_deterministic_receipt() {
    let scans = vec![scan_with(
        Subsystem::Parser,
        vec![blocking_entry(Subsystem::Parser)],
    )];
    let r1 = evaluate_gate(&scans, &[], &GateConfig::default(), &epoch(100), 500).unwrap();
    let scans2 = vec![scan_with(
        Subsystem::Parser,
        vec![blocking_entry(Subsystem::Parser)],
    )];
    let r2 = evaluate_gate(&scans2, &[], &GateConfig::default(), &epoch(100), 500).unwrap();
    assert_eq!(r1.receipt.verdict_hash, r2.receipt.verdict_hash);
}

#[test]
fn gate_multiple_waivers_for_multiple_entries() {
    let e1 = blocking_entry(Subsystem::Parser);
    let e2 = high_entry(Subsystem::Parser);
    let w1 = make_waiver(&e1, Subsystem::Parser);
    let w2 = make_waiver(&e2, Subsystem::Parser);
    let scans = vec![scan_with(Subsystem::Parser, vec![e1, e2])];
    let r = evaluate_gate(&scans, &[w1, w2], &GateConfig::default(), &epoch(100), 1).unwrap();
    assert!(r.is_pass());
    assert_eq!(r.waived_count(), 2);
}

#[test]
fn gate_expired_waivers_not_counted_toward_limit() {
    let mut cfg = GateConfig::default();
    cfg.max_active_waivers = 1;
    let e1 = blocking_entry(Subsystem::Parser);
    let e2 = high_entry(Subsystem::Parser);
    let w1 = make_waiver(&e1, Subsystem::Parser);
    let mut w2 = make_waiver(&e2, Subsystem::Parser);
    w2.expires_epoch = 50; // expired
    w2.created_epoch = 40;
    let scans = vec![scan_with(Subsystem::Parser, vec![e1, e2])];
    // Only w1 is active, which is within the limit of 1.
    let r = evaluate_gate(&scans, &[w1, w2], &cfg, &epoch(100), 1).unwrap();
    assert_eq!(r.verdict, GateVerdict::Warn); // e2 not waived -> high -> warn
    assert_eq!(r.waived_count(), 1);
}
