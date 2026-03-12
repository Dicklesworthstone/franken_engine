//! Enrichment integration tests for universal_dominance_ratchet module.
//!
//! Targets gaps: component-level serde (RatchetCell, FrontierGapEntry,
//! GapState, DomainProvenCount, TargetProvenCount), enum ordering consistency,
//! display uniqueness, skip-level advances, margin behavior on non-proven cells,
//! schema version distinctness, render summary edge cases, epoch interleaving.

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

use std::collections::BTreeSet;

use frankenengine_engine::universal_dominance_ratchet::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cell_id(domain: CellDomain, target: ComparisonTarget, dim: &str) -> CellId {
    CellId {
        domain,
        target,
        dimension: dim.to_string(),
    }
}

fn unproven_cell(domain: CellDomain, target: ComparisonTarget, dim: &str) -> RatchetCell {
    RatchetCell {
        cell_id: cell_id(domain, target, dim),
        state: CellState::Unproven,
        margin_millionths: 0,
        evidence_ids: Vec::new(),
        last_advanced_epoch: 0,
        owning_bead: "enrichment-test".to_string(),
    }
}

fn gap_entry(gap_id: &str, domain: CellDomain, kind: GapKind, priority: u32) -> FrontierGapEntry {
    FrontierGapEntry {
        gap_id: gap_id.to_string(),
        kind,
        state: GapState::Open,
        domain,
        target: None,
        description: format!("Enrichment test gap: {gap_id}"),
        registered_epoch: 0,
        closed_epoch: None,
        resolution: None,
        discovery_source: "enrichment-test".to_string(),
        priority_millionths: priority,
    }
}

// ===========================================================================
// RatchetCell serde
// ===========================================================================

#[test]
fn ratchet_cell_serde_roundtrip() {
    let cell = RatchetCell {
        cell_id: cell_id(CellDomain::ReactPerformance, ComparisonTarget::Jsc, "ssr"),
        state: CellState::Claimed,
        margin_millionths: 350_000,
        evidence_ids: vec!["ev-1".to_string(), "ev-2".to_string()],
        last_advanced_epoch: 7,
        owning_bead: "bd-test".to_string(),
    };
    let json = serde_json::to_string(&cell).unwrap();
    let back: RatchetCell = serde_json::from_str(&json).unwrap();
    assert_eq!(cell, back);
}

#[test]
fn ratchet_cell_serde_proven_with_high_margin() {
    let cell = RatchetCell {
        cell_id: cell_id(CellDomain::ExtensionIsolation, ComparisonTarget::Bun, "iso"),
        state: CellState::Proven,
        margin_millionths: 999_999,
        evidence_ids: vec!["proof-1".to_string()],
        last_advanced_epoch: 42,
        owning_bead: "bd-proven".to_string(),
    };
    let json = serde_json::to_string(&cell).unwrap();
    let back: RatchetCell = serde_json::from_str(&json).unwrap();
    assert_eq!(cell, back);
}

// ===========================================================================
// FrontierGapEntry serde
// ===========================================================================

#[test]
fn frontier_gap_entry_serde_open() {
    let entry = FrontierGapEntry {
        gap_id: "gap-serde-open".to_string(),
        kind: GapKind::PartiallyExplored,
        state: GapState::Open,
        domain: CellDomain::TypeScriptCompilation,
        target: Some(ComparisonTarget::Deno),
        description: "Test open gap".to_string(),
        registered_epoch: 3,
        closed_epoch: None,
        resolution: None,
        discovery_source: "test".to_string(),
        priority_millionths: 700_000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: FrontierGapEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn frontier_gap_entry_serde_closed() {
    let entry = FrontierGapEntry {
        gap_id: "gap-serde-closed".to_string(),
        kind: GapKind::KnownDeficient,
        state: GapState::Closed,
        domain: CellDomain::SecurityOverhead,
        target: None,
        description: "Closed gap".to_string(),
        registered_epoch: 1,
        closed_epoch: Some(5),
        resolution: Some(GapResolution::SubsumedByOther),
        discovery_source: "test".to_string(),
        priority_millionths: 200_000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: FrontierGapEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// GapState serde and display
// ===========================================================================

#[test]
fn gap_state_serde_all_variants() {
    for state in [GapState::Open, GapState::Closed] {
        let json = serde_json::to_string(&state).unwrap();
        let back: GapState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}

#[test]
fn gap_state_display_unique() {
    let displays: BTreeSet<String> = [GapState::Open, GapState::Closed]
        .iter()
        .map(|s| format!("{s}"))
        .collect();
    assert_eq!(displays.len(), 2);
}

// ===========================================================================
// DomainProvenCount / TargetProvenCount serde
// ===========================================================================

#[test]
fn domain_proven_count_serde_roundtrip() {
    let dpc = DomainProvenCount {
        domain: CellDomain::ReplayFidelity,
        proven: 3,
        total: 5,
    };
    let json = serde_json::to_string(&dpc).unwrap();
    let back: DomainProvenCount = serde_json::from_str(&json).unwrap();
    assert_eq!(dpc, back);
}

#[test]
fn target_proven_count_serde_roundtrip() {
    let tpc = TargetProvenCount {
        target: ComparisonTarget::Jsc,
        proven: 2,
        total: 4,
    };
    let json = serde_json::to_string(&tpc).unwrap();
    let back: TargetProvenCount = serde_json::from_str(&json).unwrap();
    assert_eq!(tpc, back);
}

// ===========================================================================
// Display uniqueness for all enum types
// ===========================================================================

#[test]
fn cell_domain_display_all_unique() {
    let domains = [
        CellDomain::ColdStart,
        CellDomain::Throughput,
        CellDomain::TailLatency,
        CellDomain::Memory,
        CellDomain::ReactPerformance,
        CellDomain::ModuleLoading,
        CellDomain::TypeScriptCompilation,
        CellDomain::SecurityOverhead,
        CellDomain::ReplayFidelity,
        CellDomain::ExtensionIsolation,
    ];
    let displays: BTreeSet<String> = domains.iter().map(|d| format!("{d}")).collect();
    assert_eq!(displays.len(), domains.len());
}

#[test]
fn comparison_target_display_all_unique() {
    let targets = [
        ComparisonTarget::V8Node,
        ComparisonTarget::Bun,
        ComparisonTarget::Deno,
        ComparisonTarget::Jsc,
    ];
    let displays: BTreeSet<String> = targets.iter().map(|t| format!("{t}")).collect();
    assert_eq!(displays.len(), targets.len());
}

#[test]
fn cell_state_display_all_unique() {
    let states = [CellState::Unproven, CellState::Claimed, CellState::Proven];
    let displays: BTreeSet<String> = states.iter().map(|s| format!("{s}")).collect();
    assert_eq!(displays.len(), states.len());
}

#[test]
fn gap_kind_display_all_unique() {
    let kinds = [
        GapKind::Unknown,
        GapKind::PartiallyExplored,
        GapKind::KnownDeficient,
        GapKind::OutOfScope,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| format!("{k}")).collect();
    assert_eq!(displays.len(), kinds.len());
}

#[test]
fn gap_resolution_display_all_unique() {
    let resolutions = [
        GapResolution::ProvenOnBoard,
        GapResolution::DeclaredOutOfScope,
        GapResolution::SubsumedByOther,
        GapResolution::DimensionInvalidated,
    ];
    let displays: BTreeSet<String> = resolutions.iter().map(|r| format!("{r}")).collect();
    assert_eq!(displays.len(), resolutions.len());
}

// ===========================================================================
// Ordering consistency
// ===========================================================================

#[test]
fn cell_domain_ordering_consistent() {
    let mut domains = vec![
        CellDomain::Memory,
        CellDomain::ColdStart,
        CellDomain::Throughput,
        CellDomain::ExtensionIsolation,
    ];
    domains.sort();
    let mut domains2 = domains.clone();
    domains2.sort();
    assert_eq!(domains, domains2);
}

#[test]
fn comparison_target_ordering_consistent() {
    let mut targets = vec![
        ComparisonTarget::Jsc,
        ComparisonTarget::V8Node,
        ComparisonTarget::Bun,
        ComparisonTarget::Deno,
    ];
    targets.sort();
    let mut targets2 = targets.clone();
    targets2.sort();
    assert_eq!(targets, targets2);
}

#[test]
fn cell_state_ordering_matches_rank() {
    assert!(CellState::Unproven < CellState::Claimed);
    assert!(CellState::Claimed < CellState::Proven);
    assert!(CellState::Unproven < CellState::Proven);
}

#[test]
fn gap_kind_ordering_consistent() {
    let mut kinds = vec![
        GapKind::OutOfScope,
        GapKind::Unknown,
        GapKind::KnownDeficient,
        GapKind::PartiallyExplored,
    ];
    kinds.sort();
    let mut kinds2 = kinds.clone();
    kinds2.sort();
    assert_eq!(kinds, kinds2);
}

// ===========================================================================
// Schema version constants distinctness
// ===========================================================================

#[test]
fn schema_versions_are_all_distinct() {
    let versions = vec![
        UNIVERSAL_DOMINANCE_RATCHET_SCHEMA_VERSION,
        RATCHET_BOARD_SCHEMA_VERSION,
        FRONTIER_GAP_LEDGER_SCHEMA_VERSION,
        RATCHET_EVENT_LOG_SCHEMA_VERSION,
        DOMINANCE_SNAPSHOT_SCHEMA_VERSION,
    ];
    let unique: BTreeSet<&str> = versions.iter().copied().collect();
    assert_eq!(unique.len(), versions.len());
}

#[test]
fn schema_versions_contain_module_prefix() {
    assert!(UNIVERSAL_DOMINANCE_RATCHET_SCHEMA_VERSION.contains("franken-engine"));
    assert!(RATCHET_BOARD_SCHEMA_VERSION.contains("franken-engine"));
    assert!(FRONTIER_GAP_LEDGER_SCHEMA_VERSION.contains("franken-engine"));
    assert!(RATCHET_EVENT_LOG_SCHEMA_VERSION.contains("franken-engine"));
    assert!(DOMINANCE_SNAPSHOT_SCHEMA_VERSION.contains("franken-engine"));
}

#[test]
fn bead_id_matches_expected() {
    assert_eq!(UNIVERSAL_DOMINANCE_RATCHET_BEAD_ID, "bd-1lsy.1.6.4");
}

// ===========================================================================
// Skip-level advance (Unproven -> Proven directly)
// ===========================================================================

#[test]
fn skip_level_advance_unproven_to_proven() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    let cell = unproven_cell(CellDomain::ModuleLoading, ComparisonTarget::Deno, "skip");
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();

    // Directly advance from Unproven to Proven
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        800_000,
        vec!["direct-proof".to_string()],
    )
    .unwrap();

    let found = board.find_cell(&cid).unwrap();
    assert_eq!(found.state, CellState::Proven);
    assert_eq!(found.margin_millionths, 800_000);
}

// ===========================================================================
// Margin behavior on non-proven cells
// ===========================================================================

#[test]
fn margin_decrease_allowed_on_claimed_cell() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    let cell = unproven_cell(
        CellDomain::TailLatency,
        ComparisonTarget::Bun,
        "margin-claim",
    );
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();

    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Claimed,
        500_000,
        vec!["ev-1".to_string()],
    )
    .unwrap();

    // Margin decrease on Claimed should be allowed (only Proven protects margin)
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Claimed,
        300_000,
        vec!["ev-2".to_string()],
    )
    .unwrap();

    assert_eq!(board.find_cell(&cid).unwrap().margin_millionths, 300_000);
}

#[test]
fn same_state_same_margin_on_proven_is_ok() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    let cell = unproven_cell(CellDomain::Memory, ComparisonTarget::V8Node, "same-same");
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();

    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        100_000,
        vec!["ev-1".to_string()],
    )
    .unwrap();

    // Same state + same margin = no regression
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        100_000,
        vec!["ev-2".to_string()],
    )
    .unwrap();

    let found = board.find_cell(&cid).unwrap();
    assert_eq!(found.evidence_ids.len(), 2);
}

// ===========================================================================
// CellId display format
// ===========================================================================

#[test]
fn cell_id_display_format() {
    let id = cell_id(
        CellDomain::SecurityOverhead,
        ComparisonTarget::Jsc,
        "aes-256",
    );
    let display = format!("{id}");
    assert_eq!(display, "security_overhead::jsc::aes-256");
}

#[test]
fn cell_id_ordering_by_domain_then_target() {
    let a = cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "a");
    let b = cell_id(CellDomain::Throughput, ComparisonTarget::V8Node, "a");
    assert!(a < b);
}

// ===========================================================================
// Board find_cell
// ===========================================================================

#[test]
fn find_cell_returns_none_for_missing() {
    let board = RatchetBoard::new();
    let cid = cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "ghost");
    assert!(board.find_cell(&cid).is_none());
}

#[test]
fn find_cell_returns_correct_cell() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    let cell = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "found");
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();

    let found = board.find_cell(&cid).unwrap();
    assert_eq!(found.cell_id, cid);
    assert_eq!(found.state, CellState::Unproven);
}

// ===========================================================================
// Ledger find_gap
// ===========================================================================

#[test]
fn find_gap_returns_none_for_missing() {
    let ledger = FrontierGapLedger::new();
    assert!(ledger.find_gap("nonexistent").is_none());
}

#[test]
fn find_gap_returns_correct_entry() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();

    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("found-gap", CellDomain::Memory, GapKind::Unknown, 500_000),
    )
    .unwrap();

    let found = ledger.find_gap("found-gap").unwrap();
    assert_eq!(found.gap_id, "found-gap");
    assert_eq!(found.state, GapState::Open);
}

// ===========================================================================
// open_gaps_by_priority with closed gaps excluded
// ===========================================================================

#[test]
fn open_gaps_by_priority_excludes_closed() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();

    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("high", CellDomain::ColdStart, GapKind::Unknown, 900_000),
    )
    .unwrap();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("mid", CellDomain::Memory, GapKind::KnownDeficient, 500_000),
    )
    .unwrap();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry(
            "low",
            CellDomain::Throughput,
            GapKind::PartiallyExplored,
            100_000,
        ),
    )
    .unwrap();

    // Close the highest priority gap
    close_gap(
        &mut ledger,
        &mut log,
        "high",
        GapResolution::ProvenOnBoard,
        1,
    )
    .unwrap();

    let sorted = ledger.open_gaps_by_priority();
    assert_eq!(sorted.len(), 2);
    assert_eq!(sorted[0].gap_id, "mid");
    assert_eq!(sorted[1].gap_id, "low");
}

// ===========================================================================
// open_gap_kinds after closing some gaps
// ===========================================================================

#[test]
fn open_gap_kinds_excludes_closed_gaps() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();

    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("a", CellDomain::ColdStart, GapKind::Unknown, 500_000),
    )
    .unwrap();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("b", CellDomain::Memory, GapKind::Unknown, 500_000),
    )
    .unwrap();

    close_gap(
        &mut ledger,
        &mut log,
        "a",
        GapResolution::DeclaredOutOfScope,
        1,
    )
    .unwrap();

    let kinds = ledger.open_gap_kinds();
    assert_eq!(kinds.get(&GapKind::Unknown), Some(&1));
}

// ===========================================================================
// Render summary edge cases
// ===========================================================================

#[test]
fn render_summary_empty_board_no_gaps() {
    let board = RatchetBoard::new();
    let ledger = FrontierGapLedger::new();
    let summary = render_ratchet_summary(&board, &ledger);
    assert!(summary.contains("total_cells: 0"));
    assert!(summary.contains("proven: 0"));
    assert!(summary.contains("open_gaps: 0"));
    assert!(summary.contains("closed_gaps: 0"));
    // Should not contain open_gap_kinds section when no gaps
    assert!(!summary.contains("open_gap_kinds:"));
}

#[test]
fn render_summary_with_proven_and_mixed_gaps() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let mut ledger = FrontierGapLedger::new();

    // Add and prove a cell
    let cell = unproven_cell(CellDomain::Throughput, ComparisonTarget::Bun, "render");
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        500_000,
        vec![],
    )
    .unwrap();

    // Add gaps of different kinds
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("unk", CellDomain::ColdStart, GapKind::Unknown, 500_000),
    )
    .unwrap();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("def", CellDomain::Memory, GapKind::KnownDeficient, 500_000),
    )
    .unwrap();

    advance_epoch(&mut board, &mut log, 1).unwrap();

    let summary = render_ratchet_summary(&board, &ledger);
    assert!(summary.contains("total_cells: 1"));
    assert!(summary.contains("proven: 1"));
    assert!(summary.contains("open_gaps: 2"));
    assert!(summary.contains("open_gap_kinds:"));
}

// ===========================================================================
// DominanceSnapshot detail checks
// ===========================================================================

#[test]
fn dominance_snapshot_schema_version() {
    let board = RatchetBoard::new();
    let ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();

    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    assert_eq!(snap.schema_version, DOMINANCE_SNAPSHOT_SCHEMA_VERSION);
    assert_eq!(snap.bead_id, UNIVERSAL_DOMINANCE_RATCHET_BEAD_ID);
}

#[test]
fn dominance_snapshot_epoch_matches_board() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let ledger = FrontierGapLedger::new();

    advance_epoch(&mut board, &mut log, 42).unwrap();
    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    assert_eq!(snap.epoch, 42);
}

#[test]
fn dominance_snapshot_with_closed_gaps_only() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let mut ledger = FrontierGapLedger::new();

    let cell = unproven_cell(
        CellDomain::ColdStart,
        ComparisonTarget::V8Node,
        "closed-gaps",
    );
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        1_000_000,
        vec![],
    )
    .unwrap();

    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("g", CellDomain::Memory, GapKind::Unknown, 500_000),
    )
    .unwrap();
    close_gap(
        &mut ledger,
        &mut log,
        "g",
        GapResolution::DimensionInvalidated,
        1,
    )
    .unwrap();

    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    assert!(snap.universal_dominance_achieved);
    assert_eq!(snap.open_gap_count, 0);
    assert_eq!(snap.closed_gap_count, 1);
}

// ===========================================================================
// Event log records dominance assessment
// ===========================================================================

#[test]
fn dominance_assessment_event_in_log() {
    let board = RatchetBoard::new();
    let ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();

    compute_dominance_snapshot(&board, &ledger, &mut log);

    assert_eq!(log.events.len(), 1);
    match &log.events[0].kind {
        RatchetEventKind::DominanceAssessed {
            proven_count,
            total_count,
            fraction_millionths,
        } => {
            assert_eq!(*proven_count, 0);
            assert_eq!(*total_count, 0);
            assert_eq!(*fraction_millionths, 0);
        }
        other => panic!("expected DominanceAssessed, got {other:?}"),
    }
}

// ===========================================================================
// Evidence accumulation
// ===========================================================================

#[test]
fn evidence_accumulates_across_advances() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    let cell = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "accum");
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();

    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Claimed,
        100_000,
        vec!["ev-1".to_string()],
    )
    .unwrap();

    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        200_000,
        vec!["ev-2".to_string(), "ev-3".to_string()],
    )
    .unwrap();

    let found = board.find_cell(&cid).unwrap();
    assert_eq!(found.evidence_ids, vec!["ev-1", "ev-2", "ev-3"]);
}

// ===========================================================================
// Advance cell not found
// ===========================================================================

#[test]
fn advance_cell_not_found_error() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    let cid = cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "ghost");
    let err = advance_cell(&mut board, &mut log, &cid, CellState::Claimed, 0, vec![]).unwrap_err();

    match err {
        RatchetError::CellNotFound {
            cell_id: ref found_cid,
        } => {
            assert_eq!(*found_cid, cid);
        }
        other => panic!("expected CellNotFound, got {other}"),
    }
}

// ===========================================================================
// RatchetError display coverage
// ===========================================================================

#[test]
fn ratchet_error_margin_regression_display() {
    let err = RatchetError::MarginRegressionRejected {
        cell_id: cell_id(CellDomain::Memory, ComparisonTarget::Bun, "disp"),
        current_margin: 500_000,
        attempted_margin: 100_000,
    };
    let display = err.to_string();
    assert!(display.contains("margin regression rejected"));
    assert!(display.contains("500000"));
    assert!(display.contains("100000"));
}

#[test]
fn ratchet_error_epoch_regression_display() {
    let err = RatchetError::EpochRegression {
        current_epoch: 10,
        attempted_epoch: 5,
    };
    let display = err.to_string();
    assert!(display.contains("epoch regression"));
    assert!(display.contains("10"));
    assert!(display.contains("5"));
}

#[test]
fn ratchet_error_duplicate_gap_display() {
    let err = RatchetError::DuplicateGap {
        gap_id: "gap-dup".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("duplicate gap"));
    assert!(display.contains("gap-dup"));
}

// ===========================================================================
// Epoch interleaving with cell advances
// ===========================================================================

#[test]
fn cell_last_advanced_epoch_tracks_board_epoch() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    let cell = unproven_cell(
        CellDomain::ColdStart,
        ComparisonTarget::V8Node,
        "epoch-track",
    );
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();

    advance_epoch(&mut board, &mut log, 5).unwrap();
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Claimed,
        100_000,
        vec![],
    )
    .unwrap();

    let found = board.find_cell(&cid).unwrap();
    assert_eq!(found.last_advanced_epoch, 5);

    advance_epoch(&mut board, &mut log, 10).unwrap();
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        200_000,
        vec![],
    )
    .unwrap();

    let found = board.find_cell(&cid).unwrap();
    assert_eq!(found.last_advanced_epoch, 10);
}

// ===========================================================================
// Dominance fraction edge case: all cells claimed but none proven
// ===========================================================================

#[test]
fn dominance_fraction_all_claimed_none_proven() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    for i in 0..4 {
        let cell = unproven_cell(
            CellDomain::ColdStart,
            ComparisonTarget::V8Node,
            &format!("claimed-{i}"),
        );
        let cid = cell.cell_id.clone();
        add_cell(&mut board, &mut log, cell).unwrap();
        advance_cell(
            &mut board,
            &mut log,
            &cid,
            CellState::Claimed,
            50_000,
            vec![],
        )
        .unwrap();
    }

    assert_eq!(board.proven_count(), 0);
    assert_eq!(board.dominance_fraction_millionths(), 0);
}

// ===========================================================================
// Board state counts with no cells
// ===========================================================================

#[test]
fn state_counts_empty_board() {
    let board = RatchetBoard::new();
    let counts = board.state_counts();
    assert!(counts.is_empty());
}

// ===========================================================================
// Dominance snapshot serde with full state
// ===========================================================================

#[test]
fn dominance_snapshot_full_serde_roundtrip() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let mut ledger = FrontierGapLedger::new();

    // Add cells across domains and targets
    let cell1 = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "full-1");
    let cell2 = unproven_cell(CellDomain::Throughput, ComparisonTarget::Bun, "full-2");
    let cid1 = cell1.cell_id.clone();
    add_cell(&mut board, &mut log, cell1).unwrap();
    add_cell(&mut board, &mut log, cell2).unwrap();

    advance_cell(
        &mut board,
        &mut log,
        &cid1,
        CellState::Proven,
        800_000,
        vec!["proof".to_string()],
    )
    .unwrap();

    register_gap(
        &mut ledger,
        &mut log,
        gap_entry(
            "full-gap",
            CellDomain::Memory,
            GapKind::KnownDeficient,
            700_000,
        ),
    )
    .unwrap();

    advance_epoch(&mut board, &mut log, 3).unwrap();

    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    let json = serde_json::to_string(&snap).unwrap();
    let back: DominanceSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, back);
    assert_eq!(back.domain_proven_counts.len(), 2);
    assert_eq!(back.target_proven_counts.len(), 2);
}

// ===========================================================================
// Gap resolution all variants via close_gap
// ===========================================================================

#[test]
fn close_gap_all_resolution_types() {
    let resolutions = [
        GapResolution::ProvenOnBoard,
        GapResolution::DeclaredOutOfScope,
        GapResolution::SubsumedByOther,
        GapResolution::DimensionInvalidated,
    ];

    for (i, resolution) in resolutions.iter().enumerate() {
        let mut ledger = FrontierGapLedger::new();
        let mut log = RatchetEventLog::new();

        let gap_id = format!("res-{i}");
        register_gap(
            &mut ledger,
            &mut log,
            gap_entry(&gap_id, CellDomain::ColdStart, GapKind::Unknown, 500_000),
        )
        .unwrap();

        close_gap(&mut ledger, &mut log, &gap_id, *resolution, 1).unwrap();

        let entry = ledger.find_gap(&gap_id).unwrap();
        assert_eq!(entry.state, GapState::Closed);
        assert_eq!(entry.resolution, Some(*resolution));
        assert_eq!(entry.closed_epoch, Some(1));
    }
}
