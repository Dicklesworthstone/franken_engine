#![forbid(unsafe_code)]

//! Integration tests for universal_dominance_ratchet (bd-1lsy.1.6.4 [RGC-016D]).

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
        owning_bead: "integration-test".to_string(),
    }
}

fn gap_entry(gap_id: &str, domain: CellDomain, kind: GapKind, priority: u32) -> FrontierGapEntry {
    FrontierGapEntry {
        gap_id: gap_id.to_string(),
        kind,
        state: GapState::Open,
        domain,
        target: None,
        description: format!("Integration test gap: {gap_id}"),
        registered_epoch: 0,
        closed_epoch: None,
        resolution: None,
        discovery_source: "integration-test".to_string(),
        priority_millionths: priority,
    }
}

// ---------------------------------------------------------------------------
// CellState transition matrix
// ---------------------------------------------------------------------------

#[test]
fn cell_state_transition_matrix_exhaustive() {
    let states = [CellState::Unproven, CellState::Claimed, CellState::Proven];
    let expected = [
        [true, true, true],   // from Unproven
        [false, true, true],  // from Claimed
        [false, false, true], // from Proven
    ];
    for (i, from) in states.iter().enumerate() {
        for (j, to) in states.iter().enumerate() {
            assert_eq!(
                from.can_advance_to(*to),
                expected[i][j],
                "transition {from} -> {to}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// CellDomain serde
// ---------------------------------------------------------------------------

#[test]
fn cell_domain_serde_all_variants() {
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
    for domain in &domains {
        let json = serde_json::to_string(domain).expect("serialize");
        let deser: CellDomain = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*domain, deser);
    }
}

// ---------------------------------------------------------------------------
// ComparisonTarget serde
// ---------------------------------------------------------------------------

#[test]
fn comparison_target_serde_all_variants() {
    let targets = [
        ComparisonTarget::V8Node,
        ComparisonTarget::Bun,
        ComparisonTarget::Deno,
        ComparisonTarget::Jsc,
    ];
    for target in &targets {
        let json = serde_json::to_string(target).expect("serialize");
        let deser: ComparisonTarget = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*target, deser);
    }
}

// ---------------------------------------------------------------------------
// Board lifecycle: add, advance, epoch
// ---------------------------------------------------------------------------

#[test]
fn board_full_lifecycle() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    // Add 3 cells across different domains
    let cs = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "100-mod");
    let tp = unproven_cell(
        CellDomain::Throughput,
        ComparisonTarget::Bun,
        "steady-state",
    );
    let mem = unproven_cell(CellDomain::Memory, ComparisonTarget::Deno, "heap-64mb");

    add_cell(&mut board, &mut log, cs).unwrap();
    add_cell(&mut board, &mut log, tp).unwrap();
    add_cell(&mut board, &mut log, mem).unwrap();
    assert_eq!(board.cell_count(), 3);

    // Advance epoch
    advance_epoch(&mut board, &mut log, 1).unwrap();

    // Advance cold-start to claimed
    let cs_id = cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "100-mod");
    advance_cell(
        &mut board,
        &mut log,
        &cs_id,
        CellState::Claimed,
        250_000,
        vec!["bench-cs-001".to_string()],
    )
    .unwrap();

    // Advance throughput to proven
    let tp_id = cell_id(
        CellDomain::Throughput,
        ComparisonTarget::Bun,
        "steady-state",
    );
    advance_cell(
        &mut board,
        &mut log,
        &tp_id,
        CellState::Proven,
        150_000,
        vec!["bench-tp-001".to_string(), "bench-tp-002".to_string()],
    )
    .unwrap();

    // Check state
    assert_eq!(board.proven_count(), 1);
    let counts = board.state_counts();
    assert_eq!(counts.get(&CellState::Proven), Some(&1));
    assert_eq!(counts.get(&CellState::Claimed), Some(&1));
    assert_eq!(counts.get(&CellState::Unproven), Some(&1));

    // Advance epoch again
    advance_epoch(&mut board, &mut log, 2).unwrap();

    // Prove the cold-start cell (skip claimed->proven)
    advance_cell(
        &mut board,
        &mut log,
        &cs_id,
        CellState::Proven,
        300_000,
        vec!["bench-cs-002".to_string()],
    )
    .unwrap();
    assert_eq!(board.proven_count(), 2);

    // Evidence should accumulate
    let cs_cell = board.find_cell(&cs_id).unwrap();
    assert_eq!(cs_cell.evidence_ids.len(), 2);
    assert_eq!(cs_cell.last_advanced_epoch, 2);
}

// ---------------------------------------------------------------------------
// Ratchet enforcement (regression rejection)
// ---------------------------------------------------------------------------

#[test]
fn ratchet_rejects_state_regression() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    let cell = unproven_cell(CellDomain::TailLatency, ComparisonTarget::V8Node, "p999");
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();

    // Advance to proven
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        500_000,
        vec!["ev-1".to_string()],
    )
    .unwrap();

    // Try to regress to claimed
    let err = advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Claimed,
        400_000,
        vec![],
    )
    .unwrap_err();

    match err {
        RatchetError::RegressionRejected {
            current_state,
            attempted_state,
            ..
        } => {
            assert_eq!(current_state, CellState::Proven);
            assert_eq!(attempted_state, CellState::Claimed);
        }
        other => panic!("expected RegressionRejected, got {other}"),
    }

    // Cell should be unchanged
    assert_eq!(board.find_cell(&cid).unwrap().state, CellState::Proven);
}

#[test]
fn ratchet_rejects_margin_regression_on_proven() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    let cell = unproven_cell(CellDomain::Memory, ComparisonTarget::Bun, "rss");
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();

    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        750_000,
        vec!["ev-margin".to_string()],
    )
    .unwrap();

    let err = advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        500_000,
        vec![],
    )
    .unwrap_err();

    match err {
        RatchetError::MarginRegressionRejected {
            current_margin,
            attempted_margin,
            ..
        } => {
            assert_eq!(current_margin, 750_000);
            assert_eq!(attempted_margin, 500_000);
        }
        other => panic!("expected MarginRegressionRejected, got {other}"),
    }
}

#[test]
fn ratchet_allows_margin_increase_on_proven() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    let cell = unproven_cell(CellDomain::ColdStart, ComparisonTarget::Jsc, "startup");
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

    // Increasing margin should be fine
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        200_000,
        vec!["ev-2".to_string()],
    )
    .unwrap();

    assert_eq!(board.find_cell(&cid).unwrap().margin_millionths, 200_000);
}

// ---------------------------------------------------------------------------
// Epoch enforcement
// ---------------------------------------------------------------------------

#[test]
fn epoch_strictly_monotonic() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    advance_epoch(&mut board, &mut log, 1).unwrap();
    advance_epoch(&mut board, &mut log, 10).unwrap();
    advance_epoch(&mut board, &mut log, 11).unwrap();

    // Same epoch is rejected
    assert!(advance_epoch(&mut board, &mut log, 11).is_err());
    // Earlier epoch is rejected
    assert!(advance_epoch(&mut board, &mut log, 5).is_err());
    // Later is fine
    assert!(advance_epoch(&mut board, &mut log, 12).is_ok());
}

// ---------------------------------------------------------------------------
// Frontier gap ledger
// ---------------------------------------------------------------------------

#[test]
fn gap_ledger_full_lifecycle() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();

    // Register several gaps
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("gap-cs", CellDomain::ColdStart, GapKind::Unknown, 800_000),
    )
    .unwrap();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry(
            "gap-mem",
            CellDomain::Memory,
            GapKind::KnownDeficient,
            900_000,
        ),
    )
    .unwrap();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry(
            "gap-tp",
            CellDomain::Throughput,
            GapKind::PartiallyExplored,
            300_000,
        ),
    )
    .unwrap();

    assert_eq!(ledger.open_count(), 3);
    assert_eq!(ledger.closed_count(), 0);

    // Close one gap
    close_gap(
        &mut ledger,
        &mut log,
        "gap-mem",
        GapResolution::ProvenOnBoard,
        1,
    )
    .unwrap();
    assert_eq!(ledger.open_count(), 2);
    assert_eq!(ledger.closed_count(), 1);

    // Verify priority ordering (only open gaps)
    let sorted = ledger.open_gaps_by_priority();
    assert_eq!(sorted.len(), 2);
    assert_eq!(sorted[0].gap_id, "gap-cs"); // 800k > 300k
    assert_eq!(sorted[1].gap_id, "gap-tp");

    // Close remaining
    close_gap(
        &mut ledger,
        &mut log,
        "gap-cs",
        GapResolution::DeclaredOutOfScope,
        2,
    )
    .unwrap();
    close_gap(
        &mut ledger,
        &mut log,
        "gap-tp",
        GapResolution::SubsumedByOther,
        2,
    )
    .unwrap();
    assert_eq!(ledger.open_count(), 0);
    assert_eq!(ledger.closed_count(), 3);
}

#[test]
fn gap_kinds_distribution() {
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
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry(
            "c",
            CellDomain::Throughput,
            GapKind::KnownDeficient,
            500_000,
        ),
    )
    .unwrap();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("d", CellDomain::TailLatency, GapKind::OutOfScope, 500_000),
    )
    .unwrap();

    let kinds = ledger.open_gap_kinds();
    assert_eq!(kinds.get(&GapKind::Unknown), Some(&2));
    assert_eq!(kinds.get(&GapKind::KnownDeficient), Some(&1));
    assert_eq!(kinds.get(&GapKind::OutOfScope), Some(&1));
    assert_eq!(kinds.get(&GapKind::PartiallyExplored), None);
}

#[test]
fn gap_with_target_specific() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();

    let mut gap = gap_entry(
        "target-gap",
        CellDomain::ColdStart,
        GapKind::Unknown,
        500_000,
    );
    gap.target = Some(ComparisonTarget::V8Node);
    register_gap(&mut ledger, &mut log, gap).unwrap();

    let found = ledger.find_gap("target-gap").unwrap();
    assert_eq!(found.target, Some(ComparisonTarget::V8Node));
}

// ---------------------------------------------------------------------------
// Dominance snapshot
// ---------------------------------------------------------------------------

#[test]
fn dominance_snapshot_empty_board() {
    let board = RatchetBoard::new();
    let ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();

    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    assert_eq!(snap.total_cells, 0);
    assert_eq!(snap.proven_cells, 0);
    assert_eq!(snap.dominance_fraction_millionths, 0);
    assert!(!snap.universal_dominance_achieved);
}

#[test]
fn dominance_snapshot_universal_achieved() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let ledger = FrontierGapLedger::new();

    // Add and prove all cells
    for (domain, target, dim) in [
        (CellDomain::ColdStart, ComparisonTarget::V8Node, "a"),
        (CellDomain::Throughput, ComparisonTarget::Bun, "b"),
    ] {
        let cell = unproven_cell(domain, target, dim);
        let cid = cell.cell_id.clone();
        add_cell(&mut board, &mut log, cell).unwrap();
        advance_cell(
            &mut board,
            &mut log,
            &cid,
            CellState::Proven,
            1_000_000,
            vec!["proof".to_string()],
        )
        .unwrap();
    }

    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    assert!(snap.universal_dominance_achieved);
    assert_eq!(snap.dominance_fraction_millionths, 1_000_000);
    assert_eq!(snap.proven_cells, 2);
    assert_eq!(snap.open_gap_count, 0);
}

#[test]
fn dominance_blocked_by_open_gaps() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let mut ledger = FrontierGapLedger::new();

    // All cells proven
    let cell = unproven_cell(
        CellDomain::ColdStart,
        ComparisonTarget::V8Node,
        "all-proven",
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

    // But there's an open gap
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("blocker", CellDomain::Memory, GapKind::Unknown, 500_000),
    )
    .unwrap();

    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    assert!(!snap.universal_dominance_achieved);
    assert_eq!(snap.open_gap_count, 1);
}

#[test]
fn dominance_per_domain_breakdown() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let ledger = FrontierGapLedger::new();

    // Two cold-start cells: one proven, one unproven
    let c1 = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "cs-1");
    let c2 = unproven_cell(CellDomain::ColdStart, ComparisonTarget::Bun, "cs-2");
    let c1_id = c1.cell_id.clone();
    add_cell(&mut board, &mut log, c1).unwrap();
    add_cell(&mut board, &mut log, c2).unwrap();
    advance_cell(
        &mut board,
        &mut log,
        &c1_id,
        CellState::Proven,
        100_000,
        vec![],
    )
    .unwrap();

    // One throughput cell: proven
    let t1 = unproven_cell(CellDomain::Throughput, ComparisonTarget::V8Node, "tp-1");
    let t1_id = t1.cell_id.clone();
    add_cell(&mut board, &mut log, t1).unwrap();
    advance_cell(
        &mut board,
        &mut log,
        &t1_id,
        CellState::Proven,
        200_000,
        vec![],
    )
    .unwrap();

    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);

    // Check domain breakdown
    let cs_domain = snap
        .domain_proven_counts
        .iter()
        .find(|d| d.domain == CellDomain::ColdStart)
        .unwrap();
    assert_eq!(cs_domain.proven, 1);
    assert_eq!(cs_domain.total, 2);

    let tp_domain = snap
        .domain_proven_counts
        .iter()
        .find(|d| d.domain == CellDomain::Throughput)
        .unwrap();
    assert_eq!(tp_domain.proven, 1);
    assert_eq!(tp_domain.total, 1);
}

#[test]
fn dominance_per_target_breakdown() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let ledger = FrontierGapLedger::new();

    let c1 = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "v8-1");
    let c2 = unproven_cell(CellDomain::Memory, ComparisonTarget::V8Node, "v8-2");
    let c3 = unproven_cell(CellDomain::ColdStart, ComparisonTarget::Bun, "bun-1");
    let c1_id = c1.cell_id.clone();
    let c3_id = c3.cell_id.clone();
    add_cell(&mut board, &mut log, c1).unwrap();
    add_cell(&mut board, &mut log, c2).unwrap();
    add_cell(&mut board, &mut log, c3).unwrap();

    advance_cell(
        &mut board,
        &mut log,
        &c1_id,
        CellState::Proven,
        100_000,
        vec![],
    )
    .unwrap();
    advance_cell(
        &mut board,
        &mut log,
        &c3_id,
        CellState::Proven,
        200_000,
        vec![],
    )
    .unwrap();

    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);

    let v8_target = snap
        .target_proven_counts
        .iter()
        .find(|t| t.target == ComparisonTarget::V8Node)
        .unwrap();
    assert_eq!(v8_target.proven, 1);
    assert_eq!(v8_target.total, 2);

    let bun_target = snap
        .target_proven_counts
        .iter()
        .find(|t| t.target == ComparisonTarget::Bun)
        .unwrap();
    assert_eq!(bun_target.proven, 1);
    assert_eq!(bun_target.total, 1);
}

// ---------------------------------------------------------------------------
// Event log audit trail
// ---------------------------------------------------------------------------

#[test]
fn event_log_captures_regression_attempt() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    let cell = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "regress");
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        100_000,
        vec![],
    )
    .unwrap();

    // Attempt regression
    let _ = advance_cell(&mut board, &mut log, &cid, CellState::Unproven, 0, vec![]);

    // The log should contain the rejection event
    let regression_events: Vec<_> = log
        .events
        .iter()
        .filter(|e| matches!(e.kind, RatchetEventKind::RegressionRejected { .. }))
        .collect();
    assert_eq!(regression_events.len(), 1);
}

#[test]
fn event_log_sequence_integrity() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    for i in 0..10 {
        let cell = unproven_cell(
            CellDomain::ColdStart,
            ComparisonTarget::V8Node,
            &format!("seq-{i}"),
        );
        add_cell(&mut board, &mut log, cell).unwrap();
    }

    // Verify monotonic sequences
    for (idx, event) in log.events.iter().enumerate() {
        assert_eq!(event.sequence, idx as u64);
    }
    assert_eq!(log.next_sequence, 10);
}

// ---------------------------------------------------------------------------
// Serde round-trips for all types
// ---------------------------------------------------------------------------

#[test]
fn cell_state_serde_all_variants() {
    for state in [CellState::Unproven, CellState::Claimed, CellState::Proven] {
        let json = serde_json::to_string(&state).expect("serialize");
        let deser: CellState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, deser);
    }
}

#[test]
fn gap_kind_serde_all_variants() {
    for kind in [
        GapKind::Unknown,
        GapKind::PartiallyExplored,
        GapKind::KnownDeficient,
        GapKind::OutOfScope,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let deser: GapKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, deser);
    }
}

#[test]
fn gap_resolution_serde_all_variants() {
    for res in [
        GapResolution::ProvenOnBoard,
        GapResolution::DeclaredOutOfScope,
        GapResolution::SubsumedByOther,
        GapResolution::DimensionInvalidated,
    ] {
        let json = serde_json::to_string(&res).expect("serialize");
        let deser: GapResolution = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(res, deser);
    }
}

#[test]
fn ratchet_error_serde_all_variants() {
    let cid = cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "test");
    let errors = vec![
        RatchetError::RegressionRejected {
            cell_id: cid.clone(),
            current_state: CellState::Proven,
            attempted_state: CellState::Claimed,
        },
        RatchetError::MarginRegressionRejected {
            cell_id: cid.clone(),
            current_margin: 100,
            attempted_margin: 50,
        },
        RatchetError::EpochRegression {
            current_epoch: 10,
            attempted_epoch: 5,
        },
        RatchetError::CellNotFound {
            cell_id: cid.clone(),
        },
        RatchetError::GapNotFound {
            gap_id: "test".to_string(),
        },
        RatchetError::GapAlreadyClosed {
            gap_id: "test".to_string(),
        },
        RatchetError::DuplicateCell { cell_id: cid },
        RatchetError::DuplicateGap {
            gap_id: "test".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let deser: RatchetError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, deser);
    }
}

#[test]
fn ratchet_event_kind_serde_all_variants() {
    let cid = cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "serde");
    let kinds = vec![
        RatchetEventKind::CellAdded {
            cell_id: cid.clone(),
        },
        RatchetEventKind::CellAdvanced {
            cell_id: cid.clone(),
            from_state: CellState::Unproven,
            to_state: CellState::Proven,
            margin_millionths: 500_000,
            evidence_ids: vec!["ev-1".to_string()],
        },
        RatchetEventKind::RegressionRejected {
            cell_id: cid,
            current_state: CellState::Proven,
            attempted_state: CellState::Claimed,
        },
        RatchetEventKind::GapRegistered {
            gap_id: "g1".to_string(),
        },
        RatchetEventKind::GapClosed {
            gap_id: "g1".to_string(),
            resolution: GapResolution::ProvenOnBoard,
        },
        RatchetEventKind::EpochAdvanced {
            from_epoch: 0,
            to_epoch: 1,
        },
        RatchetEventKind::DominanceAssessed {
            proven_count: 5,
            total_count: 10,
            fraction_millionths: 500_000,
        },
    ];
    for kind in &kinds {
        let event = RatchetEvent {
            sequence: 0,
            epoch: 0,
            kind: kind.clone(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let deser: RatchetEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, deser);
    }
}

// ---------------------------------------------------------------------------
// Complex serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn full_board_serde_round_trip() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    for i in 0..5 {
        let cell = unproven_cell(
            CellDomain::ColdStart,
            ComparisonTarget::V8Node,
            &format!("cell-{i}"),
        );
        add_cell(&mut board, &mut log, cell).unwrap();
    }
    let cid = cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "cell-0");
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        100_000,
        vec!["ev-1".to_string()],
    )
    .unwrap();

    let json = serde_json::to_string_pretty(&board).expect("serialize");
    let deser: RatchetBoard = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(board, deser);
}

#[test]
fn full_ledger_serde_round_trip() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();

    for i in 0..3 {
        register_gap(
            &mut ledger,
            &mut log,
            gap_entry(
                &format!("gap-{i}"),
                CellDomain::ColdStart,
                GapKind::Unknown,
                500_000,
            ),
        )
        .unwrap();
    }
    close_gap(
        &mut ledger,
        &mut log,
        "gap-0",
        GapResolution::ProvenOnBoard,
        1,
    )
    .unwrap();

    let json = serde_json::to_string_pretty(&ledger).expect("serialize");
    let deser: FrontierGapLedger = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ledger, deser);
}

#[test]
fn dominance_snapshot_serde() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let ledger = FrontierGapLedger::new();

    let cell = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "snap");
    add_cell(&mut board, &mut log, cell).unwrap();

    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    let json = serde_json::to_string_pretty(&snap).expect("serialize");
    let deser: DominanceSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(snap, deser);
}

// ---------------------------------------------------------------------------
// Display formatting
// ---------------------------------------------------------------------------

#[test]
fn ratchet_error_display_all_variants() {
    let cid = cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "disp");

    let errors: Vec<(RatchetError, &str)> = vec![
        (
            RatchetError::RegressionRejected {
                cell_id: cid.clone(),
                current_state: CellState::Proven,
                attempted_state: CellState::Unproven,
            },
            "regression rejected",
        ),
        (
            RatchetError::MarginRegressionRejected {
                cell_id: cid.clone(),
                current_margin: 100,
                attempted_margin: 50,
            },
            "margin regression rejected",
        ),
        (
            RatchetError::EpochRegression {
                current_epoch: 10,
                attempted_epoch: 5,
            },
            "epoch regression",
        ),
        (
            RatchetError::CellNotFound {
                cell_id: cid.clone(),
            },
            "cell not found",
        ),
        (
            RatchetError::GapNotFound {
                gap_id: "g".to_string(),
            },
            "gap not found",
        ),
        (
            RatchetError::GapAlreadyClosed {
                gap_id: "g".to_string(),
            },
            "gap already closed",
        ),
        (
            RatchetError::DuplicateCell { cell_id: cid },
            "duplicate cell",
        ),
        (
            RatchetError::DuplicateGap {
                gap_id: "g".to_string(),
            },
            "duplicate gap",
        ),
    ];

    for (err, expected_substring) in &errors {
        let display = err.to_string();
        assert!(
            display.contains(expected_substring),
            "error display '{display}' should contain '{expected_substring}'"
        );
    }
}

// ---------------------------------------------------------------------------
// Summary rendering
// ---------------------------------------------------------------------------

#[test]
fn render_summary_with_cells_and_gaps() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let mut ledger = FrontierGapLedger::new();

    let cell = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "sum");
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        100_000,
        vec![],
    )
    .unwrap();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("sum-gap", CellDomain::Memory, GapKind::Unknown, 500_000),
    )
    .unwrap();

    let summary = render_ratchet_summary(&board, &ledger);
    assert!(summary.contains("total_cells: 1"));
    assert!(summary.contains("proven: 1"));
    assert!(summary.contains("open_gaps: 1"));
    assert!(summary.contains("dominance:"));
    assert!(summary.contains("open_gap_kinds:"));
    assert!(summary.contains("unknown: 1"));
}

// ---------------------------------------------------------------------------
// Default constructors
// ---------------------------------------------------------------------------

#[test]
fn default_board_is_empty() {
    let board = RatchetBoard::default();
    assert_eq!(board.cell_count(), 0);
    assert_eq!(board.current_epoch, 0);
    assert_eq!(board.schema_version, RATCHET_BOARD_SCHEMA_VERSION);
}

#[test]
fn default_ledger_is_empty() {
    let ledger = FrontierGapLedger::default();
    assert_eq!(ledger.entries.len(), 0);
    assert_eq!(ledger.schema_version, FRONTIER_GAP_LEDGER_SCHEMA_VERSION);
}

#[test]
fn default_event_log_is_empty() {
    let log = RatchetEventLog::default();
    assert_eq!(log.events.len(), 0);
    assert_eq!(log.next_sequence, 0);
    assert_eq!(log.schema_version, RATCHET_EVENT_LOG_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Schema version constants
// ---------------------------------------------------------------------------

#[test]
fn schema_versions_are_nonempty() {
    assert!(!UNIVERSAL_DOMINANCE_RATCHET_SCHEMA_VERSION.is_empty());
    assert!(!RATCHET_BOARD_SCHEMA_VERSION.is_empty());
    assert!(!FRONTIER_GAP_LEDGER_SCHEMA_VERSION.is_empty());
    assert!(!RATCHET_EVENT_LOG_SCHEMA_VERSION.is_empty());
    assert!(!DOMINANCE_SNAPSHOT_SCHEMA_VERSION.is_empty());
    assert!(!UNIVERSAL_DOMINANCE_RATCHET_BEAD_ID.is_empty());
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn dominance_fraction_single_cell_unproven() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let cell = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "single");
    add_cell(&mut board, &mut log, cell).unwrap();
    assert_eq!(board.dominance_fraction_millionths(), 0);
}

#[test]
fn negative_margin_allowed() {
    // Negative margin means FrankenEngine is behind
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let cell = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "neg");
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();

    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Claimed,
        -200_000,
        vec!["bench-neg".to_string()],
    )
    .unwrap();

    assert_eq!(board.find_cell(&cid).unwrap().margin_millionths, -200_000);
}

#[test]
fn many_cells_stress() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();

    let domains = [
        CellDomain::ColdStart,
        CellDomain::Throughput,
        CellDomain::TailLatency,
        CellDomain::Memory,
        CellDomain::ReactPerformance,
    ];
    let targets = [
        ComparisonTarget::V8Node,
        ComparisonTarget::Bun,
        ComparisonTarget::Deno,
        ComparisonTarget::Jsc,
    ];

    // 5 domains x 4 targets x 3 dimensions = 60 cells
    for domain in &domains {
        for target in &targets {
            for i in 0..3 {
                let cell = unproven_cell(*domain, *target, &format!("dim-{i}"));
                add_cell(&mut board, &mut log, cell).unwrap();
            }
        }
    }
    assert_eq!(board.cell_count(), 60);
    assert_eq!(board.dominance_fraction_millionths(), 0);

    // Prove half
    for (idx, domain) in domains.iter().enumerate() {
        for target in &targets {
            let cid = cell_id(*domain, *target, "dim-0");
            if idx % 2 == 0 {
                advance_cell(
                    &mut board,
                    &mut log,
                    &cid,
                    CellState::Proven,
                    100_000,
                    vec![],
                )
                .unwrap();
            }
        }
    }

    // 3 domains x 4 targets = 12 proven out of 60
    assert_eq!(board.proven_count(), 12);
    assert_eq!(board.dominance_fraction_millionths(), 200_000); // 12/60 = 0.2
}

// ---------------------------------------------------------------------------
// Clone / Debug / PartialEq coverage on all public types
// ---------------------------------------------------------------------------

#[test]
fn test_cell_id_clone_debug_eq() {
    let cid = cell_id(
        CellDomain::ColdStart,
        ComparisonTarget::V8Node,
        "clone-test",
    );
    let cid2 = cid.clone();
    assert_eq!(cid, cid2);
    let dbg = format!("{cid:?}");
    assert!(dbg.contains("ColdStart"));
    assert!(dbg.contains("V8Node"));
    assert!(dbg.contains("clone-test"));
}

#[test]
fn test_ratchet_cell_clone_debug_eq() {
    let cell = unproven_cell(CellDomain::Throughput, ComparisonTarget::Bun, "clone-cell");
    let cell2 = cell.clone();
    assert_eq!(cell, cell2);
    let dbg = format!("{cell:?}");
    assert!(dbg.contains("Throughput"));
    assert!(dbg.contains("Bun"));
}

#[test]
fn test_ratchet_board_clone_debug_eq() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let cell = unproven_cell(CellDomain::Memory, ComparisonTarget::Deno, "clone-board");
    add_cell(&mut board, &mut log, cell).unwrap();
    let board2 = board.clone();
    assert_eq!(board, board2);
    let dbg = format!("{board:?}");
    assert!(dbg.contains("Memory"));
}

#[test]
fn test_frontier_gap_entry_clone_debug_eq() {
    let entry = gap_entry(
        "gap-clone",
        CellDomain::TailLatency,
        GapKind::Unknown,
        500_000,
    );
    let entry2 = entry.clone();
    assert_eq!(entry, entry2);
    let dbg = format!("{entry:?}");
    assert!(dbg.contains("gap-clone"));
    assert!(dbg.contains("TailLatency"));
}

#[test]
fn test_frontier_gap_ledger_clone_debug_eq() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry(
            "clone-ledger-gap",
            CellDomain::Memory,
            GapKind::KnownDeficient,
            700_000,
        ),
    )
    .unwrap();
    let ledger2 = ledger.clone();
    assert_eq!(ledger, ledger2);
    let dbg = format!("{ledger:?}");
    assert!(dbg.contains("clone-ledger-gap"));
}

#[test]
fn test_dominance_snapshot_clone_debug_eq() {
    let board = RatchetBoard::new();
    let ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();
    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    let snap2 = snap.clone();
    assert_eq!(snap, snap2);
    let dbg = format!("{snap:?}");
    assert!(dbg.contains("DominanceSnapshot"));
}

#[test]
fn test_ratchet_event_log_clone_debug_eq() {
    let mut log = RatchetEventLog::new();
    let mut board = RatchetBoard::new();
    let cell = unproven_cell(CellDomain::ColdStart, ComparisonTarget::Jsc, "log-clone");
    add_cell(&mut board, &mut log, cell).unwrap();
    let log2 = log.clone();
    assert_eq!(log, log2);
    let dbg = format!("{log:?}");
    assert!(dbg.contains("CellAdded"));
}

#[test]
fn test_ratchet_error_clone_debug_eq() {
    let cid = cell_id(CellDomain::ReplayFidelity, ComparisonTarget::Bun, "err-eq");
    let err1 = RatchetError::CellNotFound {
        cell_id: cid.clone(),
    };
    let err2 = err1.clone();
    assert_eq!(err1, err2);
    let dbg = format!("{err1:?}");
    assert!(dbg.contains("CellNotFound"));
}

#[test]
fn test_domain_proven_count_clone_debug_eq() {
    let dpc = DomainProvenCount {
        domain: CellDomain::SecurityOverhead,
        proven: 3,
        total: 5,
    };
    let dpc2 = dpc.clone();
    assert_eq!(dpc, dpc2);
    let dbg = format!("{dpc:?}");
    assert!(dbg.contains("SecurityOverhead"));
    assert!(dbg.contains("3"));
}

#[test]
fn test_target_proven_count_clone_debug_eq() {
    let tpc = TargetProvenCount {
        target: ComparisonTarget::Deno,
        proven: 2,
        total: 4,
    };
    let tpc2 = tpc.clone();
    assert_eq!(tpc, tpc2);
    let dbg = format!("{tpc2:?}");
    assert!(dbg.contains("Deno"));
    assert!(dbg.contains("2"));
}

// ---------------------------------------------------------------------------
// Display formatting for all enum types
// ---------------------------------------------------------------------------

#[test]
fn test_cell_domain_display_all_variants() {
    let cases = [
        (CellDomain::ColdStart, "cold_start"),
        (CellDomain::Throughput, "throughput"),
        (CellDomain::TailLatency, "tail_latency"),
        (CellDomain::Memory, "memory"),
        (CellDomain::ReactPerformance, "react_performance"),
        (CellDomain::ModuleLoading, "module_loading"),
        (CellDomain::TypeScriptCompilation, "typescript_compilation"),
        (CellDomain::SecurityOverhead, "security_overhead"),
        (CellDomain::ReplayFidelity, "replay_fidelity"),
        (CellDomain::ExtensionIsolation, "extension_isolation"),
    ];
    for (domain, expected) in &cases {
        assert_eq!(domain.to_string(), *expected, "domain display mismatch");
    }
}

#[test]
fn test_comparison_target_display_all_variants() {
    let cases = [
        (ComparisonTarget::V8Node, "v8_node"),
        (ComparisonTarget::Bun, "bun"),
        (ComparisonTarget::Deno, "deno"),
        (ComparisonTarget::Jsc, "jsc"),
    ];
    for (target, expected) in &cases {
        assert_eq!(target.to_string(), *expected, "target display mismatch");
    }
}

#[test]
fn test_gap_kind_display_all_variants() {
    let cases = [
        (GapKind::Unknown, "unknown"),
        (GapKind::PartiallyExplored, "partially_explored"),
        (GapKind::KnownDeficient, "known_deficient"),
        (GapKind::OutOfScope, "out_of_scope"),
    ];
    for (kind, expected) in &cases {
        assert_eq!(kind.to_string(), *expected, "gap kind display mismatch");
    }
}

#[test]
fn test_gap_resolution_display_all_variants() {
    let cases = [
        (GapResolution::ProvenOnBoard, "proven_on_board"),
        (GapResolution::DeclaredOutOfScope, "declared_out_of_scope"),
        (GapResolution::SubsumedByOther, "subsumed_by_other"),
        (GapResolution::DimensionInvalidated, "dimension_invalidated"),
    ];
    for (res, expected) in &cases {
        assert_eq!(res.to_string(), *expected, "resolution display mismatch");
    }
}

#[test]
fn test_gap_state_display_all_variants() {
    assert_eq!(GapState::Open.to_string(), "open");
    assert_eq!(GapState::Closed.to_string(), "closed");
}

#[test]
fn test_cell_id_display_format() {
    let cid = cell_id(CellDomain::ModuleLoading, ComparisonTarget::Deno, "esmx");
    assert_eq!(cid.to_string(), "module_loading::deno::esmx");
}

// ---------------------------------------------------------------------------
// Serde round-trips for structs not fully covered
// ---------------------------------------------------------------------------

#[test]
fn test_ratchet_cell_serde_round_trip() {
    let mut cell = unproven_cell(
        CellDomain::ExtensionIsolation,
        ComparisonTarget::Jsc,
        "ext-iso",
    );
    cell.margin_millionths = -50_000;
    cell.evidence_ids = vec!["ev-a".to_string(), "ev-b".to_string()];
    cell.last_advanced_epoch = 7;
    let json = serde_json::to_string(&cell).expect("serialize");
    let deser: RatchetCell = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cell, deser);
}

#[test]
fn test_frontier_gap_entry_serde_round_trip_with_target() {
    let mut entry = gap_entry(
        "serde-target-gap",
        CellDomain::SecurityOverhead,
        GapKind::KnownDeficient,
        900_000,
    );
    entry.target = Some(ComparisonTarget::Bun);
    entry.closed_epoch = Some(5);
    entry.resolution = Some(GapResolution::SubsumedByOther);
    entry.state = GapState::Closed;
    let json = serde_json::to_string(&entry).expect("serialize");
    let deser: FrontierGapEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, deser);
}

#[test]
fn test_gap_state_serde_round_trip() {
    for state in [GapState::Open, GapState::Closed] {
        let json = serde_json::to_string(&state).expect("serialize");
        let deser: GapState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, deser);
    }
}

#[test]
fn test_domain_proven_count_serde_round_trip() {
    let dpc = DomainProvenCount {
        domain: CellDomain::TypeScriptCompilation,
        proven: 10,
        total: 20,
    };
    let json = serde_json::to_string(&dpc).expect("serialize");
    let deser: DomainProvenCount = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(dpc, deser);
}

#[test]
fn test_target_proven_count_serde_round_trip() {
    let tpc = TargetProvenCount {
        target: ComparisonTarget::Jsc,
        proven: 5,
        total: 8,
    };
    let json = serde_json::to_string(&tpc).expect("serialize");
    let deser: TargetProvenCount = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(tpc, deser);
}

// ---------------------------------------------------------------------------
// Error path: operations on missing / closed entities
// ---------------------------------------------------------------------------

#[test]
fn test_advance_cell_missing_returns_cell_not_found() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let phantom = cell_id(CellDomain::Memory, ComparisonTarget::Bun, "phantom");
    let err = advance_cell(
        &mut board,
        &mut log,
        &phantom,
        CellState::Claimed,
        0,
        vec![],
    )
    .unwrap_err();
    assert!(matches!(err, RatchetError::CellNotFound { .. }));
    assert!(err.to_string().contains("cell not found"));
}

#[test]
fn test_close_gap_missing_returns_gap_not_found() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();
    let err = close_gap(
        &mut ledger,
        &mut log,
        "nonexistent",
        GapResolution::ProvenOnBoard,
        1,
    )
    .unwrap_err();
    assert!(matches!(err, RatchetError::GapNotFound { .. }));
    assert!(err.to_string().contains("gap not found"));
}

#[test]
fn test_close_gap_twice_returns_already_closed() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry(
            "double-close",
            CellDomain::ColdStart,
            GapKind::Unknown,
            500_000,
        ),
    )
    .unwrap();
    close_gap(
        &mut ledger,
        &mut log,
        "double-close",
        GapResolution::ProvenOnBoard,
        1,
    )
    .unwrap();
    let err = close_gap(
        &mut ledger,
        &mut log,
        "double-close",
        GapResolution::DeclaredOutOfScope,
        2,
    )
    .unwrap_err();
    assert!(matches!(err, RatchetError::GapAlreadyClosed { .. }));
    assert!(err.to_string().contains("gap already closed"));
}

#[test]
fn test_duplicate_gap_error_message() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry(
            "dup-gap",
            CellDomain::Throughput,
            GapKind::PartiallyExplored,
            400_000,
        ),
    )
    .unwrap();
    let err = register_gap(
        &mut ledger,
        &mut log,
        gap_entry(
            "dup-gap",
            CellDomain::Throughput,
            GapKind::PartiallyExplored,
            400_000,
        ),
    )
    .unwrap_err();
    assert!(matches!(err, RatchetError::DuplicateGap { .. }));
    assert!(err.to_string().contains("duplicate gap"));
}

#[test]
fn test_duplicate_cell_error_message() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let cell = unproven_cell(CellDomain::Memory, ComparisonTarget::V8Node, "dup-cell");
    add_cell(&mut board, &mut log, cell.clone()).unwrap();
    let err = add_cell(&mut board, &mut log, cell).unwrap_err();
    assert!(matches!(err, RatchetError::DuplicateCell { .. }));
    assert!(err.to_string().contains("duplicate cell"));
}

#[test]
fn test_epoch_regression_error_message() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    advance_epoch(&mut board, &mut log, 10).unwrap();
    let err = advance_epoch(&mut board, &mut log, 3).unwrap_err();
    assert!(matches!(err, RatchetError::EpochRegression { .. }));
    let msg = err.to_string();
    assert!(msg.contains("epoch regression"));
    assert!(msg.contains("10"));
    assert!(msg.contains("3"));
}

// ---------------------------------------------------------------------------
// Boundary / edge values
// ---------------------------------------------------------------------------

#[test]
fn test_zero_margin_on_proven_cell_stays_zero() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let cell = unproven_cell(
        CellDomain::ColdStart,
        ComparisonTarget::V8Node,
        "zero-margin",
    );
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();
    advance_cell(&mut board, &mut log, &cid, CellState::Proven, 0, vec![]).unwrap();
    // Same margin (0 == 0) is allowed for proven cells — not a regression
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        0,
        vec!["ev-z".to_string()],
    )
    .unwrap();
    assert_eq!(board.find_cell(&cid).unwrap().margin_millionths, 0);
}

#[test]
fn test_max_priority_millionths_gap() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();
    let mut gap = gap_entry(
        "max-prio",
        CellDomain::Throughput,
        GapKind::Unknown,
        u32::MAX,
    );
    gap.priority_millionths = u32::MAX;
    register_gap(&mut ledger, &mut log, gap).unwrap();
    let sorted = ledger.open_gaps_by_priority();
    assert_eq!(sorted.len(), 1);
    assert_eq!(sorted[0].priority_millionths, u32::MAX);
}

#[test]
fn test_dominance_fraction_all_cells_proven() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    for i in 0..4 {
        let cell = unproven_cell(
            CellDomain::ColdStart,
            ComparisonTarget::V8Node,
            &format!("full-{i}"),
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
    }
    assert_eq!(board.dominance_fraction_millionths(), 1_000_000);
    assert_eq!(board.proven_count(), 4);
}

#[test]
fn test_single_proven_cell_no_open_gaps_universal_dominance() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let ledger = FrontierGapLedger::new();
    let cell = unproven_cell(CellDomain::Throughput, ComparisonTarget::Jsc, "uni");
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
    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    assert!(snap.universal_dominance_achieved);
    assert_eq!(snap.dominance_fraction_millionths, 1_000_000);
}

#[test]
fn test_empty_board_empty_ledger_no_universal_dominance() {
    let board = RatchetBoard::new();
    let ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();
    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    // empty board: universal_dominance requires total > 0
    assert!(!snap.universal_dominance_achieved);
    assert_eq!(snap.total_cells, 0);
    assert_eq!(snap.proven_cells, 0);
    assert_eq!(snap.claimed_cells, 0);
    assert_eq!(snap.unproven_cells, 0);
}

#[test]
fn test_snapshot_counts_claimed_and_unproven() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let ledger = FrontierGapLedger::new();

    // Add 3 cells: 1 proven, 1 claimed, 1 unproven
    let c1 = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "snap-a");
    let c2 = unproven_cell(CellDomain::ColdStart, ComparisonTarget::Bun, "snap-b");
    let c3 = unproven_cell(CellDomain::ColdStart, ComparisonTarget::Deno, "snap-c");
    let cid1 = c1.cell_id.clone();
    let cid2 = c2.cell_id.clone();
    add_cell(&mut board, &mut log, c1).unwrap();
    add_cell(&mut board, &mut log, c2).unwrap();
    add_cell(&mut board, &mut log, c3).unwrap();
    advance_cell(
        &mut board,
        &mut log,
        &cid1,
        CellState::Proven,
        100_000,
        vec![],
    )
    .unwrap();
    advance_cell(
        &mut board,
        &mut log,
        &cid2,
        CellState::Claimed,
        50_000,
        vec![],
    )
    .unwrap();

    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    assert_eq!(snap.proven_cells, 1);
    assert_eq!(snap.claimed_cells, 1);
    assert_eq!(snap.unproven_cells, 1);
    assert_eq!(snap.total_cells, 3);
    assert!(!snap.universal_dominance_achieved);
}

// ---------------------------------------------------------------------------
// Event log: regression attempt does not create extra CellAdded events
// ---------------------------------------------------------------------------

#[test]
fn test_event_log_regression_does_not_emit_cell_added() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let cell = unproven_cell(
        CellDomain::ReplayFidelity,
        ComparisonTarget::V8Node,
        "repl-ev",
    );
    let cid = cell.cell_id.clone();
    add_cell(&mut board, &mut log, cell).unwrap();
    advance_cell(
        &mut board,
        &mut log,
        &cid,
        CellState::Proven,
        200_000,
        vec![],
    )
    .unwrap();
    // Trigger a regression rejection
    let _ = advance_cell(&mut board, &mut log, &cid, CellState::Unproven, 0, vec![]);

    let added_count = log
        .events
        .iter()
        .filter(|e| matches!(e.kind, RatchetEventKind::CellAdded { .. }))
        .count();
    assert_eq!(added_count, 1, "only one CellAdded event expected");

    let rejected_count = log
        .events
        .iter()
        .filter(|e| matches!(e.kind, RatchetEventKind::RegressionRejected { .. }))
        .count();
    assert_eq!(
        rejected_count, 1,
        "exactly one RegressionRejected event expected"
    );
}

// ---------------------------------------------------------------------------
// Render summary edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_render_summary_empty_board_and_ledger() {
    let board = RatchetBoard::new();
    let ledger = FrontierGapLedger::new();
    let summary = render_ratchet_summary(&board, &ledger);
    assert!(summary.contains("total_cells: 0"));
    assert!(summary.contains("proven: 0"));
    assert!(summary.contains("open_gaps: 0"));
    // No open_gap_kinds section when there are none
    assert!(!summary.contains("open_gap_kinds:"));
}

#[test]
fn test_render_summary_multiple_gap_kinds() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry("g1", CellDomain::Memory, GapKind::Unknown, 500_000),
    )
    .unwrap();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry(
            "g2",
            CellDomain::Throughput,
            GapKind::PartiallyExplored,
            500_000,
        ),
    )
    .unwrap();
    register_gap(
        &mut ledger,
        &mut log,
        gap_entry(
            "g3",
            CellDomain::TailLatency,
            GapKind::KnownDeficient,
            500_000,
        ),
    )
    .unwrap();
    let board = RatchetBoard::new();
    let summary = render_ratchet_summary(&board, &ledger);
    assert!(summary.contains("open_gap_kinds:"));
    assert!(summary.contains("unknown: 1"));
    assert!(summary.contains("partially_explored: 1"));
    assert!(summary.contains("known_deficient: 1"));
}

// ---------------------------------------------------------------------------
// Schema version constants embedded correctly in structs
// ---------------------------------------------------------------------------

#[test]
fn test_board_schema_version_field_matches_constant() {
    let board = RatchetBoard::new();
    assert_eq!(board.schema_version, RATCHET_BOARD_SCHEMA_VERSION);
    assert_eq!(board.bead_id, UNIVERSAL_DOMINANCE_RATCHET_BEAD_ID);
}

#[test]
fn test_ledger_schema_version_field_matches_constant() {
    let ledger = FrontierGapLedger::new();
    assert_eq!(ledger.schema_version, FRONTIER_GAP_LEDGER_SCHEMA_VERSION);
    assert_eq!(ledger.bead_id, UNIVERSAL_DOMINANCE_RATCHET_BEAD_ID);
}

#[test]
fn test_event_log_schema_version_field_matches_constant() {
    let log = RatchetEventLog::new();
    assert_eq!(log.schema_version, RATCHET_EVENT_LOG_SCHEMA_VERSION);
    assert_eq!(log.bead_id, UNIVERSAL_DOMINANCE_RATCHET_BEAD_ID);
}

#[test]
fn test_dominance_snapshot_schema_version_embedded() {
    let board = RatchetBoard::new();
    let ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();
    let snap = compute_dominance_snapshot(&board, &ledger, &mut log);
    assert_eq!(snap.schema_version, DOMINANCE_SNAPSHOT_SCHEMA_VERSION);
    assert_eq!(snap.bead_id, UNIVERSAL_DOMINANCE_RATCHET_BEAD_ID);
}

// ---------------------------------------------------------------------------
// Ordering / comparisons on enums
// ---------------------------------------------------------------------------

#[test]
fn test_cell_state_ordering() {
    assert!(CellState::Unproven < CellState::Claimed);
    assert!(CellState::Claimed < CellState::Proven);
    assert!(CellState::Unproven < CellState::Proven);
}

#[test]
fn test_cell_domain_ordering_stable() {
    // BTreeMap depends on Ord — ensure stable ordering
    use std::collections::BTreeMap;
    let mut map: BTreeMap<CellDomain, u32> = BTreeMap::new();
    map.insert(CellDomain::Throughput, 2);
    map.insert(CellDomain::ColdStart, 1);
    map.insert(CellDomain::Memory, 3);
    let keys: Vec<&CellDomain> = map.keys().collect();
    // BTreeMap returns keys in sorted order — just confirm no panic and correct count
    assert_eq!(keys.len(), 3);
}

#[test]
fn test_gap_kind_ordering_stable() {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<GapKind, usize> = BTreeMap::new();
    map.insert(GapKind::KnownDeficient, 1);
    map.insert(GapKind::Unknown, 2);
    map.insert(GapKind::OutOfScope, 3);
    map.insert(GapKind::PartiallyExplored, 4);
    assert_eq!(map.len(), 4);
}

// ---------------------------------------------------------------------------
// advance_epoch: epoch recorded in CellAdvanced events
// ---------------------------------------------------------------------------

#[test]
fn test_cell_advanced_event_records_correct_epoch() {
    let mut board = RatchetBoard::new();
    let mut log = RatchetEventLog::new();
    let cell = unproven_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "epoch-ev");
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

    let advanced_event = log
        .events
        .iter()
        .find(|e| matches!(e.kind, RatchetEventKind::CellAdvanced { .. }))
        .unwrap();
    assert_eq!(advanced_event.epoch, 5);
    assert_eq!(board.find_cell(&cid).unwrap().last_advanced_epoch, 5);
}

// ---------------------------------------------------------------------------
// open_gaps_by_priority tie-breaking: same priority preserves insertion order
// ---------------------------------------------------------------------------

#[test]
fn test_open_gaps_by_priority_same_priority_all_returned() {
    let mut ledger = FrontierGapLedger::new();
    let mut log = RatchetEventLog::new();
    for i in 0..5u32 {
        register_gap(
            &mut ledger,
            &mut log,
            gap_entry(
                &format!("tie-{i}"),
                CellDomain::Throughput,
                GapKind::Unknown,
                500_000,
            ),
        )
        .unwrap();
    }
    let sorted = ledger.open_gaps_by_priority();
    assert_eq!(sorted.len(), 5);
    // All have the same priority — just verify all are present
    for i in 0..5u32 {
        assert!(sorted.iter().any(|g| g.gap_id == format!("tie-{i}")));
    }
}

// ---------------------------------------------------------------------------
// find_gap returns None on missing gap
// ---------------------------------------------------------------------------

#[test]
fn test_find_gap_returns_none_for_missing() {
    let ledger = FrontierGapLedger::new();
    assert!(ledger.find_gap("missing-gap").is_none());
}

#[test]
fn test_find_cell_returns_none_for_missing() {
    let board = RatchetBoard::new();
    let cid = cell_id(CellDomain::Memory, ComparisonTarget::Bun, "not-there");
    assert!(board.find_cell(&cid).is_none());
}

// ---------------------------------------------------------------------------
// RatchetError serde: explicit field values survive round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_ratchet_error_margin_regression_serde_values() {
    let cid = cell_id(
        CellDomain::TailLatency,
        ComparisonTarget::Jsc,
        "margin-serde",
    );
    let err = RatchetError::MarginRegressionRejected {
        cell_id: cid.clone(),
        current_margin: 999_999,
        attempted_margin: -1,
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let deser: RatchetError = serde_json::from_str(&json).expect("deserialize");
    match deser {
        RatchetError::MarginRegressionRejected {
            cell_id: dcid,
            current_margin,
            attempted_margin,
        } => {
            assert_eq!(dcid, cid);
            assert_eq!(current_margin, 999_999);
            assert_eq!(attempted_margin, -1);
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// DOMINANCE_SNAPSHOT_SCHEMA_VERSION constant used in constant tests
// ---------------------------------------------------------------------------

#[test]
fn test_dominance_snapshot_schema_version_constant_nonempty() {
    assert!(!DOMINANCE_SNAPSHOT_SCHEMA_VERSION.is_empty());
    assert!(DOMINANCE_SNAPSHOT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn test_all_schema_version_constants_start_with_prefix() {
    let constants = [
        UNIVERSAL_DOMINANCE_RATCHET_SCHEMA_VERSION,
        RATCHET_BOARD_SCHEMA_VERSION,
        FRONTIER_GAP_LEDGER_SCHEMA_VERSION,
        RATCHET_EVENT_LOG_SCHEMA_VERSION,
        DOMINANCE_SNAPSHOT_SCHEMA_VERSION,
    ];
    for c in &constants {
        assert!(
            c.starts_with("franken-engine."),
            "constant {c} should start with 'franken-engine.'"
        );
    }
}
