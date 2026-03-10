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
