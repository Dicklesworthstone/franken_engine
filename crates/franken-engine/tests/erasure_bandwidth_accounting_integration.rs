#![forbid(unsafe_code)]

//! Integration coverage for the erasure-vs-replication bandwidth accounting
//! (`bd-cixqu.35.3`, Track II.3).
//!
//! These tests exercise the public bandwidth-accounting API against the shipped
//! erasure gossip encoder/reconstructor, validating both (a) that the reported
//! byte accounting is faithful to a real encode/reconstruct round-trip, and (b)
//! that the erasure gossip protocol itself remains correct — reconstruction
//! succeeds from the data shards, tolerates one lost data shard via parity, and
//! rejects two losses — across the documented fleet topologies and payload sizes.

use frankenengine_engine::erasure_bandwidth_accounting::{
    BANDWIDTH_REPORT_SCHEMA, BandwidthComparisonConfig, build_report, build_signed_report,
    erasure_convergence_rounds, full_replication_rounds, measure_cell, shard_wire_bytes,
};
use frankenengine_engine::erasure_reconstruction_receipts::{
    XOR_SINGLE_PARITY_SCHEME, reconstruct_with_receipt,
};
use frankenengine_engine::fleet_immune_protocol::{
    ErasureCodingPlan, ErasureShard, NodeId, encode_erasure_shards, reconstruct_erasure_payload,
};

const FLEET_SIZES: [u64; 5] = [10, 50, 100, 500, 1000];
const PAYLOAD_SIZES: [u64; 4] = [1_024, 10_240, 102_400, 1_048_576];

fn deterministic_payload(len: u64) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Encode the same deterministic payload the accounting module measures.
fn encode_for(fleet_size: u64, payload_bytes: u64) -> Vec<ErasureShard> {
    let plan = ErasureCodingPlan::tuned(fleet_size as usize, 0);
    encode_erasure_shards(
        "bandwidth-set",
        NodeId::new("bandwidth-origin"),
        1,
        1_000_000,
        &deterministic_payload(payload_bytes),
        plan,
    )
    .expect("shipped encoder must accept a tuned plan")
}

// ---------------------------------------------------------------------------
// (a) Bandwidth accounting is faithful to a real encode round-trip.
// ---------------------------------------------------------------------------

#[test]
fn every_topology_encodes_and_the_plan_matches_the_cell() {
    for &fleet in &FLEET_SIZES {
        for &payload in &PAYLOAD_SIZES {
            let cell = measure_cell(fleet, payload, 3).unwrap();
            let plan = ErasureCodingPlan::tuned(fleet as usize, 0);
            assert_eq!(cell.data_shards, plan.data_shards);
            assert_eq!(cell.total_shards, plan.total_shards);
            assert_eq!(cell.parity_shards, plan.parity_shards());
            assert_eq!(cell.total_shards as u64, fleet);
        }
    }
}

#[test]
fn emitted_bytes_equal_the_sum_of_real_shard_wire_sizes() {
    for &fleet in &[10u64, 100, 1000] {
        for &payload in &PAYLOAD_SIZES {
            let cell = measure_cell(fleet, payload, 3).unwrap();
            let shards = encode_for(fleet, payload);
            let real_total: u64 = shards.iter().map(shard_wire_bytes).sum();
            assert_eq!(
                cell.erasure_as_emitted_bytes, real_total,
                "fleet={fleet} payload={payload}"
            );
        }
    }
}

#[test]
fn data_shard_bytes_equal_first_k_real_shards() {
    for &fleet in &[10u64, 50, 500] {
        let payload = 102_400;
        let cell = measure_cell(fleet, payload, 3).unwrap();
        let shards = encode_for(fleet, payload);
        let k = cell.data_shards as usize;
        let real_k: u64 = shards.iter().take(k).map(shard_wire_bytes).sum();
        assert_eq!(cell.data_shard_wire_bytes, real_k);
    }
}

// ---------------------------------------------------------------------------
// (b) Erasure gossip protocol correctness under coding.
// ---------------------------------------------------------------------------

#[test]
fn reconstructs_from_all_data_shards_across_topologies() {
    for &fleet in &FLEET_SIZES {
        let payload = 10_240;
        let shards = encode_for(fleet, payload);
        let data: Vec<ErasureShard> = shards.iter().filter(|s| s.is_data()).cloned().collect();
        let recovered = reconstruct_erasure_payload(&data).unwrap();
        assert_eq!(recovered, deterministic_payload(payload), "fleet={fleet}");
    }
}

#[test]
fn tolerates_one_missing_data_shard_via_parity() {
    for &fleet in &[10u64, 50, 100] {
        let payload = 4_096;
        let shards = encode_for(fleet, payload);
        // Drop data shard index 0, keep the rest of the data shards + a parity.
        let available: Vec<ErasureShard> = shards
            .iter()
            .filter(|s| !(s.is_data() && s.shard_index == 0))
            .cloned()
            .collect();
        let recovered = reconstruct_erasure_payload(&available).unwrap();
        assert_eq!(recovered, deterministic_payload(payload), "fleet={fleet}");
    }
}

#[test]
fn rejects_two_missing_data_shards() {
    // Single-parity: two erasures are unrecoverable. This is the honesty crux.
    let fleet = 100;
    let payload = 8_192;
    let shards = encode_for(fleet, payload);
    let available: Vec<ErasureShard> = shards
        .iter()
        .filter(|s| !(s.is_data() && (s.shard_index == 0 || s.shard_index == 1)))
        .cloned()
        .collect();
    assert!(
        reconstruct_erasure_payload(&available).is_err(),
        "two data-shard erasures must NOT be recoverable under XOR single-parity"
    );
}

#[test]
fn reconstruction_receipt_records_xor_single_parity_scheme() {
    let fleet = 50;
    let payload = 16_384;
    let shards = encode_for(fleet, payload);
    let data: Vec<ErasureShard> = shards.iter().filter(|s| s.is_data()).cloned().collect();
    let (recovered, receipt) =
        reconstruct_with_receipt(&data, NodeId::new("recon"), 2_000_000).unwrap();
    assert_eq!(recovered, deterministic_payload(payload));
    assert_eq!(receipt.coding_scheme, XOR_SINGLE_PARITY_SCHEME);
    receipt.verify().unwrap();
}

#[test]
fn parity_shards_are_identical_copies() {
    // When the tuned plan allocates multiple parity slots they must be identical
    // (the property that makes them add duplication, not recovery capacity).
    let fleet = 100; // parity = 33
    let shards = encode_for(fleet, 65_536);
    let parity: Vec<&ErasureShard> = shards.iter().filter(|s| s.is_parity()).collect();
    assert!(parity.len() > 1, "fleet=100 should allocate >1 parity slot");
    let first = &parity[0].shard_payload;
    for p in &parity {
        assert_eq!(
            &p.shard_payload, first,
            "all parity copies must be identical"
        );
    }
}

// ---------------------------------------------------------------------------
// Savings semantics and scaling.
// ---------------------------------------------------------------------------

#[test]
fn measured_savings_never_exceed_theoretical_ceiling() {
    for &fleet in &FLEET_SIZES {
        for &payload in &PAYLOAD_SIZES {
            let cell = measure_cell(fleet, payload, 3).unwrap();
            if cell.fault_tolerance_erasures == 1 {
                assert!(
                    cell.savings_ratio_millionths
                        <= cell.theoretical_savings_ceiling_millionths as i64,
                    "fleet={fleet} payload={payload}: measured {} > ceiling {}",
                    cell.savings_ratio_millionths,
                    cell.theoretical_savings_ceiling_millionths
                );
            }
        }
    }
}

#[test]
fn large_payloads_realize_positive_savings() {
    // At 1 MiB every documented fleet size should net a positive fault-tolerance
    // -normalized saving.
    for &fleet in &FLEET_SIZES {
        let cell = measure_cell(fleet, 1_048_576, 3).unwrap();
        assert!(
            cell.savings_ratio_millionths > 0,
            "fleet={fleet}: expected positive savings, got {}",
            cell.savings_ratio_millionths
        );
    }
}

#[test]
fn tiny_payload_over_large_fleet_is_overhead_dominated() {
    let cell = measure_cell(1000, 1_024, 3).unwrap();
    assert!(cell.overhead_exceeds_savings);
    assert!(cell.savings_ratio_millionths < 0);
}

#[test]
fn savings_improve_with_payload_size_for_fixed_fleet() {
    let fleet = 100;
    let mut prev = i64::MIN;
    for &payload in &PAYLOAD_SIZES {
        let cell = measure_cell(fleet, payload, 3).unwrap();
        assert!(
            cell.savings_ratio_millionths >= prev,
            "savings should be non-decreasing in payload; payload={payload}"
        );
        prev = cell.savings_ratio_millionths;
    }
}

#[test]
fn theoretical_ceiling_increases_with_fleet_size() {
    let mut prev = 0u64;
    for &fleet in &FLEET_SIZES {
        let cell = measure_cell(fleet, 1_048_576, 3).unwrap();
        assert!(
            cell.theoretical_savings_ceiling_millionths >= prev,
            "ceiling should be non-decreasing in fleet; fleet={fleet}"
        );
        prev = cell.theoretical_savings_ceiling_millionths;
        assert!(cell.theoretical_savings_ceiling_millionths < 500_000);
    }
}

#[test]
fn full_broadcast_dominates_emitted_shards_for_large_fleets() {
    // The context lens: broadcasting a full copy to every node vastly exceeds the
    // erasure lane's emitted-shard volume for a large fleet + large payload.
    let cell = measure_cell(1000, 1_048_576, 3).unwrap();
    assert!(cell.full_broadcast_bytes > cell.erasure_as_emitted_bytes);
}

#[test]
fn per_cell_wire_bytes_are_positive() {
    for &fleet in &FLEET_SIZES {
        for &payload in &PAYLOAD_SIZES {
            let cell = measure_cell(fleet, payload, 3).unwrap();
            assert!(cell.full_copy_wire_bytes > 0);
            assert!(cell.data_shard_wire_bytes > 0);
            assert!(cell.erasure_as_emitted_bytes > 0);
            assert!(cell.parity_shard_wire_bytes > 0); // every documented fleet >1 has parity
        }
    }
}

// ---------------------------------------------------------------------------
// Convergence model.
// ---------------------------------------------------------------------------

#[test]
fn full_replication_rounds_are_monotone_in_fleet() {
    let mut prev = 0u64;
    for &fleet in &FLEET_SIZES {
        let rounds = full_replication_rounds(fleet, 3);
        assert!(
            rounds >= prev,
            "rounds should be non-decreasing; fleet={fleet}"
        );
        prev = rounds;
    }
}

#[test]
fn erasure_convergence_is_at_least_dissemination() {
    for &fleet in &FLEET_SIZES {
        let plan = ErasureCodingPlan::tuned(fleet as usize, 0);
        let disseminate = full_replication_rounds(fleet, 3);
        let converge = erasure_convergence_rounds(fleet, plan.data_shards, 3);
        assert!(converge >= disseminate, "fleet={fleet}");
    }
}

#[test]
fn convergence_model_covers_every_fleet_size() {
    let report = build_report(&BandwidthComparisonConfig::default()).unwrap();
    assert_eq!(report.convergence_model.len(), FLEET_SIZES.len());
    for point in &report.convergence_model {
        assert!(point.analytical_model);
        assert!(point.erasure_convergence_rounds >= point.full_replication_rounds);
        assert!(point.erasure_total_bytes > 0);
        assert!(point.full_replication_total_bytes > 0);
    }
}

// ---------------------------------------------------------------------------
// Report shape, determinism, honesty.
// ---------------------------------------------------------------------------

#[test]
fn default_report_has_expected_cardinality() {
    let report = build_report(&BandwidthComparisonConfig::default()).unwrap();
    assert_eq!(report.schema_version, BANDWIDTH_REPORT_SCHEMA);
    assert_eq!(report.cells.len(), FLEET_SIZES.len() * PAYLOAD_SIZES.len());
    assert_eq!(report.scaling_analysis.len(), FLEET_SIZES.len());
    assert_eq!(report.scheme_fault_tolerance_erasures, 1);
}

#[test]
fn report_coding_scheme_is_honest_xor_single_parity() {
    let report = build_report(&BandwidthComparisonConfig::default()).unwrap();
    assert_eq!(report.coding_scheme, "xor-single-parity-v1");
    assert!(
        report
            .honesty_notes
            .iter()
            .any(|n| n.contains("NOT Reed-Solomon"))
    );
    assert!(
        report
            .honesty_notes
            .iter()
            .any(|n| n.contains("(k-1)/(2k)"))
    );
}

#[test]
fn report_never_serializes_a_reed_solomon_scheme_id() {
    let report = build_report(&BandwidthComparisonConfig::default()).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    // The coding_scheme field is the single source of truth for the scheme id.
    assert!(json.contains("\"coding_scheme\":\"xor-single-parity-v1\""));
    // The scheme field value must never be a Reed-Solomon id. Note the honesty
    // notes DO mention "NOT Reed-Solomon over GF(2^8)" as a disclaimer — that is
    // desirable and must not trip this check, so we only forbid an RS *value*.
    assert!(
        !json
            .to_lowercase()
            .contains("\"coding_scheme\":\"reed-solomon")
    );
}

#[test]
fn signed_report_is_byte_identical_across_runs() {
    let config = BandwidthComparisonConfig::default();
    let a = serde_json::to_vec(&build_signed_report(&config).unwrap()).unwrap();
    let b = serde_json::to_vec(&build_signed_report(&config).unwrap()).unwrap();
    assert_eq!(a, b, "signed report must replay byte-for-byte");
}

#[test]
fn signed_report_hash_is_stable_and_verifiable() {
    let config = BandwidthComparisonConfig::default();
    let signed = build_signed_report(&config).unwrap();
    let recomputed = frankenengine_engine::hash_tiers::ContentHash::compute(
        &serde_json::to_vec(&signed.report).unwrap(),
    )
    .to_hex();
    assert_eq!(signed.report_hash, recomputed);
    assert!(!signed.signature_hex.is_empty());
    assert!(!signed.verification_key.is_empty());
}

#[test]
fn custom_config_round_trips_through_serde() {
    let config = BandwidthComparisonConfig {
        fleet_sizes: vec![7, 33],
        payload_sizes: vec![2_048, 65_536],
        fanout: 5,
    };
    let report = build_report(&config).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let restored: frankenengine_engine::erasure_bandwidth_accounting::BandwidthEfficiencyReport =
        serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
    assert_eq!(report.config.fanout, 5);
}

#[test]
fn invalid_config_is_rejected_by_build_report() {
    let config = BandwidthComparisonConfig {
        fleet_sizes: vec![],
        payload_sizes: vec![1_024],
        fanout: 3,
    };
    assert!(build_report(&config).is_err());
}

#[test]
fn scaling_analysis_best_payload_is_the_largest_for_large_fleets() {
    // For large fleets the best per-fleet savings is at the largest payload
    // (framing overhead is amortized best there).
    let report = build_report(&BandwidthComparisonConfig::default()).unwrap();
    let big = report
        .scaling_analysis
        .iter()
        .find(|s| s.fleet_size == 1000)
        .unwrap();
    assert_eq!(big.best_payload_bytes, 1_048_576);
}

#[test]
fn scaling_analysis_counts_overhead_dominated_payloads() {
    let report = build_report(&BandwidthComparisonConfig::default()).unwrap();
    let big = report
        .scaling_analysis
        .iter()
        .find(|s| s.fleet_size == 1000)
        .unwrap();
    // At least the 1 KiB payload over a 1000-node fleet is overhead-dominated.
    assert!(big.payloads_overhead_dominated >= 1);
}

#[test]
fn small_fleet_has_fewer_overhead_dominated_payloads_than_large() {
    let report = build_report(&BandwidthComparisonConfig::default()).unwrap();
    let small = report
        .scaling_analysis
        .iter()
        .find(|s| s.fleet_size == 10)
        .unwrap();
    let large = report
        .scaling_analysis
        .iter()
        .find(|s| s.fleet_size == 1000)
        .unwrap();
    assert!(small.payloads_overhead_dominated <= large.payloads_overhead_dominated);
}

#[test]
fn cells_are_ordered_by_fleet_then_payload() {
    let report = build_report(&BandwidthComparisonConfig::default()).unwrap();
    let mut idx = 0;
    for &fleet in &FLEET_SIZES {
        for &payload in &PAYLOAD_SIZES {
            assert_eq!(report.cells[idx].fleet_size, fleet);
            assert_eq!(report.cells[idx].payload_bytes, payload);
            idx += 1;
        }
    }
}

#[test]
fn full_replication_bytes_are_two_copies_when_parity_present() {
    for &fleet in &FLEET_SIZES {
        let cell = measure_cell(fleet, 102_400, 3).unwrap();
        assert_eq!(cell.fault_tolerance_erasures, 1);
        assert_eq!(cell.full_replication_bytes, 2 * cell.full_copy_wire_bytes);
    }
}

#[test]
fn erasure_coded_bytes_are_data_plus_one_parity() {
    let cell = measure_cell(500, 1_048_576, 3).unwrap();
    assert_eq!(
        cell.erasure_coded_bytes,
        cell.data_shard_wire_bytes + cell.parity_shard_wire_bytes
    );
}

#[test]
fn metadata_overhead_is_reported_and_positive() {
    for &fleet in &FLEET_SIZES {
        let cell = measure_cell(fleet, 102_400, 3).unwrap();
        assert!(cell.shard_metadata_overhead_bytes > 0);
    }
}

#[test]
fn chunk_len_matches_ceiling_division_across_cells() {
    for &fleet in &FLEET_SIZES {
        for &payload in &PAYLOAD_SIZES {
            let cell = measure_cell(fleet, payload, 3).unwrap();
            let expected = payload.div_ceil(u64::from(cell.data_shards));
            assert_eq!(cell.chunk_len, expected, "fleet={fleet} payload={payload}");
        }
    }
}

#[test]
fn reconstruct_round_trip_matches_payload_hash_for_all_topologies() {
    // Full protocol correctness: encode → drop up to one data shard → reconstruct.
    for &fleet in &FLEET_SIZES {
        let payload = 32_768;
        let shards = encode_for(fleet, payload);
        // Keep all data shards but one, plus parity.
        let available: Vec<ErasureShard> = shards
            .iter()
            .filter(|s| !(s.is_data() && s.shard_index == 2))
            .cloned()
            .collect();
        let recovered = reconstruct_erasure_payload(&available).unwrap();
        assert_eq!(recovered, deterministic_payload(payload), "fleet={fleet}");
    }
}

#[test]
fn single_node_fleet_degenerates_to_no_redundancy() {
    let cell = measure_cell(1, 4_096, 3).unwrap();
    assert_eq!(cell.parity_shards, 0);
    assert_eq!(cell.fault_tolerance_erasures, 0);
    // Full replication at fault-tolerance 0 is a single copy.
    assert_eq!(cell.full_replication_bytes, cell.full_copy_wire_bytes);
}

#[test]
fn convergence_reference_payload_is_the_largest_configured() {
    let report = build_report(&BandwidthComparisonConfig::default()).unwrap();
    for point in &report.convergence_model {
        assert_eq!(point.reference_payload_bytes, 1_048_576);
    }
}

#[test]
fn zero_payload_cells_are_encodable_but_carry_framing() {
    let config = BandwidthComparisonConfig {
        fleet_sizes: vec![10, 100],
        payload_sizes: vec![0],
        fanout: 3,
    };
    let report = build_report(&config).unwrap();
    for cell in &report.cells {
        assert_eq!(cell.payload_bytes, 0);
        assert_eq!(cell.chunk_len, 0);
        assert!(cell.erasure_as_emitted_bytes > 0);
    }
}
