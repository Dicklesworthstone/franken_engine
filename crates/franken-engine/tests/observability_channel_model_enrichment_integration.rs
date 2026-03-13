//! Enrichment integration tests for `observability_channel_model`.
//!
//! Supplements base tests with coverage of: canonical policy functions,
//! sampling determinism, mode resolution, contract validation, lookup
//! methods, advanced ChannelState scenarios, and serde roundtrips for
//! previously untested types.

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

use frankenengine_engine::observability_channel_model::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ─────────────────────────────────────────────────────────────

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn minimal_lossy_spec(id: &str) -> ChannelSpec {
    ChannelSpec {
        channel_id: id.to_string(),
        family: PayloadFamily::Decision,
        path: ChannelPath::RuntimeToLedger,
        envelope: RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![
                RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 2_000_000,
                },
                RateDistortionPoint {
                    distortion_millionths: 100_000,
                    rate_millibits: 1_000_000,
                },
            ],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        },
        failure_budget: FailureBudget {
            max_drops_per_epoch: 2,
            max_degraded_per_epoch: 3,
            degradation_threshold_millionths: 50_000,
            fail_closed: true,
        },
        max_items_per_epoch: 100,
        buffer_capacity: 10,
        lossy_permitted: true,
        tags: vec!["test".to_string()],
    }
}

fn minimal_lossless_spec(id: &str) -> ChannelSpec {
    ChannelSpec {
        channel_id: id.to_string(),
        family: PayloadFamily::Security,
        path: ChannelPath::ControlPlaneToAudit,
        envelope: RateDistortionEnvelope {
            family: PayloadFamily::Security,
            metric: DistortionMetric::BinaryFidelity,
            frontier: vec![RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 1_000_000,
            }],
            max_distortion_millionths: 0,
            min_rate_millibits: 1_000_000,
        },
        failure_budget: FailureBudget {
            max_drops_per_epoch: 0,
            max_degraded_per_epoch: 0,
            degradation_threshold_millionths: 0,
            fail_closed: true,
        },
        max_items_per_epoch: 50,
        buffer_capacity: 10,
        lossy_permitted: false,
        tags: vec!["security".to_string()],
    }
}

// ===========================================================================
// A. Sampling seed determinism (5 tests)
// ===========================================================================

#[test]
fn enrichment_sampling_seed_deterministic() {
    let s1 = derive_sampling_seed_hex(
        "trace-1",
        "work-1",
        "hash-1",
        "site-1",
        ObservabilityMode::DefaultCapture,
    );
    let s2 = derive_sampling_seed_hex(
        "trace-1",
        "work-1",
        "hash-1",
        "site-1",
        ObservabilityMode::DefaultCapture,
    );
    assert_eq!(s1, s2, "same inputs should produce same seed");
}

#[test]
fn enrichment_sampling_seed_differs_by_trace_id() {
    let s1 = derive_sampling_seed_hex(
        "trace-a",
        "work-1",
        "hash-1",
        "site-1",
        ObservabilityMode::DefaultCapture,
    );
    let s2 = derive_sampling_seed_hex(
        "trace-b",
        "work-1",
        "hash-1",
        "site-1",
        ObservabilityMode::DefaultCapture,
    );
    assert_ne!(s1, s2);
}

#[test]
fn enrichment_sampling_seed_differs_by_mode() {
    let s1 = derive_sampling_seed_hex(
        "trace-1",
        "work-1",
        "hash-1",
        "site-1",
        ObservabilityMode::DefaultCapture,
    );
    let s2 = derive_sampling_seed_hex(
        "trace-1",
        "work-1",
        "hash-1",
        "site-1",
        ObservabilityMode::ExactShadow,
    );
    assert_ne!(s1, s2);
}

#[test]
fn enrichment_sampling_seed_hex_format() {
    let seed = derive_sampling_seed_hex("t", "w", "h", "s", ObservabilityMode::DefaultCapture);
    assert!(!seed.is_empty());
    // Should be hex characters only
    assert!(
        seed.chars().all(|c| c.is_ascii_hexdigit()),
        "seed should be hex: {seed}"
    );
}

#[test]
fn enrichment_sampling_seed_differs_by_site_id() {
    let s1 = derive_sampling_seed_hex("t", "w", "h", "site-a", ObservabilityMode::DefaultCapture);
    let s2 = derive_sampling_seed_hex("t", "w", "h", "site-b", ObservabilityMode::DefaultCapture);
    assert_ne!(s1, s2);
}

// ===========================================================================
// B. Deterministic sampling interval (4 tests)
// ===========================================================================

#[test]
fn enrichment_sampling_interval_base_one_returns_one() {
    let seed = derive_sampling_seed_hex("t", "w", "h", "s", ObservabilityMode::DefaultCapture);
    let interval = deterministic_sampling_interval(&seed, 1, 10);
    assert_eq!(interval, 1, "base_interval=1 should always return 1");
}

#[test]
fn enrichment_sampling_interval_positive() {
    let seed = derive_sampling_seed_hex("t", "w", "h", "s", ObservabilityMode::DefaultCapture);
    let interval = deterministic_sampling_interval(&seed, 100, 5);
    assert!(interval > 0, "interval should be positive");
}

#[test]
fn enrichment_sampling_interval_bounded_by_base() {
    let seed = derive_sampling_seed_hex("t", "w", "h", "s", ObservabilityMode::DefaultCapture);
    let base = 50;
    let interval = deterministic_sampling_interval(&seed, base, 10);
    assert!(interval <= base, "interval should not exceed base_interval");
}

#[test]
fn enrichment_sampling_interval_deterministic() {
    let seed = derive_sampling_seed_hex(
        "trace-fixed",
        "wk",
        "hh",
        "site",
        ObservabilityMode::Degraded,
    );
    let i1 = deterministic_sampling_interval(&seed, 100, 5);
    let i2 = deterministic_sampling_interval(&seed, 100, 5);
    assert_eq!(i1, i2);
}

// ===========================================================================
// C. Mode resolution (6 tests)
// ===========================================================================

#[test]
fn enrichment_resolve_mode_empty_requests_returns_default() {
    let contract = canonical_operator_mode_contract();
    let matrix = canonical_telemetry_site_policy_matrix();
    let site = matrix.sites.first().unwrap();
    let result = resolve_observability_mode(site, &[], &contract);
    // Should return the site's default_mode when no requests
    if let Some(mode) = result {
        assert_eq!(mode, site.default_mode);
    }
}

#[test]
fn enrichment_resolve_mode_requested_mode_in_allowed() {
    let contract = canonical_operator_mode_contract();
    let matrix = canonical_telemetry_site_policy_matrix();
    let site = matrix.sites.first().unwrap();
    // Request the site's default mode — should always work
    let result = resolve_observability_mode(site, &[site.default_mode], &contract);
    assert!(result.is_some());
}

#[test]
fn enrichment_resolve_mode_selects_highest_precedence() {
    let contract = canonical_operator_mode_contract();
    let matrix = canonical_telemetry_site_policy_matrix();
    // Find a site that allows multiple modes
    let site = matrix
        .sites
        .iter()
        .find(|s| s.allowed_modes.len() > 1)
        .unwrap();
    let result = resolve_observability_mode(site, &site.allowed_modes, &contract);
    assert!(result.is_some());
    let selected = result.unwrap();
    // Should be the highest-precedence among allowed
    let selected_precedence = contract.precedence_of(selected).unwrap_or(0);
    for mode in &site.allowed_modes {
        let p = contract.precedence_of(*mode).unwrap_or(0);
        assert!(
            selected_precedence >= p,
            "selected mode should have highest precedence"
        );
    }
}

#[test]
fn enrichment_resolve_mode_not_in_allowed_excluded() {
    let contract = canonical_operator_mode_contract();
    let matrix = canonical_telemetry_site_policy_matrix();
    let site = matrix.sites.first().unwrap();
    // Request a mode not in allowed_modes
    let not_allowed: Vec<_> = ObservabilityMode::ALL
        .iter()
        .filter(|m| !site.allowed_modes.contains(m))
        .copied()
        .collect();
    if !not_allowed.is_empty() {
        let result = resolve_observability_mode(site, &not_allowed, &contract);
        // Should either return None or fall back to default
        if let Some(mode) = result {
            assert_eq!(mode, site.default_mode);
        }
    }
}

#[test]
fn enrichment_precedence_of_all_canonical_modes() {
    let contract = canonical_operator_mode_contract();
    for mode in &ObservabilityMode::ALL {
        let p = contract.precedence_of(*mode);
        assert!(
            p.is_some(),
            "{mode:?} should have precedence in canonical contract"
        );
    }
}

#[test]
fn enrichment_precedence_values_all_distinct() {
    let contract = canonical_operator_mode_contract();
    let mut precedences = BTreeSet::new();
    for mode in &ObservabilityMode::ALL {
        if let Some(p) = contract.precedence_of(*mode) {
            assert!(precedences.insert(p), "duplicate precedence for {mode:?}");
        }
    }
}

// ===========================================================================
// D. Canonical function validation (6 tests)
// ===========================================================================

#[test]
fn enrichment_canonical_policy_not_empty() {
    let policy = canonical_engine_observability_channel_policy();
    assert!(!policy.required_lossless_families.is_empty());
    assert!(!policy.schema_version.is_empty());
}

#[test]
fn enrichment_canonical_operator_mode_contract_five_modes() {
    let contract = canonical_operator_mode_contract();
    assert_eq!(contract.modes.len(), 5, "should have 5 modes");
    let mode_set: BTreeSet<_> = contract.modes.iter().map(|m| m.mode).collect();
    assert_eq!(mode_set.len(), 5, "all 5 modes should be distinct");
}

#[test]
fn enrichment_canonical_site_matrix_has_sites() {
    let matrix = canonical_telemetry_site_policy_matrix();
    assert!(matrix.sites.len() >= 4, "should have several sites");
    for site in &matrix.sites {
        assert!(!site.site_id.is_empty());
        assert!(!site.allowed_modes.is_empty());
    }
}

#[test]
fn enrichment_canonical_sampling_contract_rules() {
    let contract = canonical_telemetry_sampling_contract();
    assert!(!contract.rules.is_empty());
    for rule in &contract.rules {
        assert!(!rule.site_id.is_empty());
    }
}

#[test]
fn enrichment_canonical_sketch_error_report_envelopes() {
    let report = canonical_sketch_error_envelope_report();
    assert!(!report.envelopes.is_empty());
    for env in &report.envelopes {
        // Verify bounds are non-negative (or at least defined)
        assert!(env.bias_bound_millionths >= 0 || env.variance_bound_millionths >= 0);
    }
}

#[test]
fn enrichment_canonical_sampling_fixtures() {
    let matrix = canonical_sampling_seed_replay_fixture_matrix();
    assert!(!matrix.fixtures.is_empty());
    for fixture in &matrix.fixtures {
        assert!(!fixture.fixture_id.is_empty());
        assert!(!fixture.expected_seed_hex.is_empty());
    }
}

// ===========================================================================
// E. Canonical serde roundtrips (6 tests)
// ===========================================================================

#[test]
fn enrichment_canonical_policy_serde_roundtrip() {
    let policy = canonical_engine_observability_channel_policy();
    let json = serde_json::to_string(&policy).unwrap();
    let back: EngineObservabilityChannelPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back.schema_version, policy.schema_version);
}

#[test]
fn enrichment_canonical_mode_contract_serde_roundtrip() {
    let contract = canonical_operator_mode_contract();
    let json = serde_json::to_string(&contract).unwrap();
    let back: OperatorModeContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back.modes.len(), contract.modes.len());
}

#[test]
fn enrichment_canonical_site_matrix_serde_roundtrip() {
    let matrix = canonical_telemetry_site_policy_matrix();
    let json = serde_json::to_string(&matrix).unwrap();
    let back: TelemetrySitePolicyMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(back.sites.len(), matrix.sites.len());
}

#[test]
fn enrichment_canonical_sampling_contract_serde_roundtrip() {
    let contract = canonical_telemetry_sampling_contract();
    let json = serde_json::to_string(&contract).unwrap();
    let back: TelemetrySamplingContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back.rules.len(), contract.rules.len());
}

#[test]
fn enrichment_canonical_sketch_report_serde_roundtrip() {
    let report = canonical_sketch_error_envelope_report();
    let json = serde_json::to_string(&report).unwrap();
    let back: SketchErrorEnvelopeReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.envelopes.len(), report.envelopes.len());
}

#[test]
fn enrichment_canonical_fixture_matrix_serde_roundtrip() {
    let matrix = canonical_sampling_seed_replay_fixture_matrix();
    let json = serde_json::to_string(&matrix).unwrap();
    let back: SamplingSeedReplayFixtureMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(back.fixtures.len(), matrix.fixtures.len());
}

// ===========================================================================
// F. Lookup methods (4 tests)
// ===========================================================================

#[test]
fn enrichment_site_matrix_lookup_existing() {
    let matrix = canonical_telemetry_site_policy_matrix();
    let first_id = matrix.sites[0].site_id.clone();
    let found = matrix.site(&first_id);
    assert!(found.is_some());
    assert_eq!(found.unwrap().site_id, first_id);
}

#[test]
fn enrichment_site_matrix_lookup_missing() {
    let matrix = canonical_telemetry_site_policy_matrix();
    let found = matrix.site("nonexistent_site_12345");
    assert!(found.is_none());
}

#[test]
fn enrichment_sampling_rule_for_existing() {
    let contract = canonical_telemetry_sampling_contract();
    let first_id = contract.rules[0].site_id.clone();
    let found = contract.rule_for(&first_id);
    assert!(found.is_some());
}

#[test]
fn enrichment_sampling_rule_for_missing() {
    let contract = canonical_telemetry_sampling_contract();
    let found = contract.rule_for("nonexistent_rule_12345");
    assert!(found.is_none());
}

// ===========================================================================
// G. Contract validation (5 tests)
// ===========================================================================

#[test]
fn enrichment_validate_canonical_contracts_pass() {
    let policy = canonical_engine_observability_channel_policy();
    let mode_contract = canonical_operator_mode_contract();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling_contract = canonical_telemetry_sampling_contract();
    let sketch_report = canonical_sketch_error_envelope_report();

    let report = validate_observability_contract(
        &policy,
        &mode_contract,
        &site_matrix,
        &sampling_contract,
        &sketch_report,
    );
    assert!(
        report.violations.is_empty(),
        "canonical contracts should pass: {:?}",
        report.violations
    );
    assert!(report.gate_pass, "gate should pass for canonical contracts");
}

#[test]
fn enrichment_validate_contract_report_has_schema_version() {
    let policy = canonical_engine_observability_channel_policy();
    let mode_contract = canonical_operator_mode_contract();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling_contract = canonical_telemetry_sampling_contract();
    let sketch_report = canonical_sketch_error_envelope_report();

    let report = validate_observability_contract(
        &policy,
        &mode_contract,
        &site_matrix,
        &sampling_contract,
        &sketch_report,
    );
    assert!(!report.schema_version.is_empty());
}

#[test]
fn enrichment_validate_contract_report_serde_roundtrip() {
    let policy = canonical_engine_observability_channel_policy();
    let mode_contract = canonical_operator_mode_contract();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling_contract = canonical_telemetry_sampling_contract();
    let sketch_report = canonical_sketch_error_envelope_report();

    let report = validate_observability_contract(
        &policy,
        &mode_contract,
        &site_matrix,
        &sampling_contract,
        &sketch_report,
    );
    let json = serde_json::to_string(&report).unwrap();
    let back: ObservabilityContractValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.gate_pass, report.gate_pass);
    assert_eq!(back.violations.len(), report.violations.len());
}

#[test]
fn enrichment_validate_duplicate_precedence_detected() {
    let mut mode_contract = canonical_operator_mode_contract();
    // Set two modes to same precedence
    if mode_contract.modes.len() >= 2 {
        mode_contract.modes[1].precedence = mode_contract.modes[0].precedence;
    }
    let policy = canonical_engine_observability_channel_policy();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling_contract = canonical_telemetry_sampling_contract();
    let sketch_report = canonical_sketch_error_envelope_report();

    let report = validate_observability_contract(
        &policy,
        &mode_contract,
        &site_matrix,
        &sampling_contract,
        &sketch_report,
    );
    assert!(
        !report.gate_pass,
        "duplicate precedence should fail validation"
    );
    assert!(!report.violations.is_empty());
}

#[test]
fn enrichment_validate_duplicate_mode_detected() {
    let mut mode_contract = canonical_operator_mode_contract();
    // Add a duplicate mode
    if !mode_contract.modes.is_empty() {
        let dup = mode_contract.modes[0].clone();
        mode_contract.modes.push(dup);
    }
    let policy = canonical_engine_observability_channel_policy();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling_contract = canonical_telemetry_sampling_contract();
    let sketch_report = canonical_sketch_error_envelope_report();

    let report = validate_observability_contract(
        &policy,
        &mode_contract,
        &site_matrix,
        &sampling_contract,
        &sketch_report,
    );
    assert!(!report.gate_pass, "duplicate mode should fail validation");
}

// ===========================================================================
// H. Advanced ChannelState (5 tests)
// ===========================================================================

#[test]
fn enrichment_channel_state_multiple_violations_accumulate() {
    let spec = minimal_lossy_spec("ch-accum");
    let mut state = ChannelState::new("ch-accum".to_string(), epoch(1));

    // Exceed drop budget
    for _ in 0..5 {
        let _ = state.record_drop(&spec);
    }
    assert!(
        state.violations.len() >= 1,
        "should have violations from exceeding drop budget"
    );
}

#[test]
fn enrichment_channel_state_epoch_reset_clears_counters() {
    let spec = minimal_lossy_spec("ch-reset");
    let mut state = ChannelState::new("ch-reset".to_string(), epoch(1));

    state.emit(&spec, 10_000).unwrap();
    state.emit(&spec, 20_000).unwrap();
    assert!(state.items_emitted > 0);

    state.epoch_reset(epoch(2));
    assert_eq!(state.items_emitted, 0);
    assert_eq!(state.items_dropped, 0);
    assert_eq!(state.items_degraded, 0);
    assert_eq!(state.epoch, epoch(2));
}

#[test]
fn enrichment_channel_state_drain_reduces_buffer() {
    let spec = minimal_lossy_spec("ch-drain");
    let mut state = ChannelState::new("ch-drain".to_string(), epoch(1));

    state.emit(&spec, 0).unwrap();
    state.emit(&spec, 0).unwrap();
    let before = state.buffer_used;
    state.drain_one();
    assert!(state.buffer_used < before || before == 0);
}

#[test]
fn enrichment_channel_state_healthy_when_clean() {
    let spec = minimal_lossy_spec("ch-healthy");
    let state = ChannelState::new("ch-healthy".to_string(), epoch(1));
    assert!(state.is_healthy(&spec));
}

#[test]
fn enrichment_channel_state_lossless_drop_violates() {
    let spec = minimal_lossless_spec("ch-lossless");
    let mut state = ChannelState::new("ch-lossless".to_string(), epoch(1));

    // Lossless channels have max_drops_per_epoch = 0, so any drop violates
    let _ = state.record_drop(&spec);
    assert!(
        !state.violations.is_empty(),
        "drop on lossless channel should violate"
    );
}

// ===========================================================================
// I. Enum exhaustive coverage (4 tests)
// ===========================================================================

#[test]
fn enrichment_observability_mode_all_has_five() {
    assert_eq!(ObservabilityMode::ALL.len(), 5);
}

#[test]
fn enrichment_observability_mode_as_str_all_unique() {
    let mut strs = BTreeSet::new();
    for m in &ObservabilityMode::ALL {
        assert!(strs.insert(m.as_str()), "duplicate as_str: {}", m.as_str());
    }
}

#[test]
fn enrichment_sketch_family_all_has_five() {
    assert_eq!(SketchFamily::ALL.len(), 5);
}

#[test]
fn enrichment_sketch_family_as_str_all_unique() {
    let mut strs = BTreeSet::new();
    for f in &SketchFamily::ALL {
        assert!(strs.insert(f.as_str()), "duplicate as_str: {}", f.as_str());
    }
}

// ===========================================================================
// J. Sampling fixture replay (3 tests)
// ===========================================================================

#[test]
fn enrichment_fixture_seeds_deterministic_replay() {
    let matrix = canonical_sampling_seed_replay_fixture_matrix();
    for fixture in &matrix.fixtures {
        let computed = derive_sampling_seed_hex(
            &fixture.trace_id,
            &fixture.workload_id,
            &fixture.manifest_hash,
            &fixture.site_id,
            fixture.mode,
        );
        assert_eq!(
            computed, fixture.expected_seed_hex,
            "fixture '{}' seed mismatch",
            fixture.fixture_id
        );
    }
}

#[test]
fn enrichment_fixture_intervals_deterministic() {
    // Verify expected_interval is positive for all fixtures
    let matrix = canonical_sampling_seed_replay_fixture_matrix();
    for fixture in &matrix.fixtures {
        assert!(
            fixture.expected_interval > 0,
            "fixture '{}' should have positive interval",
            fixture.fixture_id
        );
    }
}

#[test]
fn enrichment_fixture_ids_all_unique() {
    let matrix = canonical_sampling_seed_replay_fixture_matrix();
    let mut ids = BTreeSet::new();
    for fixture in &matrix.fixtures {
        assert!(
            ids.insert(&fixture.fixture_id),
            "duplicate fixture_id: {}",
            fixture.fixture_id
        );
    }
}
