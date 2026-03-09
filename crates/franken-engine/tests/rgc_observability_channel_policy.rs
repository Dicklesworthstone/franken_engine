#![forbid(unsafe_code)]

use std::{collections::BTreeSet, fs, path::PathBuf};

use frankenengine_engine::observability_channel_model::{
    ENGINE_OBSERVABILITY_CHANNEL_POLICY_SCHEMA_VERSION, OPERATOR_MODE_CONTRACT_SCHEMA_VERSION,
    ObservabilityMode, OperatorModeContract, SAMPLING_SEED_REPLAY_FIXTURE_MATRIX_SCHEMA_VERSION,
    SKETCH_ERROR_ENVELOPE_REPORT_SCHEMA_VERSION, TELEMETRY_SAMPLING_CONTRACT_SCHEMA_VERSION,
    TELEMETRY_SITE_POLICY_MATRIX_SCHEMA_VERSION, TelemetrySamplingContract,
    TelemetrySitePolicyMatrix, canonical_engine_observability_channel_policy,
    canonical_operator_mode_contract, canonical_sampling_seed_replay_fixture_matrix,
    canonical_sketch_error_envelope_report, canonical_telemetry_sampling_contract,
    canonical_telemetry_site_policy_matrix, derive_sampling_seed_hex,
    deterministic_sampling_interval, resolve_observability_mode,
};
use serde::{Deserialize, Serialize};

const CONTRACT_SCHEMA_VERSION: &str = "rgc.observability-channel-policy.contract.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_observability_channel_policy_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ObservabilityContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: ContractTrack,
    engine_observability_channel_policy:
        frankenengine_engine::observability_channel_model::EngineObservabilityChannelPolicy,
    operator_mode_contract: OperatorModeContract,
    telemetry_site_policy_matrix: TelemetrySitePolicyMatrix,
    telemetry_sampling_contract: TelemetrySamplingContract,
    sketch_error_envelope_report:
        frankenengine_engine::observability_channel_model::SketchErrorEnvelopeReport,
    sampling_seed_replay_fixture_matrix:
        frankenengine_engine::observability_channel_model::SamplingSeedReplayFixtureMatrix,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ContractTrack {
    id: String,
    name: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> ObservabilityContract {
    serde_json::from_str(CONTRACT_JSON).expect("observability channel policy json must parse")
}

#[test]
fn rgc_066a_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_OBSERVABILITY_CHANNEL_POLICY_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# RGC Observability Channel Policy V1",
        "## Purpose",
        "## Channel Policy",
        "## Operator Modes",
        "## Telemetry Site Policy Matrix",
        "## Sampling And Sketch Contracts",
        "## Replay Fixture Matrix",
        "## Structured Logging And Artifact Contract",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_066a_contract_metadata_is_stable() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-1lsy.11.20.1");
    assert_eq!(contract.generated_by, "bd-1lsy.11.20.1");
    assert_eq!(contract.track.id, "RGC-066A");
    assert_eq!(
        contract.track.name,
        "Engine Telemetry Sampling and Distortion Contract"
    );
    assert!(contract.generated_at_utc.ends_with('Z'));
}

#[test]
fn rgc_066a_engine_policy_matches_canonical_builder() {
    let contract = parse_contract();
    let expected = canonical_engine_observability_channel_policy();

    assert_eq!(
        contract.engine_observability_channel_policy.schema_version,
        ENGINE_OBSERVABILITY_CHANNEL_POLICY_SCHEMA_VERSION
    );
    assert_eq!(contract.engine_observability_channel_policy, expected);
}

#[test]
fn rgc_066a_mode_contract_matches_canonical_builder_and_precedence_is_unique() {
    let contract = parse_contract();
    let expected = canonical_operator_mode_contract();

    assert_eq!(
        contract.operator_mode_contract.schema_version,
        OPERATOR_MODE_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(contract.operator_mode_contract, expected);

    let precedences = contract
        .operator_mode_contract
        .modes
        .iter()
        .map(|entry| entry.precedence)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        precedences.len(),
        contract.operator_mode_contract.modes.len(),
        "operator mode precedence must be unique"
    );
}

#[test]
fn rgc_066a_site_matrix_matches_canonical_builder() {
    let contract = parse_contract();
    let expected = canonical_telemetry_site_policy_matrix();

    assert_eq!(
        contract.telemetry_site_policy_matrix.schema_version,
        TELEMETRY_SITE_POLICY_MATRIX_SCHEMA_VERSION
    );
    assert_eq!(contract.telemetry_site_policy_matrix, expected);

    for site in &contract.telemetry_site_policy_matrix.sites {
        if site.lossless_required {
            assert!(
                site.allowed_sketch_families.is_empty(),
                "lossless site {} cannot allow sketches",
                site.site_id
            );
            assert_eq!(site.distortion_budget_millionths, 0);
        }
    }
}

#[test]
fn rgc_066a_sampling_contract_and_replay_fixtures_match_canonical_builders() {
    let contract = parse_contract();
    let expected_contract = canonical_telemetry_sampling_contract();
    let expected_fixtures = canonical_sampling_seed_replay_fixture_matrix();

    assert_eq!(
        contract.telemetry_sampling_contract.schema_version,
        TELEMETRY_SAMPLING_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(contract.telemetry_sampling_contract, expected_contract);

    assert_eq!(
        contract.sampling_seed_replay_fixture_matrix.schema_version,
        SAMPLING_SEED_REPLAY_FIXTURE_MATRIX_SCHEMA_VERSION
    );
    assert_eq!(contract.sampling_seed_replay_fixture_matrix, expected_fixtures);

    for fixture in &contract.sampling_seed_replay_fixture_matrix.fixtures {
        let rule = contract
            .telemetry_sampling_contract
            .rule_for(&fixture.site_id)
            .expect("fixture site must have a sampling rule");
        let seed = derive_sampling_seed_hex(
            &fixture.trace_id,
            &fixture.workload_id,
            &fixture.manifest_hash,
            &fixture.site_id,
            fixture.mode,
        );
        let interval =
            deterministic_sampling_interval(&seed, rule.base_interval, rule.max_burst_samples);
        assert_eq!(fixture.expected_seed_hex, seed);
        assert_eq!(fixture.expected_interval, interval);
    }
}

#[test]
fn rgc_066a_sketch_envelopes_match_canonical_builder() {
    let contract = parse_contract();
    let expected = canonical_sketch_error_envelope_report();

    assert_eq!(
        contract.sketch_error_envelope_report.schema_version,
        SKETCH_ERROR_ENVELOPE_REPORT_SCHEMA_VERSION
    );
    assert_eq!(contract.sketch_error_envelope_report, expected);

    for envelope in &contract.sketch_error_envelope_report.envelopes {
        assert!(envelope.bias_bound_millionths > 0);
        assert!(envelope.variance_bound_millionths > 0);
        assert!(envelope.required_exact_shadow_samples > 0);
    }
}

#[test]
fn rgc_066a_mode_resolution_prefers_highest_allowed_precedence() {
    let mode_contract = canonical_operator_mode_contract();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let decision_site = site_matrix
        .site("observability_channel_model.decision_lattice")
        .expect("decision site policy");
    let auth_site = site_matrix
        .site("runtime_observability.auth_failure_total")
        .expect("auth site policy");

    let decision_mode = resolve_observability_mode(
        decision_site,
        &[ObservabilityMode::Degraded, ObservabilityMode::ExactShadow],
        &mode_contract,
    )
    .expect("decision mode should resolve");
    assert_eq!(decision_mode, ObservabilityMode::ExactShadow);

    let auth_mode = resolve_observability_mode(
        auth_site,
        &[ObservabilityMode::Degraded, ObservabilityMode::SupportBundleExport],
        &mode_contract,
    )
    .expect("auth mode should resolve");
    assert_eq!(auth_mode, ObservabilityMode::SupportBundleExport);
}

#[test]
fn rgc_066a_operator_verification_commands_are_present() {
    let contract = parse_contract();

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("jq empty docs/rgc_observability_channel_policy_v1.json")),
        "operator verification must include json validation"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("./scripts/run_rgc_observability_channel_policy.sh ci")),
        "operator verification must include gate execution"
    );
    assert!(
        contract.operator_verification.iter().any(|cmd| {
            cmd.contains("./scripts/e2e/rgc_observability_channel_policy_replay.sh ci")
        }),
        "operator verification must include replay command"
    );
}
