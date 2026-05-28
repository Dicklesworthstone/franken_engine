#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use frankenengine_engine::frir_schema::{
    AssumptionRef, ChainVerification, EffectAnnotation, EquivalenceKind, EquivalenceWitness,
    FRIR_SCHEMA_VERSION, FrirArtifact, FrirLoweringPipeline, FrirPipelineEvent, InvariantCheck,
    InvariantKind, LaneTarget, ObligationRef, PassKind, PassWitness, PipelineConfig,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::EffectBoundary;
use serde::Serialize;

// golden_diag lives under tests/_support/ (bd-ub6x8.18); pulled in via #[path]
// so cargo does not compile it as a standalone integration-test binary.
#[path = "_support/golden_diag.rs"]
mod golden_diag;

// bd-ub6x8.6.3: migrated from tests/golden_vectors/ to tests/golden/wire_vectors/.
const GOLDEN_FILE: &str = "tests/golden/wire_vectors/frir_artifact_v1.json";

#[derive(Debug, Serialize)]
struct FrirArtifactGoldenSnapshot {
    coverage_gap: &'static str,
    schema_version: &'static str,
    pipeline_events: Vec<FrirPipelineEvent>,
    chain_verification: ChainVerification,
    artifact: FrirArtifact,
}

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_FILE)
}

// Inline assert_golden + summarize_golden_diff replaced by the shared
// GoldenDiag helper (bd-ub6x8.3).

fn hash(bytes: &[u8]) -> ContentHash {
    ContentHash::compute(bytes)
}

fn invariant(kind: InvariantKind, evidence: &'static [u8]) -> InvariantCheck {
    InvariantCheck {
        kind,
        passed: true,
        description: format!("{kind} preserved by fixed-seed FRIR lowering"),
        evidence_hash: Some(hash(evidence)),
    }
}

fn obligation(id: &str, evidence: &'static [u8]) -> ObligationRef {
    ObligationRef {
        id: id.to_string(),
        description: format!("FRIR proof obligation {id}"),
        discharged: true,
        discharge_evidence: Some(hash(evidence)),
    }
}

fn assumption(id: &str, pass_index: Option<usize>) -> AssumptionRef {
    AssumptionRef {
        id: id.to_string(),
        description: format!("FRIR deterministic lowering assumption {id}"),
        validated: true,
        established_by_pass: pass_index,
    }
}

fn effect_annotation() -> EffectAnnotation {
    EffectAnnotation {
        boundary: EffectBoundary::HostcallEffect,
        required_capabilities: BTreeSet::from([
            "capability:dom.read".to_string(),
            "capability:timer.deterministic".to_string(),
        ]),
        compatible_lanes: BTreeSet::from([LaneTarget::Js, LaneTarget::Baseline]),
        wasm_safe: false,
        requires_dom: true,
    }
}

fn pass_witness(
    pass_index: usize,
    pass_kind: PassKind,
    input: &'static [u8],
    output: &'static [u8],
    offline: bool,
    cost_millionths: i64,
) -> PassWitness {
    PassWitness {
        pass_index,
        pass_kind,
        input_hash: hash(input),
        output_hash: hash(output),
        invariants_checked: vec![
            invariant(
                InvariantKind::SemanticEquivalence,
                b"semantic-equivalence-evidence-v1",
            ),
            invariant(InvariantKind::Determinism, b"determinism-evidence-v1"),
            invariant(
                InvariantKind::CapabilityMonotonicity,
                b"capability-monotonicity-evidence-v1",
            ),
        ],
        obligations_touched: vec![obligation(
            &format!("frir.pass.{pass_index}.fixed-seed"),
            b"fixed-seed-obligation-evidence-v1",
        )],
        assumptions: vec![assumption(
            &format!("frir.pass.{pass_index}.stable-input-order"),
            Some(pass_index),
        )],
        effect_annotations: vec![effect_annotation()],
        target_lane: LaneTarget::Js,
        computed_offline: offline,
        computation_cost_millionths: cost_millionths,
        witness_hash: hash(&[input, output, format!("{pass_kind}").as_bytes()].concat()),
    }
}

fn frir_artifact_snapshot() -> FrirArtifactGoldenSnapshot {
    let mut config = PipelineConfig::offline_analysis();
    config.target_lane = LaneTarget::Js;
    config.max_passes = 8;

    let source = b"function Component(){ return view(model.count); }";
    let ir1 = b"ir1:component:function:stable-bindings";
    let ir2 = b"ir2:component:capability-annotated:dom.read";

    let mut pipeline = FrirLoweringPipeline::new(config);
    pipeline
        .record_pass(pass_witness(0, PassKind::Parse, source, ir1, true, 125_000))
        .expect("parse pass witness should record");
    pipeline
        .record_pass(pass_witness(
            1,
            PassKind::CapabilityAnnotate,
            ir1,
            ir2,
            true,
            175_000,
        ))
        .expect("capability pass witness should record");

    pipeline.record_equivalence_witness(EquivalenceWitness {
        reference_hash: hash(b"baseline-js-output-v1"),
        optimized_hash: hash(ir2),
        equivalence_kind: EquivalenceKind::Trace,
        test_input_count: 16,
        all_outputs_matched: true,
        counterexample_hash: None,
        preserved_invariants: vec![
            InvariantKind::SemanticEquivalence,
            InvariantKind::CapabilityMonotonicity,
            InvariantKind::Determinism,
        ],
        witness_hash: hash(b"frir-equivalence-witness-v1"),
    });

    let artifact = pipeline
        .finalize(hash(source))
        .expect("fixed FRIR artifact should finalize");
    let chain_verification = artifact.witness_chain.verify();

    assert!(chain_verification.valid);
    assert!(artifact.is_valid());
    assert!(artifact.all_equivalences_proven());

    FrirArtifactGoldenSnapshot {
        coverage_gap: "FRIR proof-carrying artifact JSON serialization",
        schema_version: FRIR_SCHEMA_VERSION,
        pipeline_events: pipeline.events().to_vec(),
        chain_verification,
        artifact,
    }
}

#[test]
fn frir_artifact_json_matches_golden() {
    let snapshot = frir_artifact_snapshot();
    let actual = format!("{}\n", serde_json::to_string_pretty(&snapshot).unwrap());
    let path = golden_path();
    golden_diag::GoldenDiag {
        framework_name: "FRIR artifact golden",
        regen_env_var: "UPDATE_GOLDENS",
    }
    .assert_golden_match(&actual, &path, "frir_artifact_json_matches_golden", None);
}
