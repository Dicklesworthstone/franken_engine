#![forbid(unsafe_code)]
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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use frankenengine_engine::certified_optimization_governance::{
    CertificateStatus, ForensicEntry, ForensicSurface, GovernanceConfig, GovernanceReport,
    GovernanceState, OptimizationCertificate, OptimizationTier, RollbackRecord, RollbackTrigger,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::translation_validation_receipt::{
    AppliedRuleRecord, EmitInput, EmitResult, EmitterConfig, ProofEvidence, ProofMode,
    ReceiptSummary, ReceiptVerdict, TranslationValidationReceipt, ValidationReceiptEmitter,
};
use frankenengine_engine::versioned_rewrite_pack::{
    DeterministicCostModel, InstructionCostClass, InterferenceMetadata, PackCatalog, PackVersion,
    RewriteCategory, RewritePack, RewriteRuleEntry, RuleInterference, RuleInterferenceKind,
};
use serde::{Deserialize, Serialize};

const PROOF_INDEX_SCHEMA_VERSION: &str =
    "franken-engine.rgc-certified-optimization-harness.proof-index.v1";
const TRACE_IDS_SCHEMA_VERSION: &str =
    "franken-engine.rgc-certified-optimization-harness.trace-ids.v1";
const RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.rgc-certified-optimization-harness.run-manifest.v1";
const EGRAPH_REWRITE_PACK_ARTIFACT: &str = "egraph_rewrite_pack.json";
const BEAD_ID: &str = "bd-1lsy.7.7";
const COMPONENT: &str = "rgc_certified_optimization_harness";
const SCENARIO_ID: &str = "rgc-607-certified-optimization-harness";
const ARTIFACT_ENV: &str = "RGC_CERTIFIED_OPTIMIZATION_HARNESS_ARTIFACT_DIR";
const GENERATED_AT_UNIX_MS: u64 = 1_700_006_070_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RewritePackIndexEntry {
    pack_id: String,
    pack_version: String,
    rule_count: usize,
    enabled_rule_count: usize,
    proven_sound_count: usize,
    soundness_rate_millionths: i64,
    cost_model_id: String,
    content_hash: ContentHash,
    has_internal_blocking: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OptimizationProofEntry {
    optimization_id: String,
    pack_id: String,
    receipt_hash: ContentHash,
    verdict: String,
    rule_ids: Vec<String>,
    total_cost_delta_millionths: i64,
    publishable_evidence: bool,
    quarantined: bool,
    all_rules_proven_sound: bool,
    block_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RewriteProofIndex {
    schema_version: String,
    bead_id: String,
    component: String,
    scenario_id: String,
    generated_at_unix_ms: u64,
    pack_catalog_id: String,
    pack_catalog_hash: ContentHash,
    cost_model_id: String,
    rewrite_packs: Vec<RewritePackIndexEntry>,
    receipt_summary: ReceiptSummary,
    governance_report: GovernanceReport,
    publishable_optimization_ids: Vec<String>,
    blocked_optimization_ids: Vec<String>,
    quarantined_optimization_ids: Vec<String>,
    optimization_entries: Vec<OptimizationProofEntry>,
    required_artifacts: Vec<String>,
    module_sources: Vec<String>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CertifiedOptimizationTraceIds {
    schema_version: String,
    trace_ids: Vec<String>,
    decision_ids: Vec<String>,
    policy_ids: Vec<String>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn repo_relative_env_path(var: &str, default_relative: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                repo_root().join(path)
            }
        })
        .unwrap_or_else(|| repo_root().join(default_relative))
}

fn artifact_output_dir() -> PathBuf {
    std::env::var_os(ARTIFACT_ENV)
        .map(|_| repo_relative_env_path(ARTIFACT_ENV, "artifacts"))
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "rgc-certified-optimization-harness-{}",
                process::id()
            ))
        })
}

fn epoch(raw: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(raw)
}

fn hash(bytes: &[u8]) -> ContentHash {
    ContentHash::compute(bytes)
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("artifact payload should serialize"),
    )
    .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
}

fn build_cost_model() -> DeterministicCostModel {
    let mut instruction_costs = BTreeMap::new();
    instruction_costs.insert(InstructionCostClass::Arithmetic, 1_000_000);
    instruction_costs.insert(InstructionCostClass::Allocation, 9_000_000);
    instruction_costs.insert(InstructionCostClass::ControlFlow, 2_000_000);

    let mut rule_gains = BTreeMap::new();
    rule_gains.insert("rule-fold-const".to_string(), 280_000);
    rule_gains.insert("rule-prune-dead-branch".to_string(), 180_000);

    let mut rule_application_costs = BTreeMap::new();
    rule_application_costs.insert("rule-fold-const".to_string(), 40_000);
    rule_application_costs.insert("rule-prune-dead-branch".to_string(), 30_000);

    DeterministicCostModel::new(
        "rgc-607-certified-opt-cost-v1",
        instruction_costs,
        rule_gains,
        rule_application_costs,
    )
}

fn build_demo_pack(cost_model: &DeterministicCostModel) -> RewritePack {
    let rules = vec![
        RewriteRuleEntry {
            rule_id: "rule-fold-const".to_string(),
            category: RewriteCategory::AlgebraicSimplification,
            description: "Fold constant arithmetic into immediate literals.".to_string(),
            pattern_hash: hash(b"pattern-fold-const"),
            replacement_hash: hash(b"replacement-fold-const"),
            proven_sound: true,
            priority_millionths: 900_000,
            affected_cost_classes: BTreeSet::from([InstructionCostClass::Arithmetic]),
            enabled: true,
        },
        RewriteRuleEntry {
            rule_id: "rule-prune-dead-branch".to_string(),
            category: RewriteCategory::DeadCodeElimination,
            description: "Elide branches proven unreachable after folding.".to_string(),
            pattern_hash: hash(b"pattern-prune-dead-branch"),
            replacement_hash: hash(b"replacement-prune-dead-branch"),
            proven_sound: true,
            priority_millionths: 850_000,
            affected_cost_classes: BTreeSet::from([
                InstructionCostClass::ControlFlow,
                InstructionCostClass::Allocation,
            ]),
            enabled: true,
        },
    ];

    let interference = InterferenceMetadata::build(vec![RuleInterference {
        rule_a: "rule-fold-const".to_string(),
        rule_b: "rule-prune-dead-branch".to_string(),
        kind: RuleInterferenceKind::None,
        is_blocking: false,
        detail: "demo pack keeps rule ordering deterministic without blocking overlap".to_string(),
    }]);

    RewritePack::new(
        "demo-certified-pack",
        PackVersion::CURRENT,
        epoch(7),
        "Parent-level certified optimization harness demo pack.",
        rules,
        interference,
        &cost_model.model_id,
    )
}

fn applied_rule(
    pack: &RewritePack,
    rule_id: &str,
    before: &[u8],
    after: &[u8],
) -> AppliedRuleRecord {
    let rule = pack
        .rule_by_id(rule_id)
        .unwrap_or_else(|| panic!("missing demo rule {rule_id}"));
    AppliedRuleRecord {
        pack_id: pack.pack_id.clone(),
        pack_version: pack.version,
        rule_id: rule.rule_id.clone(),
        category: rule.category,
        before_hash: hash(before),
        after_hash: hash(after),
        cost_delta_millionths: -210_000,
        rule_proven_sound: rule.proven_sound,
    }
}

fn approved_verdict() -> ReceiptVerdict {
    ReceiptVerdict::Proven {
        evidence: ProofEvidence::new(ProofMode::Composite, hash(b"proof-approved"), 48, 4_200)
            .with_metadata("mode_detail", "symbolic+golden"),
    }
}

fn rejected_verdict() -> ReceiptVerdict {
    ReceiptVerdict::Disproven {
        counterexample_hash: hash(b"counterexample-rejected"),
        divergence: "differential replay diverged after branch pruning".to_string(),
    }
}

fn build_emitter(cost_model: &DeterministicCostModel) -> ValidationReceiptEmitter {
    let config = EmitterConfig {
        chain_id: "rgc-607-certified-optimization-harness".to_string(),
        signing_key: vec![7u8; 32],
        default_cost_model_id: cost_model.model_id.clone(),
        ..EmitterConfig::default()
    };
    ValidationReceiptEmitter::new(config, epoch(7))
}

fn build_governance_state(proof_hash: ContentHash) -> GovernanceState {
    let mut state = GovernanceState::new(epoch(7));
    let certificate = OptimizationCertificate {
        cert_id: "cert-approved".to_string(),
        tier: OptimizationTier::Aggressive,
        function_id: "fn.render".to_string(),
        rewrite_count: 2,
        proof_hash,
        issued_epoch: epoch(6),
        expiry_epoch: epoch(25),
        translation_receipt_valid: true,
        status: CertificateStatus::Valid,
    };

    state.add_certificate(certificate.clone());
    state
        .promote_tier(
            "fn.render",
            OptimizationTier::Aggressive,
            Some(&certificate),
        )
        .expect("approved tier should promote with valid certificate");
    state.record_rollback(RollbackRecord {
        record_id: "rollback-rejected".to_string(),
        function_id: "fn.blocked".to_string(),
        trigger: RollbackTrigger::ProofFailure,
        from_tier: OptimizationTier::Aggressive,
        to_tier: OptimizationTier::Baseline,
        epoch: epoch(7),
        reason: "translation validation rejected blocked optimization".to_string(),
        elapsed_steps: 64,
    });
    state.add_forensic_entry(ForensicEntry {
        entry_id: "forensic-approved".to_string(),
        surface: ForensicSurface::ProofArtifact,
        function_id: "fn.render".to_string(),
        tier: OptimizationTier::Aggressive,
        description: "approved rewrite chain linked to proof artifact".to_string(),
        artifact_hash: hash(b"approved-proof-artifact"),
        epoch: epoch(7),
    });
    state
}

fn receipt_verdict_name(receipt: &TranslationValidationReceipt) -> &'static str {
    match &receipt.verdict {
        ReceiptVerdict::Proven { .. } => "proven",
        ReceiptVerdict::Disproven { .. } => "disproven",
        ReceiptVerdict::Inconclusive { .. } => "inconclusive",
    }
}

fn block_reason_for(receipt: &TranslationValidationReceipt, quarantined: bool) -> Option<String> {
    if receipt.permits_activation() {
        return None;
    }

    match &receipt.verdict {
        ReceiptVerdict::Proven { .. } => None,
        ReceiptVerdict::Disproven { divergence, .. } => Some(format!(
            "{}{}",
            if quarantined {
                "quarantined_after_counterexample: "
            } else {
                "counterexample: "
            },
            divergence
        )),
        ReceiptVerdict::Inconclusive { reason, .. } => Some(format!("inconclusive: {reason}")),
    }
}

fn build_demo_index() -> (RewriteProofIndex, CertifiedOptimizationTraceIds) {
    let cost_model = build_cost_model();
    let pack = build_demo_pack(&cost_model);
    let mut catalog = PackCatalog::new("rgc-607-demo-catalog");
    assert!(catalog.register(pack.clone()), "demo pack should register");

    let mut emitter = build_emitter(&cost_model);
    let approved_result = emitter.emit(EmitInput {
        optimization_id: "opt-approved".to_string(),
        baseline_ir_hash: hash(b"baseline-approved"),
        optimized_ir_hash: hash(b"optimized-approved"),
        applied_rules: vec![
            applied_rule(
                &pack,
                "rule-fold-const",
                b"before-approved-1",
                b"after-approved-1",
            ),
            applied_rule(
                &pack,
                "rule-prune-dead-branch",
                b"before-approved-2",
                b"after-approved-2",
            ),
        ],
        verdict: approved_verdict(),
        cost_model_id: Some(cost_model.model_id.clone()),
    });
    assert!(
        approved_result.is_approved(),
        "approved demo receipt should pass"
    );
    let approved_receipt = approved_result
        .receipt()
        .expect("approved result should expose receipt")
        .clone();
    assert!(
        emitter.verify_receipt(&approved_receipt),
        "approved demo receipt signature should verify"
    );

    emitter.tick(100);
    let rejected_result = emitter.emit(EmitInput {
        optimization_id: "opt-rejected".to_string(),
        baseline_ir_hash: hash(b"baseline-rejected"),
        optimized_ir_hash: hash(b"optimized-rejected"),
        applied_rules: vec![applied_rule(
            &pack,
            "rule-prune-dead-branch",
            b"before-rejected",
            b"after-rejected",
        )],
        verdict: rejected_verdict(),
        cost_model_id: Some(cost_model.model_id.clone()),
    });
    let rejected_receipt = match rejected_result {
        EmitResult::Rejected { receipt, .. } => receipt,
        other => panic!("expected rejected receipt, got {other:?}"),
    };
    assert!(
        emitter.verify_receipt(&rejected_receipt),
        "rejected demo receipt signature should verify"
    );

    let quarantined_result = emitter.emit(EmitInput {
        optimization_id: "opt-rejected".to_string(),
        baseline_ir_hash: hash(b"baseline-rejected-resubmit"),
        optimized_ir_hash: hash(b"optimized-rejected-resubmit"),
        applied_rules: vec![applied_rule(
            &pack,
            "rule-fold-const",
            b"before-rejected-resubmit",
            b"after-rejected-resubmit",
        )],
        verdict: approved_verdict(),
        cost_model_id: Some(cost_model.model_id.clone()),
    });
    assert!(
        matches!(quarantined_result, EmitResult::Quarantined { .. }),
        "disproven optimization should fail closed on resubmission"
    );

    let summary = emitter.summary();
    assert_eq!(summary.total_receipts, 2);
    assert_eq!(summary.total_proven, 1);
    assert_eq!(summary.total_disproven, 1);
    assert_eq!(summary.quarantine_count, 1);
    assert!(summary.chain_valid, "demo chain should be valid");

    let governance = build_governance_state(approved_receipt.content_hash);
    let governance_report = governance.report(&GovernanceConfig::default());
    assert!(
        governance_report.verdict.is_pass(),
        "demo governance report should be publishable"
    );

    let optimization_entries = emitter
        .chain
        .receipts
        .iter()
        .map(|receipt| {
            let quarantined = emitter.quarantine.contains(&receipt.optimization_id);
            let publishable = receipt.permits_activation()
                && receipt.all_rules_proven_sound()
                && summary.chain_valid
                && governance_report.verdict.is_pass()
                && !quarantined;
            OptimizationProofEntry {
                optimization_id: receipt.optimization_id.clone(),
                pack_id: receipt
                    .applied_rules
                    .first()
                    .map(|rule| rule.pack_id.clone())
                    .unwrap_or_default(),
                receipt_hash: receipt.content_hash,
                verdict: receipt_verdict_name(receipt).to_string(),
                rule_ids: receipt
                    .applied_rules
                    .iter()
                    .map(|rule| rule.rule_id.clone())
                    .collect(),
                total_cost_delta_millionths: receipt.total_cost_delta_millionths,
                publishable_evidence: publishable,
                quarantined,
                all_rules_proven_sound: receipt.all_rules_proven_sound(),
                block_reason: block_reason_for(receipt, quarantined),
            }
        })
        .collect::<Vec<_>>();

    let publishable_optimization_ids = optimization_entries
        .iter()
        .filter(|entry| entry.publishable_evidence)
        .map(|entry| entry.optimization_id.clone())
        .collect::<Vec<_>>();
    let blocked_optimization_ids = optimization_entries
        .iter()
        .filter(|entry| !entry.publishable_evidence)
        .map(|entry| entry.optimization_id.clone())
        .collect::<Vec<_>>();
    let quarantined_optimization_ids = emitter.quarantine.iter().cloned().collect::<Vec<_>>();

    let proof_index = RewriteProofIndex {
        schema_version: PROOF_INDEX_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        scenario_id: SCENARIO_ID.to_string(),
        generated_at_unix_ms: GENERATED_AT_UNIX_MS,
        pack_catalog_id: catalog.catalog_id.clone(),
        pack_catalog_hash: catalog.content_hash,
        cost_model_id: cost_model.model_id.clone(),
        rewrite_packs: vec![RewritePackIndexEntry {
            pack_id: pack.pack_id.clone(),
            pack_version: pack.version.to_string(),
            rule_count: pack.rule_count(),
            enabled_rule_count: pack.enabled_count(),
            proven_sound_count: pack.proven_sound_count,
            soundness_rate_millionths: pack.soundness_rate_millionths(),
            cost_model_id: pack.cost_model_id.clone(),
            content_hash: pack.content_hash,
            has_internal_blocking: pack.has_internal_blocking(),
        }],
        receipt_summary: summary,
        governance_report,
        publishable_optimization_ids,
        blocked_optimization_ids,
        quarantined_optimization_ids,
        optimization_entries,
        required_artifacts: vec![
            "rewrite_proof_index.json".to_string(),
            EGRAPH_REWRITE_PACK_ARTIFACT.to_string(),
            "trace_ids.json".to_string(),
            "run_manifest.json".to_string(),
            "events.jsonl".to_string(),
            "commands.txt".to_string(),
        ],
        module_sources: vec![
            "crates/franken-engine/src/versioned_rewrite_pack.rs".to_string(),
            "crates/franken-engine/src/translation_validation_receipt.rs".to_string(),
            "crates/franken-engine/src/certified_optimization_governance.rs".to_string(),
        ],
        operator_verification: vec![
            "./scripts/run_rgc_certified_optimization_harness.sh ci".to_string(),
            "./scripts/e2e/rgc_certified_optimization_harness_replay.sh ci".to_string(),
        ],
    };

    let trace_ids = CertifiedOptimizationTraceIds {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec![
            "trace-rgc-certified-optimization-harness-demo".to_string(),
            "trace-rgc-certified-optimization-harness-opt-approved".to_string(),
            "trace-rgc-certified-optimization-harness-opt-rejected".to_string(),
        ],
        decision_ids: vec![
            "decision-rgc-certified-optimization-harness-demo".to_string(),
            "decision-rgc-certified-optimization-harness-opt-approved".to_string(),
            "decision-rgc-certified-optimization-harness-opt-rejected".to_string(),
        ],
        policy_ids: vec!["policy-rgc-certified-optimization-harness-v1".to_string()],
    };

    (proof_index, trace_ids)
}

fn emit_artifacts_to_dir(run_dir: &Path) {
    fs::create_dir_all(run_dir)
        .unwrap_or_else(|err| panic!("failed to create {}: {err}", run_dir.display()));

    let (proof_index, trace_ids) = build_demo_index();
    let egraph_rewrite_pack = build_demo_pack(&build_cost_model());
    write_json_file(&run_dir.join("rewrite_proof_index.json"), &proof_index);
    write_json_file(
        &run_dir.join(EGRAPH_REWRITE_PACK_ARTIFACT),
        &egraph_rewrite_pack,
    );
    write_json_file(&run_dir.join("trace_ids.json"), &trace_ids);
}

#[test]
fn rgc_607_harness_artifact_bundle_is_emitted() {
    let output_dir = artifact_output_dir();
    emit_artifacts_to_dir(&output_dir);

    let proof_index_path = output_dir.join("rewrite_proof_index.json");
    let egraph_rewrite_pack_path = output_dir.join(EGRAPH_REWRITE_PACK_ARTIFACT);
    let trace_ids_path = output_dir.join("trace_ids.json");
    assert!(
        proof_index_path.is_file(),
        "missing proof index {}",
        proof_index_path.display()
    );
    assert!(
        egraph_rewrite_pack_path.is_file(),
        "missing egraph rewrite pack {}",
        egraph_rewrite_pack_path.display()
    );
    assert!(
        trace_ids_path.is_file(),
        "missing trace ids {}",
        trace_ids_path.display()
    );

    let proof_index: RewriteProofIndex = serde_json::from_slice(
        &fs::read(&proof_index_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", proof_index_path.display())),
    )
    .expect("proof index should parse");
    assert_eq!(proof_index.schema_version, PROOF_INDEX_SCHEMA_VERSION);
    assert_eq!(proof_index.bead_id, BEAD_ID);
    assert_eq!(proof_index.component, COMPONENT);
    assert_eq!(
        proof_index.publishable_optimization_ids,
        vec!["opt-approved".to_string()]
    );
    assert_eq!(
        proof_index.blocked_optimization_ids,
        vec!["opt-rejected".to_string()]
    );
    assert_eq!(
        proof_index.quarantined_optimization_ids,
        vec!["opt-rejected".to_string()]
    );
    assert_eq!(proof_index.receipt_summary.total_receipts, 2);
    assert_eq!(proof_index.receipt_summary.total_proven, 1);
    assert_eq!(proof_index.receipt_summary.total_disproven, 1);
    assert!(proof_index.receipt_summary.chain_valid);
    assert!(proof_index.governance_report.verdict.is_pass());
    assert!(
        proof_index
            .required_artifacts
            .contains(&"rewrite_proof_index.json".to_string())
    );
    assert!(
        proof_index
            .required_artifacts
            .contains(&EGRAPH_REWRITE_PACK_ARTIFACT.to_string())
    );
    assert!(
        proof_index
            .required_artifacts
            .contains(&"trace_ids.json".to_string())
    );

    let egraph_rewrite_pack: RewritePack =
        serde_json::from_slice(&fs::read(&egraph_rewrite_pack_path).unwrap_or_else(|err| {
            panic!(
                "failed to read {}: {err}",
                egraph_rewrite_pack_path.display()
            )
        }))
        .expect("egraph rewrite pack should parse");
    assert_eq!(egraph_rewrite_pack.pack_id, "demo-certified-pack");
    assert_eq!(egraph_rewrite_pack.cost_model_id, proof_index.cost_model_id);
    assert_eq!(egraph_rewrite_pack.rule_count(), 2);
    assert_eq!(
        egraph_rewrite_pack.content_hash,
        proof_index.rewrite_packs[0].content_hash
    );

    let trace_ids: CertifiedOptimizationTraceIds = serde_json::from_slice(
        &fs::read(&trace_ids_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", trace_ids_path.display())),
    )
    .expect("trace ids should parse");
    assert_eq!(trace_ids.schema_version, TRACE_IDS_SCHEMA_VERSION);
    assert_eq!(trace_ids.trace_ids.len(), 3);
    assert_eq!(trace_ids.decision_ids.len(), 3);
    assert_eq!(
        trace_ids.policy_ids,
        vec!["policy-rgc-certified-optimization-harness-v1".to_string()]
    );
}

#[test]
fn rgc_607_proof_index_is_deterministic() {
    let (left_index, left_trace_ids) = build_demo_index();
    let (right_index, right_trace_ids) = build_demo_index();

    assert_eq!(left_index, right_index);
    assert_eq!(left_trace_ids, right_trace_ids);
}

#[test]
fn rgc_607_gate_script_is_rch_backed_and_mentions_required_artifacts() {
    let path = repo_root().join("scripts/run_rgc_certified_optimization_harness.sh");
    let script = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for required_fragment in [
        "rch exec -- env",
        "cargo check -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration",
        "cargo test -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration",
        "cargo clippy -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration -- -D warnings",
        ARTIFACT_ENV,
        "rewrite_proof_index.json",
        EGRAPH_REWRITE_PACK_ARTIFACT,
        "trace_ids.json",
        "\"rch_logs\"",
        RUN_MANIFEST_SCHEMA_VERSION,
        "./scripts/e2e/rgc_certified_optimization_harness_replay.sh",
        "missing-remote-exit-marker",
    ] {
        assert!(
            script.contains(required_fragment),
            "script missing fragment `{required_fragment}`"
        );
    }
}

#[test]
fn rgc_607_check_mode_manifest_omits_proof_bundle_and_records_timeouts() {
    let path = repo_root().join("scripts/run_rgc_certified_optimization_harness.sh");
    let script = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for required_fragment in [
        "include_bundle_artifacts=false",
        "if [[ \"$mode\" == \"test\" || \"$mode\" == \"ci\" ]]; then",
        "failed_command",
        "(outer-timeout=${rch_timeout_seconds}s)",
        "(missing-remote-exit-marker)",
        "\\\"manifest\\\":",
        "\\\"events\\\":",
        "\\\"commands\\\":",
        "\\\"cat ${manifest_path}\\\"",
        "\\\"cat ${events_path}\\\"",
        "\\\"cat ${commands_path}\\\"",
        "\\\"${replay_command}\\\"",
    ] {
        assert!(
            script.contains(required_fragment),
            "script missing check-mode fragment `{required_fragment}`"
        );
    }
}

#[test]
fn rgc_607_replay_wrapper_is_replay_first_and_supports_explicit_run_dir() {
    let path = repo_root().join("scripts/e2e/rgc_certified_optimization_harness_replay.sh");
    let script = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for required_fragment in [
        "mode=\"${1:-show}\"",
        "RGC_CERTIFIED_OPTIMIZATION_HARNESS_REPLAY_RUN_DIR",
        "run_dir_is_complete()",
        "rewrite_proof_index.json",
        "egraph_rewrite_pack.json",
        "trace_ids.json",
        "rch-log.*",
        "explicit run directory is incomplete",
        "latest complete run directory",
        "scripts/run_rgc_certified_optimization_harness.sh",
    ] {
        assert!(
            script.contains(required_fragment),
            "replay wrapper missing fragment `{required_fragment}`"
        );
    }
}

#[test]
fn rgc_607_replay_wrapper_warns_on_incomplete_or_failed_runs() {
    let path = repo_root().join("scripts/e2e/rgc_certified_optimization_harness_replay.sh");
    let script = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for required_fragment in [
        "no complete bundle found under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete",
        "newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}",
        "gate exited with status ${prior_exit}; replay output reflects latest complete run directory ${latest_run_dir}",
        "gate exited with status ${prior_exit}; replay output reflects previous latest complete run directory ${latest_run_dir}",
        "gate exited with status ${prior_exit}; replay output reflects current run directory ${latest_run_dir}",
        "latest first rch log:",
    ] {
        assert!(
            script.contains(required_fragment),
            "replay wrapper missing failure-path fragment `{required_fragment}`"
        );
    }
}

#[test]
fn rgc_607_readme_documents_harness_lane() {
    let path = repo_root().join("README.md");
    let readme = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for required_fragment in [
        "## RGC Certified Optimization Harness",
        "./scripts/run_rgc_certified_optimization_harness.sh ci",
        "./scripts/e2e/rgc_certified_optimization_harness_replay.sh ci",
        "rewrite_proof_index.json",
        "egraph_rewrite_pack.json",
        "trace_ids.json",
        "rch-log.",
        "`check` mode emits only",
        "`test` and `ci` additionally emit",
    ] {
        assert!(
            readme.contains(required_fragment),
            "README missing fragment `{required_fragment}`"
        );
    }
}
