#![forbid(unsafe_code)]
//! Integration tests for the compounding red-team campaign orchestrator
//! (bd-cixqu.21.4, Track U.4).
//!
//! The campaign wires U.1 generation -> U.3 novelty -> U.2 promotion into one
//! deterministic pass and emits a content-addressed [`CampaignBundle`]. These
//! tests cover the acceptance criteria: deterministic byte-identical bundles
//! (replay), config-fingerprint reproducibility, novelty/promotion decision
//! accounting, and the on-disk artifact bundle + run_manifest wrapper.

use frankenengine_engine::compounding_red_team_campaign::{
    self, CAMPAIGN_BUNDLE_SCHEMA_VERSION, CampaignConfig, engine_containment_oracle, run_campaign,
    write_bundle,
};
use frankenengine_engine::corpus_promotion::PromotedLedger;
use frankenengine_engine::hierarchical_delta_debug::StepOutcome;
use serde_json::Value;
use std::path::PathBuf;

fn always_preserve(_source: &str) -> StepOutcome {
    StepOutcome::DefectPreserved
}

fn always_lost(_source: &str) -> StepOutcome {
    StepOutcome::DefectLost
}

fn unique_temp_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("franken_crt_campaign_u4_{name}"))
}

/// Every explored candidate is accounted for and the statistics are internally
/// consistent, whatever the oracle decides.
fn assert_campaign_invariants(bundle: &compounding_red_team_campaign::CampaignBundle) {
    let stats = &bundle.statistics;
    assert_eq!(
        stats.candidates_explored as usize,
        bundle.explored.len(),
        "statistics.candidates_explored must match the explored records"
    );
    assert_eq!(
        stats.promoted + stats.rejected,
        stats.candidates_explored,
        "every explored candidate is either promoted or rejected"
    );
    let dist = &stats.novelty_distribution;
    assert_eq!(
        dist.novel + dist.near_duplicate + dist.duplicate,
        stats.candidates_explored,
        "novelty distribution must sum to the explored count"
    );
    assert!(
        stats.promoted <= dist.novel,
        "only novel candidates can be promoted ({} promoted, {} novel)",
        stats.promoted,
        dist.novel
    );
    assert_eq!(
        stats.promoted as usize,
        bundle.promoted_scenarios.len(),
        "promoted count must match the promoted scenario pairs"
    );
    assert_eq!(stats.corpus_growth, stats.promoted);
    assert_eq!(
        stats.corpus_size_after,
        stats.corpus_size_before + stats.corpus_growth
    );
}

// ---------------------------------------------------------------------------
// Determinism / replay
// ---------------------------------------------------------------------------

#[test]
fn campaign_is_byte_identical_across_runs() {
    let config = CampaignConfig::default();
    let ledger = PromotedLedger::new();

    let a = run_campaign(&config, &ledger, always_preserve).expect("campaign a runs");
    let b = run_campaign(&config, &ledger, always_preserve).expect("campaign b runs");

    assert_eq!(
        a.bundle_digest, b.bundle_digest,
        "bundle digest must be deterministic"
    );
    let json_a = serde_json::to_string(&a).expect("serialize a");
    let json_b = serde_json::to_string(&b).expect("serialize b");
    assert_eq!(
        json_a, json_b,
        "identical inputs must produce byte-identical bundles"
    );

    // Generation actually produced something to reason about.
    assert!(
        !a.explored.is_empty(),
        "the generator must produce candidates"
    );
}

#[test]
fn campaign_config_fingerprint_is_input_sensitive() {
    let base = CampaignConfig::default();
    let changed = CampaignConfig {
        max_candidates_per_strategy: base.max_candidates_per_strategy + 1,
        ..CampaignConfig::default()
    };

    assert_ne!(
        base.fingerprint(),
        changed.fingerprint(),
        "a changed generation parameter must change the fingerprint"
    );

    let ledger = PromotedLedger::new();
    let bundle_base = run_campaign(&base, &ledger, always_preserve).expect("base runs");
    let bundle_changed = run_campaign(&changed, &ledger, always_preserve).expect("changed runs");
    assert_ne!(bundle_base.campaign_id, bundle_changed.campaign_id);
    assert!(
        bundle_base
            .campaign_id
            .contains(&bundle_base.config_fingerprint)
    );
}

// ---------------------------------------------------------------------------
// Novelty + promotion decision accounting
// ---------------------------------------------------------------------------

#[test]
fn campaign_promotes_every_reproduced_novel_candidate() {
    let config = CampaignConfig::default();
    let ledger = PromotedLedger::new();

    // Under an oracle that always reproduces, every NOVEL candidate is promoted.
    let bundle = run_campaign(&config, &ledger, always_preserve).expect("campaign runs");
    assert_campaign_invariants(&bundle);
    assert_eq!(
        bundle.statistics.promoted, bundle.statistics.novelty_distribution.novel,
        "with an always-reproducing oracle, every novel candidate is promoted"
    );
    assert!(
        bundle.statistics.promoted >= 1,
        "at least one novel candidate is promoted"
    );

    // Every promoted scenario is a fail-closed regression manifest.
    for scenario in &bundle.promoted_scenarios {
        let manifest: Value =
            serde_json::from_str(&scenario.manifest_json).expect("promoted manifest parses");
        assert_eq!(
            manifest["schema_version"],
            "franken-engine.red-team-scenario.v1"
        );
        assert_eq!(
            manifest["expected_outcome"]["frankenengine"]["outcome"],
            "fail_closed"
        );
    }
}

#[test]
fn campaign_rejects_non_reproducing_candidates() {
    let config = CampaignConfig::default();
    let ledger = PromotedLedger::new();

    // Under an oracle that never reproduces, nothing is promoted; every novel
    // candidate is rejected as not-reproduced.
    let bundle = run_campaign(&config, &ledger, always_lost).expect("campaign runs");
    assert_campaign_invariants(&bundle);
    assert_eq!(bundle.statistics.promoted, 0);
    assert!(bundle.promoted_scenarios.is_empty());

    let novel_rejected_not_reproduced = bundle
        .explored
        .iter()
        .filter(|r| r.novelty.verdict == "novel")
        .all(|r| r.disposition == "rejected_not_reproduced");
    assert!(
        novel_rejected_not_reproduced,
        "every novel candidate must be rejected as not-reproduced under always-lost"
    );
}

#[test]
fn campaign_runs_with_the_real_engine_oracle() {
    let config = CampaignConfig::default();
    let ledger = PromotedLedger::new();

    // The engine's own ambient-authority containment as the bypass oracle. We do
    // not assert a specific promotion count (it depends on what the generator
    // emits), only that the campaign runs deterministically and the accounting
    // holds. Any promoted scenario must genuinely fail closed at lowering.
    let bundle = run_campaign(&config, &ledger, engine_containment_oracle).expect("campaign runs");
    assert_campaign_invariants(&bundle);
    for scenario in &bundle.promoted_scenarios {
        assert_eq!(
            engine_containment_oracle(&scenario.program_js),
            StepOutcome::DefectPreserved,
            "a promoted scenario must reproduce containment at lowering"
        );
    }

    // Deterministic under the engine oracle too.
    let again = run_campaign(&config, &ledger, engine_containment_oracle).expect("campaign reruns");
    assert_eq!(bundle.bundle_digest, again.bundle_digest);
}

// ---------------------------------------------------------------------------
// Bundle shape + on-disk artifacts
// ---------------------------------------------------------------------------

#[test]
fn campaign_bundle_shape_is_well_formed() {
    let bundle = run_campaign(
        &CampaignConfig::default(),
        &PromotedLedger::new(),
        always_preserve,
    )
    .expect("campaign runs");
    assert_eq!(bundle.schema_version, CAMPAIGN_BUNDLE_SCHEMA_VERSION);
    assert!(bundle.bundle_digest.starts_with("bundle-"));
    assert!(bundle.config_fingerprint.starts_with("cfg-"));
    assert!(bundle.campaign_id.contains(&bundle.config_fingerprint));
    // Every explored record carries a novelty verdict and a disposition.
    for record in &bundle.explored {
        assert!(!record.novelty.verdict.is_empty());
        assert!(!record.disposition.is_empty());
        assert!(!record.candidate_id.is_empty());
    }
}

#[test]
fn write_bundle_is_deterministic_and_wraps_a_run_manifest() {
    let config = CampaignConfig::default();
    let ledger = PromotedLedger::new();
    let bundle = run_campaign(&config, &ledger, always_preserve).expect("campaign runs");

    let dir_a = unique_temp_dir("write_a");
    let dir_b = unique_temp_dir("write_b");
    let artifacts_a = write_bundle(&bundle, &dir_a).expect("write a");
    let _artifacts_b = write_bundle(&bundle, &dir_b).expect("write b");

    // The core bundle file is byte-identical across independent writes.
    let bundle_a = std::fs::read_to_string(dir_a.join("compounding_red_team_bundle.json"))
        .expect("read bundle a");
    let bundle_b = std::fs::read_to_string(dir_b.join("compounding_red_team_bundle.json"))
        .expect("read bundle b");
    assert_eq!(bundle_a, bundle_b, "written bundle must be deterministic");

    // The run manifest wraps every artifact with a SHA-256 and reports pass.
    let manifest_text =
        std::fs::read_to_string(dir_a.join("run_manifest.json")).expect("read run manifest");
    let manifest: Value = serde_json::from_str(&manifest_text).expect("run manifest parses");
    assert_eq!(
        manifest["schema_version"],
        "franken-engine.compounding-red-team-gate.v1"
    );
    assert_eq!(manifest["outcome"], "pass");
    assert_eq!(manifest["bundle_digest"], bundle.bundle_digest);
    let artifacts_obj = manifest["artifacts"].as_object().expect("artifacts object");
    assert!(artifacts_obj.contains_key("compounding_red_team_bundle.json"));
    assert!(artifacts_obj.contains_key("summary.md"));
    for (_name, entry) in artifacts_obj {
        assert!(entry["sha256"].as_str().is_some_and(|s| s.len() == 64));
    }

    // summary.md exists and names the campaign.
    let summary = std::fs::read_to_string(dir_a.join("summary.md")).expect("read summary");
    assert!(summary.contains(&bundle.campaign_id));

    // The reported artifact count is sane.
    assert!(artifacts_a.len() >= 3);
}
