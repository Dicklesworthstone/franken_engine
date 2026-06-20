//! CEI A.4 (`bd-sde5e.1.4`): principled freshness via an anytime-valid
//! e-process boundary, exercised end-to-end against the real
//! `collect_evidence_facts` collector and the live claim-to-proof matrix.
//!
//! Proves the two acceptance clauses of the bead:
//!  1. a row whose *committed* evidence is older than its e-process bound has
//!     its ceiling lowered (loses `Observed`) and is flagged unsound — judged on
//!     a real git-tracked bundle whose age is computed, not authored;
//!  2. the matrix's freshness fields are *computed, never authored* — every
//!     per-claim `freshness_days` is null and the e-process policy is declared.
//!
//! The collector is fed a fixed `now_unix` (never the wall clock) so the test is
//! deterministic; only the git-commit-time fallback case reads real commit time.

use std::path::{Path, PathBuf};
use std::process::Command;

use frankenengine_engine::claim_evidence_lattice::{
    ClaimAssertionState, ClaimRow, ClaimVerdict, EvidenceFacts, EvidenceTier, FreshnessEProcess,
    ceiling, collect_evidence_facts, tier,
};

/// `2026-06-01T00:00:00Z` as ISO-8601 and the matching unix seconds, so the
/// manifest timestamp and the injected `now_unix` correspond exactly.
const GEN_ISO: &str = "2026-06-01T00:00:00+00:00";
const GEN_UNIX: i64 = 1_780_272_000;
const DAY: i64 = 86_400;
const HORIZON: u64 = 30;

fn git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .status()
        .expect("git available");
    assert!(status.success(), "git {args:?} failed");
}

fn init_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    git(dir.path(), &["init", "-q"]);
    git(dir.path(), &["config", "user.email", "a4@cei.test"]);
    git(dir.path(), &["config", "user.name", "cei-a4"]);
    dir
}

/// Write a fully-sound reproducibility bundle under `docs/evidence/<claim>`:
/// passed + non-backfill verification, a zero-exit repro.lock receipt, and an
/// optional manifest generation timestamp.
fn write_bundle(repo: &Path, claim: &str, generated_at_utc: Option<&str>) -> String {
    let rel = format!("docs/evidence/{claim}");
    let dir = repo.join(&rel);
    std::fs::create_dir_all(&dir).expect("mkdir bundle");

    let mut manifest = serde_json::json!({
        "outputs": { "verification_result": "passed" },
        "provenance": { "generated_by": "run_rgc_gate.sh" },
    });
    if let Some(ts) = generated_at_utc {
        manifest["generated_at_utc"] = serde_json::json!(ts);
    }
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write manifest");

    let repro = serde_json::json!({ "expected_outputs": { "exit_code": 0 } });
    std::fs::write(
        dir.join("repro.lock"),
        serde_json::to_string_pretty(&repro).unwrap(),
    )
    .expect("write repro.lock");

    rel
}

fn observed_row(claim: &str, facts: EvidenceFacts) -> ClaimVerdict {
    ClaimVerdict::score(&ClaimRow {
        claim_id: claim.to_string(),
        asserted_state: ClaimAssertionState::Observed,
        facts,
    })
}

#[test]
fn fresh_committed_bundle_licenses_observed() {
    let repo = init_repo();
    let rel = write_bundle(repo.path(), "FE-CLAIM-FRESH", Some(GEN_ISO));
    git(repo.path(), &["add", "-A"]);

    // now == generation time -> age 0 -> fresh.
    let facts = collect_evidence_facts(repo.path(), &rel, GEN_UNIX, HORIZON);
    assert!(facts.artifact_git_tracked);
    assert!(facts.verification_passed);
    assert!(facts.receipt_exit_zero);
    assert!(facts.repro_lock_present);
    assert!(facts.fresh, "age-0 bundle must be fresh: {:?}", facts.notes);
    assert_eq!(facts.freshness_days, Some(0));
    let v = facts.freshness_eprocess.expect("e-process verdict present");
    assert!(v.fresh && v.stale_confidence_millionths == 0);

    assert_eq!(tier(&facts), EvidenceTier::Reproduced);
    assert_eq!(ceiling(tier(&facts)), ClaimAssertionState::Observed);
    assert!(observed_row("FE-CLAIM-FRESH", facts).sound);
}

#[test]
fn stale_committed_bundle_loses_observed_and_is_flagged() {
    let repo = init_repo();
    let rel = write_bundle(repo.path(), "FE-CLAIM-STALE", Some(GEN_ISO));
    git(repo.path(), &["add", "-A"]);

    // The SAME committed bundle, 45 days later — past the e-process bound.
    let now = GEN_UNIX + 45 * DAY;
    let facts = collect_evidence_facts(repo.path(), &rel, now, HORIZON);

    // Everything else is still strong; ONLY freshness fails.
    assert!(facts.verification_passed && facts.receipt_exit_zero && facts.repro_lock_present);
    assert!(!facts.fresh, "45d-old bundle must be stale");
    assert_eq!(facts.freshness_days, Some(45));
    let v = facts.freshness_eprocess.expect("e-process verdict present");
    assert_eq!(v.bound_days, 31);
    assert!(
        v.stale_confidence_millionths > 0,
        "stale => positive confidence"
    );

    // Ceiling drops Observed -> Target; an Observed claim is now flagged unsound.
    assert_eq!(tier(&facts), EvidenceTier::Exercised);
    assert_eq!(ceiling(tier(&facts)), ClaimAssertionState::Target);
    let verdict = observed_row("FE-CLAIM-STALE", facts);
    assert!(!verdict.sound, "stale Observed row must be flagged unsound");
}

#[test]
fn freshness_boundary_matches_eprocess_bound_exactly() {
    let repo = init_repo();
    let rel = write_bundle(repo.path(), "FE-CLAIM-EDGE", Some(GEN_ISO));
    git(repo.path(), &["add", "-A"]);

    let bound = FreshnessEProcess::from_horizon(HORIZON).bound_days();
    assert_eq!(bound, 31);

    // Day before the bound: fresh. On the bound: stale.
    let fresh_facts = collect_evidence_facts(
        repo.path(),
        &rel,
        GEN_UNIX + (bound as i64 - 1) * DAY,
        HORIZON,
    );
    assert!(fresh_facts.fresh, "age {} must be fresh", bound - 1);
    assert_eq!(ceiling(tier(&fresh_facts)), ClaimAssertionState::Observed);

    let stale_facts =
        collect_evidence_facts(repo.path(), &rel, GEN_UNIX + bound as i64 * DAY, HORIZON);
    assert!(!stale_facts.fresh, "age {bound} must be stale");
    assert_eq!(ceiling(tier(&stale_facts)), ClaimAssertionState::Target);
}

#[test]
fn git_commit_time_is_the_age_fallback_when_manifest_omits_timestamp() {
    let repo = init_repo();
    // No generated_at_utc in the manifest — the collector must fall back to the
    // artifact's real git commit time rather than declaring age unknown.
    let rel = write_bundle(repo.path(), "FE-CLAIM-NOSTAMP", None);
    git(repo.path(), &["add", "-A"]);
    git(repo.path(), &["commit", "-q", "-m", "commit bundle"]);

    // Read the real commit time and treat "now" as that instant (age ~0).
    let out = Command::new("git")
        .arg("-C")
        .arg(repo.path())
        .args(["log", "-1", "--format=%ct", "--", &rel])
        .output()
        .expect("git log");
    let commit_unix: i64 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("commit time");

    let facts = collect_evidence_facts(repo.path(), &rel, commit_unix, HORIZON);
    assert!(
        facts.freshness_days.is_some(),
        "git commit time must supply a computed age: {:?}",
        facts.notes
    );
    assert!(
        facts.fresh,
        "freshly-committed bundle is fresh: {:?}",
        facts.notes
    );
    assert!(
        !facts
            .notes
            .iter()
            .any(|n| n.contains("no parseable generation timestamp")),
        "fallback must avoid the 'no timestamp' note: {:?}",
        facts.notes
    );
}

#[test]
fn collector_is_deterministic_for_fixed_inputs() {
    let repo = init_repo();
    let rel = write_bundle(repo.path(), "FE-CLAIM-DET", Some(GEN_ISO));
    git(repo.path(), &["add", "-A"]);
    let now = GEN_UNIX + 10 * DAY;
    let a = collect_evidence_facts(repo.path(), &rel, now, HORIZON);
    let b = collect_evidence_facts(repo.path(), &rel, now, HORIZON);
    assert_eq!(a, b, "collector must be deterministic for fixed inputs");
}

/// Acceptance clause 2: freshness in the real matrix is computed, never authored.
#[test]
fn real_matrix_freshness_is_computed_not_authored() {
    let matrix = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .join("docs/claim_to_proof_matrix_v1.json");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&matrix).expect("read matrix"))
            .expect("parse matrix");

    let claims = json["claims"].as_array().expect("claims array");
    for c in claims {
        assert!(
            c.get("freshness_days").map(|v| v.is_null()).unwrap_or(true),
            "claim {} still authors a freshness_days measurement",
            c["claim_id"]
        );
    }

    let policy = json
        .get("freshness_eprocess_policy")
        .expect("matrix declares the e-process freshness policy");
    assert_eq!(policy["alpha_millionths"].as_i64(), Some(50_000));
    assert!(policy["horizon_days"].as_u64().is_some());
}
