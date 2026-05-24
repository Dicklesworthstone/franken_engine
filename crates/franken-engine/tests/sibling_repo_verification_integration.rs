//! Integration coverage for the sibling-repo verification operator surface
//! (`bd-cixqu.13.4`, M.4). Focuses on the pin-update round-trip: every attempt
//! is recorded in the audit ledger, and the new SHA is committed only when the
//! integration smoke passes — otherwise the pin holds at the last-passed SHA.

use frankenengine_engine::sibling_repo_verification::{
    PinAuditLedger, PinError, PinUpdateRequest, SiblingHealthReport, SiblingLogEvent, SiblingPin,
    SiblingRepo, SiblingRepoHealthDashboard, SiblingVerdict, is_valid_sha, short_sha, SCHEMA_VERSION,
};

const SHA_A: &str = "094b59c859611f7f804fac79d185538d6e7aa171";
const SHA_B: &str = "33ad1c57d545292242e41a477c8278c70ed7e0d6";
const SHA_C: &str = "c0c8f32892a71f432a3ead0e5a04a9352549ccd4";

fn req(repo: SiblingRepo, prior: &str, new: &str, pass: bool) -> PinUpdateRequest {
    PinUpdateRequest {
        repo,
        prior_sha: prior.to_string(),
        new_sha: new.to_string(),
        smoke_passed: pass,
        timestamp_utc: "2026-05-24T12:00:00Z".to_string(),
        smoke_failure_reason: if pass {
            None
        } else {
            Some("integration smoke regression".to_string())
        },
    }
}

fn pin(repo: SiblingRepo, sha: &str, verdict: SiblingVerdict) -> SiblingPin {
    SiblingPin::new(
        repo,
        sha,
        "2026-05-21",
        verdict,
        Some("2026-05-21T00:00:00Z".to_string()),
        if verdict == SiblingVerdict::Failed {
            Some("smoke failed".to_string())
        } else {
            None
        },
    )
    .expect("valid pin")
}

// --------------------------------------------------------------------------- //
// 1-6: per-sibling commit-on-pass
// --------------------------------------------------------------------------- //
#[test]
fn commit_advances_each_sibling() {
    for repo in SiblingRepo::all() {
        let mut ledger = PinAuditLedger::new();
        let out = ledger.apply_update(&req(repo, SHA_A, SHA_B, true)).unwrap();
        assert!(out.committed, "{repo} should commit on smoke pass");
        assert_eq!(out.effective_sha, SHA_B);
        assert_eq!(ledger.commit_count(repo), 1);
    }
}

// --------------------------------------------------------------------------- //
// 7-12: per-sibling hold-on-fail (pin holds at prior SHA)
// --------------------------------------------------------------------------- //
#[test]
fn hold_preserves_prior_pin_each_sibling() {
    for repo in SiblingRepo::all() {
        let mut ledger = PinAuditLedger::new();
        let out = ledger.apply_update(&req(repo, SHA_A, SHA_B, false)).unwrap();
        assert!(!out.committed, "{repo} must not commit on smoke fail");
        assert_eq!(out.effective_sha, SHA_A, "{repo} pin must hold at prior SHA");
        assert_eq!(ledger.commit_count(repo), 0);
        assert_eq!(ledger.len(), 1, "the failed attempt is still audited");
    }
}

#[test]
fn full_history_advances_through_three_pins() {
    let mut ledger = PinAuditLedger::new();
    let o1 = ledger
        .apply_update(&req(SiblingRepo::Frankentui, SHA_A, SHA_B, true))
        .unwrap();
    assert_eq!(o1.effective_sha, SHA_B);
    let o2 = ledger
        .apply_update(&req(SiblingRepo::Frankentui, SHA_B, SHA_C, true))
        .unwrap();
    assert_eq!(o2.effective_sha, SHA_C);
    assert_eq!(ledger.commit_count(SiblingRepo::Frankentui), 2);
    assert_eq!(ledger.len(), 2);
}

#[test]
fn failed_update_between_two_passes_does_not_disturb_count() {
    let mut ledger = PinAuditLedger::new();
    ledger
        .apply_update(&req(SiblingRepo::Asupersync, SHA_A, SHA_B, true))
        .unwrap();
    ledger
        .apply_update(&req(SiblingRepo::Asupersync, SHA_B, SHA_C, false))
        .unwrap();
    let last = ledger
        .apply_update(&req(SiblingRepo::Asupersync, SHA_B, SHA_C, true))
        .unwrap();
    assert!(last.committed);
    assert_eq!(ledger.len(), 3);
    assert_eq!(ledger.commit_count(SiblingRepo::Asupersync), 2);
}

#[test]
fn audit_index_is_monotonic() {
    let mut ledger = PinAuditLedger::new();
    let a = ledger.apply_update(&req(SiblingRepo::Frankentui, SHA_A, SHA_B, true)).unwrap();
    let b = ledger.apply_update(&req(SiblingRepo::Frankentui, SHA_B, SHA_C, false)).unwrap();
    assert_eq!(a.audit_index, 0);
    assert_eq!(b.audit_index, 1);
}

#[test]
fn ledger_preserves_append_order_across_repos() {
    let mut ledger = PinAuditLedger::new();
    let order = [
        SiblingRepo::Frankenpandas,
        SiblingRepo::Asupersync,
        SiblingRepo::SqlmodelRust,
    ];
    for repo in order {
        ledger.apply_update(&req(repo, SHA_A, SHA_B, true)).unwrap();
    }
    let seen: Vec<_> = ledger.entries.iter().map(|e| e.repo).collect();
    assert_eq!(seen, order);
}

#[test]
fn hold_note_records_failure_reason() {
    let mut ledger = PinAuditLedger::new();
    ledger
        .apply_update(&PinUpdateRequest {
            repo: SiblingRepo::FastapiRust,
            prior_sha: SHA_A.to_string(),
            new_sha: SHA_B.to_string(),
            smoke_passed: false,
            timestamp_utc: "2026-05-24".to_string(),
            smoke_failure_reason: Some("router contract drift".to_string()),
        })
        .unwrap();
    assert!(ledger.entries[0].note.contains("router contract drift"));
    assert!(ledger.entries[0].note.contains("held"));
}

#[test]
fn hold_note_has_default_reason_when_absent() {
    let mut ledger = PinAuditLedger::new();
    ledger
        .apply_update(&PinUpdateRequest {
            repo: SiblingRepo::FastapiRust,
            prior_sha: SHA_A.to_string(),
            new_sha: SHA_B.to_string(),
            smoke_passed: false,
            timestamp_utc: "2026-05-24".to_string(),
            smoke_failure_reason: None,
        })
        .unwrap();
    assert!(ledger.entries[0].note.contains("unspecified smoke failure"));
}

#[test]
fn commit_note_records_short_shas() {
    let mut ledger = PinAuditLedger::new();
    ledger.apply_update(&req(SiblingRepo::Frankentui, SHA_A, SHA_B, true)).unwrap();
    let note = &ledger.entries[0].note;
    assert!(note.contains(&short_sha(SHA_A)));
    assert!(note.contains(&short_sha(SHA_B)));
}

#[test]
fn invalid_prior_sha_records_nothing() {
    let mut ledger = PinAuditLedger::new();
    let err = ledger.apply_update(&req(SiblingRepo::Frankentui, "nothex!", SHA_B, true));
    assert!(matches!(err, Err(PinError::InvalidSha { field: "prior_sha", .. })));
    assert!(ledger.is_empty());
}

#[test]
fn invalid_new_sha_records_nothing() {
    let mut ledger = PinAuditLedger::new();
    let err = ledger.apply_update(&req(SiblingRepo::Frankentui, SHA_A, "zz", true));
    assert!(matches!(err, Err(PinError::InvalidSha { field: "new_sha", .. })));
    assert!(ledger.is_empty());
}

#[test]
fn empty_timestamp_rejected() {
    let mut ledger = PinAuditLedger::new();
    let mut r = req(SiblingRepo::Frankentui, SHA_A, SHA_B, true);
    r.timestamp_utc = "  ".to_string();
    assert!(matches!(
        ledger.apply_update(&r),
        Err(PinError::EmptyUpdatedDate { .. })
    ));
}

#[test]
fn ledger_content_hash_changes_after_update() {
    let mut ledger = PinAuditLedger::new();
    let before = ledger.content_hash();
    ledger.apply_update(&req(SiblingRepo::Frankentui, SHA_A, SHA_B, true)).unwrap();
    assert_ne!(before, ledger.content_hash());
}

#[test]
fn identical_update_sequences_hash_equal() {
    let build = || {
        let mut l = PinAuditLedger::new();
        l.apply_update(&req(SiblingRepo::Frankentui, SHA_A, SHA_B, true)).unwrap();
        l.apply_update(&req(SiblingRepo::Asupersync, SHA_A, SHA_C, false)).unwrap();
        l
    };
    assert_eq!(build().content_hash(), build().content_hash());
}

#[test]
fn divergent_smoke_outcome_changes_hash() {
    let mut pass = PinAuditLedger::new();
    pass.apply_update(&req(SiblingRepo::Frankentui, SHA_A, SHA_B, true)).unwrap();
    let mut fail = PinAuditLedger::new();
    fail.apply_update(&req(SiblingRepo::Frankentui, SHA_A, SHA_B, false)).unwrap();
    assert_ne!(pass.content_hash(), fail.content_hash());
}

#[test]
fn ledger_serde_roundtrip() {
    let mut ledger = PinAuditLedger::new();
    ledger.apply_update(&req(SiblingRepo::Frankentui, SHA_A, SHA_B, true)).unwrap();
    ledger.apply_update(&req(SiblingRepo::Asupersync, SHA_A, SHA_C, false)).unwrap();
    let json = serde_json::to_string(&ledger).unwrap();
    let back: PinAuditLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
    assert_eq!(ledger.content_hash(), back.content_hash());
}

#[test]
fn log_event_for_commit_and_hold() {
    let mut ledger = PinAuditLedger::new();
    let c = ledger.apply_update(&req(SiblingRepo::Frankentui, SHA_A, SHA_B, true)).unwrap();
    let h = ledger.apply_update(&req(SiblingRepo::Frankentui, SHA_B, SHA_C, false)).unwrap();
    assert_eq!(SiblingLogEvent::for_pin_update(&c, "x").outcome, "committed");
    assert_eq!(SiblingLogEvent::for_pin_update(&h, "x").outcome, "held");
    assert_eq!(SiblingLogEvent::for_pin_update(&c, "x").repo, "frankentui");
}

#[test]
fn log_event_serde_roundtrip() {
    let mut ledger = PinAuditLedger::new();
    let out = ledger.apply_update(&req(SiblingRepo::SqlmodelRust, SHA_A, SHA_B, true)).unwrap();
    let ev = SiblingLogEvent::for_pin_update(&out, "advanced");
    let back: SiblingLogEvent = serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
    assert_eq!(ev, back);
}

// --------------------------------------------------------------------------- //
// Health report end-to-end
// --------------------------------------------------------------------------- //
#[test]
fn full_six_sibling_report_is_healthy() {
    let pins = SiblingRepo::all()
        .into_iter()
        .map(|r| pin(r, SHA_A, SiblingVerdict::Passed))
        .collect();
    let report = SiblingHealthReport::from_pins("2026-05-24", pins);
    assert_eq!(report.total, 6);
    assert_eq!(report.passed, 6);
    assert!(report.is_healthy());
}

#[test]
fn report_with_one_failure_is_degraded() {
    let mut pins: Vec<_> = SiblingRepo::all()
        .into_iter()
        .map(|r| pin(r, SHA_A, SiblingVerdict::Passed))
        .collect();
    pins[2] = pin(SiblingRepo::Frankensqlite, SHA_B, SiblingVerdict::Failed);
    let report = SiblingHealthReport::from_pins("2026-05-24", pins);
    assert!(!report.is_healthy());
    assert_eq!(report.failed, 1);
}

#[test]
fn report_json_roundtrips_and_pins_schema() {
    let report = SiblingHealthReport::from_pins(
        "2026-05-24",
        vec![pin(SiblingRepo::Frankentui, SHA_A, SiblingVerdict::Passed)],
    );
    let json = report.to_json();
    assert!(json.contains(SCHEMA_VERSION));
    let back: SiblingHealthReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.content_hash(), back.content_hash());
}

#[test]
fn report_hash_independent_of_pin_order() {
    let a = SiblingHealthReport::from_pins(
        "2026-05-24",
        vec![
            pin(SiblingRepo::Frankenpandas, SHA_A, SiblingVerdict::Passed),
            pin(SiblingRepo::Asupersync, SHA_B, SiblingVerdict::Skipped),
        ],
    );
    let b = SiblingHealthReport::from_pins(
        "2026-05-24",
        vec![
            pin(SiblingRepo::Asupersync, SHA_B, SiblingVerdict::Skipped),
            pin(SiblingRepo::Frankenpandas, SHA_A, SiblingVerdict::Passed),
        ],
    );
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn report_generated_utc_affects_hash() {
    let pins = || vec![pin(SiblingRepo::Frankentui, SHA_A, SiblingVerdict::Passed)];
    let a = SiblingHealthReport::from_pins("2026-05-24", pins());
    let b = SiblingHealthReport::from_pins("2026-05-25", pins());
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn report_pin_for_each_sibling() {
    let pins = SiblingRepo::all()
        .into_iter()
        .map(|r| pin(r, SHA_A, SiblingVerdict::Passed))
        .collect();
    let report = SiblingHealthReport::from_pins("2026-05-24", pins);
    for repo in SiblingRepo::all() {
        assert!(report.pin_for(repo).is_some(), "missing {repo}");
    }
}

// --------------------------------------------------------------------------- //
// Dashboard end-to-end
// --------------------------------------------------------------------------- //
#[test]
fn dashboard_renders_all_six_rows() {
    let pins = SiblingRepo::all()
        .into_iter()
        .map(|r| pin(r, SHA_A, SiblingVerdict::Passed))
        .collect();
    let report = SiblingHealthReport::from_pins("2026-05-24", pins);
    let dash = SiblingRepoHealthDashboard::from_report(&report, &PinAuditLedger::new());
    assert_eq!(dash.rows.len(), 6);
    let text = dash.render_plain();
    for repo in SiblingRepo::all() {
        assert!(text.contains(repo.slug()), "render missing {repo}");
    }
}

#[test]
fn dashboard_shows_advances_from_ledger() {
    let mut ledger = PinAuditLedger::new();
    ledger.apply_update(&req(SiblingRepo::Frankentui, SHA_A, SHA_B, true)).unwrap();
    ledger.apply_update(&req(SiblingRepo::Frankentui, SHA_B, SHA_C, true)).unwrap();
    let report = SiblingHealthReport::from_pins(
        "2026-05-24",
        vec![pin(SiblingRepo::Frankentui, SHA_C, SiblingVerdict::Passed)],
    );
    let dash = SiblingRepoHealthDashboard::from_report(&report, &ledger);
    assert_eq!(dash.rows[0].pin_advances, 2);
    assert!(dash.render_plain().contains("ADVANCES"));
}

#[test]
fn dashboard_render_is_byte_stable() {
    let report = SiblingHealthReport::from_pins(
        "2026-05-24",
        vec![pin(SiblingRepo::Asupersync, SHA_A, SiblingVerdict::Passed)],
    );
    let dash = SiblingRepoHealthDashboard::from_report(&report, &PinAuditLedger::new());
    assert_eq!(dash.render_plain(), dash.render_plain());
    assert_eq!(dash.content_hash(), dash.content_hash());
}

#[test]
fn dashboard_serde_roundtrip() {
    let report = SiblingHealthReport::from_pins(
        "2026-05-24",
        vec![pin(SiblingRepo::Frankentui, SHA_A, SiblingVerdict::Passed)],
    );
    let dash = SiblingRepoHealthDashboard::from_report(&report, &PinAuditLedger::new());
    let back: SiblingRepoHealthDashboard =
        serde_json::from_str(&serde_json::to_string(&dash).unwrap()).unwrap();
    assert_eq!(dash, back);
}

#[test]
fn dashboard_short_sha_column_is_seven_chars() {
    let report = SiblingHealthReport::from_pins(
        "2026-05-24",
        vec![pin(SiblingRepo::Frankentui, SHA_A, SiblingVerdict::Passed)],
    );
    let dash = SiblingRepoHealthDashboard::from_report(&report, &PinAuditLedger::new());
    assert_eq!(dash.rows[0].short_sha.len(), 7);
}

#[test]
fn dashboard_failed_sibling_shows_reason_and_degraded() {
    let report = SiblingHealthReport::from_pins(
        "2026-05-24",
        vec![pin(SiblingRepo::Frankensqlite, SHA_A, SiblingVerdict::Failed)],
    );
    let dash = SiblingRepoHealthDashboard::from_report(&report, &PinAuditLedger::new());
    assert!(!dash.healthy);
    let text = dash.render_plain();
    assert!(text.contains("DEGRADED"));
    assert!(text.contains("smoke failed"));
}

#[test]
fn dashboard_skipped_sibling_uses_dash_for_last_failed() {
    let report = SiblingHealthReport::from_pins(
        "2026-05-24",
        vec![pin(SiblingRepo::Frankenpandas, SHA_A, SiblingVerdict::Skipped)],
    );
    let dash = SiblingRepoHealthDashboard::from_report(&report, &PinAuditLedger::new());
    assert_eq!(dash.rows[0].last_failed_reason, "-");
    assert_eq!(dash.rows[0].verdict, "skip");
}

// --------------------------------------------------------------------------- //
// Pure helpers / identity
// --------------------------------------------------------------------------- //
#[test]
fn sha_validation_matches_doc_regex() {
    assert!(is_valid_sha(SHA_A));
    assert!(is_valid_sha("abcdef0"));
    assert!(!is_valid_sha("abcde")); // 5
    assert!(!is_valid_sha("ABCDEF0")); // upper
    assert!(!is_valid_sha("xyz0123"));
}

#[test]
fn slug_roundtrip_for_all_siblings() {
    for repo in SiblingRepo::all() {
        assert_eq!(SiblingRepo::from_slug(repo.slug()), Some(repo));
    }
}

#[test]
fn pin_rejects_bad_sha_at_construction() {
    let err = SiblingPin::new(
        SiblingRepo::Frankentui,
        "bad",
        "2026-05-21",
        SiblingVerdict::Passed,
        None,
        None,
    );
    assert!(err.is_err());
}

#[test]
fn pin_content_hash_distinguishes_sibling() {
    let a = pin(SiblingRepo::Frankentui, SHA_A, SiblingVerdict::Passed);
    let b = pin(SiblingRepo::Asupersync, SHA_A, SiblingVerdict::Passed);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn verdict_blocking_semantics() {
    assert!(SiblingVerdict::Failed.is_blocking_failure());
    assert!(!SiblingVerdict::Skipped.is_blocking_failure());
    assert!(!SiblingVerdict::Passed.is_blocking_failure());
}
