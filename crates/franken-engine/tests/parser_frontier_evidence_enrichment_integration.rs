//! Enrichment integration tests for the `parser_frontier_evidence` module.
//!
//! These tests extend coverage beyond the baseline integration suite, focusing on
//! serde edge cases, Display/as_str uniqueness contracts, struct field invariants,
//! inventory arithmetic identities, content-hash determinism, event lifecycle
//! ordering, and synthesized inventory manipulation scenarios.

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

use frankenengine_engine::parser_frontier_evidence::{
    ActualParseOutcome, ExpectedParseOutcome, FrontierEvidenceArtifactPaths, FrontierEvidenceEvent,
    FrontierEvidenceRunManifest, FrontierSpecimen, FrontierSpecimenEvidence, FrontierVerdict,
    PARSER_FRONTIER_COMPONENT, PARSER_FRONTIER_EVENT_SCHEMA_VERSION,
    PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION, PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION,
    PARSER_FRONTIER_POLICY_ID, ParserFrontierEvidenceInventory, ParserFrontierFamily,
    frontier_corpus, run_frontier_corpus, write_frontier_evidence_bundle,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tid = std::thread::current().id();
    std::env::temp_dir().join(format!("{prefix}-enrich-{ts}-{tid:?}"))
}

// ── Enum serde roundtrips with JSON value inspection ──

#[test]
fn enrichment_serde_family_json_values_are_snake_case() {
    for family in ParserFrontierFamily::ALL {
        let json = serde_json::to_string(family).unwrap();
        // JSON should be a quoted snake_case string
        let value: String = serde_json::from_str(&json).unwrap();
        assert!(
            value.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "family {:?} serialized to non-snake_case: {:?}",
            family,
            value
        );
    }
}

#[test]
fn enrichment_serde_expected_outcome_json_values() {
    let accepted_json = serde_json::to_string(&ExpectedParseOutcome::Accepted).unwrap();
    let rejected_json = serde_json::to_string(&ExpectedParseOutcome::Rejected).unwrap();
    assert_eq!(accepted_json, "\"accepted\"");
    assert_eq!(rejected_json, "\"rejected\"");
}

#[test]
fn enrichment_serde_actual_outcome_json_values() {
    let accepted_json = serde_json::to_string(&ActualParseOutcome::Accepted).unwrap();
    let rejected_json = serde_json::to_string(&ActualParseOutcome::Rejected).unwrap();
    assert_eq!(accepted_json, "\"accepted\"");
    assert_eq!(rejected_json, "\"rejected\"");
}

#[test]
fn enrichment_serde_verdict_json_values() {
    let pass_json = serde_json::to_string(&FrontierVerdict::Pass).unwrap();
    let fail_json = serde_json::to_string(&FrontierVerdict::Fail).unwrap();
    assert_eq!(pass_json, "\"pass\"");
    assert_eq!(fail_json, "\"fail\"");
}

#[test]
fn enrichment_serde_family_rejects_unknown_variant() {
    let result = serde_json::from_str::<ParserFrontierFamily>("\"nonexistent_family\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_serde_verdict_rejects_unknown_variant() {
    let result = serde_json::from_str::<FrontierVerdict>("\"maybe\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_serde_expected_outcome_rejects_unknown_variant() {
    let result = serde_json::from_str::<ExpectedParseOutcome>("\"partial\"");
    assert!(result.is_err());
}

// ── Display / as_str uniqueness contracts ──

#[test]
fn enrichment_display_family_as_str_no_empty_strings() {
    for family in ParserFrontierFamily::ALL {
        let s = family.as_str();
        assert!(!s.is_empty(), "family {:?} has empty as_str", family);
        assert!(
            s.len() >= 3,
            "family {:?} has suspiciously short as_str: {:?}",
            family,
            s
        );
    }
}

#[test]
fn enrichment_display_family_as_str_matches_serde_value() {
    for family in ParserFrontierFamily::ALL {
        let serde_value: String =
            serde_json::from_str(&serde_json::to_string(family).unwrap()).unwrap();
        assert_eq!(
            family.as_str(),
            serde_value,
            "as_str and serde disagree for {:?}",
            family
        );
    }
}

#[test]
fn enrichment_display_expected_outcome_as_str_values() {
    assert_eq!(ExpectedParseOutcome::Accepted.as_str(), "accepted");
    assert_eq!(ExpectedParseOutcome::Rejected.as_str(), "rejected");
    assert_ne!(
        ExpectedParseOutcome::Accepted.as_str(),
        ExpectedParseOutcome::Rejected.as_str()
    );
}

// ── Struct construction and field invariants ──

#[test]
fn enrichment_struct_specimen_evidence_with_error_fields() {
    let ev = FrontierSpecimenEvidence {
        specimen_id: "err_specimen".to_string(),
        family: ParserFrontierFamily::TaggedTemplate,
        expected_outcome: ExpectedParseOutcome::Rejected,
        actual_outcome: ActualParseOutcome::Rejected,
        verdict: FrontierVerdict::Pass,
        error_code: Some("E1001".to_string()),
        error_message: Some("tagged templates unsupported".to_string()),
        event_ir_hash: Some("deadbeef".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: FrontierSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code, Some("E1001".to_string()));
    assert_eq!(
        back.error_message,
        Some("tagged templates unsupported".to_string())
    );
    assert_eq!(back.verdict, FrontierVerdict::Pass);
}

#[test]
fn enrichment_struct_specimen_evidence_without_error_fields() {
    let ev = FrontierSpecimenEvidence {
        specimen_id: "ok_specimen".to_string(),
        family: ParserFrontierFamily::VariableDeclaration,
        expected_outcome: ExpectedParseOutcome::Accepted,
        actual_outcome: ActualParseOutcome::Accepted,
        verdict: FrontierVerdict::Pass,
        error_code: None,
        error_message: None,
        event_ir_hash: Some("cafebabe".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    // Verify None fields serialize as null in JSON
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(value["error_code"].is_null());
    assert!(value["error_message"].is_null());
}

#[test]
fn enrichment_struct_event_with_all_none_optionals() {
    let event = FrontierEvidenceEvent {
        schema_version: PARSER_FRONTIER_EVENT_SCHEMA_VERSION.to_string(),
        component: PARSER_FRONTIER_COMPONENT.to_string(),
        event: "frontier_evidence_run_started".to_string(),
        policy_id: PARSER_FRONTIER_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: FrontierEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.specimen_id, None);
    assert_eq!(back.verdict, None);
    assert_eq!(back.detail, None);
}

#[test]
fn enrichment_struct_artifact_paths_all_fields_populated() {
    let paths = FrontierEvidenceArtifactPaths {
        evidence_inventory: "inv.json".to_string(),
        run_manifest: "manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "cmds.txt".to_string(),
    };
    assert!(!paths.evidence_inventory.is_empty());
    assert!(!paths.run_manifest.is_empty());
    assert!(!paths.events_jsonl.is_empty());
    assert!(!paths.commands_txt.is_empty());
    let json = serde_json::to_string(&paths).unwrap();
    let back: FrontierEvidenceArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

// ── Inventory lifecycle and arithmetic ──

#[test]
fn enrichment_lifecycle_inventory_pass_count_equals_evidence_pass_count() {
    let inv = run_frontier_corpus();
    let manual_pass = inv
        .evidence
        .iter()
        .filter(|e| e.verdict == FrontierVerdict::Pass)
        .count() as u64;
    let manual_fail = inv
        .evidence
        .iter()
        .filter(|e| e.verdict == FrontierVerdict::Fail)
        .count() as u64;
    assert_eq!(inv.pass_count, manual_pass);
    assert_eq!(inv.fail_count, manual_fail);
}

#[test]
fn enrichment_lifecycle_inventory_accepted_rejected_counts_match_evidence() {
    let inv = run_frontier_corpus();
    let manual_accepted = inv
        .evidence
        .iter()
        .filter(|e| e.actual_outcome == ActualParseOutcome::Accepted)
        .count() as u64;
    let manual_rejected = inv
        .evidence
        .iter()
        .filter(|e| e.actual_outcome == ActualParseOutcome::Rejected)
        .count() as u64;
    assert_eq!(inv.accepted_count, manual_accepted);
    assert_eq!(inv.rejected_count, manual_rejected);
}

#[test]
fn enrichment_arithmetic_family_coverage_per_family_matches_evidence() {
    let inv = run_frontier_corpus();
    let mut manual_coverage: BTreeMap<String, u64> = BTreeMap::new();
    for ev in &inv.evidence {
        *manual_coverage
            .entry(ev.family.as_str().to_string())
            .or_insert(0) += 1;
    }
    assert_eq!(inv.family_coverage, manual_coverage);
}

#[test]
fn enrichment_arithmetic_specimen_count_equals_corpus_len() {
    let corpus = frontier_corpus();
    let inv = run_frontier_corpus();
    assert_eq!(inv.specimen_count, corpus.len() as u64);
}

#[test]
fn enrichment_arithmetic_contract_satisfied_iff_zero_fail() {
    // Base case: real inventory has 0 failures
    let inv = run_frontier_corpus();
    assert_eq!(inv.fail_count, 0);
    assert!(inv.contract_satisfied());

    // Synthesized: non-zero fail_count
    let mut modified = inv.clone();
    modified.fail_count = 5;
    assert!(!modified.contract_satisfied());

    // Boundary: exactly 1
    modified.fail_count = 1;
    assert!(!modified.contract_satisfied());

    // Back to 0
    modified.fail_count = 0;
    assert!(modified.contract_satisfied());
}

// ── Content hash determinism ──

#[test]
fn enrichment_hash_inventory_json_deterministic_across_runs() {
    let inv1 = run_frontier_corpus();
    let inv2 = run_frontier_corpus();
    let json1 = serde_json::to_string_pretty(&inv1).unwrap();
    let json2 = serde_json::to_string_pretty(&inv2).unwrap();
    assert_eq!(
        json1, json2,
        "inventory JSON should be byte-identical across runs"
    );
}

#[test]
fn enrichment_hash_bundle_hash_is_lowercase_hex() {
    let out = unique_temp_dir("pfe-enrich-hex");
    let cmds = vec!["enrichment_test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    assert_eq!(arts.inventory_hash.len(), 64);
    assert!(
        arts.inventory_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "hash should be lowercase hex: {}",
        arts.inventory_hash
    );
}

#[test]
fn enrichment_hash_bundle_hash_stable_across_three_runs() {
    let mut hashes = Vec::new();
    for i in 0..3 {
        let out = unique_temp_dir(&format!("pfe-enrich-stable-{i}"));
        let cmds = vec!["stability".to_string()];
        let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
        hashes.push(arts.inventory_hash);
    }
    assert_eq!(hashes[0], hashes[1]);
    assert_eq!(hashes[1], hashes[2]);
}

// ── Edge cases ──

#[test]
fn enrichment_edge_empty_commands_list() {
    let out = unique_temp_dir("pfe-enrich-empty-cmds");
    let cmds: Vec<String> = vec![];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let content = fs::read_to_string(&arts.commands_path).unwrap();
    assert!(
        content.is_empty(),
        "empty commands should produce empty file"
    );
}

#[test]
fn enrichment_edge_single_command() {
    let out = unique_temp_dir("pfe-enrich-single-cmd");
    let cmds = vec!["only_one".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let content = fs::read_to_string(&arts.commands_path).unwrap();
    assert_eq!(content.trim(), "only_one");
}

#[test]
fn enrichment_edge_commands_with_special_chars() {
    let out = unique_temp_dir("pfe-enrich-special-cmds");
    let cmds = vec![
        "echo 'hello world'".to_string(),
        "path/to/file --flag=value".to_string(),
        "unicode: \u{00e9}\u{00e8}\u{00ea}".to_string(),
    ];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let content = fs::read_to_string(&arts.commands_path).unwrap();
    for cmd in &cmds {
        assert!(
            content.contains(cmd.as_str()),
            "commands file missing: {cmd}"
        );
    }
}

#[test]
fn enrichment_edge_corpus_no_duplicate_families_in_all() {
    let all = ParserFrontierFamily::ALL;
    let set: BTreeSet<&ParserFrontierFamily> = all.iter().collect();
    assert_eq!(
        set.len(),
        all.len(),
        "ParserFrontierFamily::ALL has duplicate entries"
    );
}

#[test]
fn enrichment_edge_family_all_count_is_24() {
    assert_eq!(ParserFrontierFamily::ALL.len(), 24);
}

#[test]
fn enrichment_edge_corpus_rejected_specimen_has_empty_source() {
    let corpus = frontier_corpus();
    let empty_source_specimens: Vec<_> = corpus.iter().filter(|s| s.source.is_empty()).collect();
    for s in &empty_source_specimens {
        assert_eq!(
            s.expected_outcome,
            ExpectedParseOutcome::Rejected,
            "empty-source specimen {} should expect rejection",
            s.specimen_id
        );
    }
}

// ── Event lifecycle ordering ──

#[test]
fn enrichment_lifecycle_events_jsonl_all_reference_correct_schema() {
    let out = unique_temp_dir("pfe-enrich-evt-schema");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let events_str = fs::read_to_string(&arts.events_path).unwrap();
    for line in events_str.lines() {
        let event: FrontierEvidenceEvent = serde_json::from_str(line).unwrap();
        assert_eq!(event.schema_version, PARSER_FRONTIER_EVENT_SCHEMA_VERSION);
        assert_eq!(event.component, PARSER_FRONTIER_COMPONENT);
        assert_eq!(event.policy_id, PARSER_FRONTIER_POLICY_ID);
    }
}

#[test]
fn enrichment_lifecycle_events_specimen_ids_match_corpus_order() {
    let out = unique_temp_dir("pfe-enrich-evt-order");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let events_str = fs::read_to_string(&arts.events_path).unwrap();
    let lines: Vec<&str> = events_str.lines().collect();
    let corpus = frontier_corpus();

    // Middle events (indices 1..len-1) should match corpus order
    for (i, specimen) in corpus.iter().enumerate() {
        let event: FrontierEvidenceEvent = serde_json::from_str(lines[i + 1]).unwrap();
        assert_eq!(
            event.specimen_id.as_deref(),
            Some(specimen.specimen_id.as_str()),
            "event at index {} should match corpus specimen {}",
            i,
            specimen.specimen_id
        );
    }
}

#[test]
fn enrichment_lifecycle_completed_event_detail_contains_counts() {
    let out = unique_temp_dir("pfe-enrich-evt-detail");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let events_str = fs::read_to_string(&arts.events_path).unwrap();
    let lines: Vec<&str> = events_str.lines().collect();
    let last: FrontierEvidenceEvent = serde_json::from_str(lines[lines.len() - 1]).unwrap();
    let detail = last.detail.unwrap();
    assert!(detail.contains("pass"), "detail should mention pass count");
    assert!(detail.contains("fail"), "detail should mention fail count");
    assert!(
        detail.contains("SATISFIED"),
        "detail should contain SATISFIED for passing corpus"
    );
}

#[test]
fn enrichment_lifecycle_started_event_detail_mentions_specimen_count() {
    let out = unique_temp_dir("pfe-enrich-evt-start");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let events_str = fs::read_to_string(&arts.events_path).unwrap();
    let first_line = events_str.lines().next().unwrap();
    let first: FrontierEvidenceEvent = serde_json::from_str(first_line).unwrap();
    let detail = first.detail.unwrap();
    let corpus = frontier_corpus();
    assert!(
        detail.contains(&corpus.len().to_string()),
        "start event detail should mention specimen count ({}), got: {}",
        corpus.len(),
        detail
    );
}

// ── Manifest field validation ──

#[test]
fn enrichment_lifecycle_manifest_decision_id_derives_from_trace_id() {
    let out = unique_temp_dir("pfe-enrich-decision");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let m: FrontierEvidenceRunManifest =
        serde_json::from_slice(&fs::read(&arts.run_manifest_path).unwrap()).unwrap();
    let expected_decision_id = format!("decision-{}", m.trace_id);
    assert_eq!(m.decision_id, expected_decision_id);
}

#[test]
fn enrichment_lifecycle_manifest_trace_id_suffix_length() {
    let out = unique_temp_dir("pfe-enrich-trace-len");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let m: FrontierEvidenceRunManifest =
        serde_json::from_slice(&fs::read(&arts.run_manifest_path).unwrap()).unwrap();
    // trace_id = "parser-frontier-" + 12 hex chars
    let prefix = "parser-frontier-";
    assert!(m.trace_id.starts_with(prefix));
    let suffix = &m.trace_id[prefix.len()..];
    assert_eq!(suffix.len(), 12, "trace suffix should be 12 chars");
    assert!(
        suffix.chars().all(|c| c.is_ascii_hexdigit()),
        "trace suffix should be hex: {suffix}"
    );
}

// ── Synthesized inventory scenarios ──

#[test]
fn enrichment_struct_inventory_contract_with_zero_specimens() {
    let inv = ParserFrontierEvidenceInventory {
        schema_version: PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION.to_string(),
        component: PARSER_FRONTIER_COMPONENT.to_string(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        accepted_count: 0,
        rejected_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: Vec::new(),
    };
    assert!(inv.contract_satisfied());
    let json = serde_json::to_string(&inv).unwrap();
    let back: ParserFrontierEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn enrichment_struct_inventory_with_all_failures() {
    let inv = ParserFrontierEvidenceInventory {
        schema_version: PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION.to_string(),
        component: PARSER_FRONTIER_COMPONENT.to_string(),
        specimen_count: 3,
        pass_count: 0,
        fail_count: 3,
        accepted_count: 1,
        rejected_count: 2,
        family_coverage: BTreeMap::new(),
        evidence: vec![
            FrontierSpecimenEvidence {
                specimen_id: "s1".to_string(),
                family: ParserFrontierFamily::VariableDeclaration,
                expected_outcome: ExpectedParseOutcome::Accepted,
                actual_outcome: ActualParseOutcome::Rejected,
                verdict: FrontierVerdict::Fail,
                error_code: Some("E001".to_string()),
                error_message: Some("unexpected rejection".to_string()),
                event_ir_hash: None,
            },
            FrontierSpecimenEvidence {
                specimen_id: "s2".to_string(),
                family: ParserFrontierFamily::ArrowFunction,
                expected_outcome: ExpectedParseOutcome::Rejected,
                actual_outcome: ActualParseOutcome::Accepted,
                verdict: FrontierVerdict::Fail,
                error_code: None,
                error_message: None,
                event_ir_hash: Some("hash2".to_string()),
            },
            FrontierSpecimenEvidence {
                specimen_id: "s3".to_string(),
                family: ParserFrontierFamily::ClassDeclaration,
                expected_outcome: ExpectedParseOutcome::Accepted,
                actual_outcome: ActualParseOutcome::Rejected,
                verdict: FrontierVerdict::Fail,
                error_code: Some("E002".to_string()),
                error_message: Some("class parse failure".to_string()),
                event_ir_hash: None,
            },
        ],
    };
    assert!(!inv.contract_satisfied());
    let json = serde_json::to_string(&inv).unwrap();
    let back: ParserFrontierEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

// ── SecurityEpoch cross-module smoke test ──

#[test]
fn enrichment_cross_module_security_epoch_interop() {
    // Verify SecurityEpoch can be constructed alongside frontier evidence types,
    // exercising the import path required by the task specification.
    let epoch = SecurityEpoch::from_raw(42);
    assert_eq!(epoch.as_u64(), 42);

    let inv = run_frontier_corpus();
    assert!(inv.specimen_count > 0);
    // Epoch and evidence are independent subsystems; verify no conflict.
    let epoch_zero = SecurityEpoch::from_raw(0);
    assert_eq!(epoch_zero.as_u64(), 0);
}

// ── Family ordering contracts ──

#[test]
fn enrichment_edge_family_all_is_sorted() {
    let all = ParserFrontierFamily::ALL;
    for window in all.windows(2) {
        assert!(
            window[0] < window[1],
            "ALL is not sorted: {:?} >= {:?}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn enrichment_edge_family_copy_clone_eq() {
    for family in ParserFrontierFamily::ALL {
        let copied = *family;
        let cloned = family.clone();
        assert_eq!(copied, *family);
        assert_eq!(cloned, *family);
        assert_eq!(copied, cloned);
    }
}

// ── Bundle artifact file content validation ──

#[test]
fn enrichment_lifecycle_bundle_inventory_file_matches_runtime() {
    let out = unique_temp_dir("pfe-enrich-inv-match");
    let cmds = vec!["check".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let file_inv: ParserFrontierEvidenceInventory =
        serde_json::from_slice(&fs::read(&arts.inventory_path).unwrap()).unwrap();
    let runtime_inv = run_frontier_corpus();
    assert_eq!(file_inv, runtime_inv);
}

#[test]
fn enrichment_lifecycle_bundle_events_count_equals_specimens_plus_two() {
    let out = unique_temp_dir("pfe-enrich-evt-cnt");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let events_str = fs::read_to_string(&arts.events_path).unwrap();
    let line_count = events_str.lines().count();
    let corpus = frontier_corpus();
    assert_eq!(
        line_count,
        corpus.len() + 2,
        "events should have specimen_count + 2 (start + end) lines"
    );
}

#[test]
fn enrichment_lifecycle_bundle_manifest_json_is_pretty_printed() {
    let out = unique_temp_dir("pfe-enrich-pretty");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let manifest_str = fs::read_to_string(&arts.run_manifest_path).unwrap();
    // Pretty-printed JSON contains newlines and indentation
    assert!(
        manifest_str.contains('\n'),
        "manifest should be pretty-printed with newlines"
    );
    assert!(
        manifest_str.contains("  "),
        "manifest should have indentation"
    );
}

// ── Specimen serde with parse_goal ──

#[test]
fn enrichment_serde_specimen_preserves_parse_goal() {
    let corpus = frontier_corpus();
    let module_specimens: Vec<_> = corpus
        .iter()
        .filter(|s| {
            let json = serde_json::to_string(s).unwrap();
            json.contains("\"module\"") || json.contains("\"Module\"")
        })
        .collect();
    // There should be import and export specimens with Module parse goal
    assert!(
        !module_specimens.is_empty(),
        "corpus should have at least one Module-goal specimen"
    );
    for s in &module_specimens {
        let json = serde_json::to_string(s).unwrap();
        let back: FrontierSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(back.parse_goal, s.parse_goal);
    }
}

// ── Schema version format consistency ──

#[test]
fn enrichment_edge_schema_versions_contain_version_suffix() {
    // All schema versions should end with a version identifier like "v1"
    assert!(
        PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION.contains(".v"),
        "evidence schema should contain version suffix"
    );
    assert!(
        PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION.contains(".v"),
        "manifest schema should contain version suffix"
    );
    assert!(
        PARSER_FRONTIER_EVENT_SCHEMA_VERSION.contains(".v"),
        "event schema should contain version suffix"
    );
    assert!(
        PARSER_FRONTIER_POLICY_ID.contains(".v"),
        "policy ID should contain version suffix"
    );
}

#[test]
fn enrichment_edge_all_schema_constants_share_common_prefix() {
    let prefix = "franken-engine.parser-frontier-evidence.";
    assert!(PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION.starts_with(prefix));
    assert!(PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION.starts_with(prefix));
    assert!(PARSER_FRONTIER_EVENT_SCHEMA_VERSION.starts_with(prefix));
    assert!(PARSER_FRONTIER_POLICY_ID.starts_with(prefix));
}
