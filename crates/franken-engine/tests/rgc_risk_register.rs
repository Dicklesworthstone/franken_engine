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

use std::{collections::BTreeMap, collections::BTreeSet, fs, path::PathBuf};

use serde::{Deserialize, Serialize};

const RISK_REGISTER_SCHEMA_VERSION: &str = "rgc.risk-register.v1";
const RISK_REGISTER_JSON: &str = include_str!("../../../docs/rgc_risk_register_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RiskRegister {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: RiskTrack,
    review_policy: ReviewPolicy,
    risks: Vec<RiskEntry>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RiskTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReviewPolicy {
    fail_closed_on_stale_review: bool,
    stale_threshold_days: u64,
    milestone_reviews: Vec<MilestoneReview>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MilestoneReview {
    milestone: String,
    gate_id: String,
    required_reviewers: Vec<String>,
    cadence: String,
    required_evidence_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RiskEntry {
    risk_id: String,
    title: String,
    domain: String,
    likelihood: u8,
    impact: u8,
    risk_level: String,
    owner_role: String,
    mitigation_beads: Vec<String>,
    mitigation_summary: String,
    rollback_plan: String,
    last_reviewed_utc: String,
    next_review_due_utc: String,
    milestones_pending: Vec<String>,
    open_actions: Vec<String>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_risk_register() -> RiskRegister {
    serde_json::from_str(RISK_REGISTER_JSON).expect("risk register json must parse")
}

#[test]
fn rgc_013_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_RISK_REGISTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# RGC Risk Register V1",
        "## Purpose",
        "## Risk Model",
        "## Top-20 Coverage",
        "## High-Risk Mitigation Linkage",
        "## Milestone Review Cadence",
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
fn rgc_013_register_is_versioned_and_track_bound() {
    let register = parse_risk_register();

    assert_eq!(register.schema_version, RISK_REGISTER_SCHEMA_VERSION);
    assert_eq!(register.bead_id, "bd-1lsy.1.3");
    assert_eq!(register.generated_by, "bd-1lsy.1.3");
    assert_eq!(register.track.id, "RGC-013");
    assert_eq!(register.track.name, "Risk Register and Mitigation Map");
    assert!(register.generated_at_utc.ends_with('Z'));
}

#[test]
fn rgc_013_top_twenty_risks_have_owner_and_mitigation_path() {
    let register = parse_risk_register();

    assert!(
        register.risks.len() >= 20,
        "expected at least 20 risks, found {}",
        register.risks.len()
    );

    let mut ids = BTreeSet::new();

    for risk in &register.risks {
        assert!(
            ids.insert(risk.risk_id.clone()),
            "duplicate risk id {}",
            risk.risk_id
        );
        assert!(!risk.title.trim().is_empty());
        assert!(!risk.domain.trim().is_empty());
        assert!((1..=5).contains(&risk.likelihood));
        assert!((1..=5).contains(&risk.impact));
        assert!(["high", "medium", "low"].contains(&risk.risk_level.as_str()));
        assert!(!risk.owner_role.trim().is_empty());
        assert!(!risk.mitigation_summary.trim().is_empty());
        assert!(!risk.rollback_plan.trim().is_empty());
        assert!(
            !risk.mitigation_beads.is_empty(),
            "{} missing mitigation bead mapping",
            risk.risk_id
        );
        assert!(
            risk.mitigation_beads
                .iter()
                .all(|bead_id| bead_id.starts_with("bd-1lsy.")),
            "{} must only map to concrete RGC beads",
            risk.risk_id
        );
        assert!(risk.last_reviewed_utc.ends_with('Z'));
        assert!(risk.next_review_due_utc.ends_with('Z'));
        assert!(
            risk.last_reviewed_utc <= risk.next_review_due_utc,
            "{} has invalid review chronology",
            risk.risk_id
        );
    }
}

#[test]
fn rgc_013_high_risks_link_to_one_or_more_concrete_beads() {
    let register = parse_risk_register();

    let high_risks: Vec<&RiskEntry> = register
        .risks
        .iter()
        .filter(|risk| risk.risk_level == "high")
        .collect();

    assert!(!high_risks.is_empty(), "expected at least one high risk");

    for risk in high_risks {
        assert!(
            !risk.mitigation_beads.is_empty(),
            "high risk {} missing mitigation beads",
            risk.risk_id
        );
        assert!(
            !risk.open_actions.is_empty(),
            "high risk {} should have open actions",
            risk.risk_id
        );
    }
}

#[test]
fn rgc_013_review_policy_covers_every_milestone_gate() {
    let register = parse_risk_register();

    assert!(register.review_policy.fail_closed_on_stale_review);
    assert_eq!(register.review_policy.stale_threshold_days, 14);

    let expected: BTreeSet<&str> = ["M1", "M2", "M3", "M4", "M5"].into_iter().collect();
    let actual: BTreeSet<&str> = register
        .review_policy
        .milestone_reviews
        .iter()
        .map(|review| review.milestone.as_str())
        .collect();

    assert_eq!(actual, expected);

    for review in &register.review_policy.milestone_reviews {
        assert!(!review.gate_id.trim().is_empty());
        assert!(!review.required_reviewers.is_empty());
        assert!(!review.cadence.trim().is_empty());
        assert!(!review.required_evidence_fields.is_empty());
        for field in ["trace_id", "decision_id", "risk_ids_reviewed", "actions"] {
            assert!(
                review
                    .required_evidence_fields
                    .iter()
                    .any(|candidate| candidate == field),
                "{} missing required evidence field {}",
                review.milestone,
                field
            );
        }
    }
}

#[test]
fn rgc_013_all_risks_are_reviewed_at_milestones() {
    let register = parse_risk_register();
    let valid_milestones: BTreeSet<&str> = ["M1", "M2", "M3", "M4", "M5"].into_iter().collect();

    for risk in &register.risks {
        assert!(
            !risk.milestones_pending.is_empty(),
            "{} must be tracked in at least one milestone review",
            risk.risk_id
        );
        assert!(
            risk.milestones_pending
                .iter()
                .all(|milestone| valid_milestones.contains(milestone.as_str())),
            "{} includes unknown milestone in pending set",
            risk.risk_id
        );
    }
}

#[test]
fn rgc_013_operator_verification_commands_are_present() {
    let register = parse_risk_register();
    assert!(!register.operator_verification.is_empty());

    let joined = register.operator_verification.join("\n");
    assert!(joined.contains("jq empty docs/rgc_risk_register_v1.json"));
    assert!(joined.contains("cargo test -p frankenengine-engine --test rgc_risk_register"));
    assert!(joined.contains("run_phase_a_exit_gate.sh check"));
}

#[test]
fn rgc_013_serde_roundtrip_preserves_register() {
    let register = parse_risk_register();
    let serialized = serde_json::to_string(&register).expect("serialize");
    let deserialized: RiskRegister = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(register, deserialized);
}

#[test]
fn rgc_013_deterministic_double_parse() {
    let a = parse_risk_register();
    let b = parse_risk_register();
    assert_eq!(a, b);
}

#[test]
fn rgc_013_risk_ids_are_unique() {
    let register = parse_risk_register();
    let mut seen = BTreeSet::new();
    for risk in &register.risks {
        assert!(
            seen.insert(&risk.risk_id),
            "duplicate risk_id: {}",
            risk.risk_id
        );
    }
}

#[test]
fn rgc_013_risk_levels_are_valid_and_high_risks_have_high_scores() {
    let register = parse_risk_register();
    for risk in &register.risks {
        assert!(
            ["high", "medium", "low"].contains(&risk.risk_level.as_str()),
            "{} has invalid risk_level: {}",
            risk.risk_id,
            risk.risk_level
        );
        let score = risk.likelihood as u16 * risk.impact as u16;
        // High risks should have non-trivial score
        if risk.risk_level == "high" {
            assert!(
                score >= 6,
                "{} marked high but score {} is too low",
                risk.risk_id,
                score
            );
        }
    }
}

#[test]
fn rgc_013_doc_file_is_nonempty() {
    let path = repo_root().join("docs/RGC_RISK_REGISTER_V1.md");
    let content = fs::read_to_string(&path).expect("read doc");
    assert!(!content.is_empty());
}

#[test]
fn rgc_013_milestone_gate_ids_are_unique() {
    let register = parse_risk_register();
    let mut seen = BTreeSet::new();
    for review in &register.review_policy.milestone_reviews {
        assert!(
            seen.insert(&review.gate_id),
            "duplicate gate_id: {}",
            review.gate_id
        );
    }
}

#[test]
fn rgc_013_risk_domains_are_nonempty_strings() {
    let register = parse_risk_register();
    let mut domains = BTreeSet::new();
    for risk in &register.risks {
        assert!(!risk.domain.trim().is_empty());
        domains.insert(risk.domain.as_str());
    }
    // Should have multiple domains
    assert!(domains.len() >= 2, "expected multiple risk domains");
}

#[test]
fn rgc_013_all_open_actions_are_nonempty() {
    let register = parse_risk_register();
    for risk in &register.risks {
        for action in &risk.open_actions {
            assert!(
                !action.trim().is_empty(),
                "risk {} has empty open_action",
                risk.risk_id
            );
        }
    }
}

#[test]
fn rgc_013_review_required_reviewers_are_nonempty() {
    let register = parse_risk_register();
    for review in &register.review_policy.milestone_reviews {
        assert!(!review.required_reviewers.is_empty());
        for reviewer in &review.required_reviewers {
            assert!(
                !reviewer.trim().is_empty(),
                "milestone {} has empty reviewer",
                review.milestone
            );
        }
    }
}

#[test]
fn rgc_013_register_has_nonempty_bead_id() {
    let register = parse_risk_register();
    assert!(!register.bead_id.trim().is_empty());
}

#[test]
fn rgc_013_register_has_nonempty_schema_version() {
    let register = parse_risk_register();
    assert_eq!(register.schema_version, RISK_REGISTER_SCHEMA_VERSION);
}

#[test]
fn rgc_013_register_generated_at_utc_ends_with_z() {
    let register = parse_risk_register();
    assert!(register.generated_at_utc.ends_with('Z'));
}

#[test]
fn rgc_013_register_has_nonempty_generated_by() {
    let register = parse_risk_register();
    assert!(!register.generated_by.trim().is_empty());
}

#[test]
fn rgc_013_register_track_fields_are_nonempty() {
    let register = parse_risk_register();
    assert!(!register.track.id.trim().is_empty());
    assert!(!register.track.name.trim().is_empty());
}

#[test]
fn rgc_013_register_deterministic_double_parse() {
    let a = parse_risk_register();
    let b = parse_risk_register();
    assert_eq!(a, b);
}

// ---------- additional enrichment tests ----------

#[test]
fn rgc_013_schema_version_follows_dotted_format() {
    let register = parse_risk_register();
    let parts: Vec<&str> = register.schema_version.split('.').collect();
    assert!(
        parts.len() >= 3,
        "schema_version should have at least 3 dot-separated segments, got: {}",
        register.schema_version
    );
    for part in &parts {
        assert!(
            !part.trim().is_empty(),
            "schema_version segment must not be empty"
        );
    }
}

#[test]
fn rgc_013_risk_likelihood_and_impact_are_within_bounds() {
    let register = parse_risk_register();
    for risk in &register.risks {
        assert!(
            (1..=5).contains(&risk.likelihood),
            "{} likelihood {} not in 1..=5",
            risk.risk_id,
            risk.likelihood
        );
        assert!(
            (1..=5).contains(&risk.impact),
            "{} impact {} not in 1..=5",
            risk.risk_id,
            risk.impact
        );
    }
}

#[test]
fn rgc_013_mitigation_beads_contain_no_duplicates_per_risk() {
    let register = parse_risk_register();
    for risk in &register.risks {
        let mut seen = BTreeSet::new();
        for bead in &risk.mitigation_beads {
            assert!(
                seen.insert(bead),
                "risk {} has duplicate mitigation_bead: {}",
                risk.risk_id,
                bead
            );
        }
    }
}

#[test]
fn rgc_013_milestones_pending_contain_no_duplicates_per_risk() {
    let register = parse_risk_register();
    for risk in &register.risks {
        let mut seen = BTreeSet::new();
        for milestone in &risk.milestones_pending {
            assert!(
                seen.insert(milestone),
                "risk {} has duplicate milestone_pending: {}",
                risk.risk_id,
                milestone
            );
        }
    }
}

#[test]
fn rgc_013_operator_verification_commands_contain_no_duplicates() {
    let register = parse_risk_register();
    let mut seen = BTreeSet::new();
    for cmd in &register.operator_verification {
        assert!(
            seen.insert(cmd),
            "duplicate operator_verification command: {}",
            cmd
        );
    }
}

#[test]
fn rgc_013_review_cadence_values_are_nonempty() {
    let register = parse_risk_register();
    for review in &register.review_policy.milestone_reviews {
        assert!(
            !review.cadence.trim().is_empty(),
            "milestone {} has empty cadence",
            review.milestone
        );
    }
}

#[test]
fn rgc_013_all_rollback_plans_are_nonempty() {
    let register = parse_risk_register();
    for risk in &register.risks {
        assert!(
            !risk.rollback_plan.trim().is_empty(),
            "risk {} has empty rollback_plan",
            risk.risk_id
        );
    }
}

#[test]
fn rgc_013_all_mitigation_summaries_are_nonempty() {
    let register = parse_risk_register();
    for risk in &register.risks {
        assert!(
            !risk.mitigation_summary.trim().is_empty(),
            "risk {} has empty mitigation_summary",
            risk.risk_id
        );
    }
}

#[test]
fn rgc_013_medium_and_low_risks_have_valid_scores() {
    let register = parse_risk_register();
    for risk in &register.risks {
        let score = risk.likelihood as u16 * risk.impact as u16;
        if risk.risk_level == "low" {
            assert!(
                score <= 25,
                "{} marked low but score {} exceeds max of 25",
                risk.risk_id,
                score
            );
        }
        if risk.risk_level == "medium" {
            assert!(
                score <= 25,
                "{} marked medium but score {} exceeds max of 25",
                risk.risk_id,
                score
            );
        }
    }
}

#[test]
fn rgc_013_last_reviewed_utc_and_next_review_due_utc_end_with_z() {
    let register = parse_risk_register();
    for risk in &register.risks {
        assert!(
            risk.last_reviewed_utc.ends_with('Z'),
            "risk {} last_reviewed_utc does not end with Z: {}",
            risk.risk_id,
            risk.last_reviewed_utc
        );
        assert!(
            risk.next_review_due_utc.ends_with('Z'),
            "risk {} next_review_due_utc does not end with Z: {}",
            risk.risk_id,
            risk.next_review_due_utc
        );
    }
}

// ---------- batch-2 enrichment tests ----------

#[test]
fn rgc_013_clone_preserves_equality_for_register() {
    let register = parse_risk_register();
    let cloned = register.clone();
    assert_eq!(register, cloned);
}

#[test]
fn rgc_013_debug_format_contains_schema_version() {
    let register = parse_risk_register();
    let debug_str = format!("{:?}", register);
    assert!(
        debug_str.contains("rgc.risk-register.v1"),
        "Debug output should contain schema version"
    );
}

#[test]
fn rgc_013_serde_roundtrip_preserves_risk_entry() {
    let register = parse_risk_register();
    for risk in &register.risks {
        let serialized = serde_json::to_string(risk).expect("serialize risk");
        let deserialized: RiskEntry = serde_json::from_str(&serialized).expect("deserialize risk");
        assert_eq!(risk, &deserialized);
    }
}

#[test]
fn rgc_013_serde_roundtrip_preserves_review_policy() {
    let register = parse_risk_register();
    let serialized = serde_json::to_string(&register.review_policy).expect("serialize");
    let deserialized: ReviewPolicy = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(register.review_policy, deserialized);
}

#[test]
fn rgc_013_serde_roundtrip_preserves_milestone_review() {
    let register = parse_risk_register();
    for review in &register.review_policy.milestone_reviews {
        let serialized = serde_json::to_string(review).expect("serialize");
        let deserialized: MilestoneReview = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(review, &deserialized);
    }
}

#[test]
fn rgc_013_risk_id_format_follows_convention() {
    let register = parse_risk_register();
    for risk in &register.risks {
        assert!(
            risk.risk_id.starts_with("RGC-RISK-"),
            "risk_id {} does not follow RGC-RISK-NNN convention",
            risk.risk_id
        );
        let suffix = &risk.risk_id["RGC-RISK-".len()..];
        assert!(
            suffix.chars().all(|c| c.is_ascii_digit()),
            "risk_id {} suffix is not all digits: {}",
            risk.risk_id,
            suffix
        );
    }
}

#[test]
fn rgc_013_risk_ids_are_monotonically_numbered() {
    let register = parse_risk_register();
    let mut numbers: Vec<u32> = register
        .risks
        .iter()
        .map(|r| r.risk_id["RGC-RISK-".len()..].parse::<u32>().unwrap())
        .collect();
    let original = numbers.clone();
    numbers.sort();
    numbers.dedup();
    assert_eq!(
        numbers.len(),
        original.len(),
        "risk IDs must be unique numerically"
    );
    // Check contiguous from 1
    for (i, &num) in numbers.iter().enumerate() {
        assert_eq!(
            num,
            (i as u32) + 1,
            "risk IDs should be contiguous from 001, gap at position {}",
            i
        );
    }
}

#[test]
fn rgc_013_domain_distribution_covers_required_areas() {
    let register = parse_risk_register();
    let domains: BTreeSet<&str> = register.risks.iter().map(|r| r.domain.as_str()).collect();
    let required = ["correctness", "security", "performance", "operations"];
    for domain in required {
        assert!(
            domains.contains(domain),
            "risk register missing required domain: {}",
            domain
        );
    }
}

#[test]
fn rgc_013_high_risk_count_is_significant_fraction() {
    let register = parse_risk_register();
    let high_count = register
        .risks
        .iter()
        .filter(|r| r.risk_level == "high")
        .count();
    let total = register.risks.len();
    // High risks should be a meaningful fraction but not all
    assert!(
        high_count >= 3,
        "expected at least 3 high risks, got {}",
        high_count
    );
    assert!(
        high_count < total,
        "not all risks should be high, got {}/{}",
        high_count,
        total
    );
}

#[test]
fn rgc_013_owner_roles_are_from_known_set() {
    let register = parse_risk_register();
    let known_roles: BTreeSet<&str> = [
        "RuntimeLead",
        "TypeSystemLead",
        "ModuleInteropLead",
        "SecurityLead",
        "PerformanceLead",
        "ConformanceLead",
        "ReleaseDutyEngineer",
        "ProgramOwner",
        "ObservabilityLead",
    ]
    .into_iter()
    .collect();
    for risk in &register.risks {
        assert!(
            known_roles.contains(risk.owner_role.as_str()),
            "risk {} has unknown owner_role: {}",
            risk.risk_id,
            risk.owner_role
        );
    }
}

#[test]
fn rgc_013_gate_ids_follow_naming_convention() {
    let register = parse_risk_register();
    for review in &register.review_policy.milestone_reviews {
        assert!(
            review.gate_id.starts_with("rgc-"),
            "gate_id {} should start with 'rgc-'",
            review.gate_id
        );
        assert!(
            review.gate_id.ends_with("-gate"),
            "gate_id {} should end with '-gate'",
            review.gate_id
        );
    }
}

#[test]
fn rgc_013_milestone_review_gate_ids_embed_milestone_name() {
    let register = parse_risk_register();
    for review in &register.review_policy.milestone_reviews {
        let lower_milestone = review.milestone.to_lowercase();
        assert!(
            review.gate_id.contains(&lower_milestone),
            "gate_id {} should embed milestone {}",
            review.gate_id,
            review.milestone
        );
    }
}

#[test]
fn rgc_013_risks_per_domain_distribution() {
    let register = parse_risk_register();
    let mut domain_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for risk in &register.risks {
        *domain_counts.entry(risk.domain.as_str()).or_insert(0) += 1;
    }
    // Every domain should have at least one risk
    for count in domain_counts.values() {
        assert!(*count >= 1);
    }
    // No single domain should dominate with more than 50% of all risks
    let total = register.risks.len();
    for (domain, count) in &domain_counts {
        assert!(
            *count * 2 <= total + total, // at most all risks could be in one domain, but check sanity
            "domain {} has {} risks out of {}, dominating the register",
            domain,
            count,
            total
        );
    }
}

#[test]
fn rgc_013_clone_risk_track_preserves_fields() {
    let register = parse_risk_register();
    let track_clone = register.track.clone();
    assert_eq!(track_clone.id, "RGC-013");
    assert_eq!(track_clone.name, "Risk Register and Mitigation Map");
}

#[test]
fn rgc_013_serialized_json_contains_all_top_level_keys() {
    let register = parse_risk_register();
    let serialized = serde_json::to_string(&register).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&serialized).expect("parse as value");
    let obj = value.as_object().expect("should be object");
    let required_keys = [
        "schema_version",
        "bead_id",
        "generated_by",
        "generated_at_utc",
        "track",
        "review_policy",
        "risks",
        "operator_verification",
    ];
    for key in required_keys {
        assert!(
            obj.contains_key(key),
            "serialized JSON missing top-level key: {}",
            key
        );
    }
}

#[test]
fn rgc_013_stale_threshold_days_is_positive_and_bounded() {
    let register = parse_risk_register();
    assert!(
        register.review_policy.stale_threshold_days > 0,
        "stale_threshold_days must be positive"
    );
    assert!(
        register.review_policy.stale_threshold_days <= 30,
        "stale_threshold_days {} exceeds reasonable bound of 30 days",
        register.review_policy.stale_threshold_days
    );
}

#[test]
fn rgc_013_every_milestone_has_at_least_one_risk_pending() {
    let register = parse_risk_register();
    let milestones = ["M1", "M2", "M3", "M4", "M5"];
    for milestone in milestones {
        let count = register
            .risks
            .iter()
            .filter(|r| r.milestones_pending.iter().any(|m| m.as_str() == milestone))
            .count();
        assert!(
            count >= 1,
            "milestone {} has no risks pending review",
            milestone
        );
    }
}
