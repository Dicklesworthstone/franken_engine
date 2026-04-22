//! Integration tests for extension host topology assessment
//!
//! Tests the content hash boundary collision fixes and other critical
//! functionality of the topology assessment framework.

use frankenengine_engine::extension_host_topology_assessment::{
    SeamAssessment, TopologyPromotionAssessment, TopologyPromotionDecision,
    TopologyPromotionSummary, TopologySeamId, build_topology_promotion_assessment,
};

fn empty_summary() -> TopologyPromotionSummary {
    TopologyPromotionSummary::from_seams(&[])
}

#[test]
fn content_hash_boundary_collision_regression() {
    // Test that different field combinations that could produce the same
    // concatenated bytes now produce different hashes due to proper JSON serialization

    // Create base assessment
    let assessment1 = TopologyPromotionAssessment {
        schema_version: "1.0".to_string(),
        bead_id: "test-bead".to_string(),
        component: "test-component".to_string(),
        policy_id: "test-policy".to_string(),
        decision: TopologyPromotionDecision::BroaderPromotion,
        rationale: "test rationale".to_string(),
        fail_closed: false,
        required_prerequisites: vec!["ab".to_string(), "c".to_string()], // "ab" + "c"
        generated_from: vec!["source1".to_string()],
        seams: vec![],
        summary: empty_summary(),
        required_artifacts: vec!["artifact1".to_string()],
        verification_commands: vec!["command1".to_string()],
        content_hash: String::new(), // Will be computed
    };

    // Create assessment with different field boundary that would collide in old implementation
    let assessment2 = TopologyPromotionAssessment {
        schema_version: "1.0".to_string(),
        bead_id: "test-bead".to_string(),
        component: "test-component".to_string(),
        policy_id: "test-policy".to_string(),
        decision: TopologyPromotionDecision::BroaderPromotion,
        rationale: "test rationale".to_string(),
        fail_closed: false,
        required_prerequisites: vec!["a".to_string(), "bc".to_string()], // "a" + "bc" = same concatenation as "ab" + "c"
        generated_from: vec!["source1".to_string()],
        seams: vec![],
        summary: empty_summary(),
        required_artifacts: vec!["artifact1".to_string()],
        verification_commands: vec!["command1".to_string()],
        content_hash: String::new(), // Will be computed
    };

    // Compute content hashes
    let hash1 = assessment1.compute_content_hash();
    let hash2 = assessment2.compute_content_hash();

    // Verify hashes are different (fixing the boundary collision)
    assert_ne!(
        hash1, hash2,
        "Content hashes should differ for different array boundaries: ['ab','c'] vs ['a','bc']"
    );

    // Verify hashes are non-empty and well-formed
    assert!(!hash1.is_empty(), "Content hash should not be empty");
    assert!(!hash2.is_empty(), "Content hash should not be empty");
    assert_eq!(
        hash1.len(),
        hash2.len(),
        "Content hashes should have same length"
    );
}

#[test]
fn content_hash_seam_boundary_collision() {
    // Test boundary collisions in seam-level fields
    let base_seam_data = SeamAssessment {
        seam_id: TopologySeamId::ExtensionLifecycleManager,
        source_files: vec![], // Will be varied
        decision: TopologyPromotionDecision::TargetedPromotion,
        rationale: "test rationale".to_string(),
        trigger_assessments: vec![],
        required_upstream_primitives: vec![],
        expected_benefits: vec![], // Will be varied
        migration_risks: vec![],
        rollback_plan: "rollback".to_string(),
        operator_diagnostic_benefit: "benefit".to_string(),
        implementation_order: vec![],
    };

    // Create assessment with different seam field boundaries
    let assessment1 = TopologyPromotionAssessment {
        schema_version: "1.0".to_string(),
        bead_id: "seam-test".to_string(),
        component: "test-component".to_string(),
        policy_id: "test-policy".to_string(),
        decision: TopologyPromotionDecision::BroaderPromotion,
        rationale: "test rationale".to_string(),
        fail_closed: false,
        required_prerequisites: vec![],
        generated_from: vec![],
        seams: vec![SeamAssessment {
            source_files: vec!["file1.rs".to_string(), "file2.rs".to_string()], // "file1.rs" + "file2.rs"
            expected_benefits: vec!["benefit".to_string(), "text".to_string()], // "benefit" + "text"
            ..base_seam_data.clone()
        }],
        summary: empty_summary(),
        required_artifacts: vec![],
        verification_commands: vec![],
        content_hash: String::new(),
    };

    let assessment2 = TopologyPromotionAssessment {
        schema_version: "1.0".to_string(),
        bead_id: "seam-test".to_string(),
        component: "test-component".to_string(),
        policy_id: "test-policy".to_string(),
        decision: TopologyPromotionDecision::BroaderPromotion,
        rationale: "test rationale".to_string(),
        fail_closed: false,
        required_prerequisites: vec![],
        generated_from: vec![],
        seams: vec![SeamAssessment {
            source_files: vec!["file1.rsfile2.rs".to_string()], // Concatenated version
            expected_benefits: vec!["benefittext".to_string()], // Concatenated version
            ..base_seam_data.clone()
        }],
        summary: empty_summary(),
        required_artifacts: vec![],
        verification_commands: vec![],
        content_hash: String::new(),
    };

    let hash1 = assessment1.compute_content_hash();
    let hash2 = assessment2.compute_content_hash();

    // Verify the boundary collision is prevented
    assert_ne!(
        hash1, hash2,
        "Content hashes should differ for seam field boundaries: ['file1.rs','file2.rs'] vs ['file1.rsfile2.rs']"
    );
}

#[test]
fn content_hash_deterministic_for_identical_assessments() {
    let assessment = build_topology_promotion_assessment();

    let hash1 = assessment.compute_content_hash();
    let hash2 = assessment.compute_content_hash();

    assert_eq!(
        hash1, hash2,
        "Identical assessments should produce identical hashes"
    );
    assert!(!hash1.is_empty(), "Content hash should not be empty");
}

#[test]
fn content_hash_sensitivity_to_minor_changes() {
    let assessment1 = build_topology_promotion_assessment();
    let mut assessment2 = assessment1.clone();

    // Make a small change that should affect the hash
    assessment2.rationale = format!("{} modified", assessment1.rationale);

    let hash1 = assessment1.compute_content_hash();
    let hash2 = assessment2.compute_content_hash();

    assert_ne!(
        hash1, hash2,
        "Small changes should result in different hashes"
    );
}

#[test]
fn content_hash_excludes_hash_field_recursion() {
    let mut assessment = build_topology_promotion_assessment();

    // Compute hash with empty content_hash field
    assessment.content_hash = String::new();
    let hash1 = assessment.compute_content_hash();

    // Set content_hash to some value and recompute - should be the same
    assessment.content_hash = "some-pre-existing-hash".to_string();
    let hash2 = assessment.compute_content_hash();

    assert_eq!(
        hash1, hash2,
        "Content hash should be independent of the content_hash field value to avoid recursion"
    );
}

#[test]
fn seam_assessment_basic_functionality() {
    let assessment = build_topology_promotion_assessment();

    assert!(
        !assessment.seams.is_empty(),
        "Assessment should contain seams"
    );
    assert_eq!(
        assessment.targeted_seams().len(),
        assessment.summary.targeted_promotion_count,
        "Targeted seam count should match summary"
    );

    for seam in &assessment.seams {
        assert!(
            !seam.seam_id.as_str().is_empty(),
            "Seam ID should not be empty"
        );
        assert!(
            !seam.rationale.is_empty(),
            "Seam rationale should not be empty"
        );
    }
}

#[test]
fn topology_promotion_summary_consistency() {
    let assessment = build_topology_promotion_assessment();
    let summary = &assessment.summary;

    // Verify summary counts match actual seam contents
    let targeted_count = assessment.targeted_seams().len();
    let broader_promotion_count = assessment
        .seams
        .iter()
        .filter(|seam| seam.decision == TopologyPromotionDecision::BroaderPromotion)
        .count();
    let candidate_trigger_total: usize = assessment
        .seams
        .iter()
        .map(|seam| seam.candidate_trigger_count())
        .sum();

    assert_eq!(
        summary.targeted_promotion_count, targeted_count,
        "Summary targeted promotion count should match actual"
    );
    assert_eq!(
        summary.broader_promotion_count, broader_promotion_count,
        "Summary broader promotion count should match actual"
    );
    assert_eq!(
        summary.promotion_candidate_trigger_count, candidate_trigger_total,
        "Summary candidate trigger count should match actual"
    );
    assert_eq!(
        summary.total_seams,
        assessment.seams.len(),
        "Summary total seam count should match actual"
    );
}
