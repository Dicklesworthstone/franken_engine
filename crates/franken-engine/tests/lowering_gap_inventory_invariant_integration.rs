use frankenengine_engine::lowering_gap_inventory::{
    lowering_gap_inventory, LoweringGapSiteDescriptor, LoweringGapSiteId, LoweringGapStatus,
};

#[test]
fn test_lowering_gap_status_execution_ready_invariant() {
    // Test the core invariant: execution_ready_semantics must derive from status

    for site in LoweringGapSiteId::ALL {
        let status = site.status();
        let execution_ready = site.execution_ready_semantics();

        match status {
            LoweringGapStatus::Resolved => {
                assert!(
                    execution_ready,
                    "Site {} has status Resolved but execution_ready_semantics is false",
                    site.as_str()
                );
            }
            LoweringGapStatus::OpenPlaceholder => {
                assert!(
                    !execution_ready,
                    "Site {} has status OpenPlaceholder but execution_ready_semantics is true",
                    site.as_str()
                );
                assert!(
                    site.parser_ready_syntax(),
                    "Site {} has status OpenPlaceholder but parser_ready_syntax is false",
                    site.as_str()
                );
            }
            LoweringGapStatus::FailClosed => {
                assert!(
                    !execution_ready,
                    "Site {} has status FailClosed but execution_ready_semantics is true",
                    site.as_str()
                );
                assert!(
                    !site.parser_ready_syntax(),
                    "Site {} has status FailClosed but parser_ready_syntax is true",
                    site.as_str()
                );
            }
        }
    }
}

#[test]
fn test_lowering_gap_descriptor_from_site_consistency() {
    // Test that LoweringGapSiteDescriptor::from_site maintains the invariant

    for site in LoweringGapSiteId::ALL {
        let descriptor = LoweringGapSiteDescriptor::from_site(site);

        // Descriptor fields must match site methods
        assert_eq!(
            descriptor.status,
            site.status(),
            "Descriptor status doesn't match site status for {}",
            site.as_str()
        );

        assert_eq!(
            descriptor.execution_ready_semantics,
            site.execution_ready_semantics(),
            "Descriptor execution_ready_semantics doesn't match site method for {}",
            site.as_str()
        );

        assert_eq!(
            descriptor.parser_ready_syntax,
            site.parser_ready_syntax(),
            "Descriptor parser_ready_syntax doesn't match site method for {}",
            site.as_str()
        );

        // Verify the invariant holds in the descriptor
        match descriptor.status {
            LoweringGapStatus::Resolved => {
                assert!(
                    descriptor.execution_ready_semantics,
                    "Descriptor for {} has Resolved status but execution_ready_semantics false",
                    site.as_str()
                );
            }
            LoweringGapStatus::OpenPlaceholder => {
                assert!(
                    !descriptor.execution_ready_semantics,
                    "Descriptor for {} has OpenPlaceholder status but execution_ready_semantics true",
                    site.as_str()
                );
                assert!(
                    descriptor.parser_ready_syntax,
                    "Descriptor for {} has OpenPlaceholder status but parser_ready_syntax false",
                    site.as_str()
                );
            }
            LoweringGapStatus::FailClosed => {
                assert!(
                    !descriptor.execution_ready_semantics,
                    "Descriptor for {} has FailClosed status but execution_ready_semantics true",
                    site.as_str()
                );
                assert!(
                    !descriptor.parser_ready_syntax,
                    "Descriptor for {} has FailClosed status but parser_ready_syntax true",
                    site.as_str()
                );
            }
        }
    }
}

#[test]
fn test_lowering_gap_inventory_count_consistency() {
    // Test that inventory count methods reflect the actual status distribution

    let inventory = lowering_gap_inventory();

    // Count sites by status
    let mut resolved_count = 0;
    let mut open_placeholder_count = 0;
    let mut fail_closed_count = 0;

    for site_descriptor in &inventory.sites {
        match site_descriptor.status {
            LoweringGapStatus::Resolved => resolved_count += 1,
            LoweringGapStatus::OpenPlaceholder => open_placeholder_count += 1,
            LoweringGapStatus::FailClosed => fail_closed_count += 1,
        }
    }

    // Verify count methods match actual counts
    assert_eq!(
        inventory.resolved_site_count(),
        resolved_count,
        "resolved_site_count() doesn't match actual resolved sites"
    );

    assert_eq!(
        inventory.open_placeholder_site_count(),
        open_placeholder_count,
        "open_placeholder_site_count() doesn't match actual open placeholder sites"
    );

    assert_eq!(
        inventory.fail_closed_site_count(),
        fail_closed_count,
        "fail_closed_site_count() doesn't match actual fail closed sites"
    );

    // Verify execution_ready_site_count matches resolved sites
    // (since all resolved sites should be execution ready)
    let execution_ready_count = inventory
        .sites
        .iter()
        .filter(|site| site.execution_ready_semantics)
        .count();

    assert_eq!(
        inventory.execution_ready_site_count(),
        execution_ready_count,
        "execution_ready_site_count() doesn't match actual execution ready sites"
    );

    // For current implementation: all sites are resolved, so execution_ready should equal total
    assert_eq!(
        resolved_count,
        execution_ready_count,
        "All resolved sites should be execution ready"
    );
}

#[test]
fn test_no_contradictory_combinations() {
    // Test that no site has contradictory status/readiness combinations

    for site in LoweringGapSiteId::ALL {
        let descriptor = LoweringGapSiteDescriptor::from_site(site);

        // Check for forbidden combinations
        if descriptor.status == LoweringGapStatus::Resolved {
            assert!(
                descriptor.execution_ready_semantics,
                "Site {} is Resolved but not execution ready - forbidden combination",
                site.as_str()
            );
        }

        if descriptor.status == LoweringGapStatus::FailClosed {
            assert!(
                !descriptor.parser_ready_syntax,
                "Site {} is FailClosed but parser ready - forbidden combination",
                site.as_str()
            );
            assert!(
                !descriptor.execution_ready_semantics,
                "Site {} is FailClosed but execution ready - forbidden combination",
                site.as_str()
            );
        }

        if !descriptor.parser_ready_syntax {
            assert!(
                !descriptor.execution_ready_semantics,
                "Site {} is not parser ready but execution ready - forbidden combination",
                site.as_str()
            );
        }
    }
}

#[test]
fn test_current_implementation_all_resolved() {
    // Test the current state: all sites should be resolved

    for site in LoweringGapSiteId::ALL {
        assert_eq!(
            site.status(),
            LoweringGapStatus::Resolved,
            "Site {} should have Resolved status in current implementation",
            site.as_str()
        );

        assert!(
            site.execution_ready_semantics(),
            "Site {} should be execution ready in current implementation",
            site.as_str()
        );

        assert!(
            site.parser_ready_syntax(),
            "Site {} should be parser ready in current implementation",
            site.as_str()
        );
    }

    let inventory = lowering_gap_inventory();

    // All sites should be resolved
    assert_eq!(
        inventory.resolved_site_count(),
        inventory.sites.len(),
        "All sites should be resolved"
    );

    // No sites should be open placeholders or fail closed
    assert_eq!(
        inventory.open_placeholder_site_count(),
        0,
        "No sites should be open placeholders in current implementation"
    );

    assert_eq!(
        inventory.fail_closed_site_count(),
        0,
        "No sites should be fail closed in current implementation"
    );

    // All sites should be execution ready
    assert_eq!(
        inventory.execution_ready_site_count(),
        inventory.sites.len(),
        "All sites should be execution ready"
    );

    assert_eq!(
        inventory.parser_ready_site_count(),
        inventory.sites.len(),
        "All sites should be parser ready"
    );
}

#[test]
fn test_invariant_validation_for_future_changes() {
    // Test that provides a template for validating the invariant when new sites are added

    // This test documents the expected behavior for different status values
    // and serves as a guide for future implementations

    // Simulate different status combinations and verify invariant holds
    let test_cases = [
        (LoweringGapStatus::Resolved, true, true),      // (status, parser_ready, execution_ready)
        (LoweringGapStatus::OpenPlaceholder, true, false),
        (LoweringGapStatus::FailClosed, false, false),
    ];

    for (status, expected_parser_ready, expected_execution_ready) in test_cases {
        // This validates the logical invariant for each status type
        match status {
            LoweringGapStatus::Resolved => {
                assert!(expected_execution_ready, "Resolved status requires execution_ready");
                assert!(expected_parser_ready, "Resolved status requires parser_ready");
            }
            LoweringGapStatus::OpenPlaceholder => {
                assert!(!expected_execution_ready, "OpenPlaceholder status forbids execution_ready");
                assert!(expected_parser_ready, "OpenPlaceholder status requires parser_ready");
            }
            LoweringGapStatus::FailClosed => {
                assert!(!expected_execution_ready, "FailClosed status forbids execution_ready");
                assert!(!expected_parser_ready, "FailClosed status forbids parser_ready");
            }
        }
    }
}