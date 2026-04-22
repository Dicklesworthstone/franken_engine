#![forbid(unsafe_code)]

//! Integration tests for compatibility advisory builder.

use frankenengine_engine::compatibility_advisory::AdvisoryBuilder;

#[test]
fn compatibility_advisory_end_to_end_workflow() {
    // Simulate a real-world scenario: module resolution divergence in a specific package
    let advisory = AdvisoryBuilder::new()
        .with_divergence("module_resolution")
        .with_context("package", "@types/node")
        .with_context("node_version", "18.17.0")
        .with_context("severity", "high")
        .build();

    // Verify the advisory contains expected content
    assert!(
        advisory
            .message
            .contains("Module resolution behavior differs"),
        "Advisory message should explain the divergence type"
    );
    assert!(
        advisory.message.contains("@types/node"),
        "Advisory message should include package context"
    );
    assert!(
        advisory.remediation.contains("URGENT"),
        "High severity should result in urgent remediation guidance"
    );
    assert!(
        advisory.remediation.contains("explicit file extensions"),
        "Module resolution remediation should include specific guidance"
    );

    // Verify advisory structure
    assert!(!advisory.message.is_empty(), "Message should not be empty");
    assert!(
        !advisory.remediation.is_empty(),
        "Remediation should not be empty"
    );
}

#[test]
fn compatibility_advisory_handles_multiple_divergence_types() {
    let test_cases = vec![
        ("import_meta", "import.meta property access"),
        ("buffer_encoding", "Buffer encoding operations"),
        ("async_hooks", "Async hooks timing"),
        ("crypto_algorithms", "Cryptographic algorithm"),
    ];

    for (divergence_tag, expected_message_fragment) in test_cases {
        let advisory = AdvisoryBuilder::new()
            .with_divergence(divergence_tag)
            .with_context("severity", "medium")
            .build();

        assert!(
            advisory.message.contains(expected_message_fragment),
            "Divergence '{}' should generate message containing '{}'",
            divergence_tag,
            expected_message_fragment
        );

        assert!(
            advisory.remediation.contains("MODERATE"),
            "Medium severity should be reflected in remediation for '{}'",
            divergence_tag
        );

        // Ensure both message and remediation are substantive
        assert!(
            advisory.message.len() > 20,
            "Message for '{}' should be substantive",
            divergence_tag
        );
        assert!(
            advisory.remediation.len() > 30,
            "Remediation for '{}' should be substantive",
            divergence_tag
        );
    }
}

#[test]
fn compatibility_advisory_context_combinations() {
    // Test various context combinations to ensure flexibility
    let scenarios = vec![
        (
            vec![("package", "express"), ("severity", "low")],
            vec!["express", "LOW"],
        ),
        (
            vec![("module", "/src/utils.js"), ("node_version", "20.0.0")],
            vec!["/src/utils.js", "20.0.0"],
        ),
        (vec![("severity", "high")], vec!["URGENT"]),
    ];

    for (context_pairs, expected_content) in scenarios {
        let mut builder = AdvisoryBuilder::new().with_divergence("stream_behavior");

        for (key, value) in context_pairs {
            builder = builder.with_context(key, value);
        }

        let advisory = builder.build();

        for expected in expected_content {
            let found_in_message = advisory.message.contains(expected);
            let found_in_remediation = advisory.remediation.contains(expected);

            assert!(
                found_in_message || found_in_remediation,
                "Expected content '{}' should appear in either message or remediation.\nMessage: {}\nRemediation: {}",
                expected,
                advisory.message,
                advisory.remediation
            );
        }
    }
}

#[test]
fn compatibility_advisory_minimal_usage() {
    // Test the most minimal usage - just the builder pattern
    let advisory = AdvisoryBuilder::new().build();

    assert_eq!(advisory.message, "Runtime behavior divergence detected");
    assert_eq!(
        advisory.remediation,
        "Review runtime-specific documentation and test with target environments"
    );

    // Test with just a divergence tag
    let advisory_with_tag = AdvisoryBuilder::new()
        .with_divergence("process_env")
        .build();

    assert!(advisory_with_tag.message.contains("Process environment"));
    assert!(
        advisory_with_tag
            .remediation
            .contains("consistent environment variable")
    );
}

#[test]
fn compatibility_advisory_builder_is_chainable() {
    // Verify the builder pattern works as expected with method chaining
    let advisory = AdvisoryBuilder::new()
        .with_divergence("fs_permissions")
        .with_context("package", "fs-extra")
        .with_context("module", "/lib/permissions.js")
        .with_context("severity", "medium")
        .build();

    // Verify all context was applied
    assert!(advisory.message.contains("File system permission"));
    assert!(advisory.message.contains("/lib/permissions.js"));
    assert!(advisory.remediation.contains("MODERATE"));

    // Ensure the builder consumed properly
    assert!(!advisory.message.is_empty());
    assert!(!advisory.remediation.is_empty());
}
