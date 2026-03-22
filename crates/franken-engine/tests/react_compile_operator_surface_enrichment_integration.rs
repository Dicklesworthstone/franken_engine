//! Enrichment integration tests for react_compile_operator_surface.
//!
//! Covers React runtime modes, build targets, operator commands,
//! compile input/output contracts, diagnostic routing, feature
//! support contracts, content hash stability, and full serde
//! round-trips.
//!
//! Plan reference: bd-1lsy.10.12 (RGC-912).

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_compile_operator_surface::{
    BEAD_ID, COMPONENT, CommandContract, DiagnosticCategory, DiagnosticSeverity, FeatureSupport,
    ReactBuildTarget, ReactCompileInput, ReactCompileOutput, ReactDiagnostic, ReactFeatureContract,
    ReactInputLanguage, ReactOperatorCommand, ReactOperatorContract, ReactRuntimeMode,
    SCHEMA_VERSION,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_compile_input(lang: ReactInputLanguage, mode: ReactRuntimeMode) -> ReactCompileInput {
    ReactCompileInput {
        source_path: "src/App.tsx".to_string(),
        language: lang,
        runtime_mode: mode,
        target: ReactBuildTarget::Client,
        source_maps: true,
        preserve_display_names: true,
        input_hash: ContentHash::compute(b"sample_source"),
    }
}

fn sample_compile_output(mode: ReactRuntimeMode) -> ReactCompileOutput {
    ReactCompileOutput {
        output_hash: ContentHash::compute(b"compiled_output"),
        source_map_hash: Some(ContentHash::compute(b"source_map")),
        elements_lowered: 42,
        fragments_lowered: 5,
        components_detected: 8,
        warnings: Vec::new(),
        runtime_mode: mode,
        target: ReactBuildTarget::Client,
    }
}

fn sample_diagnostic(
    severity: DiagnosticSeverity,
    category: DiagnosticCategory,
) -> ReactDiagnostic {
    ReactDiagnostic {
        code: "FE-REACT-0001".to_string(),
        severity,
        category,
        message: "Test diagnostic message".to_string(),
        remediation: "Fix the issue".to_string(),
        location: Some("src/App.tsx:10:5".to_string()),
    }
}

fn sample_feature(name: &str, support: FeatureSupport) -> ReactFeatureContract {
    ReactFeatureContract {
        name: name.to_string(),
        support,
        description: format!("Feature {name}"),
        limitations: Vec::new(),
        tracking_bead: None,
    }
}

fn sample_command_contract(cmd: ReactOperatorCommand, shipped: bool) -> CommandContract {
    CommandContract {
        command: cmd,
        shipped,
        description: cmd.description().to_string(),
        required_flags: vec!["--input".to_string()],
        optional_flags: vec!["--out".to_string()],
    }
}

// ---------------------------------------------------------------------------
// ReactRuntimeMode
// ---------------------------------------------------------------------------

#[test]
fn runtime_mode_all_variants() {
    assert_eq!(ReactRuntimeMode::ALL.len(), 3);
    let strs: Vec<&str> = ReactRuntimeMode::ALL.iter().map(|m| m.as_str()).collect();
    assert!(strs.contains(&"classic"));
    assert!(strs.contains(&"automatic"));
    assert!(strs.contains(&"preserve"));
}

#[test]
fn runtime_mode_display_matches_as_str() {
    for mode in ReactRuntimeMode::ALL {
        assert_eq!(format!("{mode}"), mode.as_str());
    }
}

#[test]
fn runtime_mode_serde_roundtrip() {
    for mode in ReactRuntimeMode::ALL {
        let json = serde_json::to_string(mode).unwrap();
        let back: ReactRuntimeMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, back);
    }
}

#[test]
fn runtime_mode_descriptions_non_empty() {
    for mode in ReactRuntimeMode::ALL {
        assert!(
            !mode.description().is_empty(),
            "{mode} has empty description"
        );
    }
}

// ---------------------------------------------------------------------------
// ReactBuildTarget
// ---------------------------------------------------------------------------

#[test]
fn build_target_all_variants() {
    assert_eq!(ReactBuildTarget::ALL.len(), 4);
}

#[test]
fn build_target_distinct_labels() {
    let strs: Vec<&str> = ReactBuildTarget::ALL.iter().map(|t| t.as_str()).collect();
    for (i, a) in strs.iter().enumerate() {
        for (j, b) in strs.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn build_target_serde_roundtrip() {
    for target in ReactBuildTarget::ALL {
        let json = serde_json::to_string(target).unwrap();
        let back: ReactBuildTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(*target, back);
    }
}

#[test]
fn build_target_display_matches_as_str() {
    for target in ReactBuildTarget::ALL {
        assert_eq!(format!("{target}"), target.as_str());
    }
}

// ---------------------------------------------------------------------------
// ReactOperatorCommand
// ---------------------------------------------------------------------------

#[test]
fn operator_command_all_variants() {
    assert_eq!(ReactOperatorCommand::ALL.len(), 5);
}

#[test]
fn operator_command_distinct_labels() {
    let strs: Vec<&str> = ReactOperatorCommand::ALL
        .iter()
        .map(|c| c.as_str())
        .collect();
    for (i, a) in strs.iter().enumerate() {
        for (j, b) in strs.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn operator_command_descriptions_non_empty() {
    for cmd in ReactOperatorCommand::ALL {
        assert!(!cmd.description().is_empty(), "{cmd} has empty description");
    }
}

#[test]
fn operator_command_none_shipped_yet() {
    for cmd in ReactOperatorCommand::ALL {
        assert!(!cmd.is_shipped(), "{cmd} should not be shipped yet");
    }
}

#[test]
fn operator_command_serde_roundtrip() {
    for cmd in ReactOperatorCommand::ALL {
        let json = serde_json::to_string(cmd).unwrap();
        let back: ReactOperatorCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(*cmd, back);
    }
}

#[test]
fn operator_command_display_matches_as_str() {
    for cmd in ReactOperatorCommand::ALL {
        assert_eq!(format!("{cmd}"), cmd.as_str());
    }
}

// ---------------------------------------------------------------------------
// ReactInputLanguage
// ---------------------------------------------------------------------------

#[test]
fn input_language_serde_roundtrip() {
    for lang in [ReactInputLanguage::Jsx, ReactInputLanguage::Tsx] {
        let json = serde_json::to_string(&lang).unwrap();
        let back: ReactInputLanguage = serde_json::from_str(&json).unwrap();
        assert_eq!(lang, back);
    }
}

#[test]
fn input_language_display() {
    assert_eq!(format!("{}", ReactInputLanguage::Jsx), "jsx");
    assert_eq!(format!("{}", ReactInputLanguage::Tsx), "tsx");
}

// ---------------------------------------------------------------------------
// ReactCompileInput
// ---------------------------------------------------------------------------

#[test]
fn compile_input_serde_roundtrip() {
    let input = sample_compile_input(ReactInputLanguage::Tsx, ReactRuntimeMode::Automatic);
    let json = serde_json::to_string_pretty(&input).unwrap();
    let back: ReactCompileInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn compile_input_all_mode_target_combos() {
    for mode in ReactRuntimeMode::ALL {
        for target in ReactBuildTarget::ALL {
            let input = ReactCompileInput {
                source_path: "test.tsx".to_string(),
                language: ReactInputLanguage::Tsx,
                runtime_mode: *mode,
                target: *target,
                source_maps: false,
                preserve_display_names: false,
                input_hash: ContentHash::compute(b"test"),
            };
            let json = serde_json::to_string(&input).unwrap();
            let back: ReactCompileInput = serde_json::from_str(&json).unwrap();
            assert_eq!(input.runtime_mode, back.runtime_mode);
            assert_eq!(input.target, back.target);
        }
    }
}

// ---------------------------------------------------------------------------
// ReactCompileOutput
// ---------------------------------------------------------------------------

#[test]
fn compile_output_serde_roundtrip() {
    let output = sample_compile_output(ReactRuntimeMode::Automatic);
    let json = serde_json::to_string(&output).unwrap();
    let back: ReactCompileOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

#[test]
fn compile_output_with_diagnostics() {
    let mut output = sample_compile_output(ReactRuntimeMode::Classic);
    output.warnings.push(sample_diagnostic(
        DiagnosticSeverity::Warning,
        DiagnosticCategory::DeprecatedApi,
    ));
    output.warnings.push(sample_diagnostic(
        DiagnosticSeverity::Info,
        DiagnosticCategory::Performance,
    ));
    let json = serde_json::to_string(&output).unwrap();
    let back: ReactCompileOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.warnings.len(), 2);
}

#[test]
fn compile_output_no_source_map() {
    let mut output = sample_compile_output(ReactRuntimeMode::Preserve);
    output.source_map_hash = None;
    let json = serde_json::to_string(&output).unwrap();
    let back: ReactCompileOutput = serde_json::from_str(&json).unwrap();
    assert!(back.source_map_hash.is_none());
}

// ---------------------------------------------------------------------------
// DiagnosticSeverity
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_severity_all_distinct() {
    let variants = [
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Hint,
    ];
    for (i, a) in variants.iter().enumerate() {
        for (j, b) in variants.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
                assert_ne!(a.as_str(), b.as_str());
            }
        }
    }
}

#[test]
fn diagnostic_severity_display() {
    for sev in [
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Hint,
    ] {
        assert_eq!(format!("{sev}"), sev.as_str());
    }
}

// ---------------------------------------------------------------------------
// DiagnosticCategory
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_category_all_distinct() {
    let cats = [
        DiagnosticCategory::JsxSyntax,
        DiagnosticCategory::TsxType,
        DiagnosticCategory::UnsupportedFeature,
        DiagnosticCategory::RuntimeModeMismatch,
        DiagnosticCategory::MissingDependency,
        DiagnosticCategory::DeprecatedApi,
        DiagnosticCategory::Performance,
        DiagnosticCategory::Accessibility,
    ];
    for (i, a) in cats.iter().enumerate() {
        for (j, b) in cats.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
                assert_ne!(a.as_str(), b.as_str());
            }
        }
    }
}

#[test]
fn diagnostic_category_display() {
    for cat in [
        DiagnosticCategory::JsxSyntax,
        DiagnosticCategory::TsxType,
        DiagnosticCategory::UnsupportedFeature,
        DiagnosticCategory::RuntimeModeMismatch,
        DiagnosticCategory::MissingDependency,
        DiagnosticCategory::DeprecatedApi,
        DiagnosticCategory::Performance,
        DiagnosticCategory::Accessibility,
    ] {
        assert_eq!(format!("{cat}"), cat.as_str());
    }
}

// ---------------------------------------------------------------------------
// ReactDiagnostic
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_serde_roundtrip() {
    let diag = sample_diagnostic(DiagnosticSeverity::Error, DiagnosticCategory::JsxSyntax);
    let json = serde_json::to_string(&diag).unwrap();
    let back: ReactDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

#[test]
fn diagnostic_without_location() {
    let diag = ReactDiagnostic {
        code: "FE-REACT-0042".to_string(),
        severity: DiagnosticSeverity::Warning,
        category: DiagnosticCategory::Performance,
        message: "Expensive render detected".to_string(),
        remediation: "Memoize component".to_string(),
        location: None,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: ReactDiagnostic = serde_json::from_str(&json).unwrap();
    assert!(back.location.is_none());
}

// ---------------------------------------------------------------------------
// FeatureSupport
// ---------------------------------------------------------------------------

#[test]
fn feature_support_is_available() {
    assert!(FeatureSupport::Supported.is_available());
    assert!(FeatureSupport::Partial.is_available());
    assert!(!FeatureSupport::NotImplemented.is_available());
    assert!(!FeatureSupport::Unsupported.is_available());
    assert!(!FeatureSupport::Deprecated.is_available());
}

#[test]
fn feature_support_serde_roundtrip() {
    for support in [
        FeatureSupport::Supported,
        FeatureSupport::Partial,
        FeatureSupport::NotImplemented,
        FeatureSupport::Unsupported,
        FeatureSupport::Deprecated,
    ] {
        let json = serde_json::to_string(&support).unwrap();
        let back: FeatureSupport = serde_json::from_str(&json).unwrap();
        assert_eq!(support, back);
    }
}

#[test]
fn feature_support_display() {
    for support in [
        FeatureSupport::Supported,
        FeatureSupport::Partial,
        FeatureSupport::NotImplemented,
        FeatureSupport::Unsupported,
        FeatureSupport::Deprecated,
    ] {
        assert_eq!(format!("{support}"), support.as_str());
    }
}

// ---------------------------------------------------------------------------
// ReactOperatorContract
// ---------------------------------------------------------------------------

#[test]
fn contract_new_empty() {
    let c = ReactOperatorContract::new();
    assert!(c.commands.is_empty());
    assert!(c.features.is_empty());
    assert!(c.supported_runtime_modes.is_empty());
    assert!(c.supported_build_targets.is_empty());
    assert_eq!(c.version, SCHEMA_VERSION);
}

#[test]
fn contract_add_commands() {
    let mut c = ReactOperatorContract::new();
    for cmd in ReactOperatorCommand::ALL {
        c.add_command(sample_command_contract(*cmd, false));
    }
    assert_eq!(c.commands.len(), 5);
    assert!(c.shipped_commands().is_empty()); // None shipped
}

#[test]
fn contract_shipped_vs_unshipped_commands() {
    let mut c = ReactOperatorContract::new();
    c.add_command(sample_command_contract(
        ReactOperatorCommand::ReactCompile,
        true,
    ));
    c.add_command(sample_command_contract(
        ReactOperatorCommand::ReactBuild,
        false,
    ));
    c.add_command(sample_command_contract(
        ReactOperatorCommand::ReactVerify,
        true,
    ));
    assert_eq!(c.shipped_commands().len(), 2);
}

#[test]
fn contract_available_features() {
    let mut c = ReactOperatorContract::new();
    c.add_feature(sample_feature("jsx_elements", FeatureSupport::Supported));
    c.add_feature(sample_feature("server_components", FeatureSupport::Partial));
    c.add_feature(sample_feature("suspense", FeatureSupport::NotImplemented));
    c.add_feature(sample_feature(
        "class_components",
        FeatureSupport::Deprecated,
    ));
    assert_eq!(c.available_features().len(), 2); // Supported + Partial
    assert_eq!(c.unsupported_features().len(), 2); // NotImplemented + Deprecated
}

#[test]
fn contract_supported_modes_and_targets() {
    let mut c = ReactOperatorContract::new();
    c.supported_runtime_modes
        .insert(ReactRuntimeMode::Automatic);
    c.supported_runtime_modes.insert(ReactRuntimeMode::Classic);
    c.supported_build_targets.insert(ReactBuildTarget::Client);
    c.supported_build_targets.insert(ReactBuildTarget::Ssr);
    assert_eq!(c.supported_runtime_modes.len(), 2);
    assert_eq!(c.supported_build_targets.len(), 2);
}

#[test]
fn contract_content_hash_deterministic() {
    let mut c1 = ReactOperatorContract::new();
    c1.add_command(sample_command_contract(
        ReactOperatorCommand::ReactCompile,
        false,
    ));
    c1.add_feature(sample_feature("jsx", FeatureSupport::Supported));

    let mut c2 = ReactOperatorContract::new();
    c2.add_command(sample_command_contract(
        ReactOperatorCommand::ReactCompile,
        false,
    ));
    c2.add_feature(sample_feature("jsx", FeatureSupport::Supported));

    assert_eq!(c1.content_hash(), c2.content_hash());
}

#[test]
fn contract_content_hash_changes_with_feature() {
    let mut c1 = ReactOperatorContract::new();
    c1.add_feature(sample_feature("jsx", FeatureSupport::Supported));

    let mut c2 = ReactOperatorContract::new();
    c2.add_feature(sample_feature("tsx", FeatureSupport::Supported));

    assert_ne!(c1.content_hash(), c2.content_hash());
}

#[test]
fn contract_full_serde_roundtrip() {
    let mut c = ReactOperatorContract::new();
    for cmd in ReactOperatorCommand::ALL {
        c.add_command(sample_command_contract(*cmd, false));
    }
    c.add_feature(sample_feature("jsx_elements", FeatureSupport::Supported));
    c.add_feature(sample_feature("hooks", FeatureSupport::Partial));
    c.add_feature(sample_feature("suspense", FeatureSupport::NotImplemented));
    c.supported_runtime_modes
        .insert(ReactRuntimeMode::Automatic);
    c.supported_build_targets.insert(ReactBuildTarget::Client);
    c.supported_build_targets.insert(ReactBuildTarget::Ssr);

    let json = serde_json::to_string_pretty(&c).unwrap();
    let back: ReactOperatorContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c.commands.len(), back.commands.len());
    assert_eq!(c.features.len(), back.features.len());
    assert_eq!(
        c.supported_runtime_modes.len(),
        back.supported_runtime_modes.len()
    );
    assert_eq!(c.content_hash(), back.content_hash());
}

// ---------------------------------------------------------------------------
// ReactFeatureContract
// ---------------------------------------------------------------------------

#[test]
fn feature_contract_with_limitations() {
    let feat = ReactFeatureContract {
        name: "concurrent_mode".to_string(),
        support: FeatureSupport::Partial,
        description: "Concurrent rendering".to_string(),
        limitations: vec![
            "No streaming SSR".to_string(),
            "Limited Suspense support".to_string(),
        ],
        tracking_bead: Some("bd-1lsy.10.12".to_string()),
    };
    let json = serde_json::to_string(&feat).unwrap();
    let back: ReactFeatureContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back.limitations.len(), 2);
    assert_eq!(back.tracking_bead, Some("bd-1lsy.10.12".to_string()));
}

#[test]
fn feature_contract_serde_roundtrip() {
    let feat = sample_feature("test_feature", FeatureSupport::Supported);
    let json = serde_json::to_string(&feat).unwrap();
    let back: ReactFeatureContract = serde_json::from_str(&json).unwrap();
    assert_eq!(feat, back);
}

// ---------------------------------------------------------------------------
// CommandContract
// ---------------------------------------------------------------------------

#[test]
fn command_contract_serde_roundtrip() {
    let cmd = sample_command_contract(ReactOperatorCommand::ReactCompile, true);
    let json = serde_json::to_string(&cmd).unwrap();
    let back: CommandContract = serde_json::from_str(&json).unwrap();
    assert_eq!(cmd, back);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_valid() {
    assert!(!COMPONENT.is_empty());
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(SCHEMA_VERSION.contains("react-compile-operator-surface"));
}

#[test]
fn bead_id_matches_plan() {
    assert_eq!(BEAD_ID, "bd-1lsy.10.12");
}

// ---------------------------------------------------------------------------
// Cross-cutting scenarios
// ---------------------------------------------------------------------------

#[test]
fn full_compile_pipeline_round_trip() {
    // Input -> Output -> Contract verification
    let input = sample_compile_input(ReactInputLanguage::Tsx, ReactRuntimeMode::Automatic);
    let mut output = sample_compile_output(ReactRuntimeMode::Automatic);
    output.warnings.push(sample_diagnostic(
        DiagnosticSeverity::Warning,
        DiagnosticCategory::Performance,
    ));

    let mut contract = ReactOperatorContract::new();
    contract.add_command(sample_command_contract(
        ReactOperatorCommand::ReactCompile,
        false,
    ));
    contract.add_feature(sample_feature("jsx_lowering", FeatureSupport::Supported));
    contract
        .supported_runtime_modes
        .insert(ReactRuntimeMode::Automatic);
    contract
        .supported_build_targets
        .insert(ReactBuildTarget::Client);

    // Verify contract includes the mode/target we used
    assert!(
        contract
            .supported_runtime_modes
            .contains(&input.runtime_mode)
    );
    assert!(contract.supported_build_targets.contains(&input.target));

    // Serde everything
    let json_input = serde_json::to_string(&input).unwrap();
    let json_output = serde_json::to_string(&output).unwrap();
    let json_contract = serde_json::to_string(&contract).unwrap();

    let _: ReactCompileInput = serde_json::from_str(&json_input).unwrap();
    let _: ReactCompileOutput = serde_json::from_str(&json_output).unwrap();
    let _: ReactOperatorContract = serde_json::from_str(&json_contract).unwrap();
}

#[test]
fn all_severity_category_combinations() {
    let severities = [
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Hint,
    ];
    let categories = [
        DiagnosticCategory::JsxSyntax,
        DiagnosticCategory::TsxType,
        DiagnosticCategory::UnsupportedFeature,
        DiagnosticCategory::RuntimeModeMismatch,
        DiagnosticCategory::MissingDependency,
        DiagnosticCategory::DeprecatedApi,
        DiagnosticCategory::Performance,
        DiagnosticCategory::Accessibility,
    ];
    for sev in &severities {
        for cat in &categories {
            let diag = sample_diagnostic(*sev, *cat);
            let json = serde_json::to_string(&diag).unwrap();
            let back: ReactDiagnostic = serde_json::from_str(&json).unwrap();
            assert_eq!(back.severity, *sev);
            assert_eq!(back.category, *cat);
        }
    }
}
