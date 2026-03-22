//! Integration tests for the React compile/build operator surface contract
//! (RGC-912).

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_compile_operator_surface::{
    BEAD_ID, COMPONENT, CommandContract, DiagnosticCategory, DiagnosticSeverity, FeatureSupport,
    ReactBuildTarget, ReactCompileInput, ReactCompileOutput, ReactDiagnostic, ReactFeatureContract,
    ReactInputLanguage, ReactOperatorCommand, ReactOperatorContract, ReactRuntimeMode,
    SCHEMA_VERSION, build_seed_contract,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_have_expected_values() {
    assert_eq!(COMPONENT, "react_compile_operator_surface");
    assert_eq!(BEAD_ID, "bd-1lsy.10.12");
    assert!(SCHEMA_VERSION.contains("react-compile-operator-surface"));
    assert!(SCHEMA_VERSION.contains(".v1"));
}

// ---------------------------------------------------------------------------
// ReactRuntimeMode
// ---------------------------------------------------------------------------

#[test]
fn runtime_mode_all_count() {
    assert_eq!(ReactRuntimeMode::ALL.len(), 3);
}

#[test]
fn runtime_mode_as_str_all() {
    assert_eq!(ReactRuntimeMode::Classic.as_str(), "classic");
    assert_eq!(ReactRuntimeMode::Automatic.as_str(), "automatic");
    assert_eq!(ReactRuntimeMode::Preserve.as_str(), "preserve");
}

#[test]
fn runtime_mode_display_matches_as_str() {
    for mode in ReactRuntimeMode::ALL {
        assert_eq!(format!("{mode}"), mode.as_str());
    }
}

#[test]
fn runtime_mode_description_nonempty() {
    for mode in ReactRuntimeMode::ALL {
        assert!(!mode.description().is_empty());
    }
}

#[test]
fn runtime_mode_serde_roundtrip_all() {
    for mode in ReactRuntimeMode::ALL {
        let json = serde_json::to_string(mode).unwrap();
        let back: ReactRuntimeMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, back);
    }
}

// ---------------------------------------------------------------------------
// ReactBuildTarget
// ---------------------------------------------------------------------------

#[test]
fn build_target_all_count() {
    assert_eq!(ReactBuildTarget::ALL.len(), 4);
}

#[test]
fn build_target_as_str_all() {
    assert_eq!(ReactBuildTarget::Client.as_str(), "client");
    assert_eq!(ReactBuildTarget::Ssr.as_str(), "ssr");
    assert_eq!(
        ReactBuildTarget::ServerComponent.as_str(),
        "server_component"
    );
    assert_eq!(ReactBuildTarget::StaticExport.as_str(), "static_export");
}

#[test]
fn build_target_display_matches_as_str() {
    for target in ReactBuildTarget::ALL {
        assert_eq!(format!("{target}"), target.as_str());
    }
}

#[test]
fn build_target_serde_roundtrip_all() {
    for target in ReactBuildTarget::ALL {
        let json = serde_json::to_string(target).unwrap();
        let back: ReactBuildTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(*target, back);
    }
}

// ---------------------------------------------------------------------------
// ReactOperatorCommand
// ---------------------------------------------------------------------------

#[test]
fn operator_command_all_count() {
    assert_eq!(ReactOperatorCommand::ALL.len(), 5);
}

#[test]
fn operator_command_as_str_all() {
    assert_eq!(ReactOperatorCommand::ReactCompile.as_str(), "react-compile");
    assert_eq!(ReactOperatorCommand::ReactBuild.as_str(), "react-build");
    assert_eq!(ReactOperatorCommand::ReactVerify.as_str(), "react-verify");
    assert_eq!(ReactOperatorCommand::ReactDoctor.as_str(), "react-doctor");
    assert_eq!(ReactOperatorCommand::ReactStatus.as_str(), "react-status");
}

#[test]
fn operator_command_display_matches_as_str() {
    for cmd in ReactOperatorCommand::ALL {
        assert_eq!(format!("{cmd}"), cmd.as_str());
    }
}

#[test]
fn operator_command_description_nonempty() {
    for cmd in ReactOperatorCommand::ALL {
        assert!(!cmd.description().is_empty());
    }
}

#[test]
fn operator_command_none_shipped() {
    for cmd in ReactOperatorCommand::ALL {
        assert!(!cmd.is_shipped());
    }
}

#[test]
fn operator_command_serde_roundtrip_all() {
    for cmd in ReactOperatorCommand::ALL {
        let json = serde_json::to_string(cmd).unwrap();
        let back: ReactOperatorCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(*cmd, back);
    }
}

// ---------------------------------------------------------------------------
// ReactInputLanguage
// ---------------------------------------------------------------------------

#[test]
fn input_language_as_str() {
    assert_eq!(ReactInputLanguage::Jsx.as_str(), "jsx");
    assert_eq!(ReactInputLanguage::Tsx.as_str(), "tsx");
}

#[test]
fn input_language_display_matches_as_str() {
    assert_eq!(format!("{}", ReactInputLanguage::Jsx), "jsx");
    assert_eq!(format!("{}", ReactInputLanguage::Tsx), "tsx");
}

#[test]
fn input_language_serde_roundtrip() {
    for lang in [ReactInputLanguage::Jsx, ReactInputLanguage::Tsx] {
        let json = serde_json::to_string(&lang).unwrap();
        let back: ReactInputLanguage = serde_json::from_str(&json).unwrap();
        assert_eq!(lang, back);
    }
}

// ---------------------------------------------------------------------------
// DiagnosticSeverity
// ---------------------------------------------------------------------------

#[test]
fn severity_as_str_all() {
    assert_eq!(DiagnosticSeverity::Error.as_str(), "error");
    assert_eq!(DiagnosticSeverity::Warning.as_str(), "warning");
    assert_eq!(DiagnosticSeverity::Info.as_str(), "info");
    assert_eq!(DiagnosticSeverity::Hint.as_str(), "hint");
}

#[test]
fn severity_display_matches_as_str() {
    for sev in [
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Hint,
    ] {
        assert_eq!(format!("{sev}"), sev.as_str());
    }
}

#[test]
fn severity_serde_roundtrip_all() {
    for sev in [
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Hint,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

// ---------------------------------------------------------------------------
// DiagnosticCategory
// ---------------------------------------------------------------------------

#[test]
fn category_as_str_all() {
    assert_eq!(DiagnosticCategory::JsxSyntax.as_str(), "jsx_syntax");
    assert_eq!(DiagnosticCategory::TsxType.as_str(), "tsx_type");
    assert_eq!(
        DiagnosticCategory::UnsupportedFeature.as_str(),
        "unsupported_feature"
    );
    assert_eq!(
        DiagnosticCategory::RuntimeModeMismatch.as_str(),
        "runtime_mode_mismatch"
    );
    assert_eq!(
        DiagnosticCategory::MissingDependency.as_str(),
        "missing_dependency"
    );
    assert_eq!(DiagnosticCategory::DeprecatedApi.as_str(), "deprecated_api");
    assert_eq!(DiagnosticCategory::Performance.as_str(), "performance");
    assert_eq!(DiagnosticCategory::Accessibility.as_str(), "accessibility");
}

#[test]
fn category_display_matches_as_str() {
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

#[test]
fn category_serde_roundtrip_all() {
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
        let json = serde_json::to_string(&cat).unwrap();
        let back: DiagnosticCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back);
    }
}

// ---------------------------------------------------------------------------
// FeatureSupport
// ---------------------------------------------------------------------------

#[test]
fn feature_support_as_str_all() {
    assert_eq!(FeatureSupport::Supported.as_str(), "supported");
    assert_eq!(FeatureSupport::Partial.as_str(), "partial");
    assert_eq!(FeatureSupport::NotImplemented.as_str(), "not_implemented");
    assert_eq!(FeatureSupport::Unsupported.as_str(), "unsupported");
    assert_eq!(FeatureSupport::Deprecated.as_str(), "deprecated");
}

#[test]
fn feature_support_is_available_true() {
    assert!(FeatureSupport::Supported.is_available());
    assert!(FeatureSupport::Partial.is_available());
}

#[test]
fn feature_support_is_available_false() {
    assert!(!FeatureSupport::NotImplemented.is_available());
    assert!(!FeatureSupport::Unsupported.is_available());
    assert!(!FeatureSupport::Deprecated.is_available());
}

#[test]
fn feature_support_display_matches_as_str() {
    for fs in [
        FeatureSupport::Supported,
        FeatureSupport::Partial,
        FeatureSupport::NotImplemented,
        FeatureSupport::Unsupported,
        FeatureSupport::Deprecated,
    ] {
        assert_eq!(format!("{fs}"), fs.as_str());
    }
}

#[test]
fn feature_support_serde_roundtrip_all() {
    for fs in [
        FeatureSupport::Supported,
        FeatureSupport::Partial,
        FeatureSupport::NotImplemented,
        FeatureSupport::Unsupported,
        FeatureSupport::Deprecated,
    ] {
        let json = serde_json::to_string(&fs).unwrap();
        let back: FeatureSupport = serde_json::from_str(&json).unwrap();
        assert_eq!(fs, back);
    }
}

// ---------------------------------------------------------------------------
// ReactDiagnostic
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_serde_roundtrip() {
    let diag = ReactDiagnostic {
        code: "FE-REACT-0001".to_string(),
        severity: DiagnosticSeverity::Error,
        category: DiagnosticCategory::JsxSyntax,
        message: "Invalid JSX syntax".to_string(),
        remediation: "Check your JSX brackets".to_string(),
        location: Some("test.tsx:10:5".to_string()),
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: ReactDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

#[test]
fn diagnostic_without_location() {
    let diag = ReactDiagnostic {
        code: "FE-REACT-0002".to_string(),
        severity: DiagnosticSeverity::Warning,
        category: DiagnosticCategory::DeprecatedApi,
        message: "deprecated API".to_string(),
        remediation: "upgrade".to_string(),
        location: None,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: ReactDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(back.location, None);
}

// ---------------------------------------------------------------------------
// ReactFeatureContract
// ---------------------------------------------------------------------------

#[test]
fn feature_contract_serde_roundtrip() {
    let fc = ReactFeatureContract {
        name: "jsx_elements".to_string(),
        support: FeatureSupport::Supported,
        description: "Basic JSX element creation".to_string(),
        limitations: vec!["no spread children".to_string()],
        tracking_bead: Some("bd-test".to_string()),
    };
    let json = serde_json::to_string(&fc).unwrap();
    let back: ReactFeatureContract = serde_json::from_str(&json).unwrap();
    assert_eq!(fc, back);
}

// ---------------------------------------------------------------------------
// ReactCompileInput
// ---------------------------------------------------------------------------

#[test]
fn compile_input_serde_roundtrip() {
    let input = ReactCompileInput {
        source_path: "app.tsx".to_string(),
        language: ReactInputLanguage::Tsx,
        runtime_mode: ReactRuntimeMode::Automatic,
        target: ReactBuildTarget::Client,
        source_maps: true,
        preserve_display_names: true,
        input_hash: ContentHash::compute(b"test_source"),
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: ReactCompileInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn compile_input_jsx_variant() {
    let input = ReactCompileInput {
        source_path: "component.jsx".to_string(),
        language: ReactInputLanguage::Jsx,
        runtime_mode: ReactRuntimeMode::Classic,
        target: ReactBuildTarget::Ssr,
        source_maps: false,
        preserve_display_names: false,
        input_hash: ContentHash::compute(b"jsx_source"),
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: ReactCompileInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.language, ReactInputLanguage::Jsx);
    assert_eq!(back.runtime_mode, ReactRuntimeMode::Classic);
}

// ---------------------------------------------------------------------------
// ReactCompileOutput
// ---------------------------------------------------------------------------

#[test]
fn compile_output_serde_roundtrip() {
    let output = ReactCompileOutput {
        output_hash: ContentHash::compute(b"output"),
        source_map_hash: Some(ContentHash::compute(b"sourcemap")),
        elements_lowered: 42,
        fragments_lowered: 5,
        components_detected: 10,
        warnings: Vec::new(),
        runtime_mode: ReactRuntimeMode::Automatic,
        target: ReactBuildTarget::Client,
    };
    let json = serde_json::to_string(&output).unwrap();
    let back: ReactCompileOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

#[test]
fn compile_output_without_source_map() {
    let output = ReactCompileOutput {
        output_hash: ContentHash::compute(b"out"),
        source_map_hash: None,
        elements_lowered: 0,
        fragments_lowered: 0,
        components_detected: 0,
        warnings: Vec::new(),
        runtime_mode: ReactRuntimeMode::Preserve,
        target: ReactBuildTarget::StaticExport,
    };
    let json = serde_json::to_string(&output).unwrap();
    let back: ReactCompileOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.source_map_hash, None);
}

#[test]
fn compile_output_with_warnings() {
    let output = ReactCompileOutput {
        output_hash: ContentHash::compute(b"out"),
        source_map_hash: None,
        elements_lowered: 10,
        fragments_lowered: 2,
        components_detected: 3,
        warnings: vec![ReactDiagnostic {
            code: "FE-REACT-W001".to_string(),
            severity: DiagnosticSeverity::Warning,
            category: DiagnosticCategory::Performance,
            message: "Inline object in JSX".to_string(),
            remediation: "Extract to constant".to_string(),
            location: Some("app.tsx:42:10".to_string()),
        }],
        runtime_mode: ReactRuntimeMode::Automatic,
        target: ReactBuildTarget::Client,
    };
    let json = serde_json::to_string(&output).unwrap();
    let back: ReactCompileOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.warnings.len(), 1);
}

// ---------------------------------------------------------------------------
// ReactOperatorContract
// ---------------------------------------------------------------------------

#[test]
fn empty_contract() {
    let contract = ReactOperatorContract::new();
    assert!(contract.commands.is_empty());
    assert!(contract.features.is_empty());
    assert!(contract.supported_runtime_modes.is_empty());
    assert!(contract.supported_build_targets.is_empty());
    assert_eq!(contract.version, SCHEMA_VERSION);
}

#[test]
fn default_contract_is_empty() {
    let contract = ReactOperatorContract::default();
    assert!(contract.commands.is_empty());
    assert!(contract.features.is_empty());
}

#[test]
fn contract_add_command() {
    let mut contract = ReactOperatorContract::new();
    contract.add_command(CommandContract {
        command: ReactOperatorCommand::ReactCompile,
        shipped: false,
        description: "test".to_string(),
        required_flags: vec!["--input".to_string()],
        optional_flags: Vec::new(),
    });
    assert_eq!(contract.commands.len(), 1);
}

#[test]
fn contract_add_feature() {
    let mut contract = ReactOperatorContract::new();
    contract.add_feature(ReactFeatureContract {
        name: "test_feature".to_string(),
        support: FeatureSupport::Supported,
        description: "test".to_string(),
        limitations: Vec::new(),
        tracking_bead: None,
    });
    assert_eq!(contract.features.len(), 1);
}

#[test]
fn contract_shipped_commands_empty_when_none_shipped() {
    let contract = build_seed_contract();
    assert!(contract.shipped_commands().is_empty());
}

#[test]
fn contract_available_features_count() {
    let contract = build_seed_contract();
    let available = contract.available_features();
    // 3 Supported + 1 Partial = 4 available
    assert_eq!(available.len(), 4);
}

#[test]
fn contract_unsupported_features_count() {
    let contract = build_seed_contract();
    let unsupported = contract.unsupported_features();
    // 3 NotImplemented + 1 Unsupported = 4 unsupported
    assert_eq!(unsupported.len(), 4);
}

// ---------------------------------------------------------------------------
// Seed contract
// ---------------------------------------------------------------------------

#[test]
fn seed_contract_has_all_commands() {
    let contract = build_seed_contract();
    assert_eq!(contract.commands.len(), 5);
}

#[test]
fn seed_contract_has_all_features() {
    let contract = build_seed_contract();
    assert_eq!(contract.features.len(), 8);
}

#[test]
fn seed_contract_has_all_runtime_modes() {
    let contract = build_seed_contract();
    assert_eq!(contract.supported_runtime_modes.len(), 3);
    assert!(
        contract
            .supported_runtime_modes
            .contains(&ReactRuntimeMode::Classic)
    );
    assert!(
        contract
            .supported_runtime_modes
            .contains(&ReactRuntimeMode::Automatic)
    );
    assert!(
        contract
            .supported_runtime_modes
            .contains(&ReactRuntimeMode::Preserve)
    );
}

#[test]
fn seed_contract_has_all_build_targets() {
    let contract = build_seed_contract();
    assert_eq!(contract.supported_build_targets.len(), 4);
    assert!(
        contract
            .supported_build_targets
            .contains(&ReactBuildTarget::Client)
    );
    assert!(
        contract
            .supported_build_targets
            .contains(&ReactBuildTarget::Ssr)
    );
}

// ---------------------------------------------------------------------------
// Content hash
// ---------------------------------------------------------------------------

#[test]
fn content_hash_deterministic() {
    let c1 = build_seed_contract();
    let c2 = build_seed_contract();
    assert_eq!(c1.content_hash(), c2.content_hash());
}

#[test]
fn content_hash_changes_with_extra_feature() {
    let c1 = build_seed_contract();
    let mut c2 = build_seed_contract();
    c2.add_feature(ReactFeatureContract {
        name: "extra".to_string(),
        support: FeatureSupport::Supported,
        description: "extra".to_string(),
        limitations: Vec::new(),
        tracking_bead: None,
    });
    assert_ne!(c1.content_hash(), c2.content_hash());
}

#[test]
fn content_hash_changes_with_extra_command() {
    let c1 = ReactOperatorContract::new();
    let mut c2 = ReactOperatorContract::new();
    c2.add_command(CommandContract {
        command: ReactOperatorCommand::ReactCompile,
        shipped: false,
        description: "test".to_string(),
        required_flags: Vec::new(),
        optional_flags: Vec::new(),
    });
    assert_ne!(c1.content_hash(), c2.content_hash());
}

// ---------------------------------------------------------------------------
// Contract serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn contract_serde_roundtrip() {
    let contract = build_seed_contract();
    let json = serde_json::to_string(&contract).unwrap();
    let back: ReactOperatorContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract.commands.len(), back.commands.len());
    assert_eq!(contract.features.len(), back.features.len());
    assert_eq!(contract.content_hash(), back.content_hash());
}

#[test]
fn command_contract_serde_roundtrip() {
    let cmd = CommandContract {
        command: ReactOperatorCommand::ReactBuild,
        shipped: false,
        description: "Build a React application".to_string(),
        required_flags: vec!["--input".to_string()],
        optional_flags: vec!["--out".to_string()],
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let back: CommandContract = serde_json::from_str(&json).unwrap();
    assert_eq!(cmd, back);
}

// ---------------------------------------------------------------------------
// Ordering / determinism
// ---------------------------------------------------------------------------

#[test]
fn runtime_modes_btreeset_deterministic() {
    let mut s1 = BTreeSet::new();
    s1.insert(ReactRuntimeMode::Preserve);
    s1.insert(ReactRuntimeMode::Classic);
    s1.insert(ReactRuntimeMode::Automatic);
    let mut s2 = BTreeSet::new();
    s2.insert(ReactRuntimeMode::Automatic);
    s2.insert(ReactRuntimeMode::Classic);
    s2.insert(ReactRuntimeMode::Preserve);
    assert_eq!(s1, s2);
}

#[test]
fn build_targets_btreeset_deterministic() {
    let mut s1 = BTreeSet::new();
    for target in ReactBuildTarget::ALL {
        s1.insert(*target);
    }
    let mut s2 = BTreeSet::new();
    for target in ReactBuildTarget::ALL.iter().rev() {
        s2.insert(*target);
    }
    assert_eq!(s1, s2);
}
