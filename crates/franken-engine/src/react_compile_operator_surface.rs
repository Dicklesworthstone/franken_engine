//! React compile/build operator surface for frankenctl.
//!
//! Defines the shipped operator contract for React compilation workflows,
//! including command definitions, input validation, output schemas, and
//! diagnostic routing so users can invoke, diagnose, and support React
//! compilation through frankenctl.
//!
//! ## Design
//!
//! - **Command contract**: explicit definitions for React compile, build,
//!   and verify workflows available through frankenctl.
//! - **Input validation**: JSX/TSX input requirements, runtime mode
//!   selection, and configuration validation.
//! - **Output contract**: artifact schemas for React compile outputs
//!   including lowered code, source maps, and diagnostic reports.
//! - **Diagnostic routing**: structured error classification with
//!   React-specific remediation guidance.
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.10, bd-1lsy.10.12 (RGC-912).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COMPONENT: &str = "react_compile_operator_surface";
pub const SCHEMA_VERSION: &str = "franken-engine.react-compile-operator-surface.v1";
pub const BEAD_ID: &str = "bd-1lsy.10.12";

// ---------------------------------------------------------------------------
// React runtime mode
// ---------------------------------------------------------------------------

/// React JSX runtime transformation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactRuntimeMode {
    /// Classic React.createElement calls.
    Classic,
    /// Automatic jsx/jsxs imports (React 17+).
    Automatic,
    /// Preserve JSX as-is (pass-through).
    Preserve,
}

impl ReactRuntimeMode {
    pub const ALL: &'static [Self] = &[Self::Classic, Self::Automatic, Self::Preserve];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::Automatic => "automatic",
            Self::Preserve => "preserve",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Classic => "React.createElement transformation (pre-React 17)",
            Self::Automatic => "Automatic jsx/jsxs import transformation (React 17+)",
            Self::Preserve => "Preserve JSX syntax without transformation",
        }
    }
}

impl fmt::Display for ReactRuntimeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// React build target
// ---------------------------------------------------------------------------

/// Target environment for React compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactBuildTarget {
    /// Client-side browser bundle.
    Client,
    /// Server-side rendering.
    Ssr,
    /// React Server Components.
    ServerComponent,
    /// Static site generation.
    StaticExport,
}

impl ReactBuildTarget {
    pub const ALL: &'static [Self] = &[
        Self::Client,
        Self::Ssr,
        Self::ServerComponent,
        Self::StaticExport,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Ssr => "ssr",
            Self::ServerComponent => "server_component",
            Self::StaticExport => "static_export",
        }
    }
}

impl fmt::Display for ReactBuildTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Operator command
// ---------------------------------------------------------------------------

/// React-specific operator commands available through frankenctl.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactOperatorCommand {
    /// Compile JSX/TSX to lowered output.
    ReactCompile,
    /// Build a React application bundle.
    ReactBuild,
    /// Verify a React compile artifact.
    ReactVerify,
    /// Doctor/preflight for React compilation.
    ReactDoctor,
    /// Show supported React features and limitations.
    ReactStatus,
}

impl ReactOperatorCommand {
    pub const ALL: &'static [Self] = &[
        Self::ReactCompile,
        Self::ReactBuild,
        Self::ReactVerify,
        Self::ReactDoctor,
        Self::ReactStatus,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReactCompile => "react-compile",
            Self::ReactBuild => "react-build",
            Self::ReactVerify => "react-verify",
            Self::ReactDoctor => "react-doctor",
            Self::ReactStatus => "react-status",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::ReactCompile => "Compile JSX/TSX source to lowered JavaScript with source maps",
            Self::ReactBuild => "Build a React application bundle for the target environment",
            Self::ReactVerify => "Verify a React compile artifact for schema and parity",
            Self::ReactDoctor => {
                "Run React-aware preflight diagnostics and support-bundle guidance"
            }
            Self::ReactStatus => {
                "Show supported React features, limitations, and unsupported surfaces"
            }
        }
    }

    /// Whether this command is currently shipped.
    pub const fn is_shipped(self) -> bool {
        // Currently none are shipped — they're all roadmap
        false
    }
}

impl fmt::Display for ReactOperatorCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Compile input contract
// ---------------------------------------------------------------------------

/// Input validation contract for React compilation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReactCompileInput {
    /// Source file path.
    pub source_path: String,
    /// Input language (jsx or tsx).
    pub language: ReactInputLanguage,
    /// Runtime mode.
    pub runtime_mode: ReactRuntimeMode,
    /// Build target.
    pub target: ReactBuildTarget,
    /// Whether to emit source maps.
    pub source_maps: bool,
    /// Whether to preserve display names for debugging.
    pub preserve_display_names: bool,
    /// Content hash of the input source.
    pub input_hash: ContentHash,
}

/// Input language for React compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactInputLanguage {
    Jsx,
    Tsx,
}

impl ReactInputLanguage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jsx => "jsx",
            Self::Tsx => "tsx",
        }
    }
}

impl fmt::Display for ReactInputLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Compile output contract
// ---------------------------------------------------------------------------

/// Output artifact from React compilation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReactCompileOutput {
    /// Output content hash.
    pub output_hash: ContentHash,
    /// Source map content hash (if emitted).
    pub source_map_hash: Option<ContentHash>,
    /// Number of JSX elements lowered.
    pub elements_lowered: u64,
    /// Number of fragments lowered.
    pub fragments_lowered: u64,
    /// Number of components detected.
    pub components_detected: u64,
    /// Warnings emitted during compilation.
    pub warnings: Vec<ReactDiagnostic>,
    /// Runtime mode used.
    pub runtime_mode: ReactRuntimeMode,
    /// Build target used.
    pub target: ReactBuildTarget,
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Severity of a React-specific diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Info,
    Hint,
}

impl DiagnosticSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Hint => "hint",
        }
    }
}

impl fmt::Display for DiagnosticSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Category of React-specific diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCategory {
    /// JSX syntax error.
    JsxSyntax,
    /// TypeScript type error in JSX context.
    TsxType,
    /// Unsupported React feature.
    UnsupportedFeature,
    /// Runtime mode mismatch.
    RuntimeModeMismatch,
    /// Missing import or dependency.
    MissingDependency,
    /// Deprecated API usage.
    DeprecatedApi,
    /// Performance warning.
    Performance,
    /// Accessibility issue.
    Accessibility,
}

impl DiagnosticCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JsxSyntax => "jsx_syntax",
            Self::TsxType => "tsx_type",
            Self::UnsupportedFeature => "unsupported_feature",
            Self::RuntimeModeMismatch => "runtime_mode_mismatch",
            Self::MissingDependency => "missing_dependency",
            Self::DeprecatedApi => "deprecated_api",
            Self::Performance => "performance",
            Self::Accessibility => "accessibility",
        }
    }
}

impl fmt::Display for DiagnosticCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A React-specific diagnostic with remediation guidance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReactDiagnostic {
    /// Diagnostic code (e.g., "FE-REACT-0001").
    pub code: String,
    /// Severity.
    pub severity: DiagnosticSeverity,
    /// Category.
    pub category: DiagnosticCategory,
    /// Human-readable message.
    pub message: String,
    /// Remediation guidance.
    pub remediation: String,
    /// Source location (file:line:col).
    pub location: Option<String>,
}

// ---------------------------------------------------------------------------
// Surface contract
// ---------------------------------------------------------------------------

/// Feature support status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureSupport {
    /// Fully supported and tested.
    Supported,
    /// Partially supported with known limitations.
    Partial,
    /// Not yet implemented.
    NotImplemented,
    /// Explicitly unsupported by design.
    Unsupported,
    /// Deprecated — will be removed.
    Deprecated,
}

impl FeatureSupport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Partial => "partial",
            Self::NotImplemented => "not_implemented",
            Self::Unsupported => "unsupported",
            Self::Deprecated => "deprecated",
        }
    }

    pub const fn is_available(self) -> bool {
        matches!(self, Self::Supported | Self::Partial)
    }
}

impl fmt::Display for FeatureSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A feature in the React operator surface contract.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReactFeatureContract {
    pub name: String,
    pub support: FeatureSupport,
    pub description: String,
    pub limitations: Vec<String>,
    pub tracking_bead: Option<String>,
}

/// The complete React operator surface contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactOperatorContract {
    pub version: String,
    pub commands: Vec<CommandContract>,
    pub features: Vec<ReactFeatureContract>,
    pub supported_runtime_modes: BTreeSet<ReactRuntimeMode>,
    pub supported_build_targets: BTreeSet<ReactBuildTarget>,
}

/// Contract for a single operator command.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CommandContract {
    pub command: ReactOperatorCommand,
    pub shipped: bool,
    pub description: String,
    pub required_flags: Vec<String>,
    pub optional_flags: Vec<String>,
}

impl ReactOperatorContract {
    pub fn new() -> Self {
        Self {
            version: SCHEMA_VERSION.to_string(),
            commands: Vec::new(),
            features: Vec::new(),
            supported_runtime_modes: BTreeSet::new(),
            supported_build_targets: BTreeSet::new(),
        }
    }

    pub fn add_command(&mut self, contract: CommandContract) {
        self.commands.push(contract);
    }

    pub fn add_feature(&mut self, feature: ReactFeatureContract) {
        self.features.push(feature);
    }

    pub fn shipped_commands(&self) -> Vec<&CommandContract> {
        self.commands.iter().filter(|c| c.shipped).collect()
    }

    pub fn available_features(&self) -> Vec<&ReactFeatureContract> {
        self.features
            .iter()
            .filter(|f| f.support.is_available())
            .collect()
    }

    pub fn unsupported_features(&self) -> Vec<&ReactFeatureContract> {
        self.features
            .iter()
            .filter(|f| !f.support.is_available())
            .collect()
    }

    pub fn content_hash(&self) -> ContentHash {
        let mut entries = Vec::new();

        // Sort commands by command name for insertion-order independence.
        let mut sorted_cmds: Vec<_> = self.commands.iter().collect();
        sorted_cmds.sort_by(|a, b| a.command.as_str().cmp(b.command.as_str()));
        for cmd in &sorted_cmds {
            entries.push(CanonicalValue::Map(BTreeMap::from([
                (
                    "command".to_string(),
                    CanonicalValue::String(cmd.command.as_str().to_string()),
                ),
                (
                    "shipped".to_string(),
                    CanonicalValue::String(cmd.shipped.to_string()),
                ),
            ])));
        }

        // Sort features by name for insertion-order independence.
        let mut sorted_feats: Vec<_> = self.features.iter().collect();
        sorted_feats.sort_by(|a, b| a.name.cmp(&b.name));
        for feat in &sorted_feats {
            entries.push(CanonicalValue::Map(BTreeMap::from([
                (
                    "feature".to_string(),
                    CanonicalValue::String(feat.name.clone()),
                ),
                (
                    "support".to_string(),
                    CanonicalValue::String(feat.support.as_str().to_string()),
                ),
            ])));
        }

        // Include runtime modes (BTreeSet is already sorted).
        for mode in &self.supported_runtime_modes {
            entries.push(CanonicalValue::Map(BTreeMap::from([(
                "runtime_mode".to_string(),
                CanonicalValue::String(mode.as_str().to_string()),
            )])));
        }

        // Include build targets (BTreeSet is already sorted).
        for target in &self.supported_build_targets {
            entries.push(CanonicalValue::Map(BTreeMap::from([(
                "build_target".to_string(),
                CanonicalValue::String(target.as_str().to_string()),
            )])));
        }

        let canonical = CanonicalValue::Array(entries);
        let bytes = encode_value(&canonical);
        ContentHash::compute(&bytes)
    }
}

impl Default for ReactOperatorContract {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Seed contract builder
// ---------------------------------------------------------------------------

pub fn build_seed_contract() -> ReactOperatorContract {
    let mut contract = ReactOperatorContract::new();

    // Commands
    for cmd in ReactOperatorCommand::ALL {
        contract.add_command(CommandContract {
            command: *cmd,
            shipped: cmd.is_shipped(),
            description: cmd.description().to_string(),
            required_flags: vec!["--input".to_string()],
            optional_flags: vec![
                "--runtime".to_string(),
                "--target".to_string(),
                "--out".to_string(),
            ],
        });
    }

    // Runtime modes
    for mode in ReactRuntimeMode::ALL {
        contract.supported_runtime_modes.insert(*mode);
    }

    // Build targets
    for target in ReactBuildTarget::ALL {
        contract.supported_build_targets.insert(*target);
    }

    // Features
    let features = [
        (
            "jsx_elements",
            FeatureSupport::Supported,
            "Basic JSX element creation",
        ),
        (
            "jsx_fragments",
            FeatureSupport::Supported,
            "JSX fragment syntax (<>...</>)",
        ),
        (
            "jsx_spread_attributes",
            FeatureSupport::Supported,
            "JSX spread attributes ({...props})",
        ),
        (
            "tsx_type_annotations",
            FeatureSupport::Partial,
            "TypeScript type annotations in JSX",
        ),
        (
            "react_hooks",
            FeatureSupport::NotImplemented,
            "React hooks runtime support",
        ),
        (
            "server_components",
            FeatureSupport::NotImplemented,
            "React Server Components",
        ),
        (
            "suspense_boundaries",
            FeatureSupport::NotImplemented,
            "React Suspense boundaries",
        ),
        (
            "concurrent_mode",
            FeatureSupport::Unsupported,
            "React Concurrent Mode internals",
        ),
    ];

    for (name, support, desc) in &features {
        contract.add_feature(ReactFeatureContract {
            name: name.to_string(),
            support: *support,
            description: desc.to_string(),
            limitations: Vec::new(),
            tracking_bead: None,
        });
    }

    contract
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- ReactRuntimeMode ---
    #[test]
    fn runtime_mode_all_count() {
        assert_eq!(ReactRuntimeMode::ALL.len(), 3);
    }

    #[test]
    fn runtime_mode_serde() {
        for mode in ReactRuntimeMode::ALL {
            let json = serde_json::to_string(mode).unwrap();
            let back: ReactRuntimeMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*mode, back);
        }
    }

    #[test]
    fn runtime_mode_description() {
        for mode in ReactRuntimeMode::ALL {
            assert!(!mode.description().is_empty());
        }
    }

    // --- ReactBuildTarget ---
    #[test]
    fn build_target_all_count() {
        assert_eq!(ReactBuildTarget::ALL.len(), 4);
    }

    #[test]
    fn build_target_serde() {
        for target in ReactBuildTarget::ALL {
            let json = serde_json::to_string(target).unwrap();
            let back: ReactBuildTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(*target, back);
        }
    }

    // --- ReactOperatorCommand ---
    #[test]
    fn operator_command_all_count() {
        assert_eq!(ReactOperatorCommand::ALL.len(), 5);
    }

    #[test]
    fn operator_command_serde() {
        for cmd in ReactOperatorCommand::ALL {
            let json = serde_json::to_string(cmd).unwrap();
            let back: ReactOperatorCommand = serde_json::from_str(&json).unwrap();
            assert_eq!(*cmd, back);
        }
    }

    #[test]
    fn operator_command_none_shipped() {
        for cmd in ReactOperatorCommand::ALL {
            assert!(!cmd.is_shipped());
        }
    }

    // --- ReactInputLanguage ---
    #[test]
    fn input_language_serde() {
        let langs = [ReactInputLanguage::Jsx, ReactInputLanguage::Tsx];
        for lang in &langs {
            let json = serde_json::to_string(lang).unwrap();
            let back: ReactInputLanguage = serde_json::from_str(&json).unwrap();
            assert_eq!(*lang, back);
        }
    }

    // --- DiagnosticSeverity ---
    #[test]
    fn severity_serde() {
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

    // --- DiagnosticCategory ---
    #[test]
    fn category_serde() {
        let cat = DiagnosticCategory::JsxSyntax;
        let json = serde_json::to_string(&cat).unwrap();
        let back: DiagnosticCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back);
    }

    // --- FeatureSupport ---
    #[test]
    fn feature_support_available() {
        assert!(FeatureSupport::Supported.is_available());
        assert!(FeatureSupport::Partial.is_available());
        assert!(!FeatureSupport::NotImplemented.is_available());
        assert!(!FeatureSupport::Unsupported.is_available());
        assert!(!FeatureSupport::Deprecated.is_available());
    }

    #[test]
    fn feature_support_serde() {
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

    // --- ReactOperatorContract ---
    #[test]
    fn empty_contract() {
        let contract = ReactOperatorContract::new();
        assert!(contract.commands.is_empty());
        assert!(contract.features.is_empty());
    }

    #[test]
    fn seed_contract_has_commands() {
        let contract = build_seed_contract();
        assert_eq!(contract.commands.len(), 5);
    }

    #[test]
    fn seed_contract_has_features() {
        let contract = build_seed_contract();
        assert_eq!(contract.features.len(), 8);
    }

    #[test]
    fn seed_contract_shipped_commands() {
        let contract = build_seed_contract();
        assert!(contract.shipped_commands().is_empty()); // None shipped yet
    }

    #[test]
    fn seed_contract_available_features() {
        let contract = build_seed_contract();
        let available = contract.available_features();
        assert_eq!(available.len(), 4); // 3 supported + 1 partial
    }

    #[test]
    fn seed_contract_unsupported_features() {
        let contract = build_seed_contract();
        let unsupported = contract.unsupported_features();
        assert_eq!(unsupported.len(), 4);
    }

    #[test]
    fn seed_contract_runtime_modes() {
        let contract = build_seed_contract();
        assert_eq!(contract.supported_runtime_modes.len(), 3);
    }

    #[test]
    fn seed_contract_build_targets() {
        let contract = build_seed_contract();
        assert_eq!(contract.supported_build_targets.len(), 4);
    }

    #[test]
    fn content_hash_deterministic() {
        let c1 = build_seed_contract();
        let c2 = build_seed_contract();
        assert_eq!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn content_hash_changes() {
        let c1 = build_seed_contract();
        let mut c2 = build_seed_contract();
        c2.add_feature(ReactFeatureContract {
            name: "extra_feature".to_string(),
            support: FeatureSupport::Supported,
            description: "extra".to_string(),
            limitations: Vec::new(),
            tracking_bead: None,
        });
        assert_ne!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn contract_serde_roundtrip() {
        let contract = build_seed_contract();
        let json = serde_json::to_string(&contract).unwrap();
        let back: ReactOperatorContract = serde_json::from_str(&json).unwrap();
        assert_eq!(contract.commands.len(), back.commands.len());
        assert_eq!(contract.content_hash(), back.content_hash());
    }

    #[test]
    fn default_contract_empty() {
        let contract = ReactOperatorContract::default();
        assert!(contract.commands.is_empty());
    }

    // --- ReactDiagnostic ---
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

    // --- ReactCompileInput ---
    #[test]
    fn compile_input_serde() {
        let input = ReactCompileInput {
            source_path: "app.tsx".to_string(),
            language: ReactInputLanguage::Tsx,
            runtime_mode: ReactRuntimeMode::Automatic,
            target: ReactBuildTarget::Client,
            source_maps: true,
            preserve_display_names: true,
            input_hash: ContentHash::compute(b"test"),
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: ReactCompileInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    // --- ReactCompileOutput ---
    #[test]
    fn compile_output_serde() {
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

    // --- Constants ---
    #[test]
    fn constants() {
        assert_eq!(COMPONENT, "react_compile_operator_surface");
        assert_eq!(BEAD_ID, "bd-1lsy.10.12");
    }
}
