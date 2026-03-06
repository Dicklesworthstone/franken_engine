//! Compile-time ambient-authority audit gate.
//!
//! Statically detects forbidden direct calls (raw syscalls, unmediated I/O,
//! global state mutation) in security-critical modules.  Ensures no code
//! path bypasses the capability-profile system (bd-1i2).
//!
//! The audit scans source text for forbidden patterns and produces structured
//! findings.  Exemptions are tracked in a machine-readable registry.
//!
//! Plan references: Section 10.11 item 2, 9G.1 (capability-context-first
//! runtime), Top-10 #2 (guardplane), #7 (capability lattice).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ForbiddenCallCategory — categories of forbidden ambient authority
// ---------------------------------------------------------------------------

/// Category of a forbidden ambient-authority call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ForbiddenCallCategory {
    /// Direct filesystem I/O (std::fs).
    FileSystem,
    /// Direct network access (std::net).
    Network,
    /// Process spawning (std::process).
    Process,
    /// Global mutable state (static mut, lazy_static with mutation).
    GlobalMutableState,
    /// Environment variable access (std::env).
    Environment,
    /// Raw pointer operations with external state.
    RawPointerExternalState,
    /// Direct time access (std::time::SystemTime, Instant for non-virtual).
    DirectTime,
}

impl fmt::Display for ForbiddenCallCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileSystem => write!(f, "filesystem"),
            Self::Network => write!(f, "network"),
            Self::Process => write!(f, "process"),
            Self::GlobalMutableState => write!(f, "global_mutable_state"),
            Self::Environment => write!(f, "environment"),
            Self::RawPointerExternalState => write!(f, "raw_pointer_external_state"),
            Self::DirectTime => write!(f, "direct_time"),
        }
    }
}

// ---------------------------------------------------------------------------
// ForbiddenPattern — a pattern to detect in source
// ---------------------------------------------------------------------------

/// A forbidden call pattern to detect in source text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ForbiddenPattern {
    /// Pattern identifier (e.g., "std_fs_read").
    pub pattern_id: String,
    /// Category of ambient authority.
    pub category: ForbiddenCallCategory,
    /// The text pattern to search for in source.
    pub pattern: String,
    /// Human-readable description of why this is forbidden.
    pub reason: String,
    /// Suggested capability-mediated alternative.
    pub suggested_alternative: String,
}

// ---------------------------------------------------------------------------
// Exemption — an allowed exception to the audit
// ---------------------------------------------------------------------------

/// An exemption allowing a specific forbidden pattern at a specific location.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Exemption {
    /// Exemption identifier.
    pub exemption_id: String,
    /// Module path where the exemption applies.
    pub module_path: String,
    /// Pattern ID being exempted.
    pub pattern_id: String,
    /// Human-readable reason for the exemption.
    pub reason: String,
    /// Witness reference (signed exemption artifact).
    pub witness: String,
    /// Line number (if specific line; 0 for module-wide).
    pub line: usize,
}

// ---------------------------------------------------------------------------
// ExemptionRegistry — tracks all exemptions
// ---------------------------------------------------------------------------

/// Registry of all exemptions, keyed by (module_path, pattern_id).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExemptionRegistry {
    exemptions: Vec<Exemption>,
}

impl ExemptionRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            exemptions: Vec::new(),
        }
    }

    /// Add an exemption.
    pub fn add(&mut self, exemption: Exemption) {
        self.exemptions.push(exemption);
    }

    /// Check if a finding is exempted.
    pub fn is_exempted(&self, module_path: &str, pattern_id: &str, line: usize) -> bool {
        self.exemptions.iter().any(|e| {
            e.module_path == module_path
                && e.pattern_id == pattern_id
                && (e.line == 0 || e.line == line)
        })
    }

    /// All exemptions.
    pub fn exemptions(&self) -> &[Exemption] {
        &self.exemptions
    }

    /// Number of exemptions.
    pub fn len(&self) -> usize {
        self.exemptions.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.exemptions.is_empty()
    }
}

// ---------------------------------------------------------------------------
// AuditFinding — a detected violation
// ---------------------------------------------------------------------------

/// A detected forbidden-call violation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuditFinding {
    /// Module path where the violation was found.
    pub module_path: String,
    /// Forbidden API that was detected.
    pub forbidden_api: String,
    /// Pattern ID that matched.
    pub pattern_id: String,
    /// Category of the violation.
    pub category: ForbiddenCallCategory,
    /// File path containing the violation.
    pub file_path: String,
    /// Line number of the violation.
    pub line: usize,
    /// The source line containing the violation.
    pub source_line: String,
    /// Suggested capability-mediated alternative.
    pub suggested_alternative: String,
    /// Whether this finding is exempted.
    pub exempted: bool,
}

// ---------------------------------------------------------------------------
// AuditConfig — configuration for the audit gate
// ---------------------------------------------------------------------------

/// Configuration for the ambient-authority audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Forbidden patterns to check.
    pub patterns: Vec<ForbiddenPattern>,
    /// Modules to audit (by path prefix).
    pub audited_modules: BTreeSet<String>,
}

impl AuditConfig {
    /// Create a default config with standard forbidden patterns.
    pub fn standard() -> Self {
        let patterns = vec![
            ForbiddenPattern {
                pattern_id: "std_fs".to_string(),
                category: ForbiddenCallCategory::FileSystem,
                pattern: "std::fs::".to_string(),
                reason: "Direct filesystem access bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated FileSystemCap".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "fs_read".to_string(),
                category: ForbiddenCallCategory::FileSystem,
                pattern: "fs::read".to_string(),
                reason: "Direct filesystem read bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated FileSystemCap::read".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "fs_write".to_string(),
                category: ForbiddenCallCategory::FileSystem,
                pattern: "fs::write".to_string(),
                reason: "Direct filesystem write bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated FileSystemCap::write".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "std_net".to_string(),
                category: ForbiddenCallCategory::Network,
                pattern: "std::net::".to_string(),
                reason: "Direct network access bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated NetworkCap".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "tcp_stream".to_string(),
                category: ForbiddenCallCategory::Network,
                pattern: "TcpStream::".to_string(),
                reason: "Direct TCP access bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated NetworkCap::connect".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "udp_socket".to_string(),
                category: ForbiddenCallCategory::Network,
                pattern: "UdpSocket::".to_string(),
                reason: "Direct UDP access bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated NetworkCap::bind_udp".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "std_process".to_string(),
                category: ForbiddenCallCategory::Process,
                pattern: "std::process::".to_string(),
                reason: "Direct process spawning bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated ProcessCap".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "command_new".to_string(),
                category: ForbiddenCallCategory::Process,
                pattern: "Command::new".to_string(),
                reason: "Direct command execution bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated ProcessCap::spawn".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "std_env".to_string(),
                category: ForbiddenCallCategory::Environment,
                pattern: "std::env::".to_string(),
                reason: "Direct environment access bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated EnvCap".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "env_var".to_string(),
                category: ForbiddenCallCategory::Environment,
                pattern: "env::var".to_string(),
                reason: "Direct env var read bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated EnvCap::get".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "static_mut".to_string(),
                category: ForbiddenCallCategory::GlobalMutableState,
                pattern: "static mut ".to_string(),
                reason: "Global mutable state violates capability isolation".to_string(),
                suggested_alternative: "Use scoped state via Cx parameter".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "system_time".to_string(),
                category: ForbiddenCallCategory::DirectTime,
                pattern: "SystemTime::now".to_string(),
                reason: "Direct time access breaks deterministic replay".to_string(),
                suggested_alternative: "Use virtual time from Cx::clock()".to_string(),
            },
        ];

        Self {
            patterns,
            audited_modules: BTreeSet::new(),
        }
    }

    /// Add a module to the audit scope.
    pub fn audit_module(&mut self, module_path: impl Into<String>) {
        self.audited_modules.insert(module_path.into());
    }

    /// Add a custom forbidden pattern.
    pub fn add_pattern(&mut self, pattern: ForbiddenPattern) {
        self.patterns.push(pattern);
    }
}

// ---------------------------------------------------------------------------
// AuditResult — complete audit output
// ---------------------------------------------------------------------------

/// Complete result of an ambient-authority audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditResult {
    /// All findings (including exempted).
    pub findings: Vec<AuditFinding>,
    /// Number of unexempted violations.
    pub violation_count: usize,
    /// Number of exempted findings.
    pub exemption_count: usize,
    /// Modules audited.
    pub modules_audited: Vec<String>,
    /// Whether the audit passed (zero unexempted violations).
    pub passed: bool,
}

// ---------------------------------------------------------------------------
// SourceAuditor — the audit engine
// ---------------------------------------------------------------------------

/// Source-text auditor for ambient-authority violations.
///
/// Scans source text for forbidden patterns and produces structured findings.
#[derive(Debug)]
pub struct SourceAuditor {
    config: AuditConfig,
    exemptions: ExemptionRegistry,
}

impl SourceAuditor {
    /// Create a new auditor.
    pub fn new(config: AuditConfig, exemptions: ExemptionRegistry) -> Self {
        Self { config, exemptions }
    }

    /// Audit a single source file.
    ///
    /// - `module_path`: logical module path (e.g., "franken_engine::gc").
    /// - `file_path`: filesystem path to the source file.
    /// - `source`: the source text to scan.
    pub fn audit_source(
        &self,
        module_path: &str,
        file_path: &str,
        source: &str,
    ) -> Vec<AuditFinding> {
        if !self.module_in_scope(module_path) {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for (line_num_0, line) in source.lines().enumerate() {
            let line_num = line_num_0 + 1;
            let trimmed = line.trim();

            // Skip comments.
            if trimmed.starts_with("//") {
                continue;
            }

            for pattern in &self.config.patterns {
                if line.contains(&pattern.pattern) {
                    let exempted =
                        self.exemptions
                            .is_exempted(module_path, &pattern.pattern_id, line_num);

                    findings.push(AuditFinding {
                        module_path: module_path.to_string(),
                        forbidden_api: pattern.pattern.clone(),
                        pattern_id: pattern.pattern_id.clone(),
                        category: pattern.category,
                        file_path: file_path.to_string(),
                        line: line_num,
                        source_line: trimmed.to_string(),
                        suggested_alternative: pattern.suggested_alternative.clone(),
                        exempted,
                    });
                }
            }
        }

        // Sort for deterministic output.
        findings.sort();
        findings
    }

    /// Run a full audit across multiple source files.
    ///
    /// `sources` is a map from (module_path, file_path) -> source text.
    pub fn audit_all(&self, sources: &BTreeMap<(String, String), String>) -> AuditResult {
        let mut all_findings = Vec::new();
        let mut modules_audited = BTreeSet::new();

        for ((module_path, file_path), source) in sources {
            if !self.module_in_scope(module_path) {
                continue;
            }

            modules_audited.insert(module_path.clone());
            let findings = self.audit_source(module_path, file_path, source);
            all_findings.extend(findings);
        }

        let violation_count = all_findings.iter().filter(|f| !f.exempted).count();
        let exemption_count = all_findings.iter().filter(|f| f.exempted).count();

        AuditResult {
            findings: all_findings,
            violation_count,
            exemption_count,
            modules_audited: modules_audited.into_iter().collect(),
            passed: violation_count == 0,
        }
    }

    /// Configuration.
    pub fn config(&self) -> &AuditConfig {
        &self.config
    }

    /// Exemption registry.
    pub fn exemptions(&self) -> &ExemptionRegistry {
        &self.exemptions
    }

    fn module_in_scope(&self, module_path: &str) -> bool {
        self.config.audited_modules.is_empty()
            || self.config.audited_modules.iter().any(|prefix| {
                module_path == prefix
                    || module_path
                        .strip_prefix(prefix)
                        .is_some_and(|suffix| suffix.starts_with("::"))
            })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn standard_auditor() -> SourceAuditor {
        SourceAuditor::new(AuditConfig::standard(), ExemptionRegistry::new())
    }

    // -- ForbiddenCallCategory --

    #[test]
    fn category_display() {
        assert_eq!(ForbiddenCallCategory::FileSystem.to_string(), "filesystem");
        assert_eq!(ForbiddenCallCategory::Network.to_string(), "network");
        assert_eq!(ForbiddenCallCategory::Process.to_string(), "process");
        assert_eq!(
            ForbiddenCallCategory::GlobalMutableState.to_string(),
            "global_mutable_state"
        );
        assert_eq!(
            ForbiddenCallCategory::Environment.to_string(),
            "environment"
        );
        assert_eq!(ForbiddenCallCategory::DirectTime.to_string(), "direct_time");
    }

    // -- Clean source passes --

    #[test]
    fn clean_source_produces_no_findings() {
        let auditor = standard_auditor();
        let source = r#"
            fn compute(x: i64) -> i64 {
                x * 2 + 1
            }

            fn process_data(data: &[u8]) -> Vec<u8> {
                data.to_vec()
            }
        "#;

        let findings = auditor.audit_source("engine::compute", "src/compute.rs", source);
        assert!(findings.is_empty());
    }

    // -- Filesystem detection --

    #[test]
    fn detects_std_fs_usage() {
        let auditor = standard_auditor();
        let source = r#"
            use std::fs::read_to_string;
            fn load() { let _ = std::fs::read("file.txt"); }
        "#;

        let findings = auditor.audit_source("engine::loader", "src/loader.rs", source);
        assert!(!findings.is_empty());
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::FileSystem)
        );
    }

    // -- Network detection --

    #[test]
    fn detects_tcp_stream() {
        let auditor = standard_auditor();
        let source = r#"
            let stream = TcpStream::connect("127.0.0.1:8080");
        "#;

        let findings = auditor.audit_source("engine::net", "src/net.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::Network)
        );
    }

    // -- Process detection --

    #[test]
    fn detects_command_new() {
        let auditor = standard_auditor();
        let source = r#"
            let output = Command::new("ls").output();
        "#;

        let findings = auditor.audit_source("engine::exec", "src/exec.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::Process)
        );
    }

    // -- Environment detection --

    #[test]
    fn detects_env_var() {
        let auditor = standard_auditor();
        let source = r#"
            let val = std::env::var("HOME");
        "#;

        let findings = auditor.audit_source("engine::env", "src/env.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::Environment)
        );
    }

    // -- Global mutable state --

    #[test]
    fn detects_static_mut() {
        let auditor = standard_auditor();
        let source = r#"
            static mut COUNTER: u64 = 0;
        "#;

        let findings = auditor.audit_source("engine::state", "src/state.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::GlobalMutableState)
        );
    }

    // -- Time detection --

    #[test]
    fn detects_system_time_now() {
        let auditor = standard_auditor();
        let source = r#"
            let now = SystemTime::now();
        "#;

        let findings = auditor.audit_source("engine::clock", "src/clock.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::DirectTime)
        );
    }

    // -- Comments are skipped --

    #[test]
    fn comments_are_not_flagged() {
        let auditor = standard_auditor();
        let source = r#"
            // This uses std::fs::read for documentation purposes
            /// Example: std::net::TcpStream::connect
            //! Module docs: std::process::Command
            fn clean_function() {}
        "#;

        let findings = auditor.audit_source("engine::docs", "src/docs.rs", source);
        assert!(findings.is_empty());
    }

    // -- Exemptions --

    #[test]
    fn exempted_finding_is_marked() {
        let mut exemptions = ExemptionRegistry::new();
        exemptions.add(Exemption {
            exemption_id: "ex-001".to_string(),
            module_path: "engine::bootstrap".to_string(),
            pattern_id: "std_fs".to_string(),
            reason: "Bootstrap requires one-time filesystem access".to_string(),
            witness: "signed:bootstrap-exempt-v1".to_string(),
            line: 0, // module-wide
        });
        exemptions.add(Exemption {
            exemption_id: "ex-001b".to_string(),
            module_path: "engine::bootstrap".to_string(),
            pattern_id: "fs_read".to_string(),
            reason: "Bootstrap requires one-time filesystem access".to_string(),
            witness: "signed:bootstrap-exempt-v1".to_string(),
            line: 0,
        });

        let auditor = SourceAuditor::new(AuditConfig::standard(), exemptions);
        let source = r#"
            let config = std::fs::read_to_string("config.toml");
        "#;

        let findings = auditor.audit_source("engine::bootstrap", "src/bootstrap.rs", source);
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| f.exempted));
    }

    #[test]
    fn line_specific_exemption() {
        let mut exemptions = ExemptionRegistry::new();
        exemptions.add(Exemption {
            exemption_id: "ex-002".to_string(),
            module_path: "engine::init".to_string(),
            pattern_id: "std_fs".to_string(),
            reason: "Init needs config load".to_string(),
            witness: "signed:init-exempt-v1".to_string(),
            line: 2, // only line 2
        });

        let auditor = SourceAuditor::new(AuditConfig::standard(), exemptions);
        let source =
            "fn init() {\n    let _ = std::fs::read(\"x\");\n    let _ = std::fs::read(\"y\");\n}";

        let findings = auditor.audit_source("engine::init", "src/init.rs", source);
        // Line 2 exempted, line 3 not
        let exempted = findings.iter().filter(|f| f.exempted).count();
        let violations = findings.iter().filter(|f| !f.exempted).count();
        assert_eq!(exempted, 1);
        assert!(violations >= 1);
    }

    // -- Audit result --

    #[test]
    fn audit_all_aggregates() {
        let auditor = standard_auditor();
        let mut sources = BTreeMap::new();
        sources.insert(
            ("engine::clean".to_string(), "src/clean.rs".to_string()),
            "fn ok() { 1 + 1; }".to_string(),
        );
        sources.insert(
            ("engine::dirty".to_string(), "src/dirty.rs".to_string()),
            "let _ = std::fs::read(\"x\");".to_string(),
        );

        let result = auditor.audit_all(&sources);
        assert!(!result.passed);
        assert!(result.violation_count >= 1); // multiple patterns may match
        assert_eq!(result.modules_audited.len(), 2);
    }

    #[test]
    fn clean_audit_passes() {
        let auditor = standard_auditor();
        let mut sources = BTreeMap::new();
        sources.insert(
            ("engine::pure".to_string(), "src/pure.rs".to_string()),
            "fn add(a: i64, b: i64) -> i64 { a + b }".to_string(),
        );

        let result = auditor.audit_all(&sources);
        assert!(result.passed);
        assert_eq!(result.violation_count, 0);
    }

    // -- Finding structure --

    #[test]
    fn finding_contains_actionable_info() {
        let auditor = standard_auditor();
        let source = "let _ = std::fs::read(\"x\");";

        let findings = auditor.audit_source("engine::io", "src/io.rs", source);
        let finding = &findings[0];

        assert_eq!(finding.module_path, "engine::io");
        assert_eq!(finding.file_path, "src/io.rs");
        assert_eq!(finding.line, 1);
        assert!(!finding.suggested_alternative.is_empty());
        assert!(!finding.forbidden_api.is_empty());
    }

    // -- Deterministic output --

    #[test]
    fn deterministic_output() {
        let auditor = standard_auditor();
        let source = r#"
            let _ = std::fs::read("a");
            let _ = TcpStream::connect("b");
            let _ = Command::new("c");
        "#;

        let f1 = auditor.audit_source("m", "f.rs", source);
        let f2 = auditor.audit_source("m", "f.rs", source);
        assert_eq!(f1, f2);
    }

    // -- Custom pattern --

    #[test]
    fn custom_pattern_detected() {
        let mut config = AuditConfig::standard();
        config.add_pattern(ForbiddenPattern {
            pattern_id: "custom_dangerous".to_string(),
            category: ForbiddenCallCategory::RawPointerExternalState,
            pattern: "dangerous_call()".to_string(),
            reason: "Custom dangerous function".to_string(),
            suggested_alternative: "Use safe_call() instead".to_string(),
        });

        let auditor = SourceAuditor::new(config, ExemptionRegistry::new());
        let source = "fn bad() { dangerous_call(); }";

        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.iter().any(|f| f.pattern_id == "custom_dangerous"));
    }

    // -- ExemptionRegistry --

    #[test]
    fn empty_registry() {
        let reg = ExemptionRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(!reg.is_exempted("m", "p", 1));
    }

    #[test]
    fn module_wide_exemption() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        assert!(reg.is_exempted("m", "p", 1));
        assert!(reg.is_exempted("m", "p", 99));
        assert!(!reg.is_exempted("m", "other", 1));
    }

    // -- Error display --

    #[test]
    fn category_ordering() {
        assert!(ForbiddenCallCategory::FileSystem < ForbiddenCallCategory::Network);
        assert!(ForbiddenCallCategory::Network < ForbiddenCallCategory::Process);
    }

    // -- Serialization --

    #[test]
    fn category_serialization_round_trip() {
        let categories = vec![
            ForbiddenCallCategory::FileSystem,
            ForbiddenCallCategory::Network,
            ForbiddenCallCategory::Process,
            ForbiddenCallCategory::GlobalMutableState,
            ForbiddenCallCategory::Environment,
            ForbiddenCallCategory::RawPointerExternalState,
            ForbiddenCallCategory::DirectTime,
        ];
        for cat in &categories {
            let json = serde_json::to_string(cat).expect("serialize");
            let restored: ForbiddenCallCategory = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*cat, restored);
        }
    }

    #[test]
    fn exemption_serialization_round_trip() {
        let ex = Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "test".to_string(),
            witness: "w".to_string(),
            line: 42,
        };
        let json = serde_json::to_string(&ex).expect("serialize");
        let restored: Exemption = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ex, restored);
    }

    #[test]
    fn audit_finding_serialization_round_trip() {
        let finding = AuditFinding {
            module_path: "m".to_string(),
            forbidden_api: "std::fs::read".to_string(),
            pattern_id: "std_fs".to_string(),
            category: ForbiddenCallCategory::FileSystem,
            file_path: "src/m.rs".to_string(),
            line: 10,
            source_line: "let _ = std::fs::read(\"x\");".to_string(),
            suggested_alternative: "Use FileSystemCap".to_string(),
            exempted: false,
        };
        let json = serde_json::to_string(&finding).expect("serialize");
        let restored: AuditFinding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(finding, restored);
    }

    #[test]
    fn audit_result_serialization_round_trip() {
        let result = AuditResult {
            findings: vec![],
            violation_count: 0,
            exemption_count: 0,
            modules_audited: vec!["m".to_string()],
            passed: true,
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: AuditResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    #[test]
    fn audit_config_serialization_round_trip() {
        let config = AuditConfig::standard();
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: AuditConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display covers RawPointerExternalState
    // -----------------------------------------------------------------------

    #[test]
    fn category_display_raw_pointer() {
        assert_eq!(
            ForbiddenCallCategory::RawPointerExternalState.to_string(),
            "raw_pointer_external_state"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrips for remaining types
    // -----------------------------------------------------------------------

    #[test]
    fn forbidden_pattern_serde_roundtrip() {
        let pattern = ForbiddenPattern {
            pattern_id: "test_p".to_string(),
            category: ForbiddenCallCategory::Network,
            pattern: "test_pattern".to_string(),
            reason: "test reason".to_string(),
            suggested_alternative: "use safe api".to_string(),
        };
        let json = serde_json::to_string(&pattern).unwrap();
        let restored: ForbiddenPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(pattern, restored);
    }

    #[test]
    fn exemption_registry_serde_roundtrip() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        let json = serde_json::to_string(&reg).unwrap();
        let restored: ExemptionRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ExemptionRegistry
    // -----------------------------------------------------------------------

    #[test]
    fn exemption_registry_default_is_empty() {
        let reg = ExemptionRegistry::default();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn exemption_registry_exemptions_accessor() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 5,
        });
        assert_eq!(reg.exemptions().len(), 1);
        assert_eq!(reg.exemptions()[0].exemption_id, "e1");
    }

    // -----------------------------------------------------------------------
    // Enrichment: AuditConfig
    // -----------------------------------------------------------------------

    #[test]
    fn standard_config_has_twelve_patterns() {
        let config = AuditConfig::standard();
        assert_eq!(config.patterns.len(), 12);
        assert!(config.audited_modules.is_empty());
    }

    #[test]
    fn audit_module_adds_to_scope() {
        let mut config = AuditConfig::standard();
        config.audit_module("engine::core");
        config.audit_module("engine::gc");
        assert_eq!(config.audited_modules.len(), 2);
        assert!(config.audited_modules.contains("engine::core"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: additional detection patterns
    // -----------------------------------------------------------------------

    #[test]
    fn detects_udp_socket() {
        let auditor = standard_auditor();
        let source = "let socket = UdpSocket::bind(\"0.0.0.0:0\");";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::Network)
        );
    }

    #[test]
    fn detects_std_net() {
        let auditor = standard_auditor();
        let source = "use std::net::TcpListener;";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.iter().any(|f| f.pattern_id == "std_net"));
    }

    #[test]
    fn detects_std_process() {
        let auditor = standard_auditor();
        let source = "use std::process::exit;";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.iter().any(|f| f.pattern_id == "std_process"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: multiple findings on same line
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_patterns_on_same_line() {
        let auditor = standard_auditor();
        // Both std::fs:: and fs::read patterns match here.
        let source = "let _ = std::fs::read(\"x\");";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.len() >= 2); // std_fs and fs_read both match
    }

    // -----------------------------------------------------------------------
    // Enrichment: audit_all edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn audit_all_empty_sources_passes() {
        let auditor = standard_auditor();
        let sources = BTreeMap::new();
        let result = auditor.audit_all(&sources);
        assert!(result.passed);
        assert_eq!(result.violation_count, 0);
        assert!(result.modules_audited.is_empty());
    }

    #[test]
    fn audit_source_skips_modules_outside_scope() {
        let mut config = AuditConfig::standard();
        config.audit_module("engine::audited");
        let auditor = SourceAuditor::new(config, ExemptionRegistry::new());

        let findings = auditor.audit_source(
            "engine::ignored",
            "src/ignored.rs",
            "let _ = std::fs::read(\"x\");",
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn audit_all_counts_exemptions() {
        let mut exemptions = ExemptionRegistry::new();
        exemptions.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "std_fs".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        exemptions.add(Exemption {
            exemption_id: "e2".to_string(),
            module_path: "m".to_string(),
            pattern_id: "fs_read".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });

        let auditor = SourceAuditor::new(AuditConfig::standard(), exemptions);
        let mut sources = BTreeMap::new();
        sources.insert(
            ("m".to_string(), "f.rs".to_string()),
            "let _ = std::fs::read(\"x\");".to_string(),
        );

        let result = auditor.audit_all(&sources);
        assert!(result.passed);
        assert_eq!(result.violation_count, 0);
        assert!(result.exemption_count >= 2);
    }

    #[test]
    fn audit_all_respects_configured_module_scope() {
        let mut config = AuditConfig::standard();
        config.audit_module("engine::audited");
        let auditor = SourceAuditor::new(config, ExemptionRegistry::new());
        let mut sources = BTreeMap::new();
        sources.insert(
            (
                "engine::audited::dirty".to_string(),
                "src/audited.rs".to_string(),
            ),
            "let _ = std::fs::read(\"audited\");".to_string(),
        );
        sources.insert(
            (
                "engine::ignored::dirty".to_string(),
                "src/ignored.rs".to_string(),
            ),
            "let _ = std::fs::read(\"ignored\");".to_string(),
        );

        let result = auditor.audit_all(&sources);

        assert!(!result.passed);
        assert_eq!(
            result.modules_audited,
            vec!["engine::audited::dirty".to_string()]
        );
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.module_path.starts_with("engine::audited"))
        );
    }

    #[test]
    fn audit_scope_does_not_match_sibling_prefixes() {
        let mut config = AuditConfig::standard();
        config.audit_module("engine::audit");
        let auditor = SourceAuditor::new(config, ExemptionRegistry::new());
        let mut sources = BTreeMap::new();
        sources.insert(
            (
                "engine::audit::worker".to_string(),
                "src/audited.rs".to_string(),
            ),
            "let _ = std::fs::read(\"audited\");".to_string(),
        );
        sources.insert(
            (
                "engine::auditedevil::worker".to_string(),
                "src/ignored.rs".to_string(),
            ),
            "let _ = std::fs::read(\"ignored\");".to_string(),
        );

        let result = auditor.audit_all(&sources);

        assert_eq!(
            result.modules_audited,
            vec!["engine::audit::worker".to_string()]
        );
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.module_path == "engine::audit::worker")
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: SourceAuditor accessors
    // -----------------------------------------------------------------------

    #[test]
    fn auditor_accessors() {
        let config = AuditConfig::standard();
        let exemptions = ExemptionRegistry::new();
        let auditor = SourceAuditor::new(config.clone(), exemptions);
        assert_eq!(*auditor.config(), config);
        assert!(auditor.exemptions().is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display uniqueness, boundary, determinism
    // -----------------------------------------------------------------------

    #[test]
    fn category_display_all_variants_unique() {
        let categories = [
            ForbiddenCallCategory::FileSystem,
            ForbiddenCallCategory::Network,
            ForbiddenCallCategory::Process,
            ForbiddenCallCategory::GlobalMutableState,
            ForbiddenCallCategory::Environment,
            ForbiddenCallCategory::RawPointerExternalState,
            ForbiddenCallCategory::DirectTime,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for cat in &categories {
            seen.insert(cat.to_string());
        }
        assert_eq!(seen.len(), 7, "all 7 categories must have distinct Display");
    }

    #[test]
    fn audit_finding_ordering_is_deterministic() {
        // Derived Ord compares fields in declaration order: module_path,
        // forbidden_api, pattern_id, category, ...
        // So same module_path but different forbidden_api determines order.
        let f1 = AuditFinding {
            module_path: "a::b".to_string(),
            forbidden_api: "A_api".to_string(),
            pattern_id: "p1".to_string(),
            category: ForbiddenCallCategory::Network,
            file_path: "a.rs".to_string(),
            line: 1,
            source_line: "line1".to_string(),
            suggested_alternative: "alt".to_string(),
            exempted: false,
        };
        let f2 = AuditFinding {
            module_path: "a::b".to_string(),
            forbidden_api: "B_api".to_string(),
            pattern_id: "p2".to_string(),
            category: ForbiddenCallCategory::FileSystem,
            file_path: "a.rs".to_string(),
            line: 2,
            source_line: "line2".to_string(),
            suggested_alternative: "alt".to_string(),
            exempted: false,
        };
        assert!(
            f1 < f2,
            "A_api < B_api ordering must hold for findings with same module_path"
        );
        // Same finding compared with itself should be equal
        assert_eq!(f1.cmp(&f1), std::cmp::Ordering::Equal);
    }

    #[test]
    fn audit_all_with_mixed_exempted_and_violated() {
        let mut exemptions = ExemptionRegistry::new();
        exemptions.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m1".to_string(),
            pattern_id: "std_fs".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        exemptions.add(Exemption {
            exemption_id: "e2".to_string(),
            module_path: "m1".to_string(),
            pattern_id: "fs_read".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });

        let auditor = SourceAuditor::new(AuditConfig::standard(), exemptions);
        let mut sources = BTreeMap::new();
        // m1: exempted filesystem use
        sources.insert(
            ("m1".to_string(), "f1.rs".to_string()),
            "let _ = std::fs::read(\"x\");".to_string(),
        );
        // m2: unexempted network use
        sources.insert(
            ("m2".to_string(), "f2.rs".to_string()),
            "let s = TcpStream::connect(\"x\");".to_string(),
        );

        let result = auditor.audit_all(&sources);
        assert!(!result.passed);
        assert!(result.exemption_count >= 2);
        assert!(result.violation_count >= 1);
        assert_eq!(result.modules_audited.len(), 2);
    }

    #[test]
    fn standard_config_pattern_ids_are_unique() {
        let config = AuditConfig::standard();
        let ids: std::collections::BTreeSet<_> =
            config.patterns.iter().map(|p| &p.pattern_id).collect();
        assert_eq!(
            ids.len(),
            config.patterns.len(),
            "pattern IDs must be unique"
        );
    }

    #[test]
    fn standard_config_covers_all_categories_except_raw_pointer() {
        let config = AuditConfig::standard();
        let cats: std::collections::BTreeSet<_> =
            config.patterns.iter().map(|p| p.category).collect();
        assert!(cats.contains(&ForbiddenCallCategory::FileSystem));
        assert!(cats.contains(&ForbiddenCallCategory::Network));
        assert!(cats.contains(&ForbiddenCallCategory::Process));
        assert!(cats.contains(&ForbiddenCallCategory::Environment));
        assert!(cats.contains(&ForbiddenCallCategory::GlobalMutableState));
        assert!(cats.contains(&ForbiddenCallCategory::DirectTime));
        // RawPointerExternalState not in standard config
        assert!(!cats.contains(&ForbiddenCallCategory::RawPointerExternalState));
    }

    #[test]
    fn exemption_registry_multiple_entries_for_same_module() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p1".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        reg.add(Exemption {
            exemption_id: "e2".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p2".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        assert_eq!(reg.len(), 2);
        assert!(reg.is_exempted("m", "p1", 1));
        assert!(reg.is_exempted("m", "p2", 1));
        assert!(!reg.is_exempted("m", "p3", 1));
    }

    #[test]
    fn audit_source_empty_source_has_no_findings() {
        let auditor = standard_auditor();
        let findings = auditor.audit_source("m", "f.rs", "");
        assert!(findings.is_empty());
    }

    #[test]
    fn audit_result_serde_with_findings() {
        let result = AuditResult {
            findings: vec![AuditFinding {
                module_path: "m".to_string(),
                forbidden_api: "std::fs::read".to_string(),
                pattern_id: "std_fs".to_string(),
                category: ForbiddenCallCategory::FileSystem,
                file_path: "f.rs".to_string(),
                line: 1,
                source_line: "std::fs::read(\"x\")".to_string(),
                suggested_alternative: "use cap".to_string(),
                exempted: false,
            }],
            violation_count: 1,
            exemption_count: 0,
            modules_audited: vec!["m".to_string()],
            passed: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: AuditResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, restored);
    }

    // ── Enrichment batch 2: line-specific exemptions & edge cases ──

    #[test]
    fn line_specific_exemption_only_matches_exact_line() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 10,
        });
        assert!(reg.is_exempted("m", "p", 10));
        assert!(!reg.is_exempted("m", "p", 11));
        assert!(!reg.is_exempted("m", "p", 9));
    }

    #[test]
    fn detects_global_mutable_state() {
        let auditor = standard_auditor();
        let source = "static mut GLOBAL: u32 = 0;";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::GlobalMutableState)
        );
    }

    #[test]
    fn detects_environment_access() {
        let auditor = standard_auditor();
        let source = "let val = std::env::var(\"HOME\");";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.iter().any(|f| f.pattern_id == "std_env"));
    }

    #[test]
    fn detects_direct_time_access() {
        let auditor = standard_auditor();
        let source = "let now = SystemTime::now();";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::DirectTime)
        );
    }

    #[test]
    fn multiline_source_detects_on_correct_line() {
        let auditor = standard_auditor();
        let source = "fn safe() {}\nlet x = std::fs::read(\"y\");\nfn also_safe() {}";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(!findings.is_empty());
        // Line 2 should have the finding (1-indexed)
        assert!(findings.iter().any(|f| f.line == 2));
    }

    #[test]
    fn audit_all_multiple_modules_sorted() {
        let auditor = standard_auditor();
        let mut sources = BTreeMap::new();
        sources.insert(
            ("z_mod".to_string(), "z.rs".to_string()),
            "let _ = std::fs::read(\"x\");".to_string(),
        );
        sources.insert(
            ("a_mod".to_string(), "a.rs".to_string()),
            "let s = TcpStream::connect(\"x\");".to_string(),
        );
        let result = auditor.audit_all(&sources);
        assert!(!result.passed);
        // Modules should be in sorted order (BTreeMap guarantees this)
        assert_eq!(result.modules_audited[0], "a_mod");
        assert_eq!(result.modules_audited[1], "z_mod");
    }

    #[test]
    fn exemption_for_wrong_module_does_not_match() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "correct_module".to_string(),
            pattern_id: "std_fs".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        assert!(!reg.is_exempted("wrong_module", "std_fs", 1));
    }

    #[test]
    fn comments_are_skipped_by_auditor() {
        let auditor = standard_auditor();
        // Auditor skips lines starting with //
        let source = "// TODO: replace std::fs::read with cap";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.is_empty());
    }

    #[test]
    fn clean_source_has_no_findings() {
        let auditor = standard_auditor();
        let source = "fn pure_computation(x: i64) -> i64 { x * 2 + 1 }";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.is_empty());
    }

    #[test]
    fn audit_finding_display_fields_preserved() {
        let finding = AuditFinding {
            module_path: "engine::core".to_string(),
            forbidden_api: "std::fs::read".to_string(),
            pattern_id: "std_fs".to_string(),
            category: ForbiddenCallCategory::FileSystem,
            file_path: "core.rs".to_string(),
            line: 42,
            source_line: "std::fs::read(path)".to_string(),
            suggested_alternative: "Use FileSystemCap".to_string(),
            exempted: false,
        };
        assert_eq!(finding.line, 42);
        assert_eq!(finding.file_path, "core.rs");
        assert!(!finding.exempted);
    }

    #[test]
    fn category_display_environment() {
        assert_eq!(
            ForbiddenCallCategory::Environment.to_string(),
            "environment"
        );
    }

    #[test]
    fn category_display_direct_time() {
        assert_eq!(ForbiddenCallCategory::DirectTime.to_string(), "direct_time");
    }

    // -----------------------------------------------------------------------
    // New enrichment: Copy semantics
    // -----------------------------------------------------------------------

    #[test]
    fn forbidden_call_category_copy_semantics() {
        let original = ForbiddenCallCategory::Network;
        let copied = original;
        // Both should be usable independently after copy
        assert_eq!(original, ForbiddenCallCategory::Network);
        assert_eq!(copied, ForbiddenCallCategory::Network);
    }

    #[test]
    fn category_copy_all_variants() {
        // Copy types can be assigned without moving; both bindings remain valid.
        fn use_copy(cat: ForbiddenCallCategory) -> String {
            cat.to_string()
        }
        let variants = [
            ForbiddenCallCategory::FileSystem,
            ForbiddenCallCategory::Network,
            ForbiddenCallCategory::Process,
            ForbiddenCallCategory::GlobalMutableState,
            ForbiddenCallCategory::Environment,
            ForbiddenCallCategory::RawPointerExternalState,
            ForbiddenCallCategory::DirectTime,
        ];
        for v in variants {
            // Passing v to a function copies it, but v is still usable after.
            let s = use_copy(v);
            assert!(!s.is_empty());
            // v is still valid (Copy semantics)
            assert_eq!(v, v);
        }
    }

    // -----------------------------------------------------------------------
    // New enrichment: Debug distinctness
    // -----------------------------------------------------------------------

    #[test]
    fn category_debug_all_variants_distinct() {
        let variants = [
            ForbiddenCallCategory::FileSystem,
            ForbiddenCallCategory::Network,
            ForbiddenCallCategory::Process,
            ForbiddenCallCategory::GlobalMutableState,
            ForbiddenCallCategory::Environment,
            ForbiddenCallCategory::RawPointerExternalState,
            ForbiddenCallCategory::DirectTime,
        ];
        let mut set = BTreeSet::new();
        for v in &variants {
            set.insert(format!("{v:?}"));
        }
        assert_eq!(
            set.len(),
            7,
            "all 7 category Debug outputs must be distinct"
        );
    }

    #[test]
    fn category_debug_nonempty() {
        for v in [
            ForbiddenCallCategory::FileSystem,
            ForbiddenCallCategory::Network,
            ForbiddenCallCategory::Process,
            ForbiddenCallCategory::GlobalMutableState,
            ForbiddenCallCategory::Environment,
            ForbiddenCallCategory::RawPointerExternalState,
            ForbiddenCallCategory::DirectTime,
        ] {
            assert!(!format!("{v:?}").is_empty());
        }
    }

    #[test]
    fn forbidden_pattern_debug_nonempty() {
        let p = ForbiddenPattern {
            pattern_id: "p1".to_string(),
            category: ForbiddenCallCategory::FileSystem,
            pattern: "std::fs::".to_string(),
            reason: "bad".to_string(),
            suggested_alternative: "use cap".to_string(),
        };
        assert!(!format!("{p:?}").is_empty());
    }

    #[test]
    fn exemption_debug_nonempty() {
        let ex = Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        };
        assert!(!format!("{ex:?}").is_empty());
    }

    #[test]
    fn audit_finding_debug_nonempty() {
        let f = AuditFinding {
            module_path: "m".to_string(),
            forbidden_api: "std::fs::read".to_string(),
            pattern_id: "std_fs".to_string(),
            category: ForbiddenCallCategory::FileSystem,
            file_path: "f.rs".to_string(),
            line: 1,
            source_line: "src".to_string(),
            suggested_alternative: "alt".to_string(),
            exempted: false,
        };
        assert!(!format!("{f:?}").is_empty());
    }

    #[test]
    fn audit_config_debug_nonempty() {
        let config = AuditConfig::standard();
        assert!(!format!("{config:?}").is_empty());
    }

    #[test]
    fn audit_result_debug_nonempty() {
        let r = AuditResult {
            findings: vec![],
            violation_count: 0,
            exemption_count: 0,
            modules_audited: vec![],
            passed: true,
        };
        assert!(!format!("{r:?}").is_empty());
    }

    #[test]
    fn exemption_registry_debug_nonempty() {
        let reg = ExemptionRegistry::new();
        assert!(!format!("{reg:?}").is_empty());
    }

    #[test]
    fn source_auditor_debug_nonempty() {
        let auditor = standard_auditor();
        assert!(!format!("{auditor:?}").is_empty());
    }

    // -----------------------------------------------------------------------
    // New enrichment: Serde variant distinctness
    // -----------------------------------------------------------------------

    #[test]
    fn category_serde_all_variants_distinct_json() {
        let variants = [
            ForbiddenCallCategory::FileSystem,
            ForbiddenCallCategory::Network,
            ForbiddenCallCategory::Process,
            ForbiddenCallCategory::GlobalMutableState,
            ForbiddenCallCategory::Environment,
            ForbiddenCallCategory::RawPointerExternalState,
            ForbiddenCallCategory::DirectTime,
        ];
        let mut jsons = BTreeSet::new();
        for v in &variants {
            jsons.insert(serde_json::to_string(v).unwrap());
        }
        assert_eq!(
            jsons.len(),
            7,
            "all category serde outputs must be distinct"
        );
    }

    // -----------------------------------------------------------------------
    // New enrichment: Clone independence
    // -----------------------------------------------------------------------

    #[test]
    fn exemption_clone_independence() {
        let original = Exemption {
            exemption_id: "e1".to_string(),
            module_path: "original_module".to_string(),
            pattern_id: "p1".to_string(),
            reason: "original reason".to_string(),
            witness: "w1".to_string(),
            line: 5,
        };
        let mut cloned = original.clone();
        cloned.module_path = "mutated_module".to_string();
        assert_eq!(original.module_path, "original_module");
    }

    #[test]
    fn forbidden_pattern_clone_independence() {
        let original = ForbiddenPattern {
            pattern_id: "p1".to_string(),
            category: ForbiddenCallCategory::Network,
            pattern: "std::net::".to_string(),
            reason: "original".to_string(),
            suggested_alternative: "use cap".to_string(),
        };
        let mut cloned = original.clone();
        cloned.reason = "mutated".to_string();
        assert_eq!(original.reason, "original");
    }

    #[test]
    fn audit_finding_clone_independence() {
        let original = AuditFinding {
            module_path: "m".to_string(),
            forbidden_api: "api".to_string(),
            pattern_id: "p".to_string(),
            category: ForbiddenCallCategory::Process,
            file_path: "f.rs".to_string(),
            line: 1,
            source_line: "src".to_string(),
            suggested_alternative: "alt".to_string(),
            exempted: false,
        };
        let mut cloned = original.clone();
        cloned.exempted = true;
        assert!(!original.exempted);
    }

    #[test]
    fn audit_config_clone_independence() {
        let original = AuditConfig::standard();
        let mut cloned = original.clone();
        cloned.audit_module("extra::module");
        assert!(!original.audited_modules.contains("extra::module"));
    }

    #[test]
    fn audit_result_clone_independence() {
        let original = AuditResult {
            findings: vec![],
            violation_count: 0,
            exemption_count: 0,
            modules_audited: vec!["m".to_string()],
            passed: true,
        };
        let mut cloned = original.clone();
        cloned.passed = false;
        assert!(original.passed);
    }

    #[test]
    fn exemption_registry_clone_independence() {
        let mut original = ExemptionRegistry::new();
        original.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        let mut cloned = original.clone();
        cloned.add(Exemption {
            exemption_id: "e2".to_string(),
            module_path: "m2".to_string(),
            pattern_id: "p2".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        assert_eq!(original.len(), 1);
        assert_eq!(cloned.len(), 2);
    }

    // -----------------------------------------------------------------------
    // New enrichment: JSON field-name stability
    // -----------------------------------------------------------------------

    #[test]
    fn exemption_json_field_names() {
        let ex = Exemption {
            exemption_id: "eid".to_string(),
            module_path: "mp".to_string(),
            pattern_id: "pid".to_string(),
            reason: "r".to_string(),
            witness: "w".to_string(),
            line: 7,
        };
        let json = serde_json::to_string(&ex).unwrap();
        assert!(json.contains("\"exemption_id\""));
        assert!(json.contains("\"module_path\""));
        assert!(json.contains("\"pattern_id\""));
        assert!(json.contains("\"reason\""));
        assert!(json.contains("\"witness\""));
        assert!(json.contains("\"line\""));
    }

    #[test]
    fn audit_finding_json_field_names() {
        let f = AuditFinding {
            module_path: "m".to_string(),
            forbidden_api: "api".to_string(),
            pattern_id: "p".to_string(),
            category: ForbiddenCallCategory::FileSystem,
            file_path: "f.rs".to_string(),
            line: 1,
            source_line: "src".to_string(),
            suggested_alternative: "alt".to_string(),
            exempted: false,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"module_path\""));
        assert!(json.contains("\"forbidden_api\""));
        assert!(json.contains("\"pattern_id\""));
        assert!(json.contains("\"category\""));
        assert!(json.contains("\"file_path\""));
        assert!(json.contains("\"line\""));
        assert!(json.contains("\"source_line\""));
        assert!(json.contains("\"suggested_alternative\""));
        assert!(json.contains("\"exempted\""));
    }

    #[test]
    fn forbidden_pattern_json_field_names() {
        let p = ForbiddenPattern {
            pattern_id: "pid".to_string(),
            category: ForbiddenCallCategory::Network,
            pattern: "pat".to_string(),
            reason: "r".to_string(),
            suggested_alternative: "alt".to_string(),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"pattern_id\""));
        assert!(json.contains("\"category\""));
        assert!(json.contains("\"pattern\""));
        assert!(json.contains("\"reason\""));
        assert!(json.contains("\"suggested_alternative\""));
    }

    #[test]
    fn audit_result_json_field_names() {
        let r = AuditResult {
            findings: vec![],
            violation_count: 3,
            exemption_count: 1,
            modules_audited: vec![],
            passed: false,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"findings\""));
        assert!(json.contains("\"violation_count\""));
        assert!(json.contains("\"exemption_count\""));
        assert!(json.contains("\"modules_audited\""));
        assert!(json.contains("\"passed\""));
    }

    // -----------------------------------------------------------------------
    // New enrichment: Display format checks
    // -----------------------------------------------------------------------

    #[test]
    fn category_display_filesystem_exact() {
        assert_eq!(ForbiddenCallCategory::FileSystem.to_string(), "filesystem");
    }

    #[test]
    fn category_display_network_exact() {
        assert_eq!(ForbiddenCallCategory::Network.to_string(), "network");
    }

    #[test]
    fn category_display_process_exact() {
        assert_eq!(ForbiddenCallCategory::Process.to_string(), "process");
    }

    #[test]
    fn category_display_global_mutable_state_exact() {
        assert_eq!(
            ForbiddenCallCategory::GlobalMutableState.to_string(),
            "global_mutable_state"
        );
    }

    // -----------------------------------------------------------------------
    // New enrichment: Hash consistency
    // -----------------------------------------------------------------------

    #[test]
    fn category_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let v = ForbiddenCallCategory::Network;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        v.hash(&mut h1);
        v.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn category_hash_all_variants_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        for v in [
            ForbiddenCallCategory::FileSystem,
            ForbiddenCallCategory::Network,
            ForbiddenCallCategory::Process,
            ForbiddenCallCategory::GlobalMutableState,
            ForbiddenCallCategory::Environment,
            ForbiddenCallCategory::RawPointerExternalState,
            ForbiddenCallCategory::DirectTime,
        ] {
            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();
            v.hash(&mut h1);
            v.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish(), "hash not consistent for {v:?}");
        }
    }

    // -----------------------------------------------------------------------
    // New enrichment: Boundary / edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn exemption_line_zero_matches_any_line() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        // line=0 means module-wide, so any line should match
        assert!(reg.is_exempted("m", "p", 0));
        assert!(reg.is_exempted("m", "p", 1));
        assert!(reg.is_exempted("m", "p", usize::MAX));
    }

    #[test]
    fn audit_source_whitespace_only_source() {
        let auditor = standard_auditor();
        let findings = auditor.audit_source("m", "f.rs", "   \n\t\n  ");
        assert!(findings.is_empty());
    }

    #[test]
    fn audit_source_very_long_module_path() {
        let auditor = standard_auditor();
        let long_path = "a::".repeat(100) + "b";
        let source = "fn pure() {}";
        let findings = auditor.audit_source(&long_path, "f.rs", source);
        assert!(findings.is_empty());
    }

    #[test]
    fn audit_finding_exempted_true_serde_roundtrip() {
        let f = AuditFinding {
            module_path: "m".to_string(),
            forbidden_api: "api".to_string(),
            pattern_id: "p".to_string(),
            category: ForbiddenCallCategory::DirectTime,
            file_path: "f.rs".to_string(),
            line: 99,
            source_line: "src".to_string(),
            suggested_alternative: "alt".to_string(),
            exempted: true,
        };
        let json = serde_json::to_string(&f).unwrap();
        let restored: AuditFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(f, restored);
        assert!(restored.exempted);
    }

    #[test]
    fn exemption_with_line_usize_max() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: usize::MAX,
        });
        assert!(reg.is_exempted("m", "p", usize::MAX));
        assert!(!reg.is_exempted("m", "p", 0));
        assert!(!reg.is_exempted("m", "p", 1));
    }

    #[test]
    fn exemption_registry_empty_string_fields() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: String::new(),
            module_path: String::new(),
            pattern_id: String::new(),
            reason: String::new(),
            witness: String::new(),
            line: 0,
        });
        assert_eq!(reg.len(), 1);
        assert!(reg.is_exempted("", "", 1));
        assert!(!reg.is_exempted("x", "", 1));
    }

    // -----------------------------------------------------------------------
    // New enrichment: Serde roundtrips — complex populated structs
    // -----------------------------------------------------------------------

    #[test]
    fn audit_config_with_custom_patterns_serde_roundtrip() {
        let mut config = AuditConfig::standard();
        config.add_pattern(ForbiddenPattern {
            pattern_id: "custom_p".to_string(),
            category: ForbiddenCallCategory::RawPointerExternalState,
            pattern: "raw_ptr_call()".to_string(),
            reason: "unsafe raw pointer".to_string(),
            suggested_alternative: "use safe abstraction".to_string(),
        });
        config.audit_module("engine::raw");
        config.audit_module("engine::io");
        let json = serde_json::to_string(&config).unwrap();
        let restored: AuditConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, restored);
        assert_eq!(restored.patterns.len(), 13);
        assert!(restored.audited_modules.contains("engine::raw"));
    }

    #[test]
    fn exemption_registry_multi_entry_serde_roundtrip() {
        let mut reg = ExemptionRegistry::new();
        for i in 0..5u64 {
            reg.add(Exemption {
                exemption_id: format!("e{i}"),
                module_path: format!("m{i}"),
                pattern_id: format!("p{i}"),
                reason: format!("reason {i}"),
                witness: format!("w{i}"),
                line: i as usize,
            });
        }
        let json = serde_json::to_string(&reg).unwrap();
        let restored: ExemptionRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, restored);
        assert_eq!(restored.len(), 5);
    }

    #[test]
    fn audit_result_populated_serde_roundtrip() {
        let findings: Vec<AuditFinding> = (0..3u64)
            .map(|i| AuditFinding {
                module_path: format!("m{i}"),
                forbidden_api: format!("api{i}"),
                pattern_id: format!("p{i}"),
                category: ForbiddenCallCategory::Network,
                file_path: format!("f{i}.rs"),
                line: i as usize + 1,
                source_line: format!("line{i}"),
                suggested_alternative: format!("alt{i}"),
                exempted: i.is_multiple_of(2),
            })
            .collect();
        let result = AuditResult {
            violation_count: findings.iter().filter(|f| !f.exempted).count(),
            exemption_count: findings.iter().filter(|f| f.exempted).count(),
            modules_audited: findings.iter().map(|f| f.module_path.clone()).collect(),
            passed: false,
            findings,
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: AuditResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, restored);
    }

    // -----------------------------------------------------------------------
    // New enrichment: Additional behavioral edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn audit_source_finding_suggested_alternative_nonempty() {
        let auditor = standard_auditor();
        let source = "let _ = std::net::TcpStream::connect(\"x\");";
        let findings = auditor.audit_source("m", "f.rs", source);
        for f in &findings {
            assert!(!f.suggested_alternative.is_empty());
        }
    }

    #[test]
    fn audit_all_same_module_different_files() {
        let auditor = standard_auditor();
        let mut sources = BTreeMap::new();
        sources.insert(
            ("shared::m".to_string(), "a.rs".to_string()),
            "let _ = TcpStream::connect(\"x\");".to_string(),
        );
        sources.insert(
            ("shared::m".to_string(), "b.rs".to_string()),
            "let _ = Command::new(\"ls\");".to_string(),
        );
        let result = auditor.audit_all(&sources);
        // Same module reported once in modules_audited
        assert_eq!(result.modules_audited.len(), 1);
        assert_eq!(result.modules_audited[0], "shared::m");
        assert!(result.violation_count >= 2);
    }

    #[test]
    fn category_ordering_all_variants() {
        assert!(ForbiddenCallCategory::FileSystem < ForbiddenCallCategory::GlobalMutableState);
        assert!(
            ForbiddenCallCategory::Environment < ForbiddenCallCategory::RawPointerExternalState
        );
        assert!(ForbiddenCallCategory::RawPointerExternalState < ForbiddenCallCategory::DirectTime);
    }

    #[test]
    fn add_pattern_increases_pattern_count() {
        let mut config = AuditConfig::standard();
        let before = config.patterns.len();
        config.add_pattern(ForbiddenPattern {
            pattern_id: "extra".to_string(),
            category: ForbiddenCallCategory::RawPointerExternalState,
            pattern: "unsafe_fn()".to_string(),
            reason: "bad".to_string(),
            suggested_alternative: "good".to_string(),
        });
        assert_eq!(config.patterns.len(), before + 1);
    }

    #[test]
    fn audit_source_line_number_is_one_indexed() {
        let auditor = standard_auditor();
        // Pattern on the very first line
        let source = "let _ = std::fs::read(\"x\");";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.iter().any(|f| f.line == 1));
    }

    #[test]
    fn audit_source_skips_doc_comment_lines() {
        let auditor = standard_auditor();
        // Lines starting with // (after trim) are skipped
        let source = "    // let _ = std::fs::read(\"x\");";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.is_empty());
    }

    #[test]
    fn exemption_for_wrong_pattern_id_does_not_match() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "std_fs".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        assert!(!reg.is_exempted("m", "std_net", 1));
        assert!(!reg.is_exempted("m", "fs_read", 1));
        assert!(reg.is_exempted("m", "std_fs", 1));
    }

    #[test]
    fn audit_finding_equality_and_inequality() {
        let f1 = AuditFinding {
            module_path: "m".to_string(),
            forbidden_api: "api".to_string(),
            pattern_id: "p".to_string(),
            category: ForbiddenCallCategory::Network,
            file_path: "f.rs".to_string(),
            line: 1,
            source_line: "src".to_string(),
            suggested_alternative: "alt".to_string(),
            exempted: false,
        };
        let f2 = f1.clone();
        let mut f3 = f1.clone();
        f3.line = 2;
        assert_eq!(f1, f2);
        assert_ne!(f1, f3);
    }

    #[test]
    fn forbidden_pattern_equality() {
        let p1 = ForbiddenPattern {
            pattern_id: "p".to_string(),
            category: ForbiddenCallCategory::DirectTime,
            pattern: "SystemTime::now".to_string(),
            reason: "bad".to_string(),
            suggested_alternative: "good".to_string(),
        };
        let p2 = p1.clone();
        assert_eq!(p1, p2);
    }

    #[test]
    fn exemption_equality() {
        let e1 = Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 5,
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }
}
