//! Compile-time lint / CI guard rejecting ambient authority in extension-host
//! control paths.
//!
//! This is a CI defense and review-time regression guard. It is intentionally
//! not a runtime sandbox, capability boundary, or replacement for extension-host
//! policy enforcement.
//!
//! Extends the base [`ambient_authority::SourceAuditor`] with extension-host-
//! specific checks:
//!
//! 1. **Missing Cx parameter** — effectful functions in extension-host modules
//!    that do not accept `ContextAdapter` / `&Cx` as a parameter.
//! 2. **Direct upstream imports** — `use franken_kernel`, `use franken_decision`,
//!    `use franken_evidence` bypassing the adapter layer (bd-23om).
//! 3. **Canonical type shadowing** — local type definitions shadowing canonical
//!    types (`TraceId`, `DecisionId`, `PolicyId`, `SchemaVersion`, `Budget`, `Cx`).
//! 4. **Unmediated I/O** — the full `ambient_authority::AuditConfig::standard()`
//!    pattern set (std::fs, std::net, std::process, static mut, …).
//!
//! The guard produces structured [`ExtensionHostAuditResult`] with per-finding
//! remediation instructions and supports an exemption mechanism via
//! [`ExtensionHostExemption`] entries.
//!
//! Plan references: Section 10.13 item 15, bd-11z7.
//! Dependencies: bd-2ygl (Cx threading), bd-1za (ambient authority audit),
//!               bd-23om (adapter layer).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ItemExternCrate, ItemUse, Path, UseTree};

use crate::ambient_authority::{AuditConfig, AuditFinding, ExemptionRegistry, SourceAuditor};

// ---------------------------------------------------------------------------
// ViolationKind — extension-host-specific violation types
// ---------------------------------------------------------------------------

/// Classification of an extension-host ambient-authority violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ViolationKind {
    /// Forbidden I/O or global-state pattern (from `ambient_authority` base).
    ForbiddenPattern,
    /// Effectful function missing `ContextAdapter` / `Cx` parameter.
    MissingCxParameter,
    /// Direct upstream crate import bypassing the adapter layer.
    DirectUpstreamImport,
    /// Local type definition shadowing a canonical type.
    CanonicalTypeShadow,
}

impl fmt::Display for ViolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForbiddenPattern => write!(f, "forbidden_pattern"),
            Self::MissingCxParameter => write!(f, "missing_cx_parameter"),
            Self::DirectUpstreamImport => write!(f, "direct_upstream_import"),
            Self::CanonicalTypeShadow => write!(f, "canonical_type_shadow"),
        }
    }
}

// ---------------------------------------------------------------------------
// ExtensionHostFinding — a single detected violation
// ---------------------------------------------------------------------------

/// A detected extension-host ambient-authority violation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtensionHostFinding {
    /// Violation classification.
    pub kind: ViolationKind,
    /// Module path where the violation was found.
    pub module_path: String,
    /// File path containing the violation.
    pub file_path: String,
    /// Line number of the violation (1-based).
    pub line: usize,
    /// The source line containing the violation.
    pub source_line: String,
    /// Human-readable description of the violation.
    pub description: String,
    /// Remediation instruction.
    pub remediation: String,
    /// Whether this finding is exempted.
    pub exempted: bool,
}

// ---------------------------------------------------------------------------
// ExtensionHostExemption — exemption entry
// ---------------------------------------------------------------------------

/// An exemption for a specific extension-host violation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtensionHostExemption {
    /// Exemption identifier.
    pub exemption_id: String,
    /// Module path where the exemption applies.
    pub module_path: String,
    /// Kind of violation being exempted.
    pub kind: ViolationKind,
    /// Matched pattern or token (e.g., "use franken_kernel", "fn do_io").
    pub matched_token: String,
    /// Human-readable reason for the exemption.
    pub reason: String,
    /// Line number (0 = module-wide).
    pub line: usize,
}

// ---------------------------------------------------------------------------
// ExtensionHostExemptionRegistry
// ---------------------------------------------------------------------------

/// Registry of extension-host-specific exemptions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionHostExemptionRegistry {
    entries: Vec<ExtensionHostExemption>,
}

impl ExtensionHostExemptionRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add an exemption.
    pub fn add(&mut self, entry: ExtensionHostExemption) {
        self.entries.push(entry);
    }

    /// Check if a violation is exempted.
    pub fn is_exempted(
        &self,
        module_path: &str,
        kind: ViolationKind,
        matched_token: &str,
        line: usize,
    ) -> bool {
        self.entries.iter().any(|e| {
            e.module_path == module_path
                && e.kind == kind
                && e.matched_token == matched_token
                && (e.line == 0 || e.line == line)
        })
    }

    /// All exemptions.
    pub fn entries(&self) -> &[ExtensionHostExemption] {
        &self.entries
    }

    /// Number of exemptions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// GuardConfig — configuration for the extension-host guard
// ---------------------------------------------------------------------------

/// Canonical types that must not be redefined outside the adapter layer.
const CANONICAL_TYPES: &[&str] = &[
    "TraceId",
    "DecisionId",
    "PolicyId",
    "SchemaVersion",
    "Budget",
    "Cx",
];

/// Forbidden upstream import prefixes (bypass adapter layer).
const FORBIDDEN_UPSTREAM_IMPORTS: &[(&str, &str)] = &[
    (
        "use franken_kernel",
        "Import from crate::control_plane instead of franken_kernel directly",
    ),
    (
        "use franken_decision",
        "Import from crate::control_plane instead of franken_decision directly",
    ),
    (
        "use franken_evidence",
        "Import from crate::control_plane instead of franken_evidence directly",
    ),
    (
        "extern crate franken_kernel",
        "Use crate::control_plane adapter layer instead",
    ),
    (
        "extern crate franken_decision",
        "Use crate::control_plane adapter layer instead",
    ),
    (
        "extern crate franken_evidence",
        "Use crate::control_plane adapter layer instead",
    ),
];

/// Effectful keyword tokens that signal a function should require Cx.
const EFFECTFUL_INDICATORS: &[&str] = &[
    "dispatch_hostcall",
    "evaluate_policy",
    "transition_lifecycle",
    "emit_telemetry",
    "emit_metric",
    "emit_span",
    "emit_evidence",
    "send_decision",
    "consume_budget",
];

/// Configuration for the extension-host ambient-authority guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardConfig {
    /// Forbidden upstream import patterns.
    pub forbidden_imports: Vec<(String, String)>,
    /// Canonical type names that must not be locally redefined.
    pub canonical_types: BTreeSet<String>,
    /// Effectful tokens that indicate a function should accept Cx.
    pub effectful_indicators: Vec<String>,
    /// Modules in scope for Cx-parameter checking (by path prefix).
    pub cx_audited_module_prefixes: BTreeSet<String>,
    /// Whether to include the base `ambient_authority` forbidden patterns.
    pub include_base_patterns: bool,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            forbidden_imports: FORBIDDEN_UPSTREAM_IMPORTS
                .iter()
                .map(|(p, r)| ((*p).to_string(), (*r).to_string()))
                .collect(),
            canonical_types: CANONICAL_TYPES.iter().map(|s| (*s).to_string()).collect(),
            effectful_indicators: EFFECTFUL_INDICATORS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            cx_audited_module_prefixes: BTreeSet::new(),
            include_base_patterns: true,
        }
    }
}

impl GuardConfig {
    /// Add a module prefix for Cx-parameter auditing.
    pub fn add_cx_audited_prefix(&mut self, prefix: impl Into<String>) {
        self.cx_audited_module_prefixes.insert(prefix.into());
    }

    /// Add a custom effectful indicator.
    pub fn add_effectful_indicator(&mut self, indicator: impl Into<String>) {
        self.effectful_indicators.push(indicator.into());
    }

    /// Add a custom forbidden import.
    pub fn add_forbidden_import(
        &mut self,
        pattern: impl Into<String>,
        remediation: impl Into<String>,
    ) {
        self.forbidden_imports
            .push((pattern.into(), remediation.into()));
    }
}

// ---------------------------------------------------------------------------
// ExtensionHostAuditResult — aggregated result
// ---------------------------------------------------------------------------

/// Aggregated result of the extension-host ambient-authority audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionHostAuditResult {
    /// All findings (including exempted ones).
    pub findings: Vec<ExtensionHostFinding>,
    /// Number of unexempted violations.
    pub violation_count: usize,
    /// Number of exempted findings.
    pub exemption_count: usize,
    /// Modules audited.
    pub modules_audited: Vec<String>,
    /// Whether the audit passed (zero unexempted violations).
    pub passed: bool,
    /// Summary by violation kind.
    pub summary_by_kind: BTreeMap<String, usize>,
}

// ---------------------------------------------------------------------------
// ExtensionHostGuard — the guard engine
// ---------------------------------------------------------------------------

/// Compile-time lint guard for extension-host ambient-authority violations.
///
/// Combines the base `ambient_authority::SourceAuditor` for forbidden I/O
/// patterns with extension-host-specific checks for Cx threading, direct
/// upstream imports, and canonical type shadowing.
#[derive(Debug)]
pub struct ExtensionHostGuard {
    config: GuardConfig,
    base_auditor: SourceAuditor,
    exemptions: ExtensionHostExemptionRegistry,
}

impl ExtensionHostGuard {
    /// Create a new guard with the given configuration and exemptions.
    pub fn new(config: GuardConfig, exemptions: ExtensionHostExemptionRegistry) -> Self {
        let base_config = if config.include_base_patterns {
            AuditConfig::standard()
        } else {
            AuditConfig {
                patterns: Vec::new(),
                audited_modules: BTreeSet::new(),
            }
        };

        Self {
            config,
            base_auditor: SourceAuditor::new(base_config, ExemptionRegistry::new()),
            exemptions,
        }
    }

    /// Create a guard with default configuration and no exemptions.
    pub fn standard() -> Self {
        Self::new(
            GuardConfig::default(),
            ExtensionHostExemptionRegistry::new(),
        )
    }

    /// Audit a single source file.
    ///
    /// - `module_path`: logical module path (e.g., "extension_host::lifecycle").
    /// - `file_path`: filesystem path to the source file.
    /// - `source`: the source text to scan.
    pub fn audit_source(
        &self,
        module_path: &str,
        file_path: &str,
        source: &str,
    ) -> Vec<ExtensionHostFinding> {
        let mut findings = Vec::new();

        // Phase 1: base ambient-authority patterns (forbidden I/O, static mut, etc.)
        if self.config.include_base_patterns {
            let base_findings = self
                .base_auditor
                .audit_source(module_path, file_path, source);
            for bf in base_findings {
                findings.push(self.convert_base_finding(bf));
            }
        }

        // Phase 2: direct upstream imports
        self.check_direct_imports(module_path, file_path, source, &mut findings);

        // Phase 3: canonical type shadowing
        self.check_canonical_type_shadows(module_path, file_path, source, &mut findings);

        // Phase 4: missing Cx parameter on effectful functions
        self.check_missing_cx_parameter(module_path, file_path, source, &mut findings);

        // Apply exemptions
        for finding in &mut findings {
            if self.exemptions.is_exempted(
                module_path,
                finding.kind,
                &finding.description,
                finding.line,
            ) {
                finding.exempted = true;
            }
        }

        // Sort for deterministic output
        findings.sort();
        findings
    }

    /// Run a full audit across multiple source files.
    pub fn audit_all(
        &self,
        sources: &BTreeMap<(String, String), String>,
    ) -> ExtensionHostAuditResult {
        let mut all_findings = Vec::new();
        let mut modules_audited = BTreeSet::new();

        for ((module_path, file_path), source) in sources {
            modules_audited.insert(module_path.clone());
            let findings = self.audit_source(module_path, file_path, source);
            all_findings.extend(findings);
        }

        let violation_count = all_findings.iter().filter(|f| !f.exempted).count();
        let exemption_count = all_findings.iter().filter(|f| f.exempted).count();

        let mut summary_by_kind: BTreeMap<String, usize> = BTreeMap::new();
        for finding in &all_findings {
            if !finding.exempted {
                *summary_by_kind.entry(finding.kind.to_string()).or_insert(0) += 1;
            }
        }

        ExtensionHostAuditResult {
            findings: all_findings,
            violation_count,
            exemption_count,
            modules_audited: modules_audited.into_iter().collect(),
            passed: violation_count == 0,
            summary_by_kind,
        }
    }

    /// Guard configuration.
    pub fn config(&self) -> &GuardConfig {
        &self.config
    }

    /// Exemption registry.
    pub fn exemptions(&self) -> &ExtensionHostExemptionRegistry {
        &self.exemptions
    }

    // -- Internal helpers --

    fn convert_base_finding(&self, bf: AuditFinding) -> ExtensionHostFinding {
        ExtensionHostFinding {
            kind: ViolationKind::ForbiddenPattern,
            module_path: bf.module_path,
            file_path: bf.file_path,
            line: bf.line,
            source_line: bf.source_line,
            description: format!(
                "Forbidden pattern `{}` ({})",
                bf.forbidden_api, bf.pattern_id
            ),
            remediation: bf.suggested_alternative,
            exempted: bf.exempted,
        }
    }

    fn check_direct_imports(
        &self,
        module_path: &str,
        file_path: &str,
        source: &str,
        findings: &mut Vec<ExtensionHostFinding>,
    ) {
        let forbidden_roots = forbidden_crate_roots(&self.config.forbidden_imports);

        match syn::parse_file(source) {
            Ok(file) => {
                let mut visitor = DirectImportVisitor::new(
                    module_path,
                    file_path,
                    source,
                    &forbidden_roots,
                    findings,
                );
                visitor.collect_imports(&file);
                visitor.collect_paths(&file);
            }
            Err(_) => {
                check_direct_imports_without_syn(
                    module_path,
                    file_path,
                    source,
                    &forbidden_roots,
                    findings,
                );
            }
        }
    }

    fn check_canonical_type_shadows(
        &self,
        module_path: &str,
        file_path: &str,
        source: &str,
        findings: &mut Vec<ExtensionHostFinding>,
    ) {
        for (line_num_0, line) in source.lines().enumerate() {
            let line_num = line_num_0 + 1;
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") {
                continue;
            }

            for canonical_type in &self.config.canonical_types {
                // Detect: struct <Type>, enum <Type>, type <Type>
                let shadow_patterns = [
                    format!("struct {canonical_type}"),
                    format!("enum {canonical_type}"),
                    format!("type {canonical_type}"),
                ];

                for shadow_pat in &shadow_patterns {
                    if trimmed.contains(shadow_pat.as_str()) {
                        findings.push(ExtensionHostFinding {
                            kind: ViolationKind::CanonicalTypeShadow,
                            module_path: module_path.to_string(),
                            file_path: file_path.to_string(),
                            line: line_num,
                            source_line: trimmed.to_string(),
                            description: format!(
                                "Local definition shadows canonical type `{canonical_type}`"
                            ),
                            remediation: format!(
                                "Import `{canonical_type}` from `crate::control_plane` instead of redefining it"
                            ),
                            exempted: false,
                        });
                    }
                }
            }
        }
    }

    fn check_missing_cx_parameter(
        &self,
        module_path: &str,
        file_path: &str,
        source: &str,
        findings: &mut Vec<ExtensionHostFinding>,
    ) {
        // Only check modules in scope for Cx auditing
        let in_scope = self.config.cx_audited_module_prefixes.is_empty()
            || self
                .config
                .cx_audited_module_prefixes
                .iter()
                .any(|prefix| module_path.starts_with(prefix.as_str()));

        if !in_scope {
            return;
        }

        // Scan for function definitions that contain effectful indicators
        // but do not accept ContextAdapter or Cx as a parameter.
        let lines: Vec<&str> = source.lines().collect();
        let mut idx = 0;
        while idx < lines.len() {
            let trimmed = lines[idx].trim();

            // Skip comments
            if trimmed.starts_with("//") {
                idx += 1;
                continue;
            }

            // Detect `fn <name>(` or `pub fn <name>(`
            if let Some(fn_sig) = extract_fn_signature(trimmed, &lines, idx) {
                // Check if the function body contains an effectful indicator
                let body_start = idx;
                let body_end = find_fn_body_end(&lines, body_start);
                let body_slice = &lines[body_start..body_end.min(lines.len())];
                let body_text: String = body_slice.join("\n");

                let has_effectful_call = self
                    .config
                    .effectful_indicators
                    .iter()
                    .any(|indicator| body_text.contains(indicator.as_str()));

                if has_effectful_call {
                    let has_cx = fn_sig.contains("ContextAdapter")
                        || fn_sig.contains("&Cx")
                        || fn_sig.contains("&mut Cx")
                        || fn_sig.contains(": Cx")
                        || fn_sig.contains("cx:");

                    if !has_cx {
                        let fn_name = extract_fn_name(trimmed).unwrap_or("(unknown)");
                        findings.push(ExtensionHostFinding {
                            kind: ViolationKind::MissingCxParameter,
                            module_path: module_path.to_string(),
                            file_path: file_path.to_string(),
                            line: idx + 1,
                            source_line: trimmed.to_string(),
                            description: format!(
                                "Effectful function `{fn_name}` does not accept `ContextAdapter` or `Cx`"
                            ),
                            remediation: format!(
                                "Add `cx: &dyn ContextAdapter` or `cx: &mut impl ContextAdapter` as the first parameter of `{fn_name}`"
                            ),
                            exempted: false,
                        });
                    }
                }
            }

            idx += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions for source parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectImportPass {
    Imports,
    Paths,
}

struct DirectImportVisitor<'a> {
    module_path: &'a str,
    file_path: &'a str,
    source: &'a str,
    forbidden_roots: &'a BTreeMap<String, String>,
    findings: &'a mut Vec<ExtensionHostFinding>,
    aliases: BTreeMap<String, String>,
    seen: BTreeSet<(usize, String)>,
    pass: DirectImportPass,
}

impl<'a> DirectImportVisitor<'a> {
    fn new(
        module_path: &'a str,
        file_path: &'a str,
        source: &'a str,
        forbidden_roots: &'a BTreeMap<String, String>,
        findings: &'a mut Vec<ExtensionHostFinding>,
    ) -> Self {
        Self {
            module_path,
            file_path,
            source,
            forbidden_roots,
            findings,
            aliases: BTreeMap::new(),
            seen: BTreeSet::new(),
            pass: DirectImportPass::Imports,
        }
    }

    fn collect_imports(&mut self, file: &syn::File) {
        self.pass = DirectImportPass::Imports;
        self.visit_file(file);
    }

    fn collect_paths(&mut self, file: &syn::File) {
        self.pass = DirectImportPass::Paths;
        self.visit_file(file);
    }

    fn inspect_use_tree(&mut self, tree: &UseTree, inherited_root: Option<&str>, line: usize) {
        match tree {
            UseTree::Path(path) => {
                let path_ident = path.ident.to_string();
                let root = inherited_root.unwrap_or(path_ident.as_str());
                self.push_import_if_forbidden(root, "use", line);
                self.inspect_use_tree(&path.tree, Some(root), line);
            }
            UseTree::Name(name) => {
                let ident = name.ident.to_string();
                let root = inherited_root.unwrap_or(ident.as_str());
                self.push_import_if_forbidden(root, "use", line);
            }
            UseTree::Rename(rename) => {
                let ident = rename.ident.to_string();
                let root = inherited_root.unwrap_or(ident.as_str());
                if let Some(canonical) = self.canonical_for_root(root) {
                    self.aliases
                        .insert(rename.rename.to_string(), canonical.to_string());
                    self.push_import_if_forbidden(root, "use", line);
                }
            }
            UseTree::Glob(_) => {
                if let Some(root) = inherited_root {
                    self.push_import_if_forbidden(root, "use", line);
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.inspect_use_tree(item, inherited_root, line);
                }
            }
        }
    }

    fn push_import_if_forbidden(&mut self, root: &str, import_kind: &str, line: usize) {
        if let Some(canonical) = self.canonical_for_root(root) {
            let token = format!("{import_kind} {root}");
            let description = format!("Direct upstream import: `{token}`");
            let remediation = self
                .forbidden_roots
                .get(canonical)
                .cloned()
                .unwrap_or_else(|| "Use crate::control_plane adapter layer instead".to_string());
            self.push_finding(line, description, remediation);
        }
    }

    fn push_path_if_forbidden(&mut self, path: &Path) {
        let Some(first) = path.segments.first() else {
            return;
        };
        let root = first.ident.to_string();
        let Some(canonical) = self.canonical_for_root(&root) else {
            return;
        };

        let line = path.span().start().line;
        let description = if root == canonical {
            format!("Direct upstream path access: `{root}::...`")
        } else {
            format!("Direct upstream path access via alias `{root}` for `{canonical}`")
        };
        let remediation = self
            .forbidden_roots
            .get(canonical)
            .cloned()
            .unwrap_or_else(|| "Use crate::control_plane adapter layer instead".to_string());
        self.push_finding(line, description, remediation);
    }

    fn canonical_for_root<'b>(&'b self, root: &'b str) -> Option<&'b str> {
        if self.forbidden_roots.contains_key(root) {
            Some(root)
        } else {
            self.aliases.get(root).map(String::as_str)
        }
    }

    fn push_finding(&mut self, line: usize, description: String, remediation: String) {
        if !self.seen.insert((line, description.clone())) {
            return;
        }

        self.findings.push(ExtensionHostFinding {
            kind: ViolationKind::DirectUpstreamImport,
            module_path: self.module_path.to_string(),
            file_path: self.file_path.to_string(),
            line,
            source_line: source_line(self.source, line),
            description,
            remediation,
            exempted: false,
        });
    }
}

impl<'ast> Visit<'ast> for DirectImportVisitor<'_> {
    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        if self.pass == DirectImportPass::Imports {
            self.inspect_use_tree(&item.tree, None, item.span().start().line);
            visit::visit_item_use(self, item);
        }
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        if self.pass == DirectImportPass::Imports {
            let root = item.ident.to_string();
            if let Some((_, alias)) = &item.rename
                && let Some(canonical) = self.canonical_for_root(&root)
            {
                self.aliases
                    .insert(alias.to_string(), canonical.to_string());
            }
            self.push_import_if_forbidden(&root, "extern crate", item.span().start().line);
        }
    }

    fn visit_path(&mut self, path: &'ast Path) {
        if self.pass == DirectImportPass::Paths {
            self.push_path_if_forbidden(path);
            visit::visit_path(self, path);
        }
    }
}

fn forbidden_crate_roots(patterns: &[(String, String)]) -> BTreeMap<String, String> {
    let mut roots = BTreeMap::new();
    for (pattern, remediation) in patterns {
        if let Some(root) = import_pattern_root(pattern) {
            roots.entry(root).or_insert_with(|| remediation.clone());
        }
    }
    roots
}

fn import_pattern_root(pattern: &str) -> Option<String> {
    let trimmed = pattern.trim().trim_end_matches(';').trim();
    let rest = trimmed
        .strip_prefix("use ")
        .or_else(|| trimmed.strip_prefix("extern crate "))?;

    first_ident(rest).map(str::to_string)
}

fn first_ident(text: &str) -> Option<&str> {
    let trimmed = text.trim_start();
    let mut chars = trimmed.char_indices();
    let (_, first) = chars.next()?;
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return None;
    }

    let end = chars
        .find_map(|(idx, ch)| {
            if ch == '_' || ch.is_ascii_alphanumeric() {
                None
            } else {
                Some(idx)
            }
        })
        .unwrap_or(trimmed.len());
    Some(&trimmed[..end])
}

fn check_direct_imports_without_syn(
    module_path: &str,
    file_path: &str,
    source: &str,
    forbidden_roots: &BTreeMap<String, String>,
    findings: &mut Vec<ExtensionHostFinding>,
) {
    let fallback_context = DirectImportFallbackContext {
        module_path,
        file_path,
        source,
    };
    let mut aliases: BTreeMap<String, String> = BTreeMap::new();
    let mut seen: BTreeSet<(usize, String)> = BTreeSet::new();

    for (line_num_0, line) in source.lines().enumerate() {
        let line_num = line_num_0 + 1;
        let sanitized = sanitize_rust_line_for_guard(line);
        let trimmed = sanitized.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        let import_root = use_statement_root(trimmed);
        let extern_root = trimmed
            .strip_prefix("extern crate ")
            .and_then(first_ident)
            .map(str::to_string);

        if let Some(root) = import_root.as_deref().or(extern_root.as_deref())
            && let Some(remediation) = forbidden_roots.get(root)
        {
            let token = if extern_root.is_some() {
                format!("extern crate {root}")
            } else {
                format!("use {root}")
            };
            push_direct_import_fallback(
                &fallback_context,
                findings,
                &mut seen,
                line_num,
                format!("Direct upstream import: `{token}`"),
                remediation.clone(),
            );
        }

        if let (Some(root), Some(alias)) = (
            import_root.as_ref().or(extern_root.as_ref()),
            import_alias(trimmed),
        ) && forbidden_roots.contains_key(root)
        {
            aliases.insert(alias.to_string(), root.clone());
        }
    }

    for (line_num_0, line) in source.lines().enumerate() {
        let line_num = line_num_0 + 1;
        let sanitized = sanitize_rust_line_for_guard(line);
        let trimmed = sanitized.trim();
        if use_statement_root(trimmed).is_some() || trimmed.starts_with("extern crate ") {
            continue;
        }

        for (root, remediation) in forbidden_roots {
            let needle = format!("{root}::");
            if trimmed.contains(&needle) {
                push_direct_import_fallback(
                    &fallback_context,
                    findings,
                    &mut seen,
                    line_num,
                    format!("Direct upstream path access: `{root}::...`"),
                    remediation.clone(),
                );
            }
        }

        for (alias, canonical) in &aliases {
            let needle = format!("{alias}::");
            if trimmed.contains(&needle) {
                let remediation = forbidden_roots.get(canonical).cloned().unwrap_or_else(|| {
                    "Use crate::control_plane adapter layer instead".to_string()
                });
                push_direct_import_fallback(
                    &fallback_context,
                    findings,
                    &mut seen,
                    line_num,
                    format!("Direct upstream path access via alias `{alias}` for `{canonical}`"),
                    remediation,
                );
            }
        }
    }
}

fn use_statement_root(trimmed: &str) -> Option<String> {
    let use_pos = trimmed
        .split_whitespace()
        .position(|token| token == "use")?;
    let after_use = trimmed
        .split_whitespace()
        .skip(use_pos + 1)
        .collect::<Vec<_>>()
        .join(" ");
    first_ident(&after_use).map(str::to_string)
}

fn import_alias(trimmed: &str) -> Option<&str> {
    let as_pos = trimmed.find(" as ")?;
    first_ident(&trimmed[(as_pos + 4)..])
}

fn sanitize_rust_line_for_guard(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_string = false;
    let mut in_char = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if !in_string && !in_char && ch == '/' && chars.peek() == Some(&'/') {
            break;
        }

        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            out.push(' ');
        } else if in_char {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '\'' {
                in_char = false;
            }
            out.push(' ');
        } else if ch == '"' {
            in_string = true;
            out.push(' ');
        } else if ch == '\'' {
            in_char = true;
            out.push(' ');
        } else {
            out.push(ch);
        }
    }

    out
}

struct DirectImportFallbackContext<'a> {
    module_path: &'a str,
    file_path: &'a str,
    source: &'a str,
}

fn push_direct_import_fallback(
    context: &DirectImportFallbackContext<'_>,
    findings: &mut Vec<ExtensionHostFinding>,
    seen: &mut BTreeSet<(usize, String)>,
    line: usize,
    description: String,
    remediation: String,
) {
    if !seen.insert((line, description.clone())) {
        return;
    }

    findings.push(ExtensionHostFinding {
        kind: ViolationKind::DirectUpstreamImport,
        module_path: context.module_path.to_string(),
        file_path: context.file_path.to_string(),
        line,
        source_line: source_line(context.source, line),
        description,
        remediation,
        exempted: false,
    });
}

fn source_line(source: &str, line: usize) -> String {
    source
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Extract the full function signature spanning potentially multiple lines.
fn extract_fn_signature(first_line: &str, lines: &[&str], start_idx: usize) -> Option<String> {
    // Check if this line contains "fn "
    if !first_line.contains("fn ") {
        return None;
    }

    // Don't match trait declarations (no body)
    if first_line.contains("fn ") && first_line.ends_with(';') {
        return None;
    }

    // Collect lines until we find the closing `)`
    let mut sig = String::new();
    for line in &lines[start_idx..] {
        sig.push_str(line);
        sig.push(' ');
        if line.contains(')') {
            break;
        }
    }

    Some(sig)
}

/// Extract function name from a line containing "fn ".
fn extract_fn_name(line: &str) -> Option<&str> {
    let fn_pos = line.find("fn ")?;
    let after_fn = &line[(fn_pos + 3)..];
    // Find end of function name (first non-alphanumeric/underscore)
    let name_end = after_fn
        .find(|c: char| !c.is_alphanumeric() && c != '_')
        .unwrap_or(after_fn.len());
    if name_end == 0 {
        return None;
    }
    Some(&after_fn[..name_end])
}

/// Find the approximate end of a function body (matching braces).
fn find_fn_body_end(lines: &[&str], start_idx: usize) -> usize {
    let mut depth: i32 = 0;
    let mut found_open = false;

    for (i, line) in lines.iter().enumerate().skip(start_idx) {
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                found_open = true;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        if found_open && depth <= 0 {
            return i + 1;
        }
        // Safety: don't scan more than 200 lines for a single function
        if i - start_idx > 200 {
            return i + 1;
        }
    }

    lines.len()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn standard_guard() -> ExtensionHostGuard {
        ExtensionHostGuard::standard()
    }

    // -----------------------------------------------------------------------
    // ViolationKind
    // -----------------------------------------------------------------------

    #[test]
    fn violation_kind_display() {
        assert_eq!(
            ViolationKind::ForbiddenPattern.to_string(),
            "forbidden_pattern"
        );
        assert_eq!(
            ViolationKind::MissingCxParameter.to_string(),
            "missing_cx_parameter"
        );
        assert_eq!(
            ViolationKind::DirectUpstreamImport.to_string(),
            "direct_upstream_import"
        );
        assert_eq!(
            ViolationKind::CanonicalTypeShadow.to_string(),
            "canonical_type_shadow"
        );
    }

    #[test]
    fn violation_kind_ordering() {
        assert!(ViolationKind::ForbiddenPattern < ViolationKind::MissingCxParameter);
        assert!(ViolationKind::MissingCxParameter < ViolationKind::DirectUpstreamImport);
        assert!(ViolationKind::DirectUpstreamImport < ViolationKind::CanonicalTypeShadow);
    }

    #[test]
    fn violation_kind_serde_roundtrip() {
        let kinds = vec![
            ViolationKind::ForbiddenPattern,
            ViolationKind::MissingCxParameter,
            ViolationKind::DirectUpstreamImport,
            ViolationKind::CanonicalTypeShadow,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let restored: ViolationKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Clean source passes
    // -----------------------------------------------------------------------

    #[test]
    fn clean_pure_computation_produces_no_findings() {
        let guard = standard_guard();
        let source = r#"
            fn compute(x: i64) -> i64 {
                x * 2 + 1
            }

            fn transform(data: &[u8]) -> Vec<u8> {
                data.iter().map(|b| b.wrapping_add(1)).collect()
            }
        "#;

        let findings = guard.audit_source("ext_host::compute", "src/compute.rs", source);
        assert!(findings.is_empty());
    }

    #[test]
    fn clean_cx_gated_function_passes() {
        let mut guard_config = GuardConfig::default();
        guard_config.add_cx_audited_prefix("ext_host");
        let guard = ExtensionHostGuard::new(guard_config, ExtensionHostExemptionRegistry::new());

        let source = r#"
            fn do_work(cx: &dyn ContextAdapter, data: &[u8]) {
                dispatch_hostcall(cx, "read_data");
            }
        "#;

        let findings = guard.audit_source("ext_host::worker", "src/worker.rs", source);
        // No missing-cx violation — function accepts ContextAdapter
        let cx_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::MissingCxParameter)
            .collect();
        assert!(cx_violations.is_empty());
    }

    // -----------------------------------------------------------------------
    // Forbidden I/O patterns (delegated to base auditor)
    // -----------------------------------------------------------------------

    #[test]
    fn detects_std_fs_in_extension_host() {
        let guard = standard_guard();
        let source = r#"
            let data = std::fs::read("secrets.txt");
        "#;

        let findings = guard.audit_source("ext_host::loader", "src/loader.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == ViolationKind::ForbiddenPattern)
        );
    }

    #[test]
    fn detects_tcp_stream_in_extension_host() {
        let guard = standard_guard();
        let source = r#"
            let stream = TcpStream::connect("evil.example.com:443");
        "#;

        let findings = guard.audit_source("ext_host::net", "src/net.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == ViolationKind::ForbiddenPattern)
        );
    }

    #[test]
    fn detects_command_new_in_extension_host() {
        let guard = standard_guard();
        let source = r#"
            let output = Command::new("rm").arg("-rf").output();
        "#;

        let findings = guard.audit_source("ext_host::exec", "src/exec.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == ViolationKind::ForbiddenPattern)
        );
    }

    #[test]
    fn detects_static_mut_in_extension_host() {
        let guard = standard_guard();
        let source = r#"
            static mut GLOBAL_COUNTER: u64 = 0;
        "#;

        let findings = guard.audit_source("ext_host::state", "src/state.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == ViolationKind::ForbiddenPattern)
        );
    }

    #[test]
    fn detects_system_time_in_extension_host() {
        let guard = standard_guard();
        let source = r#"
            let now = SystemTime::now();
        "#;

        let findings = guard.audit_source("ext_host::clock", "src/clock.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == ViolationKind::ForbiddenPattern)
        );
    }

    // -----------------------------------------------------------------------
    // Direct upstream imports
    // -----------------------------------------------------------------------

    #[test]
    fn detects_direct_franken_kernel_import() {
        let guard = standard_guard();
        let source = r#"
            use franken_kernel::Cx;
        "#;

        let findings = guard.audit_source("ext_host::bridge", "src/bridge.rs", source);
        let import_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
            .collect();
        assert!(!import_violations.is_empty());
        assert!(
            import_violations[0]
                .remediation
                .contains("crate::control_plane")
        );
    }

    #[test]
    fn detects_direct_franken_decision_import() {
        let guard = standard_guard();
        let source = r#"
            use franken_decision::DecisionContract;
        "#;

        let findings = guard.audit_source("ext_host::policy", "src/policy.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
        );
    }

    #[test]
    fn detects_direct_franken_evidence_import() {
        let guard = standard_guard();
        let source = r#"
            use franken_evidence::EvidenceLedger;
        "#;

        let findings = guard.audit_source("ext_host::evidence", "src/evidence.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
        );
    }

    #[test]
    fn detects_extern_crate_franken_kernel() {
        let guard = standard_guard();
        let source = r#"
            extern crate franken_kernel;
        "#;

        let findings = guard.audit_source("ext_host::old", "src/old.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
        );
    }

    #[test]
    fn detects_fully_qualified_upstream_path_access() {
        let guard = standard_guard();
        let source = r#"
            fn bypass_adapter() {
                let _ = franken_kernel::Cx::default();
            }
        "#;

        let findings = guard.audit_source("ext_host::bridge", "src/bridge.rs", source);
        assert!(findings.iter().any(|f| {
            f.kind == ViolationKind::DirectUpstreamImport
                && f.description
                    .contains("Direct upstream path access: `franken_kernel::...`")
        }));
    }

    #[test]
    fn detects_upstream_alias_path_after_extern_crate_alias() {
        let guard = standard_guard();
        let source = r#"
            extern crate franken_kernel as kernel_upstream;

            fn bypass_adapter() {
                let _ = kernel_upstream::Cx::default();
            }
        "#;

        let findings = guard.audit_source("ext_host::bridge", "src/bridge.rs", source);
        assert!(findings.iter().any(|f| {
            f.kind == ViolationKind::DirectUpstreamImport
                && f.description.contains(
                    "Direct upstream path access via alias `kernel_upstream` for `franken_kernel`",
                )
        }));
    }

    #[test]
    fn detects_pub_use_upstream_reexport() {
        let guard = standard_guard();
        let source = r#"
            pub use franken_decision::{DecisionContract as Contract};
        "#;

        let findings = guard.audit_source("ext_host::policy", "src/policy.rs", source);
        assert!(findings.iter().any(|f| {
            f.kind == ViolationKind::DirectUpstreamImport
                && f.description == "Direct upstream import: `use franken_decision`"
        }));
    }

    #[test]
    fn does_not_flag_upstream_names_in_strings_or_macro_arguments() {
        let guard = standard_guard();
        let source = r#"
            fn diagnostic_text() {
                let _message = "use franken_kernel::Cx";
                tracing::debug!("franken_evidence::EvidenceLedger");
            }
        "#;

        let findings = guard.audit_source("ext_host::diag", "src/diag.rs", source);
        let import_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
            .collect();
        assert!(import_violations.is_empty());
    }

    #[test]
    fn does_not_flag_control_plane_import() {
        let guard = standard_guard();
        let source = r#"
            use crate::control_plane::ContextAdapter;
            use crate::control_plane::{TraceId, DecisionId, PolicyId};
        "#;

        let findings = guard.audit_source("ext_host::adapter", "src/adapter.rs", source);
        let import_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
            .collect();
        assert!(import_violations.is_empty());
    }

    #[test]
    fn does_not_flag_commented_import() {
        let guard = standard_guard();
        let source = r#"
            // use franken_kernel::Cx;
            /// use franken_decision::DecisionContract;
        "#;

        let findings = guard.audit_source("ext_host::docs", "src/docs.rs", source);
        let import_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
            .collect();
        assert!(import_violations.is_empty());
    }

    // -----------------------------------------------------------------------
    // Canonical type shadowing
    // -----------------------------------------------------------------------

    #[test]
    fn detects_struct_trace_id_shadow() {
        let guard = standard_guard();
        let source = r#"
            pub struct TraceId(u64);
        "#;

        let findings = guard.audit_source("ext_host::types", "src/types.rs", source);
        let shadow_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
            .collect();
        assert!(!shadow_violations.is_empty());
        assert!(shadow_violations[0].description.contains("TraceId"));
    }

    #[test]
    fn detects_enum_budget_shadow() {
        let guard = standard_guard();
        let source = r#"
            pub enum Budget { Limited, Unlimited }
        "#;

        let findings = guard.audit_source("ext_host::budget", "src/budget.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == ViolationKind::CanonicalTypeShadow
                    && f.description.contains("Budget"))
        );
    }

    #[test]
    fn detects_type_alias_shadow() {
        let guard = standard_guard();
        let source = r#"
            type DecisionId = u64;
        "#;

        let findings = guard.audit_source("ext_host::ids", "src/ids.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == ViolationKind::CanonicalTypeShadow
                    && f.description.contains("DecisionId"))
        );
    }

    #[test]
    fn detects_cx_shadow() {
        let guard = standard_guard();
        let source = r#"
            struct Cx { inner: u64 }
        "#;

        let findings = guard.audit_source("ext_host::context", "src/context.rs", source);
        assert!(findings.iter().any(
            |f| f.kind == ViolationKind::CanonicalTypeShadow && f.description.contains("`Cx`")
        ));
    }

    #[test]
    fn does_not_flag_commented_type_shadow() {
        let guard = standard_guard();
        let source = r#"
            // struct TraceId(u64);
            /// type Budget = f64;
        "#;

        let findings = guard.audit_source("ext_host::docs", "src/docs.rs", source);
        let shadow_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
            .collect();
        assert!(shadow_violations.is_empty());
    }

    #[test]
    fn does_not_flag_non_canonical_type() {
        let guard = standard_guard();
        let source = r#"
            pub struct MyCustomType(u64);
            pub enum WorkerState { Idle, Running }
        "#;

        let findings = guard.audit_source("ext_host::types", "src/types.rs", source);
        let shadow_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::CanonicalTypeShadow)
            .collect();
        assert!(shadow_violations.is_empty());
    }

    // -----------------------------------------------------------------------
    // Missing Cx parameter on effectful functions
    // -----------------------------------------------------------------------

    #[test]
    fn detects_effectful_function_without_cx() {
        let mut config = GuardConfig::default();
        config.add_cx_audited_prefix("ext_host");
        let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());

        let source = r#"
fn send_data(payload: &[u8]) {
    dispatch_hostcall("write_data");
}
"#;

        let findings = guard.audit_source("ext_host::sender", "src/sender.rs", source);
        let cx_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::MissingCxParameter)
            .collect();
        assert!(!cx_violations.is_empty());
        assert!(cx_violations[0].description.contains("send_data"));
        assert!(cx_violations[0].remediation.contains("ContextAdapter"));
    }

    #[test]
    fn does_not_flag_non_effectful_function() {
        let mut config = GuardConfig::default();
        config.add_cx_audited_prefix("ext_host");
        let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());

        let source = r#"
fn pure_compute(x: i64, y: i64) -> i64 {
    x + y
}
"#;

        let findings = guard.audit_source("ext_host::math", "src/math.rs", source);
        let cx_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::MissingCxParameter)
            .collect();
        assert!(cx_violations.is_empty());
    }

    #[test]
    fn cx_parameter_accepted_via_context_adapter() {
        let mut config = GuardConfig::default();
        config.add_cx_audited_prefix("ext_host");
        let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());

        let source = r#"
fn do_work(cx: &dyn ContextAdapter, data: &[u8]) {
    dispatch_hostcall(cx, "process");
}
"#;

        let findings = guard.audit_source("ext_host::worker", "src/worker.rs", source);
        let cx_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::MissingCxParameter)
            .collect();
        assert!(cx_violations.is_empty());
    }

    #[test]
    fn cx_parameter_accepted_via_cx_ref() {
        let mut config = GuardConfig::default();
        config.add_cx_audited_prefix("ext_host");
        let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());

        let source = r#"
fn do_work(cx: &Cx, data: &[u8]) {
    emit_telemetry(cx, "metric", 42);
}
"#;

        let findings = guard.audit_source("ext_host::worker", "src/worker.rs", source);
        let cx_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::MissingCxParameter)
            .collect();
        assert!(cx_violations.is_empty());
    }

    #[test]
    fn cx_parameter_accepted_via_cx_named_param() {
        let mut config = GuardConfig::default();
        config.add_cx_audited_prefix("ext_host");
        let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());

        let source = r#"
fn do_work(cx: &mut impl ContextAdapter) {
    consume_budget(cx, 10);
}
"#;

        let findings = guard.audit_source("ext_host::budget", "src/budget.rs", source);
        let cx_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::MissingCxParameter)
            .collect();
        assert!(cx_violations.is_empty());
    }

    #[test]
    fn only_audits_configured_module_prefixes() {
        let mut config = GuardConfig::default();
        config.add_cx_audited_prefix("ext_host");
        let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());

        // This module is NOT under "ext_host" prefix, so Cx check is skipped
        let source = r#"
fn unchecked_send(payload: &[u8]) {
    dispatch_hostcall("write_data");
}
"#;

        let findings = guard.audit_source("engine::sender", "src/sender.rs", source);
        let cx_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::MissingCxParameter)
            .collect();
        assert!(cx_violations.is_empty());
    }

    #[test]
    fn empty_cx_prefixes_audits_all_modules() {
        // No prefixes configured = all modules checked
        let config = GuardConfig::default();
        let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());

        let source = r#"
fn send_data(payload: &[u8]) {
    dispatch_hostcall("write_data");
}
"#;

        let findings = guard.audit_source("any_module::sender", "src/sender.rs", source);
        let cx_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::MissingCxParameter)
            .collect();
        assert!(!cx_violations.is_empty());
    }

    #[test]
    fn multiple_effectful_indicators_detected() {
        let config = GuardConfig::default();
        let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());

        let source = r#"
fn bad_function(data: &[u8]) {
    dispatch_hostcall("read");
    emit_telemetry("metric", 1);
    consume_budget(10);
}
"#;

        let findings = guard.audit_source("ext::bad", "src/bad.rs", source);
        let cx_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::MissingCxParameter)
            .collect();
        // One finding per function, not per indicator
        assert_eq!(cx_violations.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Exemptions
    // -----------------------------------------------------------------------

    #[test]
    fn exemption_suppresses_finding() {
        let mut exemptions = ExtensionHostExemptionRegistry::new();
        exemptions.add(ExtensionHostExemption {
            exemption_id: "ehx-001".to_string(),
            module_path: "ext_host::bootstrap".to_string(),
            kind: ViolationKind::DirectUpstreamImport,
            matched_token: "Direct upstream import: `use franken_kernel`".to_string(),
            reason: "Bootstrap needs direct kernel access for init".to_string(),
            line: 0,
        });

        let guard = ExtensionHostGuard::new(GuardConfig::default(), exemptions);
        let source = r#"
            use franken_kernel::Cx;
        "#;

        let findings = guard.audit_source("ext_host::bootstrap", "src/bootstrap.rs", source);
        let import_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
            .collect();
        assert!(!import_findings.is_empty());
        assert!(import_findings.iter().all(|f| f.exempted));
    }

    #[test]
    fn line_specific_exemption_only_applies_to_that_line() {
        let mut exemptions = ExtensionHostExemptionRegistry::new();
        exemptions.add(ExtensionHostExemption {
            exemption_id: "ehx-002".to_string(),
            module_path: "ext_host::mixed".to_string(),
            kind: ViolationKind::DirectUpstreamImport,
            matched_token: "Direct upstream import: `use franken_kernel`".to_string(),
            reason: "Line 2 only".to_string(),
            line: 2,
        });

        let guard = ExtensionHostGuard::new(GuardConfig::default(), exemptions);
        let source = "// header\nuse franken_kernel::Cx;\nuse franken_kernel::Budget;";

        let findings = guard.audit_source("ext_host::mixed", "src/mixed.rs", source);
        let import_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::DirectUpstreamImport)
            .collect();
        let exempted_count = import_findings.iter().filter(|f| f.exempted).count();
        let violation_count = import_findings.iter().filter(|f| !f.exempted).count();
        assert_eq!(exempted_count, 1);
        assert!(violation_count >= 1);
    }

    #[test]
    fn empty_exemption_registry() {
        let reg = ExtensionHostExemptionRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(!reg.is_exempted("m", ViolationKind::ForbiddenPattern, "x", 1));
    }

    // -----------------------------------------------------------------------
    // Audit all (multi-file)
    // -----------------------------------------------------------------------

    #[test]
    fn audit_all_aggregates_findings() {
        let guard = standard_guard();
        let mut sources = BTreeMap::new();
        sources.insert(
            ("ext_host::clean".to_string(), "src/clean.rs".to_string()),
            "fn ok() { 1 + 1; }".to_string(),
        );
        sources.insert(
            ("ext_host::dirty".to_string(), "src/dirty.rs".to_string()),
            "use franken_kernel::Cx;\nlet _ = std::fs::read(\"x\");".to_string(),
        );

        let result = guard.audit_all(&sources);
        assert!(!result.passed);
        assert!(result.violation_count >= 2);
        assert_eq!(result.modules_audited.len(), 2);
        assert!(!result.summary_by_kind.is_empty());
    }

    #[test]
    fn clean_audit_all_passes() {
        let guard = standard_guard();
        let mut sources = BTreeMap::new();
        sources.insert(
            ("ext_host::pure".to_string(), "src/pure.rs".to_string()),
            "fn add(a: i64, b: i64) -> i64 { a + b }".to_string(),
        );

        let result = guard.audit_all(&sources);
        assert!(result.passed);
        assert_eq!(result.violation_count, 0);
        assert_eq!(result.exemption_count, 0);
    }

    #[test]
    fn summary_by_kind_counts_correctly() {
        let guard = standard_guard();
        let mut sources = BTreeMap::new();
        sources.insert(
            ("ext_host::mix".to_string(), "src/mix.rs".to_string()),
            "use franken_kernel::Cx;\nlet _ = std::fs::read(\"x\");".to_string(),
        );

        let result = guard.audit_all(&sources);
        // Should have at least 1 DirectUpstreamImport and 1 ForbiddenPattern
        assert!(
            result
                .summary_by_kind
                .get("direct_upstream_import")
                .copied()
                .unwrap_or(0)
                >= 1
        );
        assert!(
            result
                .summary_by_kind
                .get("forbidden_pattern")
                .copied()
                .unwrap_or(0)
                >= 1
        );
    }

    // -----------------------------------------------------------------------
    // Deterministic output
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_output() {
        let guard = standard_guard();
        let source = r#"
            use franken_kernel::Cx;
            let _ = std::fs::read("a");
            struct TraceId(u64);
        "#;

        let f1 = guard.audit_source("ext_host::m", "f.rs", source);
        let f2 = guard.audit_source("ext_host::m", "f.rs", source);
        assert_eq!(f1, f2);
    }

    // -----------------------------------------------------------------------
    // GuardConfig
    // -----------------------------------------------------------------------

    #[test]
    fn default_config_has_all_forbidden_imports() {
        let config = GuardConfig::default();
        assert_eq!(
            config.forbidden_imports.len(),
            FORBIDDEN_UPSTREAM_IMPORTS.len()
        );
    }

    #[test]
    fn default_config_has_all_canonical_types() {
        let config = GuardConfig::default();
        assert_eq!(config.canonical_types.len(), CANONICAL_TYPES.len());
        for canonical in CANONICAL_TYPES {
            assert!(config.canonical_types.contains(*canonical));
        }
    }

    #[test]
    fn default_config_has_effectful_indicators() {
        let config = GuardConfig::default();
        assert_eq!(
            config.effectful_indicators.len(),
            EFFECTFUL_INDICATORS.len()
        );
    }

    #[test]
    fn custom_effectful_indicator_detected() {
        let mut config = GuardConfig::default();
        config.add_effectful_indicator("custom_effect");
        let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());

        let source = r#"
fn bad_fn(data: &[u8]) {
    custom_effect(data);
}
"#;

        let findings = guard.audit_source("ext_host::custom", "src/custom.rs", source);
        let cx_violations: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::MissingCxParameter)
            .collect();
        assert!(!cx_violations.is_empty());
    }

    #[test]
    fn custom_forbidden_import_detected() {
        let mut config = GuardConfig::default();
        config.add_forbidden_import("use secret_crate", "Use crate::safe_wrapper instead");
        let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());

        let source = r#"
            use secret_crate::DangerousApi;
        "#;

        let findings = guard.audit_source("ext_host::x", "src/x.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == ViolationKind::DirectUpstreamImport)
        );
    }

    #[test]
    fn disable_base_patterns() {
        let config = GuardConfig {
            include_base_patterns: false,
            ..GuardConfig::default()
        };
        let guard = ExtensionHostGuard::new(config, ExtensionHostExemptionRegistry::new());

        let source = r#"
            let _ = std::fs::read("x");
        "#;

        let findings = guard.audit_source("ext_host::io", "src/io.rs", source);
        let base_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == ViolationKind::ForbiddenPattern)
            .collect();
        assert!(base_findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Serialization roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn finding_serde_roundtrip() {
        let finding = ExtensionHostFinding {
            kind: ViolationKind::DirectUpstreamImport,
            module_path: "ext_host::bridge".to_string(),
            file_path: "src/bridge.rs".to_string(),
            line: 5,
            source_line: "use franken_kernel::Cx;".to_string(),
            description: "Direct upstream import: `use franken_kernel`".to_string(),
            remediation: "Import from crate::control_plane instead".to_string(),
            exempted: false,
        };
        let json = serde_json::to_string(&finding).unwrap();
        let restored: ExtensionHostFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, restored);
    }

    #[test]
    fn exemption_serde_roundtrip() {
        let exemption = ExtensionHostExemption {
            exemption_id: "ehx-001".to_string(),
            module_path: "ext_host::bootstrap".to_string(),
            kind: ViolationKind::DirectUpstreamImport,
            matched_token: "use franken_kernel".to_string(),
            reason: "Bootstrap needs direct access".to_string(),
            line: 0,
        };
        let json = serde_json::to_string(&exemption).unwrap();
        let restored: ExtensionHostExemption = serde_json::from_str(&json).unwrap();
        assert_eq!(exemption, restored);
    }

    #[test]
    fn exemption_registry_serde_roundtrip() {
        let mut reg = ExtensionHostExemptionRegistry::new();
        reg.add(ExtensionHostExemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            kind: ViolationKind::ForbiddenPattern,
            matched_token: "t".to_string(),
            reason: "r".to_string(),
            line: 0,
        });
        let json = serde_json::to_string(&reg).unwrap();
        let restored: ExtensionHostExemptionRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, restored);
    }

    #[test]
    fn audit_result_serde_roundtrip() {
        let result = ExtensionHostAuditResult {
            findings: vec![],
            violation_count: 0,
            exemption_count: 0,
            modules_audited: vec!["ext_host::clean".to_string()],
            passed: true,
            summary_by_kind: BTreeMap::new(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: ExtensionHostAuditResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, restored);
    }

    #[test]
    fn guard_config_serde_roundtrip() {
        let config = GuardConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: GuardConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, restored);
    }

    // -----------------------------------------------------------------------
    // Helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_fn_name_works() {
        assert_eq!(extract_fn_name("fn compute(x: i64)"), Some("compute"));
        assert_eq!(extract_fn_name("pub fn do_work(cx: &Cx)"), Some("do_work"));
        assert_eq!(
            extract_fn_name("pub(crate) fn internal_op()"),
            Some("internal_op")
        );
        assert_eq!(extract_fn_name("let x = 1;"), None);
    }

    #[test]
    fn extract_fn_signature_skips_trait_declarations() {
        let lines = vec!["    fn abstract_method(&self) -> bool;"];
        let result = extract_fn_signature(lines[0].trim(), &lines, 0);
        assert!(result.is_none());
    }

    #[test]
    fn extract_fn_signature_multi_line() {
        let lines = vec![
            "fn long_function(",
            "    cx: &dyn ContextAdapter,",
            "    data: &[u8],",
            ") {",
        ];
        let result = extract_fn_signature(lines[0].trim(), &lines, 0);
        assert!(result.is_some());
        let sig = result.unwrap();
        assert!(sig.contains("ContextAdapter"));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn empty_source_produces_no_findings() {
        let guard = standard_guard();
        let findings = guard.audit_source("m", "f.rs", "");
        assert!(findings.is_empty());
    }

    #[test]
    fn whitespace_only_source_produces_no_findings() {
        let guard = standard_guard();
        let findings = guard.audit_source("m", "f.rs", "   \n  \n   ");
        assert!(findings.is_empty());
    }

    #[test]
    fn mixed_violations_in_single_file() {
        let guard = standard_guard();
        let source = r#"
            use franken_kernel::Cx;
            use franken_evidence::EvidenceLedger;
            struct TraceId(u64);
            let _ = std::fs::read("x");
            static mut BAD: u64 = 0;
        "#;

        let findings = guard.audit_source("ext_host::mix", "src/mix.rs", source);
        let kinds: BTreeSet<ViolationKind> = findings.iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&ViolationKind::DirectUpstreamImport));
        assert!(kinds.contains(&ViolationKind::CanonicalTypeShadow));
        assert!(kinds.contains(&ViolationKind::ForbiddenPattern));
    }

    #[test]
    fn remediation_messages_are_actionable() {
        let guard = standard_guard();
        let source = r#"
            use franken_kernel::Cx;
            struct Budget { amount: u64 }
        "#;

        let findings = guard.audit_source("ext_host::bad", "src/bad.rs", source);
        for finding in &findings {
            assert!(
                !finding.remediation.is_empty(),
                "Finding should have non-empty remediation: {:?}",
                finding.kind
            );
        }
    }

    #[test]
    fn large_file_performance_scan() {
        let guard = standard_guard();
        // Simulate a large file (1000 lines of clean code)
        let mut source = String::new();
        for i in 0..1000 {
            source.push_str(&format!("fn compute_{i}(x: i64) -> i64 {{ x + {i} }}\n"));
        }

        let findings = guard.audit_source("ext_host::big", "src/big.rs", &source);
        assert!(findings.is_empty());
    }

    // ── enrichment: ViolationKind display uniqueness ────────────────────

    #[test]
    fn violation_kind_display_all_unique() {
        let kinds = [
            ViolationKind::ForbiddenPattern,
            ViolationKind::MissingCxParameter,
            ViolationKind::DirectUpstreamImport,
            ViolationKind::CanonicalTypeShadow,
        ];
        let strings: BTreeSet<_> = kinds.iter().map(|k| k.to_string()).collect();
        assert_eq!(strings.len(), kinds.len());
    }

    // ── enrichment: ExemptionRegistry len/is_empty ──────────────────────

    #[test]
    fn exemption_registry_empty_by_default() {
        let reg = ExtensionHostExemptionRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(reg.entries().is_empty());
    }

    #[test]
    fn exemption_registry_tracks_size() {
        let mut reg = ExtensionHostExemptionRegistry::new();
        reg.add(ExtensionHostExemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            kind: ViolationKind::ForbiddenPattern,
            matched_token: "std::fs".to_string(),
            reason: "bootstrap".to_string(),
            line: 0,
        });
        assert!(!reg.is_empty());
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.entries().len(), 1);
    }

    // ── enrichment: config()/exemptions() accessors ─────────────────────

    #[test]
    fn guard_config_accessor() {
        let guard = standard_guard();
        let cfg = guard.config();
        assert!(cfg.include_base_patterns);
        assert_eq!(cfg.canonical_types.len(), CANONICAL_TYPES.len());
    }

    #[test]
    fn guard_exemptions_accessor() {
        let guard = standard_guard();
        assert!(guard.exemptions().is_empty());
    }

    // ── enrichment: audit_result serde with findings ────────────────────

    #[test]
    fn audit_result_serde_with_findings() {
        let finding = ExtensionHostFinding {
            kind: ViolationKind::CanonicalTypeShadow,
            module_path: "ext_host::m".to_string(),
            file_path: "src/m.rs".to_string(),
            line: 10,
            source_line: "struct TraceId(u64);".to_string(),
            description: "shadows canonical type".to_string(),
            remediation: "import instead".to_string(),
            exempted: false,
        };
        let mut summary = BTreeMap::new();
        summary.insert("canonical_type_shadow".to_string(), 1);
        let result = ExtensionHostAuditResult {
            findings: vec![finding],
            violation_count: 1,
            exemption_count: 0,
            modules_audited: vec!["ext_host::m".to_string()],
            passed: false,
            summary_by_kind: summary,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deser: ExtensionHostAuditResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deser);
    }

    // ── enrichment: exemption line matching ─────────────────────────────

    #[test]
    fn exemption_module_wide_matches_any_line() {
        let mut reg = ExtensionHostExemptionRegistry::new();
        reg.add(ExtensionHostExemption {
            exemption_id: "e1".to_string(),
            module_path: "ext_host::boot".to_string(),
            kind: ViolationKind::DirectUpstreamImport,
            matched_token: "use franken_kernel".to_string(),
            reason: "bootstrap".to_string(),
            line: 0, // module-wide
        });
        // line=0 means matches any line
        assert!(reg.is_exempted(
            "ext_host::boot",
            ViolationKind::DirectUpstreamImport,
            "use franken_kernel",
            42,
        ));
        assert!(reg.is_exempted(
            "ext_host::boot",
            ViolationKind::DirectUpstreamImport,
            "use franken_kernel",
            1,
        ));
    }

    #[test]
    fn exemption_specific_line_only_matches_that_line() {
        let mut reg = ExtensionHostExemptionRegistry::new();
        reg.add(ExtensionHostExemption {
            exemption_id: "e2".to_string(),
            module_path: "ext_host::boot".to_string(),
            kind: ViolationKind::ForbiddenPattern,
            matched_token: "std::fs".to_string(),
            reason: "test".to_string(),
            line: 5,
        });
        assert!(reg.is_exempted(
            "ext_host::boot",
            ViolationKind::ForbiddenPattern,
            "std::fs",
            5,
        ));
        assert!(!reg.is_exempted(
            "ext_host::boot",
            ViolationKind::ForbiddenPattern,
            "std::fs",
            6,
        ));
    }

    #[test]
    fn exemption_wrong_module_not_matched() {
        let mut reg = ExtensionHostExemptionRegistry::new();
        reg.add(ExtensionHostExemption {
            exemption_id: "e3".to_string(),
            module_path: "ext_host::a".to_string(),
            kind: ViolationKind::ForbiddenPattern,
            matched_token: "std::fs".to_string(),
            reason: "test".to_string(),
            line: 0,
        });
        assert!(!reg.is_exempted("ext_host::b", ViolationKind::ForbiddenPattern, "std::fs", 1,));
    }

    // ── enrichment: GuardConfig serde with custom fields ────────────────

    #[test]
    fn guard_config_with_custom_fields_serde() {
        let mut config = GuardConfig::default();
        config.add_cx_audited_prefix("ext_host");
        config.add_effectful_indicator("custom_op");
        config.add_forbidden_import("use bad_crate", "use good_crate instead");
        let json = serde_json::to_string(&config).unwrap();
        let deser: GuardConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deser);
    }

    // ── enrichment: ExtensionHostFinding ordering ───────────────────────

    #[test]
    fn finding_ordering_by_kind_then_path() {
        let f1 = ExtensionHostFinding {
            kind: ViolationKind::DirectUpstreamImport,
            module_path: "a".to_string(),
            file_path: "a.rs".to_string(),
            line: 1,
            source_line: "x".to_string(),
            description: "d".to_string(),
            remediation: "r".to_string(),
            exempted: false,
        };
        let f2 = ExtensionHostFinding {
            kind: ViolationKind::CanonicalTypeShadow,
            module_path: "a".to_string(),
            file_path: "a.rs".to_string(),
            line: 1,
            source_line: "x".to_string(),
            description: "d".to_string(),
            remediation: "r".to_string(),
            exempted: false,
        };
        assert!(f1 < f2); // DirectUpstreamImport < CanonicalTypeShadow
    }

    // ── enrichment: extract_fn_name edge cases ──────────────────────────

    #[test]
    fn extract_fn_name_async_fn() {
        assert_eq!(
            extract_fn_name("async fn process(cx: &Cx)"),
            Some("process")
        );
    }

    #[test]
    fn extract_fn_name_empty_string() {
        assert_eq!(extract_fn_name(""), None);
    }
}
