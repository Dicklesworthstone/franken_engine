//! Package-level authority/IFC intake (E5.T2, `bd-fqlfw.5.2`).
//!
//! This module backs `frankenctl onboard <pkg>`. It takes a single-entrypoint
//! package (an entry file plus its on-disk root) and walks the **static
//! ES-module graph** reachable from the entry, reusing E5.T1's per-file analyzer
//! ([`crate::authority_footprint::analyze_authority_footprint`]) on every module
//! and the runtime's own module resolver
//! ([`crate::module_resolver::DeterministicModuleResolver`]) for resolution. By
//! construction the intake report and the runtime share a single source of truth
//! for both the authority footprint (the lowering pipeline) and module
//! resolution (the resolver), so a wrong line is a UX bug, not a soundness
//! regression — the same discipline E5.T1 established.
//!
//! v1 is a **compiler, not a wizard**: every output is explicit, reviewable, and
//! content-addressed, and the analyzer fail-closes on anything it cannot justify.
//! It emits five artifacts:
//!
//! 1. **Manifest proposal** — the normalized entry + reachable local module list
//!    + external (bare) dependency list.
//! 2. **Capability-profile proposal** — the union of required capabilities across
//!    the graph, each with the exact owning module and source span(s) (the
//!    lowered op that demanded it), plus a least-authority suggestion.
//! 3. **Denied-ambient-authority report** — every `error[FE-CAP-0001]` ambient
//!    access across the graph, with module + accessor + span.
//! 4. **IFC flow inventory** — required declassifications (runtime checkpoints),
//!    unsupported/denied flows, and the modules that could not be analyzed.
//! 5. **Module-resolution report** — for each relative import edge, the resolved
//!    target under `Native` / `NodeCompat` / `BunCompat`, the extension-probe
//!    sequences, and whether the three modes agree (extensionless imports
//!    resolve under `BunCompat` but fail closed under `Native`/`NodeCompat`).
//!
//! **Honest boundaries (v1).** Only ES `import` declarations are followed as
//! graph edges; CommonJS `require(...)` and dynamic `import(...)` are *not* yet
//! followed as edges (they still surface in each module's per-file footprint as
//! ambient-authority findings — they are never silently dropped). External
//! (bare / npm) specifiers are reported, never analyzed. Re-export sources
//! (`export … from "x"`) are carried inside the export clause and are not split
//! out as edges in v1. Every such boundary is reflected in the report's
//! `completeness` + `completeness_notes`, never hidden — most real npm packages
//! will honestly report "bounded" / "external" until language coverage rises
//! (E4/E7). Guardplane-prior synthesis and red-team-corpus generation are
//! explicitly out of scope for v1 (separate later beads).
//!
//! The report is a pure function of `(root contents, entry, parse_goal)` with all
//! paths relativized to the package root, so `--format json` is
//! byte-deterministic and content-addressed via `report_sha256`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ast::{ParseGoal, Statement};
use crate::authority_footprint::{
    AnalysisCompleteness, AuthorityFootprintReport, CheckFindingKind, SourceLocation,
    analyze_authority_footprint,
};
use crate::capability::RuntimeCapability;
use crate::module_compatibility_matrix::CompatibilityMode;
use crate::module_resolver::{
    AllowAllPolicy, DeterministicModuleResolver, ImportStyle, ModuleDefinition, ModuleDependency,
    ModuleRequest, ModuleResolver, ModuleSyntax, ResolutionContext,
};
use crate::parser::{CanonicalEs2020Parser, ParserOptions};
use crate::ts_normalization::prepare_source_entry_for_public_entrypoints;

/// Schema id stamped on every emitted intake report and `run_manifest.json`.
pub const PACKAGE_INTAKE_SCHEMA_VERSION: &str = "franken-engine.package-intake.v1";

/// On-thesis wording discipline (E5): the intake is for the supported ES-module
/// graph and fail-closes on anything it cannot analyze. It is never a
/// noninterference proof and never claims to have covered external packages,
/// CommonJS/dynamic edges, or unanalyzable modules.
pub const PACKAGE_INTAKE_DISCLAIMER: &str = "inferred package authority footprint over the SUPPORTED ES-module graph reachable from the entry; \
not a proof of noninterference for arbitrary JS/TS. External packages, CommonJS/dynamic edges, and unanalyzable modules are reported, never silently covered.";

// Deterministic identity for the analysis passes. `onboard` is a static,
// side-effect-free analysis, so these are fixed (never wall-clock or
// per-invocation) to keep the report content-addressable.
const INTAKE_TRACE_ID: &str = "trace-frankenctl-onboard";
const INTAKE_DECISION_ID: &str = "decision-frankenctl-onboard";
const INTAKE_POLICY_ID: &str = "frankenctl.onboard.v1";

/// Source-file extensions discovered + registered for resolution. Deterministic
/// order; mirrors the runtime's accepted module surfaces.
const SOURCE_EXTENSIONS: &[&str] = &["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"];

/// Bound on the number of files walked under the package root. A package larger
/// than this is truncated and the truncation is surfaced (never silent).
const MAX_PACKAGE_FILES: usize = 1024;

/// The three runtime compatibility modes, in deterministic report order.
const RESOLUTION_MODES: [CompatibilityMode; 3] = [
    CompatibilityMode::Native,
    CompatibilityMode::NodeCompat,
    CompatibilityMode::BunCompat,
];

fn mode_label(mode: CompatibilityMode) -> &'static str {
    match mode {
        CompatibilityMode::Native => "native",
        CompatibilityMode::NodeCompat => "node_compat",
        CompatibilityMode::BunCompat => "bun_compat",
    }
}

// ---------------------------------------------------------------------------
// Path helpers (mirror module_resolver's private normalization so module ids
// produced here match the ids the resolver returns, keeping relativization
// exact and the report content-addressable).
// ---------------------------------------------------------------------------

/// Collapse `.`/`..`/empty segments to a `/`-rooted canonical path. Mirrors
/// `module_resolver::normalize_absolute_path` so ids agree with the resolver.
fn normalize_abs(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            value => stack.push(value),
        }
    }
    if stack.is_empty() {
        return "/".to_string();
    }
    format!("/{}", stack.join("/"))
}

/// Relativize an absolute module id against the resolver's normalized root,
/// returning a forward-slash root-relative path (`index.js`, `lib/util.js`).
/// Falls back to the absolute id when it is not under the root (best effort).
fn relativize(root: &str, abs: &str) -> String {
    if let Some(stripped) = abs.strip_prefix(root) {
        let trimmed = stripped.trim_start_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    abs.to_string()
}

/// Relativize each extension-probe candidate against the resolver root so the
/// report carries portable, root-relative probe sequences (the raw candidates
/// are absolute paths under the root).
fn relativize_probes(root: &str, probes: &[String]) -> Vec<String> {
    probes.iter().map(|p| relativize(root, p)).collect()
}

/// True for a relative specifier (`.`, `..`, `./x`, `../x`). Bare and absolute
/// specifiers are treated as external (reported, not followed).
fn is_relative_specifier(specifier: &str) -> bool {
    specifier == "."
        || specifier == ".."
        || specifier.starts_with("./")
        || specifier.starts_with("../")
}

// ---------------------------------------------------------------------------
// Report data model
// ---------------------------------------------------------------------------

/// A module + source location pair (the citation backing every aggregated fact).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EdgeSite {
    /// Module path relative to the package root.
    pub module: String,
    /// Source location, when a span is available.
    pub location: Option<SourceLocation>,
}

/// One analyzed local module and its full per-file authority footprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleIntake {
    /// Path relative to the package root.
    pub path: String,
    /// `es_module` if the file carries ES `import`/`export`, else `common_js`.
    pub syntax: String,
    /// The reused E5.T1 per-file report (capabilities, findings, completeness).
    pub analysis: AuthorityFootprintReport,
}

/// A bare/external (npm-style) dependency: reported, never analyzed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalDependency {
    /// The bare specifier as written (`react`, `@scope/pkg`, `fs`).
    pub specifier: String,
    /// Where it is imported from (module + span), sorted + deduped.
    pub sites: Vec<EdgeSite>,
}

/// Normalized manifest proposal: the reviewable shape of the package graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestProposal {
    /// Entry module, relative to root.
    pub entry: String,
    /// Reachable local modules analyzed, sorted relative paths.
    pub modules: Vec<String>,
    /// Bare/external specifiers, sorted.
    pub external_dependencies: Vec<String>,
    pub module_count: usize,
    pub external_count: usize,
}

/// One capability the package requires, with every owning module + call site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySite {
    /// Typed capability when the raw tag maps to one.
    pub capability: Option<RuntimeCapability>,
    /// Raw capability tag (the authority of record).
    pub capability_tag: String,
    /// Module + span citations demanding this capability, sorted + deduped.
    pub sites: Vec<EdgeSite>,
}

/// Capability-profile proposal: the union footprint across the graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProfileProposal {
    /// Capabilities required, sorted by tag.
    pub capabilities: Vec<CapabilitySite>,
    /// Least-authority guidance for the operator.
    pub least_authority_suggestion: String,
}

/// A single denied ambient-authority access (`error[FE-CAP-0001]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeniedAmbientAccess {
    pub module: String,
    pub accessor: Option<String>,
    pub implied_capability: Option<RuntimeCapability>,
    pub location: Option<SourceLocation>,
    pub message: String,
}

/// An IFC finding (denied flow or required declassification) with its citation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfcFinding {
    pub module: String,
    pub location: Option<SourceLocation>,
    pub message: String,
}

/// A module that could not be analyzed (parse error / unsupported construct).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnanalyzableModule {
    pub module: String,
    pub reason: String,
}

/// IFC flow inventory across the graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfcFlowInventory {
    /// Flows permitted only under a signed declassification receipt
    /// (`error[FE-CAP-0003]`) — runtime checkpoints the operator must satisfy.
    pub required_declassifications: Vec<IfcFinding>,
    /// Flows denied by the lattice (`error[FE-CAP-0002]`) — unsupported as-is.
    pub unsupported_flows: Vec<IfcFinding>,
    /// Modules that fail-closed (no footprint asserted), with reasons.
    pub unanalyzable_modules: Vec<UnanalyzableModule>,
}

/// Resolution outcome for one import edge under one compatibility mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionModeOutcome {
    /// `native` / `node_compat` / `bun_compat`.
    pub mode: String,
    /// Resolved target relative to root, when resolution succeeded.
    pub resolved_path: Option<String>,
    /// Stable `FE-MODRES-…` code when resolution failed (fail-closed).
    pub error_code: Option<String>,
    /// Extension-probe candidates tried, in order.
    pub probe_sequence: Vec<String>,
}

/// One relative import edge resolved under all three modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionEdge {
    pub from_module: String,
    pub specifier: String,
    pub location: Option<SourceLocation>,
    pub outcomes: Vec<ResolutionModeOutcome>,
    /// True when all three modes resolve to the identical target (or all fail).
    pub modes_agree: bool,
}

/// Per-mode module-resolution report (Native/NodeCompat/BunCompat differences).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleResolutionReport {
    /// Relative import edges, sorted by `(from_module, specifier)`.
    pub edges: Vec<ResolutionEdge>,
    /// Edges where the three modes disagree.
    pub divergent_edge_count: usize,
}

/// How much of the package the intake actually covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageIntakeCompleteness {
    /// Whole reachable ES-module graph analyzed cleanly; nothing truncated or
    /// left unresolved. (External deps are still reported, not "covered".)
    Complete,
    /// Some module fail-closed/bounded, some relative edge did not resolve in
    /// any mode, or the file walk was truncated — see `completeness_notes`.
    Bounded,
    /// The entry could not be ingested at all; no graph is asserted.
    Unanalyzable,
}

impl PackageIntakeCompleteness {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Bounded => "bounded",
            Self::Unanalyzable => "unanalyzable",
        }
    }
}

/// Coarse outcome of an `onboard` run, used to derive the process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageIntakeOutcome {
    /// Whole graph clean and complete.
    Clean,
    /// At least one finding, unresolved edge, or bounded/truncated coverage.
    FindingsPresent,
    /// Entry unanalyzable (fail-closed): exit 2.
    Unanalyzable,
}

impl PackageIntakeOutcome {
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Clean => 0,
            Self::FindingsPresent => 1,
            Self::Unanalyzable => 2,
        }
    }
}

/// The full package intake report. All paths are relativized to the package
/// root, so the serialized body is a pure function of `(root contents, entry,
/// parse_goal)`; `report_sha256` content-addresses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIntakeReport {
    pub schema_version: String,
    /// Operator-facing root label (the path the operator passed). Display only.
    pub package_root: String,
    /// Entry module, relative to root.
    pub entry: String,
    pub parse_goal: String,
    pub disclaimer: String,
    pub completeness: PackageIntakeCompleteness,
    /// Explicit enumeration of *why* coverage is bounded (never silent).
    pub completeness_notes: Vec<String>,
    /// `false` ⇒ the entry could not be ingested (fail-closed).
    pub analyzable: bool,
    pub fail_closed_reason: Option<String>,
    pub modules: Vec<ModuleIntake>,
    pub external_dependencies: Vec<ExternalDependency>,
    pub manifest_proposal: ManifestProposal,
    pub capability_profile_proposal: CapabilityProfileProposal,
    pub denied_ambient_authority: Vec<DeniedAmbientAccess>,
    pub ifc_flow_inventory: IfcFlowInventory,
    pub module_resolution_report: ModuleResolutionReport,
    /// SHA-256 over the canonical body (with this field blank). Content address.
    pub report_sha256: String,
}

impl PackageIntakeReport {
    /// Coarse outcome (drives the process exit code).
    pub fn outcome(&self) -> PackageIntakeOutcome {
        if !self.analyzable {
            return PackageIntakeOutcome::Unanalyzable;
        }
        let clean = self.completeness == PackageIntakeCompleteness::Complete
            && self.denied_ambient_authority.is_empty()
            && self.ifc_flow_inventory.unsupported_flows.is_empty()
            && self
                .ifc_flow_inventory
                .required_declassifications
                .is_empty()
            && self.ifc_flow_inventory.unanalyzable_modules.is_empty();
        if clean {
            PackageIntakeOutcome::Clean
        } else {
            PackageIntakeOutcome::FindingsPresent
        }
    }

    /// Stamp the content hash over the canonical body (with `report_sha256`
    /// blank). Caller is responsible for sorting all vectors first.
    fn finalize(mut self) -> Self {
        self.report_sha256.clear();
        let body = serde_json::to_vec(&self).unwrap_or_default();
        self.report_sha256 = hex::encode(Sha256::digest(&body));
        self
    }

    /// Render a compact human-readable summary for the terminal.
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("package intake: {}\n", self.package_root));
        out.push_str(&format!("  entry: {}\n", self.entry));
        out.push_str(&format!("  ({})\n", self.disclaimer));
        out.push_str(&format!("  completeness: {}\n", self.completeness.as_str()));
        if !self.analyzable {
            out.push_str(&format!(
                "  status: UNANALYZABLE (fail-closed) — {}\n",
                self.fail_closed_reason.as_deref().unwrap_or("unknown")
            ));
            return out;
        }
        for note in &self.completeness_notes {
            out.push_str(&format!("  note: {note}\n"));
        }
        out.push_str(&format!(
            "  modules analyzed: {} | external deps: {}\n",
            self.manifest_proposal.module_count, self.manifest_proposal.external_count
        ));
        // Capability profile proposal.
        if self.capability_profile_proposal.capabilities.is_empty() {
            out.push_str("  capability profile: <none> (compute-only)\n");
        } else {
            out.push_str("  capability profile proposal:\n");
            for cap in &self.capability_profile_proposal.capabilities {
                let typed = cap
                    .capability
                    .map(|c| format!(" ({c})"))
                    .unwrap_or_default();
                let sites: Vec<String> = cap
                    .sites
                    .iter()
                    .map(|s| match &s.location {
                        Some(loc) => format!("{}@{loc}", s.module),
                        None => format!("{}@<no span>", s.module),
                    })
                    .collect();
                out.push_str(&format!(
                    "    - {}{} :: {}\n",
                    cap.capability_tag,
                    typed,
                    sites.join(", ")
                ));
            }
        }
        out.push_str(&format!(
            "  suggestion: {}\n",
            self.capability_profile_proposal.least_authority_suggestion
        ));
        // Denied ambient authority.
        if !self.denied_ambient_authority.is_empty() {
            out.push_str(&format!(
                "  denied ambient authority: {}\n",
                self.denied_ambient_authority.len()
            ));
            for denied in &self.denied_ambient_authority {
                let loc = denied
                    .location
                    .as_ref()
                    .map(|l| l.to_string())
                    .unwrap_or_else(|| "<no span>".to_string());
                out.push_str(&format!(
                    "    {} @ {loc}: {}\n",
                    denied.module, denied.message
                ));
            }
        }
        // IFC inventory.
        let ifc = &self.ifc_flow_inventory;
        if !ifc.required_declassifications.is_empty()
            || !ifc.unsupported_flows.is_empty()
            || !ifc.unanalyzable_modules.is_empty()
        {
            out.push_str(&format!(
                "  IFC inventory: {} required declassifications, {} unsupported flows, {} unanalyzable modules\n",
                ifc.required_declassifications.len(),
                ifc.unsupported_flows.len(),
                ifc.unanalyzable_modules.len()
            ));
            for m in &ifc.unanalyzable_modules {
                out.push_str(&format!("    unanalyzable: {} — {}\n", m.module, m.reason));
            }
        }
        // Resolution divergence.
        out.push_str(&format!(
            "  module resolution: {} relative edges, {} mode-divergent\n",
            self.module_resolution_report.edges.len(),
            self.module_resolution_report.divergent_edge_count
        ));
        for edge in &self.module_resolution_report.edges {
            if edge.modes_agree {
                continue;
            }
            out.push_str(&format!(
                "    divergent: {} imports `{}` →\n",
                edge.from_module, edge.specifier
            ));
            for outcome in &edge.outcomes {
                let target = outcome
                    .resolved_path
                    .clone()
                    .or_else(|| outcome.error_code.clone())
                    .unwrap_or_else(|| "<unresolved>".to_string());
                out.push_str(&format!("        {}: {target}\n", outcome.mode));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// ES-module extraction
// ---------------------------------------------------------------------------

/// An ES `import` declaration projected to (specifier, location).
struct ImportEdge {
    specifier: String,
    location: SourceLocation,
}

/// What a single file contributes to the graph: its detected syntax and the ES
/// import declarations it carries (the graph edges to follow).
struct ExtractedModule {
    syntax: ModuleSyntax,
    imports: Vec<ImportEdge>,
}

/// Parse a source file (after TS normalization) and extract its ES `import`
/// declarations + detected syntax. Never panics: a parse/normalization failure
/// yields an empty edge set with `CommonJs` syntax (the file will still be
/// analyzed and fail-closed by [`analyze_authority_footprint`] downstream).
fn extract_es_module(source: &str, label: &str) -> ExtractedModule {
    let empty = || ExtractedModule {
        syntax: ModuleSyntax::CommonJs,
        imports: Vec::new(),
    };
    let prepared = match prepare_source_entry_for_public_entrypoints(
        source,
        label,
        INTAKE_TRACE_ID,
        INTAKE_DECISION_ID,
        INTAKE_POLICY_ID,
    ) {
        Ok(prepared) => prepared,
        Err(_) => return empty(),
    };
    let parser = CanonicalEs2020Parser;
    let (parse_result, _event_ir) = parser.parse_with_event_ir(
        prepared.prepared_source.as_str(),
        ParseGoal::Module,
        &ParserOptions::default(),
    );
    let tree = match parse_result {
        Ok(tree) => tree,
        Err(_) => return empty(),
    };

    let mut imports = Vec::new();
    let mut has_module_syntax = false;
    for statement in &tree.body {
        match statement {
            Statement::Import(decl) => {
                has_module_syntax = true;
                imports.push(ImportEdge {
                    specifier: decl.source.clone(),
                    location: SourceLocation::from(decl.span),
                });
            }
            Statement::Export(_) => {
                // Re-export sources are folded into the export clause in v1 and
                // are not split out as edges; their presence still marks ESM.
                has_module_syntax = true;
            }
            _ => {}
        }
    }
    ExtractedModule {
        syntax: if has_module_syntax {
            ModuleSyntax::EsModule
        } else {
            ModuleSyntax::CommonJs
        },
        imports,
    }
}

fn syntax_str(syntax: ModuleSyntax) -> &'static str {
    match syntax {
        ModuleSyntax::EsModule => "es_module",
        ModuleSyntax::CommonJs => "common_js",
        ModuleSyntax::Wasm => "wasm",
    }
}

// ---------------------------------------------------------------------------
// Filesystem discovery
// ---------------------------------------------------------------------------

fn has_source_extension(name: &str) -> bool {
    name.rsplit_once('.')
        .map(|(_, ext)| SOURCE_EXTENSIONS.contains(&ext))
        .unwrap_or(false)
}

/// Deterministically walk `root`, collecting forward-slash relative paths of
/// source files. Skips `node_modules`, dot-directories, and symlinks (cycle
/// safety). Returns `(sorted relative paths, truncated)`.
fn discover_source_files(root: &Path) -> (Vec<String>, bool) {
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut truncated = false;
    // Deterministic DFS over a sorted stack of (dir, relative-prefix).
    let mut stack: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let mut entries: Vec<(String, std::fs::Metadata)> = Vec::new();
        let read = match std::fs::read_dir(&dir) {
            Ok(read) => read,
            Err(_) => continue,
        };
        for entry in read.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip dotfiles/dirs and node_modules.
            if name.starts_with('.') || name == "node_modules" {
                continue;
            }
            // Use symlink_metadata so symlinks are not followed (cycle safety).
            let meta = match entry.path().symlink_metadata() {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            entries.push((name, meta));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        // Push subdirs in reverse so the sorted order pops smallest-first.
        let mut subdirs: Vec<(PathBuf, String)> = Vec::new();
        for (name, meta) in entries {
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                subdirs.push((dir.join(&name), rel));
            } else if meta.is_file() && has_source_extension(&name) {
                if found.len() >= MAX_PACKAGE_FILES {
                    truncated = true;
                } else {
                    found.insert(rel);
                }
            }
        }
        for sub in subdirs.into_iter().rev() {
            stack.push(sub);
        }
    }
    (found.into_iter().collect(), truncated)
}

// ---------------------------------------------------------------------------
// onboard_package
// ---------------------------------------------------------------------------

/// Walk the static ES-module graph rooted at `entry_relative` under `root_dir`
/// and produce the full package intake report.
///
/// * `root_dir` — the on-disk package root to walk and register modules under.
/// * `entry_relative` — entry module path relative to `root_dir`
///   (forward-slash).
/// * `root_label` — operator-facing display label for the root (the path the
///   operator passed); recorded but never used for resolution.
/// * `parse_goal` — analysis goal for each module (modules use [`ParseGoal::Module`]).
///
/// Never panics on malformed input: an unreadable entry yields a fail-closed
/// (`analyzable = false`) report.
pub fn onboard_package(
    root_dir: &Path,
    entry_relative: &str,
    root_label: &str,
    parse_goal: ParseGoal,
) -> PackageIntakeReport {
    let resolver = DeterministicModuleResolver::new(root_dir.to_string_lossy().to_string());
    let resolver_root = resolver.root_dir().to_string();

    let base_unanalyzable = |reason: String| -> PackageIntakeReport {
        PackageIntakeReport {
            schema_version: PACKAGE_INTAKE_SCHEMA_VERSION.to_string(),
            package_root: root_label.to_string(),
            entry: entry_relative.to_string(),
            parse_goal: parse_goal.as_str().to_string(),
            disclaimer: PACKAGE_INTAKE_DISCLAIMER.to_string(),
            completeness: PackageIntakeCompleteness::Unanalyzable,
            completeness_notes: vec![reason.clone()],
            analyzable: false,
            fail_closed_reason: Some(reason),
            modules: Vec::new(),
            external_dependencies: Vec::new(),
            manifest_proposal: ManifestProposal {
                entry: entry_relative.to_string(),
                modules: Vec::new(),
                external_dependencies: Vec::new(),
                module_count: 0,
                external_count: 0,
            },
            capability_profile_proposal: CapabilityProfileProposal {
                capabilities: Vec::new(),
                least_authority_suggestion: String::new(),
            },
            denied_ambient_authority: Vec::new(),
            ifc_flow_inventory: IfcFlowInventory {
                required_declassifications: Vec::new(),
                unsupported_flows: Vec::new(),
                unanalyzable_modules: Vec::new(),
            },
            module_resolution_report: ModuleResolutionReport {
                edges: Vec::new(),
                divergent_edge_count: 0,
            },
            report_sha256: String::new(),
        }
        .finalize()
    };

    // Read the entry first: an unreadable entry is the one true fail-closed case.
    let entry_fs = root_dir.join(entry_relative);
    if std::fs::read_to_string(&entry_fs).is_err() {
        return base_unanalyzable(format!(
            "entry `{entry_relative}` could not be read under the package root"
        ));
    }

    // 1. Discover + register all on-disk source files (resolution candidates).
    let (mut discovered, truncated) = discover_source_files(root_dir);
    if !discovered.iter().any(|p| p == entry_relative) {
        // Always include the entry even if the walk missed it (e.g. truncation).
        discovered.push(entry_relative.to_string());
        discovered.sort();
        discovered.dedup();
    }

    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let mut extracted: BTreeMap<String, ExtractedModule> = BTreeMap::new();
    let mut resolver = resolver;
    for rel in &discovered {
        let source = match std::fs::read_to_string(root_dir.join(rel)) {
            Ok(source) => source,
            Err(_) => continue,
        };
        let module = extract_es_module(&source, rel);
        let mut definition = ModuleDefinition::new(module.syntax, source.clone())
            .with_provenance("frankenctl-onboard");
        for edge in &module.imports {
            definition = definition.with_dependency(ModuleDependency::new(
                edge.specifier.clone(),
                ImportStyle::Import,
            ));
        }
        // Registration only fails for empty/outside-root keys; skip those files.
        if resolver
            .register_workspace_module(rel.clone(), definition)
            .is_ok()
        {
            sources.insert(rel.clone(), source);
            extracted.insert(rel.clone(), module);
        }
    }

    // 2. BFS the graph from the entry, resolving each relative edge under all
    //    three modes and classifying bare specifiers as external.
    let context = ResolutionContext::new(INTAKE_TRACE_ID, INTAKE_DECISION_ID, INTAKE_POLICY_ID);
    let mut edges: Vec<ResolutionEdge> = Vec::new();
    let mut external: BTreeMap<String, Vec<EdgeSite>> = BTreeMap::new();
    let mut reached: BTreeSet<String> = BTreeSet::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    reached.insert(entry_relative.to_string());
    queue.push_back(entry_relative.to_string());

    while let Some(current) = queue.pop_front() {
        if !visited.insert(current.clone()) {
            continue;
        }
        let Some(module) = extracted.get(&current) else {
            continue;
        };
        let referrer = normalize_abs(&format!("{resolver_root}/{current}"));
        for edge in &module.imports {
            let location = Some(edge.location.clone());
            if !is_relative_specifier(&edge.specifier) {
                external
                    .entry(edge.specifier.clone())
                    .or_default()
                    .push(EdgeSite {
                        module: current.clone(),
                        location,
                    });
                continue;
            }
            let mut outcomes = Vec::with_capacity(RESOLUTION_MODES.len());
            let mut resolved_targets: Vec<Option<String>> = Vec::new();
            for &mode in &RESOLUTION_MODES {
                let request = ModuleRequest::new(edge.specifier.clone(), ImportStyle::Import)
                    .with_referrer(referrer.clone())
                    .with_compatibility_mode(mode);
                match resolver.resolve(&request, &context, &AllowAllPolicy) {
                    Ok(outcome) => {
                        let resolved =
                            relativize(&resolver_root, &outcome.module.canonical_specifier);
                        outcomes.push(ResolutionModeOutcome {
                            mode: mode_label(mode).to_string(),
                            resolved_path: Some(resolved.clone()),
                            error_code: None,
                            probe_sequence: relativize_probes(
                                &resolver_root,
                                &outcome.module.probe_sequence,
                            ),
                        });
                        resolved_targets.push(Some(resolved));
                    }
                    Err(error) => {
                        outcomes.push(ResolutionModeOutcome {
                            mode: mode_label(mode).to_string(),
                            resolved_path: None,
                            error_code: Some(error.code.stable_code().to_string()),
                            probe_sequence: relativize_probes(
                                &resolver_root,
                                &error.probe_sequence,
                            ),
                        });
                        resolved_targets.push(None);
                    }
                }
            }
            let modes_agree = resolved_targets.windows(2).all(|w| w[0] == w[1]);
            // Follow every distinct successfully-resolved target (any mode).
            for target in resolved_targets.iter().flatten() {
                if extracted.contains_key(target) {
                    reached.insert(target.clone());
                    if !visited.contains(target) {
                        queue.push_back(target.clone());
                    }
                }
            }
            edges.push(ResolutionEdge {
                from_module: current.clone(),
                specifier: edge.specifier.clone(),
                location,
                outcomes,
                modes_agree,
            });
        }
    }

    // 3. Analyze every reached local module via the reused E5.T1 analyzer.
    let mut modules: Vec<ModuleIntake> = Vec::new();
    for rel in &reached {
        let Some(source) = sources.get(rel) else {
            continue;
        };
        let analysis = analyze_authority_footprint(source, rel, parse_goal);
        let syntax = extracted
            .get(rel)
            .map(|m| m.syntax)
            .unwrap_or(ModuleSyntax::CommonJs);
        modules.push(ModuleIntake {
            path: rel.clone(),
            syntax: syntax_str(syntax).to_string(),
            analysis,
        });
    }
    modules.sort_by(|a, b| a.path.cmp(&b.path));

    // 4. Aggregate the five artifacts from the per-module reports.
    let mut capability_index: BTreeMap<String, (Option<RuntimeCapability>, BTreeSet<EdgeSite>)> =
        BTreeMap::new();
    let mut denied_ambient: Vec<DeniedAmbientAccess> = Vec::new();
    let mut required_declassifications: Vec<IfcFinding> = Vec::new();
    let mut unsupported_flows: Vec<IfcFinding> = Vec::new();
    let mut unanalyzable_modules: Vec<UnanalyzableModule> = Vec::new();

    for module in &modules {
        let report = &module.analysis;
        for requirement in &report.required_capabilities {
            let entry = capability_index
                .entry(requirement.capability_tag.clone())
                .or_insert_with(|| (requirement.capability, BTreeSet::new()));
            if requirement.call_sites.is_empty() {
                entry.1.insert(EdgeSite {
                    module: module.path.clone(),
                    location: None,
                });
            } else {
                for site in &requirement.call_sites {
                    entry.1.insert(EdgeSite {
                        module: module.path.clone(),
                        location: Some(site.clone()),
                    });
                }
            }
        }
        for finding in &report.findings {
            match finding.kind {
                CheckFindingKind::AmbientAuthorityViolation => {
                    denied_ambient.push(DeniedAmbientAccess {
                        module: module.path.clone(),
                        accessor: finding.accessor.clone(),
                        implied_capability: finding.implied_capability,
                        location: finding.location.clone(),
                        message: finding.message.clone(),
                    });
                }
                CheckFindingKind::DeclassificationRequired => {
                    required_declassifications.push(IfcFinding {
                        module: module.path.clone(),
                        location: finding.location.clone(),
                        message: finding.message.clone(),
                    });
                }
                CheckFindingKind::UnauthorizedFlow => {
                    unsupported_flows.push(IfcFinding {
                        module: module.path.clone(),
                        location: finding.location.clone(),
                        message: finding.message.clone(),
                    });
                }
            }
        }
        if !report.analyzable {
            unanalyzable_modules.push(UnanalyzableModule {
                module: module.path.clone(),
                reason: report
                    .fail_closed_reason
                    .clone()
                    .unwrap_or_else(|| "unanalyzable".to_string()),
            });
        }
    }

    // Capability profile proposal (sorted by tag; sites already sorted via set).
    let capabilities: Vec<CapabilitySite> = capability_index
        .into_iter()
        .map(|(tag, (cap, sites))| CapabilitySite {
            capability: cap,
            capability_tag: tag,
            sites: sites.into_iter().collect(),
        })
        .collect();
    let least_authority_suggestion = if capabilities.is_empty() {
        "this package requires no host capabilities for its supported syntax; grant nothing beyond compute-only".to_string()
    } else {
        let tags: Vec<String> = capabilities
            .iter()
            .map(|cap| cap.capability_tag.clone())
            .collect();
        format!(
            "grant exactly the capabilities this package uses and no more: [{}]",
            tags.join(", ")
        )
    };

    denied_ambient.sort_by(|a, b| {
        (a.module.as_str(), &a.location, a.accessor.as_deref()).cmp(&(
            b.module.as_str(),
            &b.location,
            b.accessor.as_deref(),
        ))
    });
    required_declassifications
        .sort_by(|a, b| (a.module.as_str(), &a.location).cmp(&(b.module.as_str(), &b.location)));
    unsupported_flows
        .sort_by(|a, b| (a.module.as_str(), &a.location).cmp(&(b.module.as_str(), &b.location)));
    unanalyzable_modules.sort_by(|a, b| a.module.cmp(&b.module));

    let mut external_dependencies: Vec<ExternalDependency> = external
        .into_iter()
        .map(|(specifier, mut sites)| {
            sites.sort();
            sites.dedup();
            ExternalDependency { specifier, sites }
        })
        .collect();
    external_dependencies.sort_by(|a, b| a.specifier.cmp(&b.specifier));

    edges.sort_by(|a, b| {
        (a.from_module.as_str(), a.specifier.as_str())
            .cmp(&(b.from_module.as_str(), b.specifier.as_str()))
    });
    let divergent_edge_count = edges.iter().filter(|edge| !edge.modes_agree).count();

    // 5. Completeness: enumerate every reason coverage is bounded (no silent caps).
    let mut completeness_notes: Vec<String> = Vec::new();
    if truncated {
        completeness_notes.push(format!(
            "file walk truncated at {MAX_PACKAGE_FILES} files; the package is larger than the intake bound"
        ));
    }
    let bounded_modules: Vec<&str> = modules
        .iter()
        .filter(|m| m.analysis.analysis_completeness != AnalysisCompleteness::Complete)
        .map(|m| m.path.as_str())
        .collect();
    if !bounded_modules.is_empty() {
        completeness_notes.push(format!(
            "{} module(s) not fully analyzed (fail-closed or bounded at first violation): {}",
            bounded_modules.len(),
            bounded_modules.join(", ")
        ));
    }
    let unresolved_edges: Vec<&ResolutionEdge> = edges
        .iter()
        .filter(|edge| edge.outcomes.iter().all(|o| o.resolved_path.is_none()))
        .collect();
    if !unresolved_edges.is_empty() {
        let specs: Vec<String> = unresolved_edges
            .iter()
            .map(|edge| format!("{}→`{}`", edge.from_module, edge.specifier))
            .collect();
        completeness_notes.push(format!(
            "{} relative import edge(s) did not resolve in any mode: {}",
            unresolved_edges.len(),
            specs.join(", ")
        ));
    }
    // Mode-fragile edges: resolve under some compatibility mode but not another
    // (e.g. an extensionless import that BunCompat probes but Native/NodeCompat
    // reject). Under the strict mode the target is unreachable, so the analyzed
    // graph is mode-dependent — surfaced here rather than buried in the
    // resolution report (no silent caps). Disjoint from unresolved_edges, which
    // fail in *every* mode (and so agree, modes_agree = true).
    let mode_fragile_edges: Vec<&ResolutionEdge> =
        edges.iter().filter(|edge| !edge.modes_agree).collect();
    if !mode_fragile_edges.is_empty() {
        let specs: Vec<String> = mode_fragile_edges
            .iter()
            .map(|edge| format!("{}→`{}`", edge.from_module, edge.specifier))
            .collect();
        completeness_notes.push(format!(
            "{} import edge(s) resolve differently across Native/NodeCompat/BunCompat (mode-fragile; unreachable under the stricter mode): {}",
            mode_fragile_edges.len(),
            specs.join(", ")
        ));
    }
    if !external_dependencies.is_empty() {
        completeness_notes.push(format!(
            "{} external (bare) dependency specifier(s) reported but not analyzed",
            external_dependencies.len()
        ));
    }
    let completeness = if truncated
        || !bounded_modules.is_empty()
        || !unresolved_edges.is_empty()
        || !mode_fragile_edges.is_empty()
    {
        PackageIntakeCompleteness::Bounded
    } else {
        PackageIntakeCompleteness::Complete
    };

    let manifest_modules: Vec<String> = modules.iter().map(|m| m.path.clone()).collect();
    let external_specifiers: Vec<String> = external_dependencies
        .iter()
        .map(|dep| dep.specifier.clone())
        .collect();
    let manifest_proposal = ManifestProposal {
        entry: entry_relative.to_string(),
        module_count: manifest_modules.len(),
        external_count: external_specifiers.len(),
        modules: manifest_modules,
        external_dependencies: external_specifiers,
    };

    PackageIntakeReport {
        schema_version: PACKAGE_INTAKE_SCHEMA_VERSION.to_string(),
        package_root: root_label.to_string(),
        entry: entry_relative.to_string(),
        parse_goal: parse_goal.as_str().to_string(),
        disclaimer: PACKAGE_INTAKE_DISCLAIMER.to_string(),
        completeness,
        completeness_notes,
        analyzable: true,
        fail_closed_reason: None,
        modules,
        external_dependencies,
        manifest_proposal,
        capability_profile_proposal: CapabilityProfileProposal {
            capabilities,
            least_authority_suggestion,
        },
        denied_ambient_authority: denied_ambient,
        ifc_flow_inventory: IfcFlowInventory {
            required_declassifications,
            unsupported_flows,
            unanalyzable_modules,
        },
        module_resolution_report: ModuleResolutionReport {
            edges,
            divergent_edge_count,
        },
        report_sha256: String::new(),
    }
    .finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a temporary package on disk and return (root, cleanup-on-drop).
    struct TempPackage {
        root: PathBuf,
    }

    impl TempPackage {
        fn new(name: &str) -> Self {
            // Deterministic per-test dir under the system temp root. No
            // wall-clock: the test name disambiguates. Cleared if it exists.
            let root = std::env::temp_dir().join(format!("franken_onboard_{name}"));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("create temp package root");
            Self { root }
        }

        fn write(&self, rel: &str, contents: &str) {
            let path = self.root.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("create parent dir");
            }
            std::fs::write(path, contents).expect("write package file");
        }
    }

    impl Drop for TempPackage {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn clean_two_module_package_has_empty_footprint_and_resolves_in_all_modes() {
        let pkg = TempPackage::new("clean_two_module");
        pkg.write(
            "index.js",
            "import { add } from \"./math.js\";\nconst x = add(1, 2);\n",
        );
        pkg.write("math.js", "export function add(a, b) { return a + b; }\n");

        let report = onboard_package(&pkg.root, "index.js", "demo-pkg", ParseGoal::Module);

        assert!(report.analyzable);
        assert_eq!(report.entry, "index.js");
        // Both modules reachable + analyzed.
        assert_eq!(report.manifest_proposal.module_count, 2);
        assert!(
            report
                .manifest_proposal
                .modules
                .contains(&"index.js".to_string())
        );
        assert!(
            report
                .manifest_proposal
                .modules
                .contains(&"math.js".to_string())
        );
        // Pure arithmetic: no ambient violations.
        assert!(report.denied_ambient_authority.is_empty());
        // The `./math.js` edge has an explicit extension → resolves in all modes.
        let edge = report
            .module_resolution_report
            .edges
            .iter()
            .find(|e| e.specifier == "./math.js")
            .expect("relative edge present");
        assert!(
            edge.modes_agree,
            "explicit-extension import agrees across modes"
        );
        for outcome in &edge.outcomes {
            assert_eq!(outcome.resolved_path.as_deref(), Some("math.js"));
        }
    }

    #[test]
    fn ambient_access_surfaces_in_denied_report_with_module_and_span() {
        let pkg = TempPackage::new("ambient_access");
        pkg.write(
            "index.js",
            "import { cfg } from \"./config.js\";\nconst all = cfg;\n",
        );
        pkg.write("config.js", "export const cfg = process.env.SECRET;\n");

        let report = onboard_package(&pkg.root, "index.js", "demo-pkg", ParseGoal::Module);

        assert!(report.analyzable);
        let denied = report
            .denied_ambient_authority
            .iter()
            .find(|d| d.module == "config.js")
            .expect("config.js ambient access reported");
        assert_eq!(denied.accessor.as_deref(), Some("process.env"));
        assert_eq!(denied.implied_capability, Some(RuntimeCapability::EnvRead));
        assert!(
            denied.location.is_some(),
            "ambient finding is span-accurate"
        );
        // The capability profile proposal carries EnvRead attributed to config.js.
        let cap = report
            .capability_profile_proposal
            .capabilities
            .iter()
            .find(|c| c.capability == Some(RuntimeCapability::EnvRead))
            .expect("EnvRead in profile proposal");
        assert!(cap.sites.iter().any(|s| s.module == "config.js"));
    }

    #[test]
    fn extensionless_import_diverges_by_mode_and_is_bounded() {
        let pkg = TempPackage::new("extensionless");
        // Extensionless relative import: resolves under BunCompat probing, fails
        // closed under Native/NodeCompat.
        pkg.write("index.js", "import { y } from \"./dep\";\nconst z = y;\n");
        pkg.write("dep.js", "export const y = 1;\n");

        let report = onboard_package(&pkg.root, "index.js", "demo-pkg", ParseGoal::Module);
        let edge = report
            .module_resolution_report
            .edges
            .iter()
            .find(|e| e.specifier == "./dep")
            .expect("extensionless edge present");
        assert!(
            !edge.modes_agree,
            "modes must diverge on extensionless import"
        );
        let bun = edge
            .outcomes
            .iter()
            .find(|o| o.mode == "bun_compat")
            .expect("bun outcome");
        assert_eq!(bun.resolved_path.as_deref(), Some("dep.js"));
        let native = edge
            .outcomes
            .iter()
            .find(|o| o.mode == "native")
            .expect("native outcome");
        assert!(
            native.resolved_path.is_none(),
            "native fails closed on extensionless import"
        );
        assert!(native.error_code.is_some());
        assert_eq!(report.module_resolution_report.divergent_edge_count, 1);
        // dep.js resolved under BunCompat, so it was reached + analyzed...
        assert!(
            report
                .manifest_proposal
                .modules
                .contains(&"dep.js".to_string())
        );
        // ...but the edge is mode-fragile (unreachable under Native/NodeCompat),
        // so coverage is bounded and the boundary is surfaced explicitly, never
        // buried in the resolution report.
        assert_eq!(report.completeness, PackageIntakeCompleteness::Bounded);
        assert!(
            report
                .completeness_notes
                .iter()
                .any(|note| note.contains("mode-fragile")),
            "mode-fragile edge must be enumerated in completeness notes"
        );
    }

    #[test]
    fn bare_specifier_is_reported_external_not_analyzed() {
        let pkg = TempPackage::new("bare_specifier");
        pkg.write(
            "index.js",
            "import { readFile } from \"fs\";\nimport { z } from \"./local.js\";\nconst a = z;\n",
        );
        pkg.write("local.js", "export const z = 41;\n");

        let report = onboard_package(&pkg.root, "index.js", "demo-pkg", ParseGoal::Module);
        let ext = report
            .external_dependencies
            .iter()
            .find(|d| d.specifier == "fs")
            .expect("bare specifier reported as external");
        assert!(ext.sites.iter().any(|s| s.module == "index.js"));
        // `fs` must NOT appear as an analyzed module.
        assert!(!report.manifest_proposal.modules.iter().any(|m| m == "fs"));
        // Honest completeness note about the unanalyzed external.
        assert!(
            report
                .completeness_notes
                .iter()
                .any(|n| n.contains("external")),
            "external deps must be enumerated in completeness notes"
        );
    }

    #[test]
    fn report_is_deterministic_and_content_addressed() {
        let pkg = TempPackage::new("deterministic");
        pkg.write("index.js", "import { v } from \"./v.js\";\nconst w = v;\n");
        pkg.write("v.js", "export const v = process.env.TOKEN;\n");

        let first = onboard_package(&pkg.root, "index.js", "demo-pkg", ParseGoal::Module);
        let second = onboard_package(&pkg.root, "index.js", "demo-pkg", ParseGoal::Module);

        let first_json = serde_json::to_string(&first).expect("serialize");
        let second_json = serde_json::to_string(&second).expect("serialize");
        assert_eq!(
            first_json, second_json,
            "--format json must be deterministic"
        );
        assert!(
            !first.report_sha256.is_empty(),
            "report is content-addressed"
        );
        assert_eq!(first.report_sha256, second.report_sha256);
    }

    #[test]
    fn unreadable_entry_fails_closed() {
        let pkg = TempPackage::new("unreadable_entry");
        // No entry written.
        let report = onboard_package(&pkg.root, "missing.js", "demo-pkg", ParseGoal::Module);
        assert!(!report.analyzable, "missing entry must fail closed");
        assert_eq!(report.outcome(), PackageIntakeOutcome::Unanalyzable);
        assert_eq!(report.outcome().exit_code(), 2);
        assert!(report.fail_closed_reason.is_some());
        assert_eq!(report.completeness, PackageIntakeCompleteness::Unanalyzable);
    }

    #[test]
    fn no_dynamic_output_overclaims_a_noninterference_proof() {
        let pkg = TempPackage::new("no_overclaim");
        pkg.write("index.js", "export const v = process.env.K;\n");
        let report = onboard_package(&pkg.root, "index.js", "demo-pkg", ParseGoal::Module);

        let forbidden = [
            "proof of noninterference",
            "guarantees",
            "guaranteed",
            "provably secure",
            "always safe",
            "category-defining",
        ];
        let mut blobs = vec![
            report
                .capability_profile_proposal
                .least_authority_suggestion
                .clone(),
        ];
        blobs.extend(report.completeness_notes.iter().cloned());
        blobs.extend(
            report
                .denied_ambient_authority
                .iter()
                .map(|d| d.message.clone()),
        );
        for blob in &blobs {
            let lower = blob.to_ascii_lowercase();
            for phrase in &forbidden {
                assert!(
                    !lower.contains(phrase),
                    "over-claim phrase `{phrase}` found in onboard output: {blob}"
                );
            }
        }
    }
}
