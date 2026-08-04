//! Supply-chain behavioral diff over existing package-intake reports.
//!
//! This module backs `frankenctl diff-behavior`: it compares two
//! [`PackageIntakeReport`] values produced by the existing E5 authority/IFC
//! analyzer and emits a bounded, content-addressed delta. It does not introduce
//! a second analyzer or a new authority model; all facts come from
//! `package_intake`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authority_footprint::SourceLocation;
use crate::capability::RuntimeCapability;
use crate::package_intake::{
    DeniedAmbientAccess, ExternalDependency, IfcFinding, ModuleResolutionReport,
    PackageIntakeCompleteness, PackageIntakeReport, ResolutionEdge, UnanalyzableModule,
};

pub const BEHAVIORAL_DIFF_SCHEMA_VERSION: &str = "franken-engine.behavioral-diff.v1";

pub const BEHAVIORAL_DIFF_DISCLAIMER: &str = "behavioral delta for the analyzable SUPPORTED subset; \
not a proof of package safety. External dependencies, dynamic edges, native addons, and unanalyzable modules are listed as boundary growth, not silently covered.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehavioralDiffSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl BehavioralDiffSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehavioralDiffOutcome {
    Unchanged,
    DeltasPresent,
    Unanalyzable,
}

impl BehavioralDiffOutcome {
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Unchanged => 0,
            Self::DeltasPresent => 1,
            Self::Unanalyzable => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehavioralVersionSummary {
    pub label: String,
    pub report_sha256: String,
    pub completeness: PackageIntakeCompleteness,
    pub analyzable: bool,
    pub module_count: usize,
    pub external_dependency_count: usize,
    pub capability_count: usize,
    pub denied_ambient_count: usize,
    pub required_declassification_count: usize,
    pub unsupported_flow_count: usize,
    pub unanalyzable_module_count: usize,
    pub mode_divergent_edge_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CapabilityBehavior {
    pub capability_tag: String,
    pub capability: Option<RuntimeCapability>,
    pub sites: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDelta {
    pub added: Vec<CapabilityBehavior>,
    pub removed: Vec<CapabilityBehavior>,
    pub unchanged: Vec<CapabilityBehavior>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AmbientAuthorityBehavior {
    pub module: String,
    pub accessor: Option<String>,
    pub implied_capability: Option<RuntimeCapability>,
    pub location: Option<SourceLocation>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientAuthorityDelta {
    pub added: Vec<AmbientAuthorityBehavior>,
    pub removed: Vec<AmbientAuthorityBehavior>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IfcBehavior {
    pub kind: String,
    pub module: String,
    pub location: Option<SourceLocation>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfcDelta {
    pub added_required_declassifications: Vec<IfcBehavior>,
    pub removed_required_declassifications: Vec<IfcBehavior>,
    pub added_unsupported_flows: Vec<IfcBehavior>,
    pub removed_unsupported_flows: Vec<IfcBehavior>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExternalDependencyBehavior {
    pub specifier: String,
    pub sites: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnanalyzableModuleBehavior {
    pub module: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResolutionDivergenceBehavior {
    pub from_module: String,
    pub specifier: String,
    pub outcomes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryDelta {
    pub added_external_dependencies: Vec<ExternalDependencyBehavior>,
    pub removed_external_dependencies: Vec<ExternalDependencyBehavior>,
    pub added_unanalyzable_modules: Vec<UnanalyzableModuleBehavior>,
    pub removed_unanalyzable_modules: Vec<UnanalyzableModuleBehavior>,
    pub added_resolution_divergences: Vec<ResolutionDivergenceBehavior>,
    pub removed_resolution_divergences: Vec<ResolutionDivergenceBehavior>,
    pub completeness_changed: bool,
    pub boundary_grew: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehavioralDiffReport {
    pub schema_version: String,
    pub before: BehavioralVersionSummary,
    pub after: BehavioralVersionSummary,
    pub disclaimer: String,
    pub severity: BehavioralDiffSeverity,
    pub severity_rationale: Vec<String>,
    pub capability_delta: CapabilityDelta,
    pub ambient_authority_delta: AmbientAuthorityDelta,
    pub ifc_delta: IfcDelta,
    pub boundary_delta: BoundaryDelta,
    pub delta_count: usize,
    pub report_sha256: String,
}

impl BehavioralDiffReport {
    pub fn outcome(&self) -> BehavioralDiffOutcome {
        if !self.before.analyzable || !self.after.analyzable {
            BehavioralDiffOutcome::Unanalyzable
        } else if self.delta_count == 0 && !self.boundary_delta.completeness_changed {
            BehavioralDiffOutcome::Unchanged
        } else {
            BehavioralDiffOutcome::DeltasPresent
        }
    }

    fn finalize(mut self) -> Self {
        self.report_sha256.clear();
        let body = serde_json::to_vec(&self).unwrap_or_default();
        self.report_sha256 = hex::encode(Sha256::digest(&body));
        self
    }

    pub fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "behavioral diff: {} -> {}\n",
            self.before.label, self.after.label
        ));
        out.push_str(&format!("  ({})\n", self.disclaimer));
        out.push_str(&format!("  severity: {}\n", self.severity.as_str()));
        for rationale in &self.severity_rationale {
            out.push_str(&format!("  rationale: {rationale}\n"));
        }
        render_capability_delta(&mut out, &self.capability_delta);
        render_ambient_delta(&mut out, &self.ambient_authority_delta);
        render_ifc_delta(&mut out, &self.ifc_delta);
        render_boundary_delta(&mut out, &self.boundary_delta);
        out.push_str(&format!("  report_sha256: {}\n", self.report_sha256));
        out
    }
}

pub fn diff_package_behavior(
    before_label: &str,
    before: &PackageIntakeReport,
    after_label: &str,
    after: &PackageIntakeReport,
) -> BehavioralDiffReport {
    let before_summary = summarize_version(before_label, before);
    let after_summary = summarize_version(after_label, after);

    let capability_delta = diff_capabilities(before, after);
    let ambient_authority_delta = diff_ambient_authority(before, after);
    let ifc_delta = diff_ifc(before, after);
    let boundary_delta = diff_boundary(before, after);

    let delta_count = capability_delta.added.len()
        + capability_delta.removed.len()
        + ambient_authority_delta.added.len()
        + ambient_authority_delta.removed.len()
        + ifc_delta.added_required_declassifications.len()
        + ifc_delta.removed_required_declassifications.len()
        + ifc_delta.added_unsupported_flows.len()
        + ifc_delta.removed_unsupported_flows.len()
        + boundary_delta.added_external_dependencies.len()
        + boundary_delta.removed_external_dependencies.len()
        + boundary_delta.added_unanalyzable_modules.len()
        + boundary_delta.removed_unanalyzable_modules.len()
        + boundary_delta.added_resolution_divergences.len()
        + boundary_delta.removed_resolution_divergences.len();

    let (severity, severity_rationale) = classify_severity(
        &before_summary,
        &after_summary,
        &capability_delta,
        &ambient_authority_delta,
        &ifc_delta,
        &boundary_delta,
        delta_count,
    );

    BehavioralDiffReport {
        schema_version: BEHAVIORAL_DIFF_SCHEMA_VERSION.to_string(),
        before: before_summary,
        after: after_summary,
        disclaimer: BEHAVIORAL_DIFF_DISCLAIMER.to_string(),
        severity,
        severity_rationale,
        capability_delta,
        ambient_authority_delta,
        ifc_delta,
        boundary_delta,
        delta_count,
        report_sha256: String::new(),
    }
    .finalize()
}

fn summarize_version(label: &str, report: &PackageIntakeReport) -> BehavioralVersionSummary {
    BehavioralVersionSummary {
        label: label.to_string(),
        report_sha256: report.report_sha256.clone(),
        completeness: report.completeness,
        analyzable: report.analyzable,
        module_count: report.manifest_proposal.module_count,
        external_dependency_count: report.manifest_proposal.external_count,
        capability_count: report.capability_profile_proposal.capabilities.len(),
        denied_ambient_count: report.denied_ambient_authority.len(),
        required_declassification_count: report.ifc_flow_inventory.required_declassifications.len(),
        unsupported_flow_count: report.ifc_flow_inventory.unsupported_flows.len(),
        unanalyzable_module_count: report.ifc_flow_inventory.unanalyzable_modules.len(),
        mode_divergent_edge_count: report.module_resolution_report.divergent_edge_count,
    }
}

fn diff_capabilities(before: &PackageIntakeReport, after: &PackageIntakeReport) -> CapabilityDelta {
    let before_map = capability_map(before);
    let after_map = capability_map(after);
    let before_keys: BTreeSet<String> = before_map.keys().cloned().collect();
    let after_keys: BTreeSet<String> = after_map.keys().cloned().collect();

    CapabilityDelta {
        added: after_keys
            .difference(&before_keys)
            .filter_map(|tag| after_map.get(tag).cloned())
            .collect(),
        removed: before_keys
            .difference(&after_keys)
            .filter_map(|tag| before_map.get(tag).cloned())
            .collect(),
        unchanged: before_keys
            .intersection(&after_keys)
            .filter_map(|tag| after_map.get(tag).cloned())
            .collect(),
    }
}

fn capability_map(report: &PackageIntakeReport) -> BTreeMap<String, CapabilityBehavior> {
    report
        .capability_profile_proposal
        .capabilities
        .iter()
        .map(|capability| {
            let sites = capability
                .sites
                .iter()
                .map(|site| format_site(&site.module, site.location.as_ref()))
                .collect();
            (
                capability.capability_tag.clone(),
                CapabilityBehavior {
                    capability_tag: capability.capability_tag.clone(),
                    capability: capability.capability,
                    sites,
                },
            )
        })
        .collect()
}

fn diff_ambient_authority(
    before: &PackageIntakeReport,
    after: &PackageIntakeReport,
) -> AmbientAuthorityDelta {
    let before_set = ambient_set(&before.denied_ambient_authority);
    let after_set = ambient_set(&after.denied_ambient_authority);
    AmbientAuthorityDelta {
        added: after_set.difference(&before_set).cloned().collect(),
        removed: before_set.difference(&after_set).cloned().collect(),
    }
}

fn ambient_set(values: &[DeniedAmbientAccess]) -> BTreeSet<AmbientAuthorityBehavior> {
    values
        .iter()
        .map(|value| AmbientAuthorityBehavior {
            module: value.module.clone(),
            accessor: value.accessor.clone(),
            implied_capability: value.implied_capability,
            location: value.location.clone(),
            message: value.message.clone(),
        })
        .collect()
}

fn diff_ifc(before: &PackageIntakeReport, after: &PackageIntakeReport) -> IfcDelta {
    let before_declass = ifc_set(
        "required_declassification",
        &before.ifc_flow_inventory.required_declassifications,
    );
    let after_declass = ifc_set(
        "required_declassification",
        &after.ifc_flow_inventory.required_declassifications,
    );
    let before_unsupported = ifc_set(
        "unsupported_flow",
        &before.ifc_flow_inventory.unsupported_flows,
    );
    let after_unsupported = ifc_set(
        "unsupported_flow",
        &after.ifc_flow_inventory.unsupported_flows,
    );

    IfcDelta {
        added_required_declassifications: after_declass
            .difference(&before_declass)
            .cloned()
            .collect(),
        removed_required_declassifications: before_declass
            .difference(&after_declass)
            .cloned()
            .collect(),
        added_unsupported_flows: after_unsupported
            .difference(&before_unsupported)
            .cloned()
            .collect(),
        removed_unsupported_flows: before_unsupported
            .difference(&after_unsupported)
            .cloned()
            .collect(),
    }
}

fn ifc_set(kind: &str, values: &[IfcFinding]) -> BTreeSet<IfcBehavior> {
    values
        .iter()
        .map(|value| IfcBehavior {
            kind: kind.to_string(),
            module: value.module.clone(),
            location: value.location.clone(),
            message: value.message.clone(),
        })
        .collect()
}

fn diff_boundary(before: &PackageIntakeReport, after: &PackageIntakeReport) -> BoundaryDelta {
    let before_external = external_set(&before.external_dependencies);
    let after_external = external_set(&after.external_dependencies);
    let before_unanalyzable = unanalyzable_set(&before.ifc_flow_inventory.unanalyzable_modules);
    let after_unanalyzable = unanalyzable_set(&after.ifc_flow_inventory.unanalyzable_modules);
    let before_divergence = divergence_set(&before.module_resolution_report);
    let after_divergence = divergence_set(&after.module_resolution_report);

    let added_external_dependencies: Vec<_> = after_external
        .difference(&before_external)
        .cloned()
        .collect();
    let removed_external_dependencies: Vec<_> = before_external
        .difference(&after_external)
        .cloned()
        .collect();
    let added_unanalyzable_modules: Vec<_> = after_unanalyzable
        .difference(&before_unanalyzable)
        .cloned()
        .collect();
    let removed_unanalyzable_modules: Vec<_> = before_unanalyzable
        .difference(&after_unanalyzable)
        .cloned()
        .collect();
    let added_resolution_divergences: Vec<_> = after_divergence
        .difference(&before_divergence)
        .cloned()
        .collect();
    let removed_resolution_divergences: Vec<_> = before_divergence
        .difference(&after_divergence)
        .cloned()
        .collect();
    let completeness_changed = before.completeness != after.completeness;
    let boundary_grew = after.external_dependencies.len() > before.external_dependencies.len()
        || after.ifc_flow_inventory.unanalyzable_modules.len()
            > before.ifc_flow_inventory.unanalyzable_modules.len()
        || after.module_resolution_report.divergent_edge_count
            > before.module_resolution_report.divergent_edge_count
        || is_less_complete(before.completeness, after.completeness);

    BoundaryDelta {
        added_external_dependencies,
        removed_external_dependencies,
        added_unanalyzable_modules,
        removed_unanalyzable_modules,
        added_resolution_divergences,
        removed_resolution_divergences,
        completeness_changed,
        boundary_grew,
    }
}

fn external_set(values: &[ExternalDependency]) -> BTreeSet<ExternalDependencyBehavior> {
    values
        .iter()
        .map(|value| ExternalDependencyBehavior {
            specifier: value.specifier.clone(),
            sites: value
                .sites
                .iter()
                .map(|site| format_site(&site.module, site.location.as_ref()))
                .collect(),
        })
        .collect()
}

fn unanalyzable_set(values: &[UnanalyzableModule]) -> BTreeSet<UnanalyzableModuleBehavior> {
    values
        .iter()
        .map(|value| UnanalyzableModuleBehavior {
            module: value.module.clone(),
            reason: value.reason.clone(),
        })
        .collect()
}

fn divergence_set(report: &ModuleResolutionReport) -> BTreeSet<ResolutionDivergenceBehavior> {
    report
        .edges
        .iter()
        .filter(|edge| !edge.modes_agree)
        .map(resolution_divergence_behavior)
        .collect()
}

fn resolution_divergence_behavior(edge: &ResolutionEdge) -> ResolutionDivergenceBehavior {
    ResolutionDivergenceBehavior {
        from_module: edge.from_module.clone(),
        specifier: edge.specifier.clone(),
        outcomes: edge
            .outcomes
            .iter()
            .map(|outcome| {
                let target = outcome
                    .resolved_path
                    .clone()
                    .or_else(|| outcome.error_code.clone())
                    .unwrap_or_else(|| "unresolved".to_string());
                format!("{}={target}", outcome.mode)
            })
            .collect(),
    }
}

fn classify_severity(
    before: &BehavioralVersionSummary,
    after: &BehavioralVersionSummary,
    capability_delta: &CapabilityDelta,
    ambient_delta: &AmbientAuthorityDelta,
    ifc_delta: &IfcDelta,
    boundary_delta: &BoundaryDelta,
    delta_count: usize,
) -> (BehavioralDiffSeverity, Vec<String>) {
    let mut severity = BehavioralDiffSeverity::None;
    let mut rationale = Vec::new();

    if !before.analyzable || !after.analyzable {
        severity = severity.max(BehavioralDiffSeverity::High);
        rationale.push(
            "one side is unanalyzable; the diff is a fail-closed boundary signal".to_string(),
        );
    }

    for capability in &capability_delta.added {
        match capability.capability {
            Some(RuntimeCapability::ProcessSpawn) => {
                severity = severity.max(BehavioralDiffSeverity::Critical);
                rationale.push("new ProcessSpawn capability requirement".to_string());
            }
            Some(RuntimeCapability::NetworkEgress) => {
                severity = severity.max(BehavioralDiffSeverity::Critical);
                rationale.push("new NetworkEgress capability requirement".to_string());
            }
            Some(RuntimeCapability::EnvRead) => {
                severity = severity.max(BehavioralDiffSeverity::High);
                rationale.push("new EnvRead capability requirement".to_string());
            }
            Some(_) | None => {
                severity = severity.max(BehavioralDiffSeverity::Medium);
            }
        }
    }

    if !ifc_delta.added_required_declassifications.is_empty() {
        severity = severity.max(BehavioralDiffSeverity::High);
        rationale.push("new signed declassification requirement".to_string());
    }
    if !ifc_delta.added_unsupported_flows.is_empty() {
        severity = severity.max(BehavioralDiffSeverity::High);
        rationale.push("new denied IFC flow".to_string());
    }
    if !ambient_delta.added.is_empty() {
        severity = severity.max(BehavioralDiffSeverity::Medium);
        rationale.push("new denied ambient-authority access".to_string());
    }
    if boundary_delta.boundary_grew {
        severity = severity.max(BehavioralDiffSeverity::Medium);
        rationale.push("unanalyzed or mode-fragile surface grew".to_string());
    }
    if delta_count > 0 && severity == BehavioralDiffSeverity::None {
        severity = BehavioralDiffSeverity::Low;
        rationale.push("only removals or non-security deltas detected".to_string());
    }
    if rationale.is_empty() {
        rationale.push("no behavioral delta detected across the supported subset".to_string());
    }
    rationale.sort();
    rationale.dedup();
    (severity, rationale)
}

fn is_less_complete(before: PackageIntakeCompleteness, after: PackageIntakeCompleteness) -> bool {
    completeness_rank(after) > completeness_rank(before)
}

fn completeness_rank(value: PackageIntakeCompleteness) -> u8 {
    match value {
        PackageIntakeCompleteness::Complete => 0,
        PackageIntakeCompleteness::Bounded => 1,
        PackageIntakeCompleteness::Unanalyzable => 2,
    }
}

fn format_site(module: &str, location: Option<&SourceLocation>) -> String {
    match location {
        Some(location) => format!("{module}@{location}"),
        None => format!("{module}@<no span>"),
    }
}

fn render_capability_delta(out: &mut String, delta: &CapabilityDelta) {
    if delta.added.is_empty() && delta.removed.is_empty() {
        out.push_str("  capability delta: none\n");
        return;
    }
    if !delta.added.is_empty() {
        out.push_str("  added capabilities:\n");
        for capability in &delta.added {
            out.push_str(&format!(
                "    - {} @ {}\n",
                capability.capability_tag,
                capability.sites.join(", ")
            ));
        }
    }
    if !delta.removed.is_empty() {
        out.push_str("  removed capabilities:\n");
        for capability in &delta.removed {
            out.push_str(&format!("    - {}\n", capability.capability_tag));
        }
    }
}

fn render_ambient_delta(out: &mut String, delta: &AmbientAuthorityDelta) {
    if delta.added.is_empty() && delta.removed.is_empty() {
        out.push_str("  ambient-authority delta: none\n");
        return;
    }
    for added in &delta.added {
        out.push_str(&format!(
            "  added ambient denial: {} {:?} {}\n",
            added.module,
            added.accessor,
            added
                .implied_capability
                .map(|capability| capability.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ));
    }
    for removed in &delta.removed {
        out.push_str(&format!(
            "  removed ambient denial: {} {:?}\n",
            removed.module, removed.accessor
        ));
    }
}

fn render_ifc_delta(out: &mut String, delta: &IfcDelta) {
    if delta.added_required_declassifications.is_empty()
        && delta.removed_required_declassifications.is_empty()
        && delta.added_unsupported_flows.is_empty()
        && delta.removed_unsupported_flows.is_empty()
    {
        out.push_str("  IFC delta: none\n");
        return;
    }
    for finding in &delta.added_required_declassifications {
        out.push_str(&format!(
            "  added declassification: {} {}\n",
            finding.module, finding.message
        ));
    }
    for finding in &delta.added_unsupported_flows {
        out.push_str(&format!(
            "  added unsupported flow: {} {}\n",
            finding.module, finding.message
        ));
    }
}

fn render_boundary_delta(out: &mut String, delta: &BoundaryDelta) {
    if !delta.completeness_changed
        && delta.added_external_dependencies.is_empty()
        && delta.removed_external_dependencies.is_empty()
        && delta.added_unanalyzable_modules.is_empty()
        && delta.removed_unanalyzable_modules.is_empty()
        && delta.added_resolution_divergences.is_empty()
        && delta.removed_resolution_divergences.is_empty()
    {
        out.push_str("  boundary delta: none\n");
        return;
    }
    if delta.completeness_changed {
        out.push_str("  boundary delta: completeness changed\n");
    }
    for dep in &delta.added_external_dependencies {
        out.push_str(&format!("  added external dependency: {}\n", dep.specifier));
    }
    for module in &delta.added_unanalyzable_modules {
        out.push_str(&format!(
            "  added unanalyzable module: {} ({})\n",
            module.module, module.reason
        ));
    }
    for edge in &delta.added_resolution_divergences {
        out.push_str(&format!(
            "  added resolution divergence: {} imports `{}`\n",
            edge.from_module, edge.specifier
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::ParseGoal;
    use crate::package_intake::onboard_package;

    struct TempPackage {
        root: std::path::PathBuf,
    }

    impl TempPackage {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!("franken_behavior_diff_{name}"));
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
    fn added_network_capability_is_critical_and_content_addressed() {
        let before_pkg = TempPackage::new("before");
        before_pkg.write("index.js", "export const value = 1;\n");
        let after_pkg = TempPackage::new("after");
        after_pkg.write(
            "index.js",
            "export const out = hostcall<\"network_egress\">(\"https://example.test\");\n",
        );
        let before = onboard_package(&before_pkg.root, "index.js", "before", ParseGoal::Module);
        let after = onboard_package(&after_pkg.root, "index.js", "after", ParseGoal::Module);

        let diff = diff_package_behavior("before", &before, "after", &after);

        assert_eq!(diff.severity, BehavioralDiffSeverity::Critical);
        // The typed `hostcall<"network_egress">` surfaces TWO required
        // capabilities: `network_egress` (the declared effect, via the
        // ts-normalization capability intent) and `hostcall.invoke` (the generic
        // privilege to make any hostcall, from the lowered invoke op). Both are
        // legitimate deltas for a supply-chain behavioral diff, so assert that
        // NetworkEgress is present among the added set rather than pinning a
        // single-capability count (bd-bu6dt: the prior `len()==1`/`added[0]`
        // expectation predated the `hostcall.invoke` companion capability).
        assert_eq!(diff.capability_delta.added.len(), 2);
        assert!(
            diff.capability_delta
                .added
                .iter()
                .any(|c| c.capability == Some(RuntimeCapability::NetworkEgress)),
            "expected NetworkEgress among added capabilities, got {:?}",
            diff.capability_delta.added
        );
        assert_eq!(diff.outcome(), BehavioralDiffOutcome::DeltasPresent);
        assert_eq!(diff.outcome().exit_code(), 1);
        assert_eq!(diff.report_sha256.len(), 64);
    }

    #[test]
    fn identical_reports_are_unchanged() {
        let pkg = TempPackage::new("same");
        pkg.write("index.js", "export const value = 1;\n");
        let report = onboard_package(&pkg.root, "index.js", "same", ParseGoal::Module);

        let diff = diff_package_behavior("before", &report, "after", &report);

        assert_eq!(diff.severity, BehavioralDiffSeverity::None);
        assert_eq!(diff.delta_count, 0);
        assert_eq!(diff.outcome(), BehavioralDiffOutcome::Unchanged);
    }
}
