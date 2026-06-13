//! Integration coverage for the package-level intake (E5.T2, `bd-fqlfw.5.2`).
//!
//! Drives the public [`frankenengine_engine::package_intake::onboard_package`]
//! entrypoint that backs `frankenctl onboard <pkg>` against on-disk packages,
//! exercising a transitive ES-module graph, external-dependency classification,
//! per-mode resolution divergence, and the content-addressing / fail-closed
//! contracts. The per-function unit tests live alongside the module; this suite
//! locks the *public* API shape and the multi-hop graph behaviour.

use std::path::{Path, PathBuf};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::package_intake::{
    PackageIntakeCompleteness, PackageIntakeOutcome, onboard_package,
};

/// A deterministic temp package directory (cleaned up on drop). No wall-clock:
/// the test name disambiguates concurrent suites.
struct TempPackage {
    root: PathBuf,
}

impl TempPackage {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("franken_onboard_it_{name}"));
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

    fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for TempPackage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn transitive_graph_is_walked_and_aggregated_with_citations() {
    let pkg = TempPackage::new("transitive_graph");
    // index -> lib/a.js -> lib/b.js ; b reads process.env (ambient) ; index
    // also imports an external bare package.
    pkg.write(
        "index.js",
        "import { a } from \"./lib/a.js\";\nimport { fmt } from \"left-pad\";\nconst out = fmt(a);\n",
    );
    pkg.write(
        "lib/a.js",
        "import { b } from \"./b.js\";\nexport const a = b + 1;\n",
    );
    pkg.write("lib/b.js", "export const b = process.env.SEED;\n");

    let report = onboard_package(pkg.root(), "index.js", "demo-pkg", ParseGoal::Module);

    assert!(report.analyzable, "package is analyzable");
    // All three local modules reachable + analyzed (entry, a, b).
    assert_eq!(
        report.manifest_proposal.module_count, 3,
        "transitive graph fully walked"
    );
    for expected in ["index.js", "lib/a.js", "lib/b.js"] {
        assert!(
            report
                .manifest_proposal
                .modules
                .iter()
                .any(|m| m == expected),
            "module {expected} present in manifest"
        );
    }
    // The bare specifier is external, never analyzed.
    assert!(
        report
            .external_dependencies
            .iter()
            .any(|d| d.specifier == "left-pad"),
        "external bare dependency reported"
    );
    assert!(
        !report
            .manifest_proposal
            .modules
            .iter()
            .any(|m| m == "left-pad"),
        "external dep is not analyzed as a local module"
    );

    // The ambient process.env read in lib/b.js surfaces in the denied report,
    // attributed to the right module with a span.
    let denied = report
        .denied_ambient_authority
        .iter()
        .find(|d| d.module == "lib/b.js")
        .expect("lib/b.js ambient access reported");
    assert_eq!(denied.accessor.as_deref(), Some("process.env"));
    assert!(
        denied.location.is_some(),
        "ambient finding is span-accurate"
    );

    // Capability-profile proposal carries EnvRead attributed to lib/b.js.
    let env_cap = report
        .capability_profile_proposal
        .capabilities
        .iter()
        .find(|c| c.capability == Some(RuntimeCapability::EnvRead))
        .expect("EnvRead in capability profile proposal");
    assert!(
        env_cap.sites.iter().any(|s| s.module == "lib/b.js"),
        "EnvRead attributed to lib/b.js"
    );

    // The explicit-extension relative edges agree across all three modes.
    for edge in &report.module_resolution_report.edges {
        assert!(
            edge.modes_agree,
            "explicit-extension edge {} -> {} should agree across modes",
            edge.from_module, edge.specifier
        );
    }
}

#[test]
fn extensionless_edge_diverges_by_compat_mode() {
    let pkg = TempPackage::new("extensionless_edge");
    pkg.write("index.js", "import { y } from \"./dep\";\nconst z = y;\n");
    pkg.write("dep.js", "export const y = 1;\n");

    let report = onboard_package(pkg.root(), "index.js", "demo-pkg", ParseGoal::Module);

    let edge = report
        .module_resolution_report
        .edges
        .iter()
        .find(|e| e.specifier == "./dep")
        .expect("extensionless edge present");
    assert!(!edge.modes_agree, "extensionless import diverges by mode");
    assert_eq!(report.module_resolution_report.divergent_edge_count, 1);

    let bun = edge
        .outcomes
        .iter()
        .find(|o| o.mode == "bun_compat")
        .unwrap();
    assert_eq!(bun.resolved_path.as_deref(), Some("dep.js"));
    let native = edge.outcomes.iter().find(|o| o.mode == "native").unwrap();
    assert!(
        native.resolved_path.is_none(),
        "native fails closed on extensionless"
    );
    assert!(native.error_code.is_some());

    // Resolved under BunCompat, so dep.js was reached + analyzed.
    assert!(
        report
            .manifest_proposal
            .modules
            .iter()
            .any(|m| m == "dep.js")
    );
}

#[test]
fn report_is_byte_deterministic_and_content_addressed() {
    let pkg = TempPackage::new("deterministic_it");
    pkg.write("index.js", "import { v } from \"./v.js\";\nconst w = v;\n");
    pkg.write("v.js", "export const v = process.env.TOKEN;\n");

    let first = onboard_package(pkg.root(), "index.js", "demo-pkg", ParseGoal::Module);
    let second = onboard_package(pkg.root(), "index.js", "demo-pkg", ParseGoal::Module);

    let first_json = serde_json::to_string(&first).expect("serialize");
    let second_json = serde_json::to_string(&second).expect("serialize");
    assert_eq!(first_json, second_json, "json output is byte-deterministic");
    assert!(
        !first.report_sha256.is_empty(),
        "report is content-addressed"
    );
    assert_eq!(first.report_sha256, second.report_sha256);
}

#[test]
fn missing_entry_fails_closed_with_exit_two() {
    let pkg = TempPackage::new("missing_entry_it");
    let report = onboard_package(
        pkg.root(),
        "does_not_exist.js",
        "demo-pkg",
        ParseGoal::Module,
    );
    assert!(!report.analyzable);
    assert_eq!(report.completeness, PackageIntakeCompleteness::Unanalyzable);
    assert_eq!(report.outcome(), PackageIntakeOutcome::Unanalyzable);
    assert_eq!(report.outcome().exit_code(), 2);
    assert!(report.fail_closed_reason.is_some());
}

#[test]
fn clean_pure_package_reports_complete_and_exits_zero() {
    let pkg = TempPackage::new("clean_pure_it");
    pkg.write(
        "index.js",
        "import { add } from \"./math.js\";\nconst r = add(2, 3);\n",
    );
    pkg.write("math.js", "export function add(a, b) { return a + b; }\n");

    let report = onboard_package(pkg.root(), "index.js", "demo-pkg", ParseGoal::Module);
    assert!(report.analyzable);
    assert!(report.denied_ambient_authority.is_empty());
    assert!(report.ifc_flow_inventory.unsupported_flows.is_empty());
    assert!(report.ifc_flow_inventory.unanalyzable_modules.is_empty());
    assert_eq!(report.completeness, PackageIntakeCompleteness::Complete);
    assert_eq!(report.outcome(), PackageIntakeOutcome::Clean);
    assert_eq!(report.outcome().exit_code(), 0);
}
