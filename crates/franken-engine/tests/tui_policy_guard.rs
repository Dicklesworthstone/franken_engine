#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

const POLICY_ID: &str = "policy-frankentui-first-v1";
const TRACE_PREFIX: &str = "trace-tui-policy";
const COMPONENT: &str = "tui_policy_guard";

const FORBIDDEN_TUI_DEPENDENCIES: &[&str] = &[
    "crossterm",
    "ratatui",
    "cursive",
    "termion",
    "tuirealm",
    "tui-realm",
    "console_engine",
    "tui",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestInput {
    path: String,
    content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExceptionDocumentInput {
    path: String,
    content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExceptionScope {
    Dependency(String),
    ModulePattern(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedException {
    scopes: Vec<ExceptionScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PolicyGuardEvent {
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    subject: String,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyViolation {
    error_code: &'static str,
    subject: String,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyGuardReport {
    events: Vec<PolicyGuardEvent>,
    violations: Vec<PolicyViolation>,
}

impl PolicyGuardReport {
    fn as_jsonl(&self) -> String {
        let mut out = String::new();
        for event in &self.events {
            let line =
                serde_json::to_string(event).expect("policy guard event serialization should work");
            out.push_str(&line);
            out.push('\n');
        }
        out
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn dependency_section(section: &str) -> bool {
    section == "dependencies"
        || section == "dev-dependencies"
        || section == "build-dependencies"
        || section == "workspace.dependencies"
        || section.ends_with(".dependencies")
        || section.ends_with(".dev-dependencies")
        || section.ends_with(".build-dependencies")
}

fn dependency_names(manifest: &str) -> Vec<String> {
    let mut section = String::new();
    let mut deps = Vec::new();

    for raw_line in manifest.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }
        if !dependency_section(section.as_str()) {
            continue;
        }

        let Some((raw_key, _raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim().trim_matches('"');
        if key.is_empty() {
            continue;
        }
        deps.push(key.to_string());
    }

    deps
}

fn parse_exception_docs(docs: &[ExceptionDocumentInput]) -> Vec<ParsedException> {
    docs.iter().filter_map(parse_exception_doc).collect()
}

fn parse_exception_doc(doc: &ExceptionDocumentInput) -> Option<ParsedException> {
    let normalized_path = doc.path.replace('\\', "/");
    if !normalized_path.starts_with("docs/adr/exceptions/ADR-EXCEPTION-TUI-")
        || !normalized_path.ends_with(".md")
    {
        return None;
    }

    let mut approved = false;
    let mut scopes = Vec::new();

    for raw_line in doc.content.lines() {
        let normalized = raw_line.trim().trim_start_matches('-').trim();
        if normalized.eq_ignore_ascii_case("Status: Approved") {
            approved = true;
            continue;
        }

        let lower = normalized.to_ascii_lowercase();
        if let Some(scope_raw) = lower.strip_prefix("scope:") {
            let scope_raw = scope_raw.trim();
            if let Some(dep) = scope_raw.strip_prefix("dependency:") {
                scopes.push(ExceptionScope::Dependency(dep.trim().to_string()));
            } else if let Some(path_pattern) = scope_raw.strip_prefix("module:") {
                scopes.push(ExceptionScope::ModulePattern(
                    path_pattern.trim().to_string(),
                ));
            }
        }
    }

    if approved && !scopes.is_empty() {
        Some(ParsedException { scopes })
    } else {
        None
    }
}

fn is_forbidden_tui_dependency(dep: &str) -> bool {
    let dep = dep.to_ascii_lowercase();
    if dep.starts_with("frankentui") {
        return false;
    }
    FORBIDDEN_TUI_DEPENDENCIES
        .iter()
        .any(|forbidden| *forbidden == dep)
}

fn dependency_exception_allowed(dep: &str, exceptions: &[ParsedException]) -> bool {
    let dep = dep.to_ascii_lowercase();
    exceptions.iter().any(|exception| {
        exception
            .scopes
            .iter()
            .any(|scope| matches!(scope, ExceptionScope::Dependency(allowed) if *allowed == dep))
    })
}

fn is_blocked_local_tui_module(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    if !normalized.ends_with(".rs") {
        return false;
    }
    if !normalized.starts_with("crates/") {
        return false;
    }
    if !normalized.contains("/src/") {
        return false;
    }
    if normalized.contains("frankentui") {
        return false;
    }
    normalized.contains("tui")
        || normalized.contains("ratatui")
        || normalized.contains("crossterm")
        || normalized.contains("cursive")
        || normalized.contains("termion")
}

fn pattern_match(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        value == pattern
    }
}

fn module_exception_allowed(path: &str, exceptions: &[ParsedException]) -> bool {
    exceptions.iter().any(|exception| {
        exception.scopes.iter().any(|scope| match scope {
            ExceptionScope::ModulePattern(pattern) => pattern_match(pattern.as_str(), path),
            ExceptionScope::Dependency(_) => false,
        })
    })
}

fn evaluate_guard(
    manifests: &[ManifestInput],
    module_paths: &[String],
    exception_docs: &[ExceptionDocumentInput],
) -> PolicyGuardReport {
    let mut events = Vec::new();
    let mut violations = Vec::new();
    let mut next_id = 1usize;
    let exceptions = parse_exception_docs(exception_docs);

    for manifest in manifests {
        for dep in dependency_names(manifest.content.as_str()) {
            if !is_forbidden_tui_dependency(dep.as_str()) {
                continue;
            }
            if dependency_exception_allowed(dep.as_str(), &exceptions) {
                events.push(PolicyGuardEvent {
                    trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
                    decision_id: format!("decision-{next_id:04}"),
                    policy_id: POLICY_ID.to_string(),
                    component: COMPONENT.to_string(),
                    event: "dependency_scan".to_string(),
                    outcome: "pass".to_string(),
                    error_code: None,
                    subject: dep,
                    detail: format!(
                        "forbidden dependency allowed via approved ADR exception ({})",
                        manifest.path
                    ),
                });
                next_id += 1;
                continue;
            }

            let detail = format!(
                "forbidden local TUI framework dependency found in {}",
                manifest.path
            );
            events.push(PolicyGuardEvent {
                trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
                decision_id: format!("decision-{next_id:04}"),
                policy_id: POLICY_ID.to_string(),
                component: COMPONENT.to_string(),
                event: "dependency_scan".to_string(),
                outcome: "fail".to_string(),
                error_code: Some("FE-TUI-DEPENDENCY-FORBIDDEN".to_string()),
                subject: dep.clone(),
                detail: detail.clone(),
            });
            next_id += 1;

            violations.push(PolicyViolation {
                error_code: "FE-TUI-DEPENDENCY-FORBIDDEN",
                subject: dep,
                detail,
            });
        }
    }

    for path in module_paths {
        if !is_blocked_local_tui_module(path) {
            continue;
        }
        if module_exception_allowed(path.as_str(), &exceptions) {
            events.push(PolicyGuardEvent {
                trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
                decision_id: format!("decision-{next_id:04}"),
                policy_id: POLICY_ID.to_string(),
                component: COMPONENT.to_string(),
                event: "module_scan".to_string(),
                outcome: "pass".to_string(),
                error_code: None,
                subject: path.clone(),
                detail: "blocked module pattern allowed via approved ADR exception".to_string(),
            });
            next_id += 1;
            continue;
        }

        let detail = "blocked local interactive TUI module path detected".to_string();
        events.push(PolicyGuardEvent {
            trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
            decision_id: format!("decision-{next_id:04}"),
            policy_id: POLICY_ID.to_string(),
            component: COMPONENT.to_string(),
            event: "module_scan".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("FE-TUI-MODULE-FORBIDDEN".to_string()),
            subject: path.clone(),
            detail: detail.clone(),
        });
        next_id += 1;

        violations.push(PolicyViolation {
            error_code: "FE-TUI-MODULE-FORBIDDEN",
            subject: path.clone(),
            detail,
        });
    }

    events.push(PolicyGuardEvent {
        trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
        decision_id: format!("decision-{next_id:04}"),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "guard_summary".to_string(),
        outcome: if violations.is_empty() {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if violations.is_empty() {
            None
        } else {
            Some("FE-TUI-GUARD-BLOCKED".to_string())
        },
        subject: "frankenengine-repo".to_string(),
        detail: format!("violations={}", violations.len()),
    });

    PolicyGuardReport { events, violations }
}

fn collect_rs_files(root: &Path, out: &mut Vec<String>) {
    if !root.exists() {
        return;
    }
    let entries =
        fs::read_dir(root).unwrap_or_else(|err| panic!("failed to read {}: {err}", root.display()));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|err| panic!("failed to read dir entry in {}: {err}", root.display()));
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(path.as_path(), out);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            let relative = path
                .strip_prefix(repo_root())
                .unwrap_or_else(|_| panic!("path must be under repo root: {}", path.display()))
                .to_string_lossy()
                .replace('\\', "/");
            out.push(relative);
        }
    }
}

fn repo_manifests() -> Vec<ManifestInput> {
    let root = repo_root();
    let manifest_paths = [
        root.join("Cargo.toml"),
        root.join("crates/franken-engine/Cargo.toml"),
        root.join("crates/franken-extension-host/Cargo.toml"),
    ];

    let mut manifests = Vec::new();
    for path in manifest_paths {
        if !path.exists() {
            continue;
        }
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let relative = path
            .strip_prefix(&root)
            .unwrap_or_else(|_| panic!("path must be under repo root: {}", path.display()))
            .to_string_lossy()
            .replace('\\', "/");
        manifests.push(ManifestInput {
            path: relative,
            content,
        });
    }
    manifests
}

fn repo_exception_docs() -> Vec<ExceptionDocumentInput> {
    let root = repo_root();
    let exceptions_root = root.join("docs/adr/exceptions");
    if !exceptions_root.exists() {
        return Vec::new();
    }

    let mut docs = Vec::new();
    let entries = fs::read_dir(&exceptions_root)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", exceptions_root.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|err| {
            panic!(
                "failed to read dir entry in {}: {err}",
                exceptions_root.display()
            )
        });
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let relative = path
            .strip_prefix(&root)
            .unwrap_or_else(|_| panic!("path must be under repo root: {}", path.display()))
            .to_string_lossy()
            .replace('\\', "/");
        docs.push(ExceptionDocumentInput {
            path: relative,
            content,
        });
    }
    docs
}

#[test]
fn ratatui_dependency_is_blocked_without_approved_adr_exception() {
    let manifests = vec![ManifestInput {
        path: "crates/franken-engine/Cargo.toml".to_string(),
        content: r#"
[dependencies]
ratatui = "0.29"
"#
        .to_string(),
    }];

    let report = evaluate_guard(&manifests, &[], &[]);

    assert_eq!(report.violations.len(), 1);
    assert_eq!(
        report.violations[0].error_code,
        "FE-TUI-DEPENDENCY-FORBIDDEN"
    );
    assert!(report.events.iter().any(|event| {
        event.event == "dependency_scan"
            && event.outcome == "fail"
            && event.error_code.as_deref() == Some("FE-TUI-DEPENDENCY-FORBIDDEN")
    }));
}

#[test]
fn frankentui_dependency_is_allowed() {
    let manifests = vec![ManifestInput {
        path: "crates/franken-engine/Cargo.toml".to_string(),
        content: r#"
[dependencies]
frankentui = "0.1"
"#
        .to_string(),
    }];

    let report = evaluate_guard(&manifests, &[], &[]);

    assert!(report.violations.is_empty());
    assert!(report.events.iter().any(|event| {
        event.event == "guard_summary"
            && event.outcome == "pass"
            && event.error_code.is_none()
            && event.detail == "violations=0"
    }));
}

#[test]
fn approved_adr_exception_can_bypass_forbidden_dependency() {
    let manifests = vec![ManifestInput {
        path: "crates/franken-engine/Cargo.toml".to_string(),
        content: r#"
[dependencies]
ratatui = "0.29"
"#
        .to_string(),
    }];
    let exception_docs = vec![ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-EXCEPTION-TUI-0001.md".to_string(),
        content: r#"
# ADR Exception
Status: Approved
Scope: dependency:ratatui
"#
        .to_string(),
    }];

    let report = evaluate_guard(&manifests, &[], &exception_docs);

    assert!(report.violations.is_empty());
    assert!(report.events.iter().any(|event| {
        event.event == "dependency_scan"
            && event.outcome == "pass"
            && event.error_code.is_none()
            && event.subject == "ratatui"
    }));
}

#[test]
fn module_pattern_violation_is_blocked_without_exception() {
    let report = evaluate_guard(
        &[],
        &[String::from(
            "crates/franken-engine/src/local_tui_dashboard.rs",
        )],
        &[],
    );

    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations[0].error_code, "FE-TUI-MODULE-FORBIDDEN");
    assert!(report.events.iter().any(|event| {
        event.event == "module_scan"
            && event.outcome == "fail"
            && event.error_code.as_deref() == Some("FE-TUI-MODULE-FORBIDDEN")
    }));
}

#[test]
fn repository_tui_policy_guard_passes() {
    let manifests = repo_manifests();

    let mut module_paths = Vec::new();
    collect_rs_files(repo_root().join("crates").as_path(), &mut module_paths);
    module_paths.sort();

    let exceptions = repo_exception_docs();
    let report = evaluate_guard(&manifests, &module_paths, &exceptions);

    assert!(
        report.violations.is_empty(),
        "TUI policy guard violations detected:\n{}",
        report.as_jsonl()
    );
    assert!(report.events.iter().any(|event| {
        event.event == "guard_summary"
            && event.outcome == "pass"
            && event.error_code.is_none()
            && event.policy_id == POLICY_ID
            && event.component == COMPONENT
    }));
}

// ---------- constants ----------

#[test]
fn policy_constants_are_nonempty() {
    assert!(!POLICY_ID.is_empty());
    assert!(!TRACE_PREFIX.is_empty());
    assert!(!COMPONENT.is_empty());
}

#[test]
fn forbidden_tui_deps_is_nonempty() {
    assert!(!FORBIDDEN_TUI_DEPENDENCIES.is_empty());
    assert!(FORBIDDEN_TUI_DEPENDENCIES.contains(&"ratatui"));
    assert!(FORBIDDEN_TUI_DEPENDENCIES.contains(&"crossterm"));
}

// ---------- dependency_section ----------

#[test]
fn dependency_section_recognizes_standard_sections() {
    assert!(dependency_section("dependencies"));
    assert!(dependency_section("dev-dependencies"));
    assert!(dependency_section("build-dependencies"));
    assert!(dependency_section("workspace.dependencies"));
    assert!(dependency_section(
        "target.x86_64-unknown-linux-gnu.dependencies"
    ));
}

#[test]
fn dependency_section_rejects_non_dep_sections() {
    assert!(!dependency_section("package"));
    assert!(!dependency_section("features"));
    assert!(!dependency_section("profile.release"));
}

// ---------- dependency_names ----------

#[test]
fn dependency_names_extracts_deps_from_toml() {
    let toml = r#"
[package]
name = "test"

[dependencies]
serde = "1"
tokio = { version = "1" }

[dev-dependencies]
insta = "1.34"
"#;
    let deps = dependency_names(toml);
    assert!(deps.contains(&"serde".to_string()));
    assert!(deps.contains(&"tokio".to_string()));
    assert!(deps.contains(&"insta".to_string()));
    assert!(!deps.contains(&"name".to_string()));
}

#[test]
fn dependency_names_handles_empty_input() {
    let deps = dependency_names("");
    assert!(deps.is_empty());
}

// ---------- is_forbidden_tui_dependency ----------

#[test]
fn is_forbidden_tui_dependency_blocks_known() {
    assert!(is_forbidden_tui_dependency("ratatui"));
    assert!(is_forbidden_tui_dependency("crossterm"));
    assert!(is_forbidden_tui_dependency("tui"));
    assert!(is_forbidden_tui_dependency("cursive"));
}

#[test]
fn is_forbidden_tui_dependency_allows_frankentui() {
    assert!(!is_forbidden_tui_dependency("frankentui"));
    assert!(!is_forbidden_tui_dependency("frankentui-core"));
}

#[test]
fn is_forbidden_tui_dependency_allows_unrelated() {
    assert!(!is_forbidden_tui_dependency("serde"));
    assert!(!is_forbidden_tui_dependency("tokio"));
}

// ---------- is_blocked_local_tui_module ----------

#[test]
fn is_blocked_local_tui_module_blocks_tui_in_src() {
    assert!(is_blocked_local_tui_module(
        "crates/foo/src/tui_dashboard.rs"
    ));
    assert!(is_blocked_local_tui_module(
        "crates/bar/src/ratatui_adapter.rs"
    ));
}

#[test]
fn is_blocked_local_tui_module_allows_frankentui() {
    assert!(!is_blocked_local_tui_module(
        "crates/frankentui/src/main.rs"
    ));
}

#[test]
fn is_blocked_local_tui_module_allows_non_rs() {
    assert!(!is_blocked_local_tui_module("crates/foo/src/tui.toml"));
}

#[test]
fn is_blocked_local_tui_module_allows_non_crates() {
    assert!(!is_blocked_local_tui_module("src/tui_module.rs"));
}

// ---------- pattern_match ----------

#[test]
fn pattern_match_exact() {
    assert!(pattern_match("foo/bar.rs", "foo/bar.rs"));
    assert!(!pattern_match("foo/bar.rs", "foo/baz.rs"));
}

#[test]
fn pattern_match_wildcard_suffix() {
    assert!(pattern_match("crates/foo/*", "crates/foo/bar.rs"));
    assert!(!pattern_match("crates/foo/*", "crates/bar/baz.rs"));
}

// ---------- parse_exception_doc ----------

#[test]
fn parse_exception_doc_requires_approved_status() {
    let doc = ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-EXCEPTION-TUI-0001.md".to_string(),
        content: "# Exception\nScope: dependency:ratatui\n".to_string(),
    };
    assert!(parse_exception_doc(&doc).is_none());
}

#[test]
fn parse_exception_doc_ignores_non_exception_paths() {
    let doc = ExceptionDocumentInput {
        path: "docs/adr/something-else.md".to_string(),
        content: "Status: Approved\nScope: dependency:ratatui\n".to_string(),
    };
    assert!(parse_exception_doc(&doc).is_none());
}

// ---------- PolicyGuardReport ----------

#[test]
fn policy_guard_report_as_jsonl_is_parseable() {
    let report = evaluate_guard(&[], &[], &[]);
    let jsonl = report.as_jsonl();
    for line in jsonl.lines() {
        let _: serde_json::Value =
            serde_json::from_str(line).expect("each JSONL line should be valid JSON");
    }
}

// ---------- evaluate_guard ----------

#[test]
fn evaluate_guard_empty_inputs_passes() {
    let report = evaluate_guard(&[], &[], &[]);
    assert!(report.violations.is_empty());
    assert!(
        report
            .events
            .iter()
            .any(|e| e.event == "guard_summary" && e.outcome == "pass")
    );
}

#[test]
fn evaluate_guard_multiple_violations_accumulate() {
    let manifests = vec![ManifestInput {
        path: "Cargo.toml".to_string(),
        content: "[dependencies]\nratatui = \"1\"\ncrossterm = \"1\"\n".to_string(),
    }];
    let report = evaluate_guard(&manifests, &[], &[]);
    assert_eq!(report.violations.len(), 2);
}

// ---------- module exception with wildcard ----------

#[test]
fn tui_module_exception_wildcard_covers_subtree() {
    let module_paths = vec![
        "crates/franken-engine/src/legacy_tui/widget.rs".to_string(),
        "crates/franken-engine/src/legacy_tui/renderer.rs".to_string(),
    ];
    let exception_docs = vec![ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-EXCEPTION-TUI-0002.md".to_string(),
        content: "Status: Approved\nScope: module:crates/franken-engine/src/legacy_tui/*\n"
            .to_string(),
    }];
    let report = evaluate_guard(&[], &module_paths, &exception_docs);
    assert!(
        report.violations.is_empty(),
        "wildcard module exception should cover all files under the subtree"
    );
    assert!(
        report
            .events
            .iter()
            .filter(|e| e.event == "module_scan" && e.outcome == "pass")
            .count()
            == 2,
        "both modules should produce pass events via exception"
    );
}

// ---------- combined dependency + module violations ----------

#[test]
fn tui_combined_dep_and_module_violations_both_reported() {
    let manifests = vec![ManifestInput {
        path: "Cargo.toml".to_string(),
        content: "[dependencies]\ncrossterm = \"0.27\"\n".to_string(),
    }];
    let module_paths = vec!["crates/franken-engine/src/local_tui_renderer.rs".to_string()];
    let report = evaluate_guard(&manifests, &module_paths, &[]);
    assert!(
        report.violations.len() >= 2,
        "should have both dependency and module violations"
    );
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.error_code == "FE-TUI-DEPENDENCY-FORBIDDEN"),
        "must have a dependency violation"
    );
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.error_code == "FE-TUI-MODULE-FORBIDDEN"),
        "must have a module violation"
    );
}

// ---------- guard_summary is always the last event ----------

#[test]
fn tui_guard_summary_is_always_last_event() {
    // Test with violations present
    let manifests = vec![ManifestInput {
        path: "Cargo.toml".to_string(),
        content: "[dependencies]\ntui = \"1\"\n".to_string(),
    }];
    let report = evaluate_guard(&manifests, &[], &[]);
    let last = report
        .events
        .last()
        .expect("should have at least one event");
    assert_eq!(last.event, "guard_summary");
    assert_eq!(last.outcome, "fail");
    assert_eq!(last.error_code.as_deref(), Some("FE-TUI-GUARD-BLOCKED"));
    assert_eq!(last.detail, "violations=1");

    // Test with no violations
    let clean_report = evaluate_guard(&[], &[], &[]);
    let clean_last = clean_report
        .events
        .last()
        .expect("should have summary event");
    assert_eq!(clean_last.event, "guard_summary");
    assert_eq!(clean_last.outcome, "pass");
    assert!(clean_last.error_code.is_none());
}

// ---------- is_blocked_local_tui_module requires /src/ ----------

#[test]
fn tui_is_blocked_local_module_requires_src_directory() {
    // A tui-named file in tests/ (not src/) should not be blocked
    assert!(
        !is_blocked_local_tui_module("crates/foo/tests/tui_integration.rs"),
        "tui file outside /src/ should not be blocked"
    );
    // Same name under src/ should be blocked
    assert!(
        is_blocked_local_tui_module("crates/foo/src/tui_integration.rs"),
        "tui file under /src/ should be blocked"
    );
}

// ---------- PolicyGuardEvent serde roundtrip ----------

#[test]
fn tui_policy_guard_event_serde_roundtrip() {
    let event = PolicyGuardEvent {
        trace_id: "trace-tui-policy-0001".to_string(),
        decision_id: "decision-0001".to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "module_scan".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-TUI-MODULE-FORBIDDEN".to_string()),
        subject: "crates/foo/src/tui_widget.rs".to_string(),
        detail: "blocked local interactive TUI module path detected".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize event");
    let recovered: serde_json::Value = serde_json::from_str(&json).expect("parse event json");
    assert_eq!(recovered["trace_id"], "trace-tui-policy-0001");
    assert_eq!(recovered["policy_id"], POLICY_ID);
    assert_eq!(recovered["component"], COMPONENT);
    assert_eq!(recovered["error_code"], "FE-TUI-MODULE-FORBIDDEN");

    // Verify null error_code for pass events
    let pass_event = PolicyGuardEvent {
        error_code: None,
        outcome: "pass".to_string(),
        ..event
    };
    let pass_json = serde_json::to_string(&pass_event).expect("serialize pass event");
    let pass_recovered: serde_json::Value =
        serde_json::from_str(&pass_json).expect("parse pass json");
    assert!(pass_recovered["error_code"].is_null());
}
