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

const POLICY_ID: &str = "policy-frankensqlite-first-v1";
const TRACE_PREFIX: &str = "trace-sqlite-policy";
const COMPONENT: &str = "sqlite_policy_guard";

const FORBIDDEN_SQLITE_DEPENDENCIES: &[&str] = &[
    "rusqlite",
    "libsqlite3-sys",
    "sqlite",
    "sqlite3",
    "sqlx-sqlite",
];
const FORBIDDEN_SQLITE_TOKENS: &[&str] = &[
    "rusqlite::",
    "libsqlite3_sys",
    "sqlite3::",
    "sqlx::sqlite::",
    "sqlx::Sqlite",
];
const ADAPTER_ALLOWED_PATHS: &[&str] = &[
    "crates/franken-engine/src/storage_adapter.rs",
    "crates/franken-engine/tests/storage_adapter.rs",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestInput {
    path: String,
    content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceInput {
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
    PathPattern(String),
    Token(String),
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
            let line = serde_json::to_string(event).expect("event serialization should work");
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
        deps.push(key.to_ascii_lowercase());
    }

    deps
}

fn parse_exception_docs(docs: &[ExceptionDocumentInput]) -> Vec<ParsedException> {
    docs.iter().filter_map(parse_exception_doc).collect()
}

fn parse_exception_doc(doc: &ExceptionDocumentInput) -> Option<ParsedException> {
    let normalized_path = doc.path.replace('\\', "/");
    if !normalized_path.starts_with("docs/adr/exceptions/ADR-EXCEPTION-SQLITE-")
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
            } else if let Some(path) = scope_raw.strip_prefix("path:") {
                scopes.push(ExceptionScope::PathPattern(path.trim().to_string()));
            } else if let Some(token) = scope_raw.strip_prefix("token:") {
                scopes.push(ExceptionScope::Token(token.trim().to_string()));
            }
        }
    }

    if approved && !scopes.is_empty() {
        Some(ParsedException { scopes })
    } else {
        None
    }
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        value == pattern
    }
}

fn dependency_exception_allowed(dep: &str, exceptions: &[ParsedException]) -> bool {
    exceptions.iter().any(|exception| {
        exception
            .scopes
            .iter()
            .any(|scope| matches!(scope, ExceptionScope::Dependency(allowed) if allowed == dep))
    })
}

fn path_exception_allowed(path: &str, exceptions: &[ParsedException]) -> bool {
    exceptions.iter().any(|exception| {
        exception.scopes.iter().any(|scope| match scope {
            ExceptionScope::PathPattern(pattern) => matches_pattern(pattern, path),
            ExceptionScope::Dependency(_) | ExceptionScope::Token(_) => false,
        })
    })
}

fn token_exception_allowed(token: &str, exceptions: &[ParsedException]) -> bool {
    exceptions.iter().any(|exception| {
        exception
            .scopes
            .iter()
            .any(|scope| matches!(scope, ExceptionScope::Token(allowed) if allowed == token))
    })
}

fn is_forbidden_sqlite_dependency(dep: &str) -> bool {
    FORBIDDEN_SQLITE_DEPENDENCIES.contains(&dep)
}

fn is_adapter_allowed_path(path: &str) -> bool {
    ADAPTER_ALLOWED_PATHS.contains(&path)
}

fn evaluate_guard(
    manifests: &[ManifestInput],
    sources: &[SourceInput],
    exception_docs: &[ExceptionDocumentInput],
) -> PolicyGuardReport {
    let exceptions = parse_exception_docs(exception_docs);
    let mut events = Vec::new();
    let mut violations = Vec::new();
    let mut next_id = 1usize;

    for manifest in manifests {
        for dep in dependency_names(manifest.content.as_str()) {
            if !is_forbidden_sqlite_dependency(dep.as_str()) {
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
                "direct sqlite dependency is forbidden outside storage adapter policy ({})",
                manifest.path
            );
            events.push(PolicyGuardEvent {
                trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
                decision_id: format!("decision-{next_id:04}"),
                policy_id: POLICY_ID.to_string(),
                component: COMPONENT.to_string(),
                event: "dependency_scan".to_string(),
                outcome: "fail".to_string(),
                error_code: Some("FE-SQLITE-DEPENDENCY-FORBIDDEN".to_string()),
                subject: dep.clone(),
                detail: detail.clone(),
            });
            next_id += 1;
            violations.push(PolicyViolation {
                error_code: "FE-SQLITE-DEPENDENCY-FORBIDDEN",
                subject: dep,
                detail,
            });
        }
    }

    for source in sources {
        if is_adapter_allowed_path(source.path.as_str()) {
            continue;
        }

        for token in FORBIDDEN_SQLITE_TOKENS {
            if !source.content.contains(token) {
                continue;
            }

            if path_exception_allowed(source.path.as_str(), &exceptions)
                || token_exception_allowed(token, &exceptions)
            {
                events.push(PolicyGuardEvent {
                    trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
                    decision_id: format!("decision-{next_id:04}"),
                    policy_id: POLICY_ID.to_string(),
                    component: COMPONENT.to_string(),
                    event: "usage_scan".to_string(),
                    outcome: "pass".to_string(),
                    error_code: None,
                    subject: source.path.clone(),
                    detail: format!(
                        "forbidden sqlite token `{token}` allowed via approved ADR exception"
                    ),
                });
                next_id += 1;
                continue;
            }

            let detail = format!(
                "forbidden sqlite token `{token}` detected in {}",
                source.path
            );
            events.push(PolicyGuardEvent {
                trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
                decision_id: format!("decision-{next_id:04}"),
                policy_id: POLICY_ID.to_string(),
                component: COMPONENT.to_string(),
                event: "usage_scan".to_string(),
                outcome: "fail".to_string(),
                error_code: Some("FE-SQLITE-USAGE-FORBIDDEN".to_string()),
                subject: source.path.clone(),
                detail: detail.clone(),
            });
            next_id += 1;
            violations.push(PolicyViolation {
                error_code: "FE-SQLITE-USAGE-FORBIDDEN",
                subject: source.path.clone(),
                detail,
            });
        }
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
            Some("FE-SQLITE-GUARD-BLOCKED".to_string())
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

fn repo_sources() -> Vec<SourceInput> {
    let root = repo_root();
    let mut paths = Vec::new();
    collect_rs_files(root.join("crates").as_path(), &mut paths);
    paths.sort();

    paths
        .into_iter()
        .filter(|path| path.contains("/src/"))
        .map(|path| {
            let abs = root.join(path.as_str());
            let content = fs::read_to_string(&abs)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", abs.display()));
            SourceInput { path, content }
        })
        .collect()
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
fn rusqlite_dependency_is_blocked_without_exception() {
    let manifests = vec![ManifestInput {
        path: "crates/franken-engine/Cargo.toml".to_string(),
        content: r#"
[dependencies]
rusqlite = "0.35"
"#
        .to_string(),
    }];
    let report = evaluate_guard(&manifests, &[], &[]);

    assert_eq!(report.violations.len(), 1);
    assert_eq!(
        report.violations[0].error_code,
        "FE-SQLITE-DEPENDENCY-FORBIDDEN"
    );
    assert!(report.events.iter().any(|event| {
        event.event == "dependency_scan"
            && event.outcome == "fail"
            && event.error_code.as_deref() == Some("FE-SQLITE-DEPENDENCY-FORBIDDEN")
            && event.policy_id == POLICY_ID
            && event.component == COMPONENT
    }));
}

#[test]
fn direct_sqlite_usage_token_is_blocked_outside_adapter_path() {
    let sources = vec![SourceInput {
        path: "crates/franken-engine/src/local_sqlite_wrapper.rs".to_string(),
        content: "use rusqlite::Connection;\n".to_string(),
    }];
    let report = evaluate_guard(&[], &sources, &[]);

    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations[0].error_code, "FE-SQLITE-USAGE-FORBIDDEN");
    assert!(report.events.iter().any(|event| {
        event.event == "usage_scan"
            && event.outcome == "fail"
            && event.error_code.as_deref() == Some("FE-SQLITE-USAGE-FORBIDDEN")
    }));
}

#[test]
fn adapter_boundary_path_is_allowed_for_sqlite_tokens() {
    let sources = vec![SourceInput {
        path: "crates/franken-engine/src/storage_adapter.rs".to_string(),
        content: "use rusqlite::Connection;\n".to_string(),
    }];
    let report = evaluate_guard(&[], &sources, &[]);

    assert!(report.violations.is_empty());
    assert!(report.events.iter().any(|event| {
        event.event == "guard_summary"
            && event.outcome == "pass"
            && event.error_code.is_none()
            && event.detail == "violations=0"
    }));
}

#[test]
fn approved_exception_can_bypass_dependency_and_usage_rules() {
    let manifests = vec![ManifestInput {
        path: "crates/franken-engine/Cargo.toml".to_string(),
        content: r#"
[dependencies]
rusqlite = "0.35"
"#
        .to_string(),
    }];
    let sources = vec![SourceInput {
        path: "crates/franken-engine/src/legacy_adapter.rs".to_string(),
        content: "use rusqlite::Connection;\n".to_string(),
    }];
    let exception_docs = vec![ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-EXCEPTION-SQLITE-0001.md".to_string(),
        content: r#"
Status: Approved
Scope: dependency:rusqlite
Scope: token:rusqlite::
Scope: path:crates/franken-engine/src/legacy_adapter.rs
"#
        .to_string(),
    }];

    let report = evaluate_guard(&manifests, &sources, &exception_docs);

    assert!(report.violations.is_empty());
    assert!(report.events.iter().any(|event| {
        event.outcome == "pass"
            && event.error_code.is_none()
            && (event.event == "dependency_scan" || event.event == "usage_scan")
    }));
}

#[test]
fn migration_policy_adr_contains_ci_enforcement_and_transition_timeline() {
    let adr_path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let adr = fs::read_to_string(&adr_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", adr_path.display()));

    let required_markers = [
        "## Migration Policy (No Ad-Hoc Local SQLite Wrappers)",
        "scripts/check_no_local_sqlite_wrappers.sh ci",
        "January 31, 2027",
        "docs/adr/exceptions/ADR-EXCEPTION-SQLITE-",
    ];

    for marker in required_markers {
        assert!(
            adr.contains(marker),
            "ADR-0004 must contain migration-policy marker: {marker}"
        );
    }
}

#[test]
fn version_matrix_workflow_runs_sqlite_policy_guard_check() {
    let workflow_path = repo_root().join(".github/workflows/version_matrix_conformance.yml");
    let workflow = fs::read_to_string(&workflow_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow_path.display()));

    assert!(
        workflow.contains("./scripts/check_no_local_sqlite_wrappers.sh ci"),
        "version_matrix_conformance workflow must run sqlite wrapper policy guard script"
    );
}

#[test]
fn repository_sqlite_policy_guard_passes() {
    let manifests = repo_manifests();
    let sources = repo_sources();
    let exceptions = repo_exception_docs();
    let report = evaluate_guard(&manifests, &sources, &exceptions);

    assert!(
        report.violations.is_empty(),
        "SQLite policy guard violations detected:\n{}",
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
fn sqlite_policy_constants_are_nonempty() {
    assert!(!POLICY_ID.is_empty());
    assert!(!TRACE_PREFIX.is_empty());
    assert!(!COMPONENT.is_empty());
}

#[test]
fn forbidden_sqlite_deps_is_nonempty() {
    assert!(!FORBIDDEN_SQLITE_DEPENDENCIES.is_empty());
    assert!(FORBIDDEN_SQLITE_DEPENDENCIES.contains(&"rusqlite"));
}

#[test]
fn forbidden_sqlite_tokens_is_nonempty() {
    assert!(!FORBIDDEN_SQLITE_TOKENS.is_empty());
    assert!(FORBIDDEN_SQLITE_TOKENS.contains(&"rusqlite::"));
}

#[test]
fn adapter_allowed_paths_is_nonempty() {
    assert!(!ADAPTER_ALLOWED_PATHS.is_empty());
}

// ---------- dependency_section ----------

#[test]
fn sqlite_dependency_section_recognizes_standard() {
    assert!(dependency_section("dependencies"));
    assert!(dependency_section("dev-dependencies"));
    assert!(dependency_section("build-dependencies"));
    assert!(dependency_section("workspace.dependencies"));
}

#[test]
fn sqlite_dependency_section_rejects_non_dep() {
    assert!(!dependency_section("package"));
    assert!(!dependency_section("features"));
}

// ---------- dependency_names ----------

#[test]
fn sqlite_dependency_names_extracts_deps() {
    let toml = "[dependencies]\nserde = \"1\"\ntokio = \"1\"\n";
    let deps = dependency_names(toml);
    assert!(deps.contains(&"serde".to_string()));
    assert!(deps.contains(&"tokio".to_string()));
}

#[test]
fn sqlite_dependency_names_handles_empty() {
    assert!(dependency_names("").is_empty());
}

// ---------- is_forbidden_sqlite_dependency ----------

#[test]
fn is_forbidden_sqlite_dep_blocks_known() {
    assert!(is_forbidden_sqlite_dependency("rusqlite"));
    assert!(is_forbidden_sqlite_dependency("libsqlite3-sys"));
    assert!(is_forbidden_sqlite_dependency("sqlite3"));
}

#[test]
fn is_forbidden_sqlite_dep_allows_unrelated() {
    assert!(!is_forbidden_sqlite_dependency("serde"));
    assert!(!is_forbidden_sqlite_dependency("frankensqlite"));
}

// ---------- is_adapter_allowed_path ----------

#[test]
fn adapter_allowed_path_matches() {
    assert!(is_adapter_allowed_path(
        "crates/franken-engine/src/storage_adapter.rs"
    ));
    assert!(!is_adapter_allowed_path(
        "crates/franken-engine/src/something.rs"
    ));
}

// ---------- matches_pattern ----------

#[test]
fn matches_pattern_exact_match() {
    assert!(matches_pattern("foo.rs", "foo.rs"));
    assert!(!matches_pattern("foo.rs", "bar.rs"));
}

#[test]
fn matches_pattern_wildcard() {
    assert!(matches_pattern("crates/*", "crates/foo.rs"));
    assert!(!matches_pattern("crates/*", "src/foo.rs"));
}

// ---------- parse_exception_doc ----------

#[test]
fn sqlite_parse_exception_doc_requires_approved() {
    let doc = ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-EXCEPTION-SQLITE-0001.md".to_string(),
        content: "Scope: dependency:rusqlite\n".to_string(),
    };
    assert!(parse_exception_doc(&doc).is_none());
}

#[test]
fn sqlite_parse_exception_doc_ignores_non_sqlite_path() {
    let doc = ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-OTHER.md".to_string(),
        content: "Status: Approved\nScope: dependency:rusqlite\n".to_string(),
    };
    assert!(parse_exception_doc(&doc).is_none());
}

// ---------- PolicyGuardReport ----------

#[test]
fn sqlite_report_jsonl_is_parseable() {
    let report = evaluate_guard(&[], &[], &[]);
    for line in report.as_jsonl().lines() {
        let _: serde_json::Value = serde_json::from_str(line).expect("valid JSONL");
    }
}

// ---------- evaluate_guard ----------

#[test]
fn sqlite_evaluate_guard_empty_passes() {
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
fn sqlite_multiple_violations_accumulate() {
    let manifests = vec![ManifestInput {
        path: "Cargo.toml".to_string(),
        content: "[dependencies]\nrusqlite = \"1\"\nsqlite3 = \"1\"\n".to_string(),
    }];
    let report = evaluate_guard(&manifests, &[], &[]);
    assert_eq!(report.violations.len(), 2);
}

// ---------- dependency_names with comments ----------

#[test]
fn sqlite_dependency_names_ignores_comments_in_toml() {
    let toml = "[dependencies]\n# rusqlite = \"1\"\nserde = \"1\"\n";
    let deps = dependency_names(toml);
    assert!(
        !deps.contains(&"rusqlite".to_string()),
        "commented-out dependency must be ignored"
    );
    assert!(deps.contains(&"serde".to_string()));
}

// ---------- guard summary event always present ----------

#[test]
fn sqlite_guard_summary_event_always_last_with_violation_count() {
    let manifests = vec![ManifestInput {
        path: "Cargo.toml".to_string(),
        content: "[dependencies]\nrusqlite = \"1\"\nlibsqlite3-sys = \"1\"\n".to_string(),
    }];
    let report = evaluate_guard(&manifests, &[], &[]);
    let last = report.events.last().expect("events should not be empty");
    assert_eq!(last.event, "guard_summary");
    assert_eq!(last.outcome, "fail");
    assert_eq!(last.error_code.as_deref(), Some("FE-SQLITE-GUARD-BLOCKED"));
    assert_eq!(last.detail, "violations=2");
}

// ---------- token scan combined with dependency scan ----------

#[test]
fn sqlite_combined_dependency_and_usage_violations_both_reported() {
    let manifests = vec![ManifestInput {
        path: "Cargo.toml".to_string(),
        content: "[dependencies]\nrusqlite = \"1\"\n".to_string(),
    }];
    let sources = vec![SourceInput {
        path: "crates/franken-engine/src/bad_module.rs".to_string(),
        content: "fn connect() { let _ = sqlite3::open(\"test.db\"); }".to_string(),
    }];
    let report = evaluate_guard(&manifests, &sources, &[]);
    assert!(
        report.violations.len() >= 2,
        "should have both dependency and usage violations"
    );
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.error_code == "FE-SQLITE-DEPENDENCY-FORBIDDEN"),
        "should have a dependency violation"
    );
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.error_code == "FE-SQLITE-USAGE-FORBIDDEN"),
        "should have a usage violation"
    );
}

// ---------- exception with path wildcard ----------

#[test]
fn sqlite_path_wildcard_exception_covers_subtree() {
    let sources = vec![
        SourceInput {
            path: "crates/franken-engine/src/legacy/old_db.rs".to_string(),
            content: "use rusqlite::Connection;\n".to_string(),
        },
        SourceInput {
            path: "crates/franken-engine/src/legacy/old_schema.rs".to_string(),
            content: "use rusqlite::params;\n".to_string(),
        },
    ];
    let exception_docs = vec![ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-EXCEPTION-SQLITE-0002.md".to_string(),
        content: "Status: Approved\nScope: path:crates/franken-engine/src/legacy/*\n".to_string(),
    }];
    let report = evaluate_guard(&[], &sources, &exception_docs);
    assert!(
        report.violations.is_empty(),
        "wildcard path exception should cover all files under the subtree"
    );
}

// ---------- PolicyGuardEvent serde ----------

#[test]
fn sqlite_policy_guard_event_serde_roundtrip() {
    let event = PolicyGuardEvent {
        trace_id: "trace-sqlite-policy-0001".to_string(),
        decision_id: "decision-0001".to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "dependency_scan".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-SQLITE-DEPENDENCY-FORBIDDEN".to_string()),
        subject: "rusqlite".to_string(),
        detail: "test detail".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize event");
    let recovered: serde_json::Value = serde_json::from_str(&json).expect("parse event json");
    assert_eq!(recovered["trace_id"], "trace-sqlite-policy-0001");
    assert_eq!(recovered["error_code"], "FE-SQLITE-DEPENDENCY-FORBIDDEN");
    assert_eq!(recovered["policy_id"], POLICY_ID);
    assert_eq!(recovered["component"], COMPONENT);

    // Also verify null error_code path
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

// ---------- enrichment: clone/debug/eq ----------

#[test]
fn sqlite_manifest_input_clone_debug_eq() {
    let m = ManifestInput {
        path: "Cargo.toml".to_string(),
        content: "[package]\nname = \"test\"\n".to_string(),
    };
    let m2 = m.clone();
    assert_eq!(m, m2);
    let dbg = format!("{m:?}");
    assert!(dbg.contains("ManifestInput"));
    assert!(dbg.contains("Cargo.toml"));
}

#[test]
fn sqlite_source_input_clone_debug_eq() {
    let s = SourceInput {
        path: "src/lib.rs".to_string(),
        content: "fn main() {}".to_string(),
    };
    let s2 = s.clone();
    assert_eq!(s, s2);
    let dbg = format!("{s:?}");
    assert!(dbg.contains("SourceInput"));
}

#[test]
fn sqlite_exception_document_input_clone_debug_eq() {
    let d = ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-EXCEPTION-SQLITE-0099.md".to_string(),
        content: "Status: Approved\nScope: dependency:sqlite\n".to_string(),
    };
    let d2 = d.clone();
    assert_eq!(d, d2);
    let dbg = format!("{d:?}");
    assert!(dbg.contains("ExceptionDocumentInput"));
}

#[test]
fn sqlite_exception_scope_variants_clone_debug_eq() {
    let dep = ExceptionScope::Dependency("rusqlite".to_string());
    let path = ExceptionScope::PathPattern("crates/*".to_string());
    let tok = ExceptionScope::Token("rusqlite::".to_string());

    assert_eq!(dep.clone(), dep);
    assert_eq!(path.clone(), path);
    assert_eq!(tok.clone(), tok);

    assert_ne!(dep, path);
    assert_ne!(path, tok);
    assert_ne!(dep, tok);

    let dbg_dep = format!("{dep:?}");
    assert!(dbg_dep.contains("Dependency"));
    let dbg_path = format!("{path:?}");
    assert!(dbg_path.contains("PathPattern"));
    let dbg_tok = format!("{tok:?}");
    assert!(dbg_tok.contains("Token"));
}

#[test]
fn sqlite_parsed_exception_clone_debug_eq() {
    let pe = ParsedException {
        scopes: vec![
            ExceptionScope::Dependency("sqlite3".to_string()),
            ExceptionScope::Token("sqlite3::".to_string()),
        ],
    };
    let pe2 = pe.clone();
    assert_eq!(pe, pe2);
    let dbg = format!("{pe:?}");
    assert!(dbg.contains("ParsedException"));
    assert!(dbg.contains("sqlite3"));
}

#[test]
fn sqlite_policy_violation_clone_debug_eq() {
    let v = PolicyViolation {
        error_code: "FE-SQLITE-DEPENDENCY-FORBIDDEN",
        subject: "rusqlite".to_string(),
        detail: "test detail".to_string(),
    };
    let v2 = v.clone();
    assert_eq!(v, v2);
    let dbg = format!("{v:?}");
    assert!(dbg.contains("PolicyViolation"));
    assert!(dbg.contains("FE-SQLITE-DEPENDENCY-FORBIDDEN"));
}

#[test]
fn sqlite_policy_guard_report_clone_debug_eq() {
    let report = evaluate_guard(&[], &[], &[]);
    let r2 = report.clone();
    assert_eq!(report, r2);
    let dbg = format!("{report:?}");
    assert!(dbg.contains("PolicyGuardReport"));
}

// ---------- enrichment: dependency_section edge cases ----------

#[test]
fn sqlite_dependency_section_recognizes_target_specific() {
    // e.g. [target.'cfg(windows)'.dependencies]
    assert!(dependency_section("target.'cfg(windows)'.dependencies"));
    assert!(dependency_section("target.'cfg(unix)'.dev-dependencies"));
    assert!(dependency_section(
        "target.'cfg(target_os = \"linux\")'.build-dependencies"
    ));
}

#[test]
fn sqlite_dependency_section_rejects_misc_sections() {
    assert!(!dependency_section(""));
    assert!(!dependency_section("lib"));
    assert!(!dependency_section("bin"));
    assert!(!dependency_section("profile.release"));
    assert!(!dependency_section("patch.crates-io"));
    assert!(!dependency_section("workspace.metadata"));
}

// ---------- enrichment: dependency_names edge cases ----------

#[test]
fn sqlite_dependency_names_skips_non_dep_sections() {
    let toml = "[package]\nname = \"test\"\nversion = \"0.1.0\"\n\n[features]\ndefault = []\n";
    let deps = dependency_names(toml);
    assert!(deps.is_empty());
}

#[test]
fn sqlite_dependency_names_case_normalizes() {
    let toml = "[dependencies]\nMyPkg = \"1\"\nANOTHER = { version = \"2\" }\n";
    let deps = dependency_names(toml);
    assert!(deps.contains(&"mypkg".to_string()));
    assert!(deps.contains(&"another".to_string()));
}

#[test]
fn sqlite_dependency_names_handles_inline_table_values() {
    let toml = "[dependencies]\nserde = { version = \"1\", features = [\"derive\"] }\ntokio = { version = \"1.0\", optional = true }\n";
    let deps = dependency_names(toml);
    assert!(deps.contains(&"serde".to_string()));
    assert!(deps.contains(&"tokio".to_string()));
}

#[test]
fn sqlite_dependency_names_ignores_inline_comments() {
    let toml = "[dependencies]\nserde = \"1\" # serialization\n";
    let deps = dependency_names(toml);
    assert!(deps.contains(&"serde".to_string()));
    assert_eq!(deps.len(), 1);
}

#[test]
fn sqlite_dependency_names_handles_quoted_keys() {
    let toml = "[dependencies]\n\"my-crate\" = \"1.0\"\n";
    let deps = dependency_names(toml);
    assert!(deps.contains(&"my-crate".to_string()));
}

#[test]
fn sqlite_dependency_names_skips_blank_lines_between_deps() {
    let toml = "[dependencies]\nserde = \"1\"\n\n\ntokio = \"1\"\n";
    let deps = dependency_names(toml);
    assert_eq!(deps.len(), 2);
}

// ---------- enrichment: parse_exception_doc edge cases ----------

#[test]
fn sqlite_parse_exception_doc_requires_scope() {
    let doc = ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-EXCEPTION-SQLITE-0001.md".to_string(),
        content: "Status: Approved\n".to_string(),
    };
    // Approved but no scopes → None
    assert!(parse_exception_doc(&doc).is_none());
}

#[test]
fn sqlite_parse_exception_doc_not_approved_with_scope_rejected() {
    let doc = ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-EXCEPTION-SQLITE-0001.md".to_string(),
        content: "Status: Draft\nScope: dependency:rusqlite\n".to_string(),
    };
    assert!(parse_exception_doc(&doc).is_none());
}

#[test]
fn sqlite_parse_exception_doc_multiple_scopes() {
    let doc = ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-EXCEPTION-SQLITE-0005.md".to_string(),
        content: "Status: Approved\nScope: dependency:rusqlite\nScope: dependency:sqlite3\nScope: token:rusqlite::\nScope: path:crates/legacy/*\n".to_string(),
    };
    let parsed = parse_exception_doc(&doc).expect("should parse");
    assert_eq!(parsed.scopes.len(), 4);
    assert!(
        parsed
            .scopes
            .iter()
            .any(|s| matches!(s, ExceptionScope::Dependency(d) if d == "rusqlite"))
    );
    assert!(
        parsed
            .scopes
            .iter()
            .any(|s| matches!(s, ExceptionScope::Dependency(d) if d == "sqlite3"))
    );
    assert!(
        parsed
            .scopes
            .iter()
            .any(|s| matches!(s, ExceptionScope::Token(t) if t == "rusqlite::"))
    );
    assert!(
        parsed
            .scopes
            .iter()
            .any(|s| matches!(s, ExceptionScope::PathPattern(p) if p == "crates/legacy/*"))
    );
}

#[test]
fn sqlite_parse_exception_doc_backslash_path_normalized() {
    // Windows-style backslash paths should be normalized
    let doc = ExceptionDocumentInput {
        path: "docs\\adr\\exceptions\\ADR-EXCEPTION-SQLITE-0010.md".to_string(),
        content: "Status: Approved\nScope: dependency:sqlite\n".to_string(),
    };
    let parsed = parse_exception_doc(&doc);
    assert!(
        parsed.is_some(),
        "backslash paths should be normalized to forward slashes"
    );
}

#[test]
fn sqlite_parse_exception_doc_case_insensitive_status() {
    let doc = ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-EXCEPTION-SQLITE-0011.md".to_string(),
        content: "status: approved\nScope: dependency:sqlite\n".to_string(),
    };
    let parsed = parse_exception_doc(&doc);
    assert!(
        parsed.is_some(),
        "Status: Approved should be case-insensitive"
    );
}

#[test]
fn sqlite_parse_exception_docs_filters_invalid() {
    let docs = vec![
        ExceptionDocumentInput {
            path: "docs/adr/exceptions/ADR-EXCEPTION-SQLITE-0001.md".to_string(),
            content: "Status: Approved\nScope: dependency:rusqlite\n".to_string(),
        },
        ExceptionDocumentInput {
            path: "docs/adr/exceptions/ADR-OTHER-0001.md".to_string(),
            content: "Status: Approved\nScope: dependency:serde\n".to_string(),
        },
        ExceptionDocumentInput {
            path: "docs/adr/exceptions/ADR-EXCEPTION-SQLITE-0002.md".to_string(),
            content: "Status: Draft\nScope: dependency:sqlite3\n".to_string(),
        },
    ];
    let parsed = parse_exception_docs(&docs);
    assert_eq!(parsed.len(), 1, "only the first doc should pass filtering");
}

// ---------- enrichment: matches_pattern edge cases ----------

#[test]
fn sqlite_matches_pattern_empty_pattern_empty_value() {
    assert!(matches_pattern("", ""));
    assert!(!matches_pattern("", "something"));
}

#[test]
fn sqlite_matches_pattern_wildcard_only() {
    // Pattern "*" means prefix is "", so everything matches
    assert!(matches_pattern("*", "anything"));
    assert!(matches_pattern("*", ""));
}

// ---------- enrichment: exception allowed functions ----------

#[test]
fn sqlite_dependency_exception_allowed_no_exceptions() {
    assert!(!dependency_exception_allowed("rusqlite", &[]));
}

#[test]
fn sqlite_path_exception_allowed_no_exceptions() {
    assert!(!path_exception_allowed("crates/foo/src/lib.rs", &[]));
}

#[test]
fn sqlite_token_exception_allowed_no_exceptions() {
    assert!(!token_exception_allowed("rusqlite::", &[]));
}

#[test]
fn sqlite_dependency_exception_allowed_wrong_dep() {
    let exceptions = vec![ParsedException {
        scopes: vec![ExceptionScope::Dependency("sqlite3".to_string())],
    }];
    assert!(!dependency_exception_allowed("rusqlite", &exceptions));
    assert!(dependency_exception_allowed("sqlite3", &exceptions));
}

#[test]
fn sqlite_token_exception_allowed_matching() {
    let exceptions = vec![ParsedException {
        scopes: vec![ExceptionScope::Token("rusqlite::".to_string())],
    }];
    assert!(token_exception_allowed("rusqlite::", &exceptions));
    assert!(!token_exception_allowed("sqlite3::", &exceptions));
}

#[test]
fn sqlite_path_exception_allowed_exact() {
    let exceptions = vec![ParsedException {
        scopes: vec![ExceptionScope::PathPattern(
            "crates/foo/src/db.rs".to_string(),
        )],
    }];
    assert!(path_exception_allowed("crates/foo/src/db.rs", &exceptions));
    assert!(!path_exception_allowed(
        "crates/foo/src/other.rs",
        &exceptions
    ));
}

#[test]
fn sqlite_path_exception_allowed_wildcard() {
    let exceptions = vec![ParsedException {
        scopes: vec![ExceptionScope::PathPattern("crates/legacy/*".to_string())],
    }];
    assert!(path_exception_allowed("crates/legacy/db.rs", &exceptions));
    assert!(path_exception_allowed(
        "crates/legacy/nested/deep.rs",
        &exceptions
    ));
    assert!(!path_exception_allowed("crates/other/db.rs", &exceptions));
}

// ---------- enrichment: is_forbidden_sqlite_dependency completeness ----------

#[test]
fn sqlite_all_forbidden_deps_detected() {
    for dep in FORBIDDEN_SQLITE_DEPENDENCIES {
        assert!(
            is_forbidden_sqlite_dependency(dep),
            "expected {dep} to be forbidden"
        );
    }
}

#[test]
fn sqlite_forbidden_deps_are_case_sensitive() {
    // The function does exact match; uppercase should not match
    assert!(!is_forbidden_sqlite_dependency("Rusqlite"));
    assert!(!is_forbidden_sqlite_dependency("SQLITE3"));
}

// ---------- enrichment: evaluate_guard trace_id and decision_id sequencing ----------

#[test]
fn sqlite_evaluate_guard_trace_ids_are_sequential() {
    let manifests = vec![ManifestInput {
        path: "Cargo.toml".to_string(),
        content: "[dependencies]\nrusqlite = \"1\"\nsqlite3 = \"1\"\n".to_string(),
    }];
    let report = evaluate_guard(&manifests, &[], &[]);
    // Should have 2 violation events + 1 summary = 3 events
    assert_eq!(report.events.len(), 3);
    assert_eq!(report.events[0].trace_id, "trace-sqlite-policy-0001");
    assert_eq!(report.events[0].decision_id, "decision-0001");
    assert_eq!(report.events[1].trace_id, "trace-sqlite-policy-0002");
    assert_eq!(report.events[1].decision_id, "decision-0002");
    assert_eq!(report.events[2].trace_id, "trace-sqlite-policy-0003");
    assert_eq!(report.events[2].decision_id, "decision-0003");
}

// ---------- enrichment: evaluate_guard with all forbidden tokens ----------

#[test]
fn sqlite_all_forbidden_tokens_detected_as_violations() {
    let sources: Vec<SourceInput> = FORBIDDEN_SQLITE_TOKENS
        .iter()
        .enumerate()
        .map(|(i, token)| SourceInput {
            path: format!("crates/franken-engine/src/test_module_{i}.rs"),
            content: format!("// usage: {token}\n"),
        })
        .collect();

    let report = evaluate_guard(&[], &sources, &[]);
    // Each source has exactly one forbidden token, so one violation per source
    assert_eq!(
        report.violations.len(),
        FORBIDDEN_SQLITE_TOKENS.len(),
        "each forbidden token in a non-adapter path should produce a violation"
    );
    for v in &report.violations {
        assert_eq!(v.error_code, "FE-SQLITE-USAGE-FORBIDDEN");
    }
}

// ---------- enrichment: adapter path allows all tokens ----------

#[test]
fn sqlite_adapter_allowed_paths_bypass_all_tokens() {
    let mut sources = Vec::new();
    for path in ADAPTER_ALLOWED_PATHS {
        sources.push(SourceInput {
            path: path.to_string(),
            content: FORBIDDEN_SQLITE_TOKENS.to_vec().join("\n"),
        });
    }
    let report = evaluate_guard(&[], &sources, &[]);
    assert!(
        report.violations.is_empty(),
        "adapter allowed paths should bypass all token checks"
    );
}

// ---------- enrichment: report as_jsonl contains all events ----------

#[test]
fn sqlite_report_as_jsonl_line_count_matches_events() {
    let manifests = vec![ManifestInput {
        path: "Cargo.toml".to_string(),
        content: "[dependencies]\nrusqlite = \"1\"\n".to_string(),
    }];
    let report = evaluate_guard(&manifests, &[], &[]);
    let jsonl = report.as_jsonl();
    let line_count = jsonl.lines().count();
    assert_eq!(
        line_count,
        report.events.len(),
        "JSONL line count must match event count"
    );
}

// ---------- enrichment: serde roundtrip for PolicyGuardEvent with all fields ----------

#[test]
fn sqlite_policy_guard_event_serde_all_fields_present() {
    let event = PolicyGuardEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "c1".to_string(),
        event: "e1".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("EC1".to_string()),
        subject: "s1".to_string(),
        detail: "det1".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&json).expect("parse");
    let expected_keys = [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "subject",
        "detail",
    ];
    for key in expected_keys {
        assert!(map.contains_key(key), "JSON must contain key: {key}");
    }
    assert_eq!(map.len(), expected_keys.len(), "no extra keys in JSON");
}

// ---------- enrichment: multiple manifests scanned ----------

#[test]
fn sqlite_evaluate_guard_scans_all_manifests() {
    let manifests = vec![
        ManifestInput {
            path: "Cargo.toml".to_string(),
            content: "[dependencies]\nrusqlite = \"1\"\n".to_string(),
        },
        ManifestInput {
            path: "crates/foo/Cargo.toml".to_string(),
            content: "[dependencies]\nsqlite3 = \"0.5\"\n".to_string(),
        },
    ];
    let report = evaluate_guard(&manifests, &[], &[]);
    assert_eq!(report.violations.len(), 2);
    assert!(report.violations.iter().any(|v| v.subject == "rusqlite"));
    assert!(report.violations.iter().any(|v| v.subject == "sqlite3"));
}

// ---------- enrichment: dev-dependencies and build-dependencies scanned ----------

#[test]
fn sqlite_evaluate_guard_scans_dev_and_build_deps() {
    let manifests = vec![ManifestInput {
        path: "Cargo.toml".to_string(),
        content: "[dev-dependencies]\nrusqlite = \"1\"\n\n[build-dependencies]\nlibsqlite3-sys = \"0.28\"\n".to_string(),
    }];
    let report = evaluate_guard(&manifests, &[], &[]);
    assert_eq!(report.violations.len(), 2);
    assert!(report.violations.iter().any(|v| v.subject == "rusqlite"));
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.subject == "libsqlite3-sys")
    );
}

// ---------- enrichment: non-forbidden dependency not flagged ----------

#[test]
fn sqlite_evaluate_guard_clean_manifest_no_violations() {
    let manifests = vec![ManifestInput {
        path: "Cargo.toml".to_string(),
        content: "[dependencies]\nserde = \"1\"\ntokio = \"1\"\nrand = \"0.8\"\n".to_string(),
    }];
    let report = evaluate_guard(&manifests, &[], &[]);
    assert!(report.violations.is_empty());
    let summary = report.events.last().unwrap();
    assert_eq!(summary.outcome, "pass");
}

// ---------- enrichment: source with no forbidden tokens passes ----------

#[test]
fn sqlite_source_without_forbidden_tokens_passes() {
    let sources = vec![SourceInput {
        path: "crates/franken-engine/src/clean_module.rs".to_string(),
        content: "use std::collections::BTreeMap;\nfn main() {}\n".to_string(),
    }];
    let report = evaluate_guard(&[], &sources, &[]);
    assert!(report.violations.is_empty());
}

// ---------- enrichment: violation detail contains path ----------

#[test]
fn sqlite_violation_detail_contains_manifest_path() {
    let manifests = vec![ManifestInput {
        path: "my/custom/Cargo.toml".to_string(),
        content: "[dependencies]\nrusqlite = \"1\"\n".to_string(),
    }];
    let report = evaluate_guard(&manifests, &[], &[]);
    assert_eq!(report.violations.len(), 1);
    assert!(
        report.violations[0].detail.contains("my/custom/Cargo.toml"),
        "violation detail must reference the manifest path"
    );
}

#[test]
fn sqlite_violation_detail_contains_source_path() {
    let sources = vec![SourceInput {
        path: "crates/franken-engine/src/my_mod.rs".to_string(),
        content: "use rusqlite::Connection;\n".to_string(),
    }];
    let report = evaluate_guard(&[], &sources, &[]);
    assert_eq!(report.violations.len(), 1);
    assert!(
        report.violations[0].detail.contains("my_mod.rs"),
        "violation detail must reference the source file"
    );
}
