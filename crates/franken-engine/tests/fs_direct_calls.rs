//! Direct filesystem calls must remain analyzable and traverse the real host seam.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::authority_footprint::{analyze_authority_footprint, CheckOutcome};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};
use frankenengine_extension_host::host_io::{
    HostIoRecorder, InMemoryHostIoTranscript, SandboxedHostIo,
};

fn run(source: &str, root: &Path, capabilities: &[&str]) -> Result<Vec<String>, String> {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox provider"));
    let recorder: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_host_io(provider, Some(recorder));
    let package = ExtensionPackage {
        extension_id: "fs-direct-call-regression".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: capabilities.iter().map(|capability| (*capability).to_string()).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    orchestrator.execute(&package)
        .map(|result| result.console_output.into_iter().map(|entry| entry.message).collect())
        .map_err(|error| format!("{error:?}"))
}

#[test]
fn inline_read_has_analyzable_read_only_authority_without_unused_method_flows() {
    for specifier in ["fs", "node:fs"] {
        let source = format!("require('{specifier}').readFileSync('input.txt', 'utf8');");
        let report = analyze_authority_footprint(&source, "direct-read.js", ParseGoal::Script);
        assert_eq!(report.outcome(), CheckOutcome::Clean, "{report:?}");
        assert!(report.required_capabilities.iter().any(|requirement| {
            requirement.capability == Some(RuntimeCapability::FsRead)
        }));
        assert!(!report.required_capabilities.iter().any(|requirement| {
            requirement.capability == Some(RuntimeCapability::FsWrite)
        }), "unused writer bodies must not pollute the read footprint");
    }
}

#[test]
fn inline_read_uses_real_bytes_without_builtin_or_write_authority() {
    let root = tempfile::tempdir().expect("sandbox");
    std::fs::write(root.path().join("input.txt"), "native bytes").expect("input");
    let output = run(
        "console.log(require('fs').readFileSync('input.txt', 'utf8'));",
        root.path(),
        &["vm_dispatch", "heap_allocate", "console", "fs_read"],
    ).expect("direct read");
    assert_eq!(output, ["native bytes"]);
    assert_eq!(std::fs::read_to_string(root.path().join("input.txt")).unwrap(), "native bytes");
}

#[test]
fn direct_writer_still_requires_write_authority_and_never_fakes_success() {
    let root = tempfile::tempdir().expect("sandbox");
    let denied = run(
        "require('fs').writeFileSync('blocked.txt', 'must not escape');",
        root.path(),
        &["vm_dispatch", "heap_allocate", "fs_read"],
    );
    assert!(denied.is_err());
    assert!(!root.path().join("blocked.txt").exists());
    run(
        "require('node:fs').writeFileSync('allowed.txt', 'first'); \
         require('fs').appendFileSync('allowed.txt', ':second');",
        root.path(),
        &["vm_dispatch", "heap_allocate", "fs_write"],
    ).expect("authorized writes");
    assert_eq!(std::fs::read_to_string(root.path().join("allowed.txt")).unwrap(), "first:second");
}

#[test]
fn inline_read_keeps_operand_order_and_catchable_filesystem_errors() {
    let root = tempfile::tempdir().expect("sandbox");
    std::fs::write(root.path().join("input.txt"), "payload").unwrap();
    let output = run(
        "function path() { console.log('path'); return 'input.txt'; } \
         function encoding() { console.log('encoding'); return 'utf8'; } \
         console.log(require('fs').readFileSync(path(), encoding())); \
         try { require('node:fs').readFileSync('missing.txt', 'utf8'); } \
         catch (error) { console.log(error.code); }",
        root.path(),
        &["vm_dispatch", "heap_allocate", "console", "fs_read"],
    ).expect("operand order and original exception boundary");
    assert_eq!(output, ["path", "encoding", "payload", "ENOENT"]);
}

#[test]
fn an_observable_module_keeps_method_mutation_visible_to_inline_calls() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "const fs = require('fs'); \
         fs.readFileSync = function () { return 'replacement'; }; \
         console.log(require('node:fs').readFileSync('missing.txt'));",
        root.path(),
        &["vm_dispatch", "heap_allocate", "builtin", "console"],
    ).expect("full module fallback, with no filesystem authority");
    assert_eq!(output, ["replacement"]);
}

#[test]
fn direct_lowering_does_not_relax_secret_to_filesystem_flow_checks() {
    let report = analyze_authority_footprint(
        "const secret = process.env.TOKEN; require('fs').writeFileSync('out.txt', secret);",
        "secret-write.js",
        ParseGoal::Script,
    );
    assert_ne!(report.outcome(), CheckOutcome::Clean);
    assert!(report.fail_closed_reason.as_deref().is_some_and(|reason| {
        reason.contains("unauthorized flow")
    }), "the original IFC gate must refuse the secret flow: {report:?}");
}

#[test]
fn bound_reads_have_only_read_authority_at_the_original_call_sites() {
    for (declaration, call) in [
        ("const fs = require('fs');", "fs.readFileSync"),
        ("const {readFileSync} = require('node:fs');", "readFileSync"),
        ("const {readFileSync: read} = require('fs');", "read"),
    ] {
        let source = format!("{declaration}\n{call}('input.txt', 'utf8');\n{call}('second.txt');");
        let report = analyze_authority_footprint(&source, "bound-read.js", ParseGoal::Script);
        assert_eq!(report.outcome(), CheckOutcome::Clean, "{report:?}");
        let reads = report.required_capabilities.iter().filter(|requirement| {
            requirement.capability == Some(RuntimeCapability::FsRead)
        }).collect::<Vec<_>>();
        assert_eq!(reads.len(), 1, "read capability is deduplicated: {report:?}");
        assert_eq!(reads[0].call_sites.iter().map(|site| site.start_line).collect::<Vec<_>>(), [2, 3]);
        assert!(!report.required_capabilities.iter().any(|requirement| {
            requirement.capability == Some(RuntimeCapability::FsWrite)
        }), "no unused writer capability: {report:?}");
        assert_eq!(report, analyze_authority_footprint(&source, "bound-read.js", ParseGoal::Script));
    }
}

// These exact source/expected pairs are also executed in Node as a semantic
// reference. Those runs do NOT execute the Rust lowerer or its capability gates.
const BOUND_READ_SOURCE: &str = r#"
const fs = require('fs');
const {readFileSync: read, existsSync: exists} = require('node:fs');
console.log(fs.readFileSync('input.txt', 'utf8'), read('input.txt', 'utf8'));
console.log(exists('input.txt'), exists('missing.txt'));
"#;
const BOUND_READ_EXPECTED: &str = "native bytes native bytes\ntrue false";

#[test]
fn namespace_and_destructured_reads_execute_without_builtin_or_write_grants() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("input.txt"), "native bytes").unwrap();
    let actual = run(BOUND_READ_SOURCE, root.path(),
        &["vm_dispatch", "heap_allocate", "console", "fs_read"])
        .expect("bound reads use only their original authority");
    assert_eq!(actual.join("\n"), BOUND_READ_EXPECTED);
    assert_eq!(std::fs::read_to_string(root.path().join("input.txt")).unwrap(), "native bytes");
}

const BOUND_WRITE_SOURCE: &str = r#"
const fs = require('fs');
const {appendFileSync: append, renameSync: rename} = require('node:fs');
fs.writeFileSync('first.txt', 'first');
append('first.txt', ':second');
rename('first.txt', 'result.txt');
"#;

#[test]
fn bound_writers_require_real_write_authority_and_produce_real_disk_contents() {
    let root = tempfile::tempdir().unwrap();
    assert!(run(BOUND_WRITE_SOURCE, root.path(),
        &["vm_dispatch", "heap_allocate", "fs_read"]).is_err());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    run(BOUND_WRITE_SOURCE, root.path(),
        &["vm_dispatch", "heap_allocate", "fs_write"]).expect("authorized native writes");
    assert!(!root.path().join("first.txt").exists());
    assert_eq!(std::fs::read_to_string(root.path().join("result.txt")).unwrap(), "first:second");
}

const BOUND_ORDER_SOURCE: &str = r#"
function before() { console.log('before'); return 1; }
function after() { console.log('after'); return 2; }
function path() { console.log('path'); return 'input.txt'; }
function encoding() { console.log('encoding'); return 'utf8'; }
const a = before(), {readFileSync: read, existsSync: exists} = require('fs'), z = after();
console.log(a, z, read(path(), encoding()), exists('input.txt'));
try { read('missing.txt', 'utf8'); } catch (error) { console.log(error.code); }
"#;
const BOUND_ORDER_EXPECTED: &str = "before\nafter\npath\nencoding\n1 2 payload true\nENOENT";

#[test]
fn alias_expansion_preserves_operand_order_and_catchable_error_boundaries() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("input.txt"), "payload").unwrap();
    let actual = run(BOUND_ORDER_SOURCE, root.path(),
        &["vm_dispatch", "heap_allocate", "console", "fs_read"])
        .expect("declarations, operand effects and native exception");
    assert_eq!(actual.join("\n"), BOUND_ORDER_EXPECTED);
}

const BOUND_MUTATION_SOURCE: &str = r#"
const fs = require('fs');
fs.readFileSync = function () { return 'replacement'; };
console.log(fs.readFileSync('missing.txt'), require('node:fs').readFileSync('missing.txt'));
"#;
const BOUND_MUTATION_EXPECTED: &str = "replacement replacement";

#[test]
fn an_alias_method_mutation_keeps_alias_and_inline_calls_on_the_same_object() {
    let root = tempfile::tempdir().unwrap();
    let actual = run(BOUND_MUTATION_SOURCE, root.path(),
        &["vm_dispatch", "heap_allocate", "builtin", "console"])
        .expect("observable module uses retain the original path");
    assert_eq!(actual.join("\n"), BOUND_MUTATION_EXPECTED);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn bound_writes_retain_the_secret_flow_refusal() {
    for source in [
        "const fs = require('fs'); const secret = process.env.TOKEN; fs.writeFileSync('out', secret);",
        "const {writeFileSync: write} = require('fs'); const secret = process.env.TOKEN; write('out', secret);",
    ] {
        let report = analyze_authority_footprint(source, "bound-secret-write.js", ParseGoal::Script);
        assert_ne!(report.outcome(), CheckOutcome::Clean);
        assert!(report.fail_closed_reason.as_deref().is_some_and(|reason| {
            reason.contains("unauthorized flow")
        }), "the original IFC boundary must reject this data flow: {report:?}");
    }
}

#[test]
fn access_constant_reads_are_analyzable_without_filesystem_or_builtin_authority() {
    for source in [
        "require('fs').constants.R_OK;",
        "const fs = require('node:fs'); fs.constants.F_OK | fs.constants.W_OK;",
    ] {
        let report = analyze_authority_footprint(source, "fs-constants.js", ParseGoal::Script);
        assert_eq!(
            report.outcome(),
            CheckOutcome::Clean,
            "{source}: {report:?}"
        );
        assert!(
            !report.required_capabilities.iter().any(|requirement| {
                matches!(
                    requirement.capability,
                    Some(
                        RuntimeCapability::FsRead
                            | RuntimeCapability::FsWrite
                            | RuntimeCapability::Builtin
                    )
                )
            }),
            "constant data must not add module authority: {report:?}"
        );
        assert_eq!(
            report,
            analyze_authority_footprint(source, "fs-constants.js", ParseGoal::Script)
        );
    }
}

#[test]
fn access_with_mode_constants_keeps_only_the_read_capability() {
    for source in [
        "require('fs').accessSync('input.txt', require('node:fs').constants.R_OK);",
        "const fs = require('fs'); fs.accessSync('input.txt', fs.constants.F_OK | fs.constants.R_OK);",
    ] {
        let report = analyze_authority_footprint(source, "fs-access.js", ParseGoal::Script);
        assert_eq!(
            report.outcome(),
            CheckOutcome::Clean,
            "{source}: {report:?}"
        );
        assert!(
            report
                .required_capabilities
                .iter()
                .any(|requirement| { requirement.capability == Some(RuntimeCapability::FsRead) })
        );
        assert!(
            !report.required_capabilities.iter().any(|requirement| {
                matches!(
                    requirement.capability,
                    Some(RuntimeCapability::FsWrite | RuntimeCapability::Builtin)
                )
            }),
            "unused facade methods must not add authority: {report:?}"
        );
    }
}

#[test]
fn access_constants_need_no_filesystem_grant_but_access_still_does() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("input.txt"), "unchanged").unwrap();
    let output = run(
        "const fs = require('fs'); console.log(fs.constants.F_OK, fs.constants.X_OK, \
         fs.constants.W_OK, fs.constants.R_OK);",
        root.path(),
        &["vm_dispatch", "heap_allocate", "console"],
    )
    .expect("access constants are inert data");
    assert_eq!(output, ["0 1 2 4"]);
    let source = "const fs = require('node:fs'); fs.accessSync('input.txt', fs.constants.R_OK);";
    let denied = run(source, root.path(), &["vm_dispatch", "heap_allocate"])
        .expect_err("access still requires read authority");
    assert!(
        denied.contains("CapabilityDenied") && denied.contains("fs:read"),
        "{denied}"
    );
    run(
        source,
        root.path(),
        &["vm_dispatch", "heap_allocate", "fs_read"],
    )
    .expect("access runs without unused builtin or writer grants");
    assert_eq!(
        std::fs::read_to_string(root.path().join("input.txt")).unwrap(),
        "unchanged"
    );
}

#[test]
fn literal_numeric_result_indexing_preserves_analyzable_read_authority() {
    for (prefix, receiver) in [
        ("", "require('fs')"),
        ("const fs = require('node:fs');", "fs"),
    ] {
        for suffix in ["[0]", ".split('\\n')[0]"] {
            let source = format!("{prefix} {receiver}.readFileSync('input.txt', 'utf8'){suffix};");
            let report = analyze_authority_footprint(&source, "indexed-read.js", ParseGoal::Script);
            assert_eq!(
                report.outcome(),
                CheckOutcome::Clean,
                "{source}: {report:?}"
            );
            assert!(
                report.required_capabilities.iter().any(|requirement| {
                    requirement.capability == Some(RuntimeCapability::FsRead)
                })
            );
            assert!(
                !report.required_capabilities.iter().any(|requirement| {
                    requirement.capability == Some(RuntimeCapability::FsWrite)
                }),
                "unused writer methods must not pollute an indexed read: {report:?}"
            );
        }
        for observer in [
            "const key = 'constructor'; const dynamic = (() => {})[key];",
            "const dynamic = (() => {})['constructor'];",
        ] {
            let source =
                format!("{prefix} {receiver}.readFileSync('input.txt', 'utf8')[0]; {observer}");
            let report = analyze_authority_footprint(&source, "indexed-read.js", ParseGoal::Script);
            assert_eq!(
                report.outcome(),
                CheckOutcome::FindingsPresent,
                "{source}: {report:?}"
            );
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.error_code == "FE-CAP-0001")
            );
        }
    }
}
