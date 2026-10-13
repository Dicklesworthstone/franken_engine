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
