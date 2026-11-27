#![forbid(unsafe_code)]
//! Real binary files enter the same bounded Rust Wasm VM as resolver-delivered
//! modules. These tests cover the filesystem root, CLI and exact replay input.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorResult,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, DeterministicModuleResolver, ExecutionModuleResolver, ImportStyle,
    ModuleDefinition, ModuleRequest, ModuleResolver, ModuleSyntax, ResolutionContext,
};

fn directory(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "fe_filesystem_wasm_{label}_{}_{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("module directory");
    path.canonicalize().expect("canonical module root")
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    let mut remaining = payload.len();
    loop {
        let byte = (remaining & 127) as u8;
        remaining >>= 7;
        module.push(byte | if remaining == 0 { 0 } else { 128 });
        if remaining == 0 {
            break;
        }
    }
    module.extend_from_slice(payload);
}

/// A private mutable i32 initialized to 128 + offset, exported through bump.
/// Its signed-LEB constant contains a non-UTF-8 byte; no text adapter is usable.
fn counter_binary(offset: u8) -> Vec<u8> {
    assert!(offset < 64);
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[1, 0x60, 1, 0x7f, 1, 0x7f]);
    section(&mut bytes, 3, &[1, 0]);
    section(&mut bytes, 6, &[1, 0x7f, 1, 0x41, 0x80 | offset, 1, 0x0b]);
    section(&mut bytes, 7, &[1, 4, b'b', b'u', b'm', b'p', 0, 0]);
    section(
        &mut bytes,
        10,
        &[1, 11, 0, 0x23, 0, 0x20, 0, 0x6a, 0x24, 0, 0x23, 0, 0x0b],
    );
    bytes
}

fn package(root: &Path, source: &str) -> ExtensionPackage {
    fs::write(root.join("entry.mjs"), source).expect("entry source");
    ExtensionPackage {
        extension_id: "filesystem-wasm".into(),
        source: source.into(),
        source_file: Some(root.join("entry.mjs").to_str().expect("entry path").into()),
        module_root: Some(root.to_str().expect("module root").into()),
        capabilities: vec!["module_load".into(), "vm_dispatch".into(), "builtin".into()],
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    }
}

fn engine(lane: LaneChoice) -> ExecutionOrchestrator {
    ExecutionOrchestrator::try_new_lab(OrchestratorConfig {
        force_lane: Some(lane),
        parse_goal: ParseGoal::Module,
        ..OrchestratorConfig::default()
    })
    .expect("orchestrator")
}

fn lines(result: &OrchestratorResult) -> Vec<&str> {
    result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect()
}

#[test]
fn static_dynamic_and_cached_imports_share_the_captured_binary_instance() {
    let root = directory("imports");
    let bytes = counter_binary(0);
    assert!(std::str::from_utf8(&bytes).is_err());
    fs::write(root.join("counter.wasm"), &bytes).expect("binary module");
    let package = package(
        &root,
        r#"
import * as first from './counter.wasm';
import { bump } from './counter.wasm';
console.log(bump(2));
const second = await import('./counter.wasm');
console.log(second.bump(3), first === second, second.bump === bump);
console.log(Object.getPrototypeOf(first) === null, typeof WebAssembly);
"#,
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let result = engine(lane)
            .execute(&package)
            .unwrap_or_else(|error| panic!("{lane:?}: {error}"));
        assert_eq!(lines(&result), ["130", "133 true true", "true undefined"]);
        assert_eq!(
            result.imported_module_hashes.get("counter.wasm"),
            Some(&ContentHash::compute(&bytes).to_hex())
        );
    }
}

#[test]
fn distinct_files_own_distinct_instances_even_when_their_bytes_match() {
    let root = directory("identity");
    let bytes = counter_binary(0);
    fs::write(root.join("first.wasm"), &bytes).expect("first binary");
    fs::write(root.join("second.wasm"), &bytes).expect("second binary");
    let package = package(
        &root,
        r#"
import { bump as first } from './first.wasm';
import { bump as second } from './second.wasm';
console.log(first(1), first(1), second(1), first === second);
"#,
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let result = engine(lane).execute(&package).expect("two instances");
        assert_eq!(lines(&result), ["129 130 129 false"]);
        assert_eq!(
            result.imported_module_hashes.get("first.wasm"),
            result.imported_module_hashes.get("second.wasm")
        );
    }
}

#[test]
fn raw_binary_hashes_replay_exactly_and_refuse_changed_bytes_before_execution() {
    let root = directory("replay");
    let bytes = counter_binary(0);
    fs::write(root.join("counter.wasm"), &bytes).expect("binary");
    let package = package(
        &root,
        "import { bump } from './counter.wasm'; console.log(bump(2));",
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        fs::write(root.join("counter.wasm"), &bytes).expect("original binary");
        let mut engine = engine(lane);
        let first = engine.execute(&package).expect("initial execution");
        engine.set_expected_imported_module_hashes(first.imported_module_hashes.clone());
        let replayed = engine.execute(&package).expect("exact binary replay");
        assert_eq!(lines(&first), lines(&replayed));
        assert_eq!(first.imported_module_hashes, replayed.imported_module_hashes);
        fs::write(root.join("counter.wasm"), counter_binary(1)).expect("changed binary");
        let error = engine.execute(&package).expect_err("changed input refused");
        assert!(
            error.to_string().contains("module integrity content mismatch"),
            "{lane:?}: {error}"
        );
        assert!(engine.last_failed_console_output().is_empty());
    }
}

#[test]
fn missing_module_authority_refuses_the_file_before_binary_input_capture() {
    let root = directory("authority");
    fs::write(root.join("counter.wasm"), counter_binary(0)).expect("binary");
    let mut package = package(
        &root,
        "const wasm = await import('./counter.wasm'); console.log(wasm.bump(1));",
    );
    package.capabilities.retain(|value| value != "module_load");
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut engine = engine(lane);
        let error = engine.execute(&package).expect_err("ModuleLoad is required");
        assert!(error.to_string().contains("module_load"), "{lane:?}: {error}");
        assert!(engine.last_failed_console_output().is_empty());
        if let Some(context) = engine.last_failed_execution_replay_context() {
            assert!(!context.imported_module_hashes.contains_key("counter.wasm"));
        }
    }
}

#[test]
fn require_and_json_attributes_cannot_reuse_a_wasm_namespace() {
    let root = directory("format");
    fs::write(root.join("counter.wasm"), counter_binary(0)).expect("binary");
    let package = package(
        &root,
        r#"
import * as first from './counter.wasm';
try {
    await import('./counter.wasm', { with: { type: 'json' } });
    console.log('unexpected json import');
} catch (error) {
    console.log(error instanceof TypeError);
}
console.log(first.bump(1));
"#,
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let result = engine(lane).execute(&package).expect("format rejection caught");
        assert_eq!(lines(&result), ["true", "129"]);
        let mut cjs = package.clone();
        cjs.source = "require('./counter.wasm'); console.log('unreachable');".into();
        let mut engine = ExecutionOrchestrator::try_new_lab(OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: ParseGoal::Script,
            commonjs_entry: true,
            ..OrchestratorConfig::default()
        })
        .expect("CommonJS engine");
        let error = engine.execute(&cjs).expect_err("require cannot execute Wasm");
        assert!(error.to_string().contains("ESM import"), "{lane:?}: {error}");
        assert!(engine.last_failed_console_output().is_empty());
    }
}

#[test]
fn binary_reads_obey_the_source_byte_limit_and_malformed_modules_fail_closed() {
    let root = directory("bounds");
    let bytes = counter_binary(0);
    fs::write(root.join("counter.wasm"), &bytes).expect("small binary");
    let package = package(
        &root,
        "import { bump } from './counter.wasm'; console.log(bump(2));",
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut config = OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: ParseGoal::Module,
            ..OrchestratorConfig::default()
        };
        config.parser_options.budget.max_source_bytes = 256;
        let mut engine = ExecutionOrchestrator::try_new_lab(config).expect("bounded engine");
        fs::write(root.join("counter.wasm"), &bytes).expect("small binary");
        assert_eq!(
            lines(&engine.execute(&package).expect("small binary fits")),
            ["130"]
        );
        let mut large = bytes.clone();
        let mut custom = vec![1, b'x'];
        custom.resize(1024, 0xff);
        section(&mut large, 0, &custom);
        fs::write(root.join("counter.wasm"), large).expect("large binary");
        let error = engine.execute(&package).expect_err("oversized source refused");
        assert!(error.to_string().contains("source-byte budget"), "{lane:?}: {error}");
        assert!(engine.last_failed_console_output().is_empty());
        fs::write(root.join("counter.wasm"), b"not a wasm module").expect("malformed binary");
        let error = engine.execute(&package).expect_err("invalid binary refused");
        assert!(error.to_string().contains("numeric Wasm module refused"), "{lane:?}: {error}");
        assert!(engine.last_failed_console_output().is_empty());
    }
}

#[test]
#[cfg(unix)]
fn module_root_confines_wasm_and_in_root_aliases_share_identity() {
    use std::os::unix::fs::symlink;

    let outer = directory("root");
    let root = outer.join("app");
    fs::create_dir(&root).expect("confined module root");
    fs::write(outer.join("outside.wasm"), counter_binary(0)).expect("outside binary");
    fs::write(root.join("counter.wasm"), counter_binary(0)).expect("inside binary");
    symlink(outer.join("outside.wasm"), root.join("escape.wasm")).expect("escape link");
    symlink(root.join("counter.wasm"), root.join("alias.wasm")).expect("inside link");
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let allowed = package(
            &root,
            r#"
import * as first from './counter.wasm';
import * as alias from './alias.wasm';
console.log(first === alias, first.bump(1), alias.bump(1));
"#,
        );
        let result = engine(lane).execute(&allowed).expect("canonical in-root alias");
        assert_eq!(lines(&result), ["true 129 130"]);
        assert!(result.imported_module_hashes.contains_key("counter.wasm"));
        assert!(!result.imported_module_hashes.contains_key("alias.wasm"));
        for specifier in ["../outside.wasm", "./escape.wasm"] {
            let denied = package(
                &root,
                &format!("await import('{specifier}'); console.log('unreachable');"),
            );
            let mut engine = engine(lane);
            let error = engine.execute(&denied).expect_err("root escape refused");
            assert!(error.to_string().contains("escape"), "{lane:?}: {error}");
            assert!(engine.last_failed_console_output().is_empty());
        }
    }
}

#[test]
fn an_installed_resolver_never_falls_back_to_an_adjacent_wasm_file() {
    let root = directory("closed_world");
    fs::write(root.join("counter.wasm"), counter_binary(0)).expect("undelivered binary");
    let package = package(
        &root,
        "await import('./counter.wasm'); console.log('unreachable');",
    );
    let mut resolver = DeterministicModuleResolver::new(root.to_str().expect("root"));
    let entry_path = package.source_file.as_deref().expect("entry path");
    resolver
        .register_workspace_module(
            entry_path,
            ModuleDefinition::new(ModuleSyntax::EsModule, package.source.clone()),
        )
        .expect("only the entry is delivered");
    let resolver = Arc::new(resolver);
    let entry = resolver
        .resolve(
            &ModuleRequest::new(entry_path, ImportStyle::Import),
            &ResolutionContext::new("filesystem-test", "filesystem-test", "filesystem-test"),
            &AllowAllPolicy,
        )
        .expect("captured entry");
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let installed = ExecutionModuleResolver::new(
            entry_path,
            resolver.clone(),
            Arc::new(AllowAllPolicy),
        );
        let mut engine = engine(lane);
        assert!(
            engine
                .execute_resolved_entry_with_resolver(&package, &entry, installed)
                .is_err(),
            "an existing file must not satisfy an undelivered import"
        );
        assert!(engine.last_failed_console_output().is_empty());
    }
}

fn cli(root: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .current_dir(root)
        .args(arguments)
        .output()
        .expect("frankenctl")
}

#[test]
fn cli_executes_binary_imports_and_strict_replay_detects_binary_tampering() {
    let root = directory("cli");
    fs::write(root.join("counter.wasm"), counter_binary(0)).expect("binary");
    fs::write(
        root.join("main.mjs"),
        r#"
import { bump } from './counter.wasm';
console.log(bump(2));
const again = await import('./counter.wasm');
console.log(again.bump(3));
"#,
    )
    .expect("entry");
    let run = cli(
        &root,
        &[
            "run", "--input", "main.mjs", "--goal", "module",
            "--extension-id", "filesystem-wasm-cli", "--out", "run.json",
        ],
    );
    assert!(
        run.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr),
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("run.json")).expect("run report"))
            .expect("JSON report");
    let messages: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console output")
        .iter()
        .map(|entry| entry["message"].as_str().expect("console message"))
        .collect();
    assert_eq!(messages, ["130", "133"]);
    let replay_args = ["replay", "run", "--trace", "run.json", "--mode", "strict"];
    let replayed = cli(&root, &replay_args);
    assert!(
        replayed.status.success(),
        "strict replay failed: {}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    fs::write(root.join("counter.wasm"), counter_binary(1)).expect("changed binary");
    let rejected = cli(&root, &replay_args);
    assert!(
        !rejected.status.success(),
        "strict replay accepted changed Wasm input: {}",
        String::from_utf8_lossy(&rejected.stdout)
    );
}
