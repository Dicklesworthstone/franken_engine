#![forbid(unsafe_code)]

//! bd-9vouw.188: a `require` that does not resolve throws a catchable Error
//! with code MODULE_NOT_FOUND, as Node's does. It ended the run, so feature
//! detection (`try { require('buffer') } catch {}` in js-yaml,
//! `freeModule.require('util')` in lodash, optional dependencies) failed
//! whole programs. The module stays unloaded: a path outside the module root
//! is refused the same way. Expected line is Node v22.2.0's output (Bun
//! 1.4.2 prints the same).

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

#[test]
fn failed_requires_throw_catchable_module_not_found_errors() {
    let root = tempfile::tempdir().expect("module root");
    let entry = root.path().join("app.cjs");
    std::fs::write(&entry, "const out = [];\nfor (const spec of ['./nope', 'no-such-package-xyz', '../outside/x']) {\n  try {\n    require(spec);\n    out.push('loaded');\n  } catch (e) {\n    out.push(e.code + ' ' + e.message.split('\\n')[0]);\n  }\n}\ntry {\n  module.require('also-missing');\n} catch (e) {\n  out.push(e.code + ' ' + (e instanceof Error));\n}\nconsole.log(out.join(' | '));\n").expect("entry");
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let package = ExtensionPackage {
            extension_id: "require-missing".to_string(),
            source: std::fs::read_to_string(&entry).expect("entry source"),
            source_file: Some(entry.display().to_string()),
            module_root: Some(root.path().display().to_string()),
            capabilities: vec!["module_load".to_string(), "builtin".to_string()],
            version: "1.0.0".to_string(),
            metadata: Default::default(),
        };
        let lines: Vec<String> = ExecutionOrchestrator::new(OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: ParseGoal::Script,
            commonjs_entry: true,
            ..OrchestratorConfig::default()
        })
        .execute(&package)
        .unwrap_or_else(|error| panic!("{lane:?}: {error}"))
        .console_output
        .into_iter()
        .map(|line| line.message)
        .collect();
        assert_eq!(
            lines,
            [
                "MODULE_NOT_FOUND Cannot find module './nope' | MODULE_NOT_FOUND Cannot find module 'no-such-package-xyz' | MODULE_NOT_FOUND Cannot find module '../outside/x' | MODULE_NOT_FOUND true"
            ],
            "{lane:?}"
        );
    }
}
