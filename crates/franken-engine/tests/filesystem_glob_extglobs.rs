//! Positive extglob discovery through the native filesystem capability boundary.
//! JavaScript host differential tests do not establish that these tests pass.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};
use frankenengine_extension_host::host_io::{
    FsOperation, HostIoCapability, HostIoOutcome, HostIoRecorder, HostIoRequest,
    InMemoryHostIoTranscript, SandboxedHostIo,
};

type Run = (Vec<String>, Vec<(HostIoRequest, HostIoOutcome)>);

fn run(source: &str, root: &Path, caps: &[&str], lane: LaneChoice) -> Result<Run, String> {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox provider"));
    let recording = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder: Arc<dyn HostIoRecorder> = recording.clone();
    let mut runtime = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        ..OrchestratorConfig::default()
    });
    runtime.set_host_io(provider, Some(recorder));
    let mut capabilities = vec!["vm_dispatch", "heap_allocate", "builtin", "console"];
    capabilities.extend_from_slice(caps);
    let package = ExtensionPackage {
        extension_id: "filesystem-glob-extglobs".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: capabilities.into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = runtime.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok((
        result.console_output.into_iter().map(|entry| entry.message).collect(),
        recording.entries(),
    ))
}

fn workspace(root: &Path) {
    for (name, content) in [
        ("packages/alpha/package.json", r#"{"name":"alpha"}"#),
        ("apps/ui/package.json", r#"{"name":"ui"}"#),
        ("src/main.js", "alpha"),
        ("src/main.test.js", "not a build input"),
        ("src/index.ts", "beta"),
        ("src/unused.txt", "unused"),
        ("vendor/private/ignored.js", "vendor"),
        ("build/private/ignored.ts", "build"),
    ] {
        let file = root.join(name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, content).unwrap();
    }
}

#[test]
fn extglob_workspace_and_source_discovery_share_native_read_only_traversal() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path());
        let (lines, effects) = run(
            r#"const fs=require('node:fs');const Object='guest';const String='guest';
            console.log('MANIFESTS',fs.globSync('@(packages|apps)/*/package.json').sort().join('|'));
            console.log('INPUTS',fs.globSync('**/*.@(js|ts)',{
              exclude:['@(vendor|build)','**/*.@(test|spec).js']}).sort().join('|'));
            console.log('DISCOVERY_COMPLETE');"#,
            root.path(), &["fs_read"], lane,
        ).expect("native extglob discovery completes");
        assert_eq!(lines, [
            "MANIFESTS apps/ui/package.json|packages/alpha/package.json",
            "INPUTS src/index.ts|src/main.js",
            "DISCOVERY_COMPLETE",
        ]);
        assert!(effects.iter().all(|(request, _)| {
            request.required_capability() == HostIoCapability::FsRead
        }));
        let directories = effects.iter().filter(|(request, _)| matches!(request,
            HostIoRequest::FsMeta { operation: FsOperation::ReadDir, .. })).count();
        // Five snapshots discover manifests. Six discover source files, never
        // opening either excluded tree or the unrelated src tree on pass one.
        assert_eq!(directories, 11);
    }
}

#[test]
fn typed_callback_and_async_discovery_drive_a_complete_build() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path());
        let (lines, _) = run(
            r#"const fs=require('fs');
            fs.glob('src/@(main|index).@(js|ts)',{withFileTypes:true},function(error,entries){
              if(error)throw error;
              const inputs=entries.map(e=>{if(!e.isFile())throw Error('file expected');return e.parentPath+'/'+e.name;}).sort();
              fs.writeFileSync('bundle.txt',inputs.map(p=>fs.readFileSync(p,'utf8')).join('\n')+'\n');
              (async function(){const names=[];
                for await(const name of fs.promises.glob('@(packages|apps)/*/package.json'))names.push(name);
                fs.writeFileSync('manifest-index.txt',names.sort().join('\n')+'\n');
                console.log('BUILD_COMPLETE',inputs.length,names.length);
              })();
            });"#,
            root.path(), &["fs_read", "fs_write"], lane,
        ).expect("native callback and iterator build completes");
        assert_eq!(lines, ["BUILD_COMPLETE 2 2"]);
        assert_eq!(std::fs::read(root.path().join("bundle.txt")).unwrap(), b"beta\nalpha\n");
        assert_eq!(std::fs::read(root.path().join("manifest-index.txt")).unwrap(),
            b"apps/ui/package.json\npackages/alpha/package.json\n");
    }
}

#[test]
fn positive_extglobs_preserve_preflight_limits_and_do_not_grant_read_authority() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path());
        let (lines, effects) = run(
            r#"const fs=require('fs');
            for(const pattern of ['src/!(test).js','@(unfinished','@('.repeat(17)+'a'+')'.repeat(17)]){
              try{fs.globSync(pattern);throw Error('must reject');}catch(error){console.log(error.code);}
            }
            const patterns=new Array(128).fill('@('+'a'.repeat(260)+'|b)');
            try{fs.globSync(patterns);throw Error('must reject');}catch(error){console.log(error.code);}
            console.log('PREFLIGHT_COMPLETE');"#,
            root.path(), &[], lane,
        ).expect("preflight performs no filesystem operation");
        assert_eq!(lines, ["ERR_FS_GLOB_UNSUPPORTED", "ERR_FS_GLOB_UNSUPPORTED",
            "ERR_FS_GLOB_LIMIT", "ERR_FS_GLOB_LIMIT", "PREFLIGHT_COMPLETE"]);
        assert!(effects.is_empty());
        assert!(run(
            "require('fs').globSync('src/*.@(js|ts)');console.log('UNAUTHORIZED_SUCCESS');",
            root.path(), &[], lane,
        ).is_err(), "positive extglobs cannot bypass filesystem capability checks");
    }
}

#[test]
fn repeated_and_nested_alternatives_do_not_expand_pattern_combinations() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        let name = format!("{}.js", "ab".repeat(16));
        std::fs::write(root.path().join(&name), b"bounded").unwrap();
        std::fs::write(root.path().join("abac"), b"nullable").unwrap();
        let (lines, _) = run(
            r#"const fs=require('fs');
            console.log('ALTERNATIVES',fs.globSync('@(a|b)'.repeat(32)+'.js').length);
            console.log('NULLABLE',fs.globSync('*(@(|a)|?(b))c').join('|'));
            console.log('MACHINE_COMPLETE');"#,
            root.path(), &["fs_read"], lane,
        ).expect("native compact matching completes within ordinary budgets");
        assert_eq!(lines, ["ALTERNATIVES 1", "NULLABLE abac", "MACHINE_COMPLETE"]);
    }
}
