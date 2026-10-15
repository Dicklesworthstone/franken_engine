//! Native execution tests: the hosted path factory cannot establish these pass.
#![forbid(unsafe_code)]
use std::collections::BTreeMap;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};

fn run(source: &str, lane: LaneChoice) -> Vec<String> {
    let mut engine = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane), ..OrchestratorConfig::default()
    });
    let package = ExtensionPackage {
        extension_id: "path-namespace-values".into(), source: source.into(),
        source_file: None, module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(), metadata: BTreeMap::new(),
    };
    engine.execute(&package).expect("native path namespace completion")
        .console_output.into_iter().map(|line| line.message).collect()
}

const NAMESPACES: &str = r#"
const p=require('path/posix'), w=require('node:path/win32'), q=require('path');
console.log('IDENTITY',p===q,w===q.win32,w.posix===p,w.win32===w,p.posix===p);
console.log('PATH',w.join('C:\\work','..','out','file.txt'),
 w.resolve('D:\\ignored','C:\\base','..','out'),w.relative('C:\\base\\src','c:\\base\\out'),
 w.basename('D:\\file.txt','.txt'),w.sep==='\\',w.delimiter);
"#;

const COMPONENTS: &str = r#"
const {parse,format,dirname,extname,toNamespacedPath}=require('path/win32');
const paths=['C:\\base\\file.tar.gz','//server/share/a.txt','C:relative','.hidden','C:\\é\\😀.txt'];
for(const input of paths){const p=parse(input);console.log(JSON.stringify([p,format(p),dirname(input),extname(input)]));}
console.log('NAMESPACE',toNamespacedPath('C:\\work\\..\\out'),toNamespacedPath('\\\\server\\share\\file'));
"#;

const MUTATION: &str = r#"
const p=require('path');const w=p.win32;const old=w.join;
w.join=function(){return 'patched';};
console.log('MUTATION',p.win32.join(),require('path').win32.join(),require('node:path/win32').join(),w.posix.win32===w);
w.join=old;const select=w.join;
console.log('CALLBACK', ['a','b'].map(function(value){return select('C:\\root',value);}).join(','));
console.log('RESTORED',require('path').win32.join('C:\\root','c'));
"#;

const GETTERS: &str = r#"
const {format}=require('path/win32');const Array='guest';const seen=[];
const object={get dir(){seen.push('dir');return 'C:\\out';},get root(){seen.push('root');return 'C:\\';},
 get base(){seen.push('base');return '';},get name(){seen.push('name');return 'file';},get ext(){seen.push('ext');return 'txt';}};
console.log('FORMAT',format(object),seen.join(','));
for(const require of [function(name){return {sep:name};}]) console.log('LOCAL',require('path/win32').sep);
try{format([]);}catch(error){console.log('ERROR',error.code);}
"#;

#[test]
fn windows_and_posix_values_share_one_native_namespace_pair() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(NAMESPACES, lane), [
            "IDENTITY true true true true true",
            "PATH C:\\out\\file.txt C:\\out ..\\out file true ;",
        ]);
    }
}

#[test]
fn components_roundtrip_and_namespace_roots_preserve_windows_meaning() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(COMPONENTS, lane), [
            r#"[{"root":"C:\\","dir":"C:\\base","base":"file.tar.gz","ext":".gz","name":"file.tar"},"C:\\base\\file.tar.gz","C:\\base",".gz"]"#,
            r#"[{"root":"//server/share/","dir":"//server/share/","base":"a.txt","ext":".txt","name":"a"},"//server/share/a.txt","//server/share/",".txt"]"#,
            r#"[{"root":"C:","dir":"C:","base":"relative","ext":"","name":"relative"},"C:relative","C:",""]"#,
            r#"[{"root":"","dir":"","base":".hidden","ext":"","name":".hidden"},".hidden",".",""]"#,
            r#"[{"root":"C:\\","dir":"C:\\é","base":"😀.txt","ext":".txt","name":"😀"},"C:\\é\\😀.txt","C:\\é",".txt"]"#,
            "NAMESPACE \\\\?\\C:\\out \\\\?\\UNC\\server\\share\\file",
        ]);
    }
}

#[test]
fn mixed_inline_and_escaped_path_values_observe_namespace_mutations() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(MUTATION, lane), [
            "MUTATION patched patched patched true", "CALLBACK C:\\root\\a,C:\\root\\b", "RESTORED C:\\root\\c",
        ]);
    }
}

#[test]
fn path_format_orders_getters_and_preserves_shadowed_loaders() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(GETTERS, lane), [
            "FORMAT C:\\out\\file.txt dir,base,name,ext,root", "LOCAL path/win32", "ERROR ERR_INVALID_ARG_TYPE",
        ]);
    }
}
