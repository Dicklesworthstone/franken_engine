#!/usr/bin/env python3
"""Reproduce only issue #6's bounded native parser/lowerer/authority probe.

Copies exact source from recorded starting main, overlays the qualified files,
and extracts unchanged production test bodies. Never executes InterpreterCore.
Use an adequately provisioned host with the pinned toolchain and Cargo cache.
The JSON evidence is the selection/lockfile input; repository sources are read
only and all generated files are confined to a new --work directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

def prepare_source_snapshot(P,R):
    import pathlib,subprocess,re,json,hashlib,os
    REV='f658c30622bd21e19d2137676a724360f604851f'
    mods=['ast','authority_footprint','capability','deterministic_serde','effect_set','engine_object_id','epoch_barrier','feature_parity_tracker','flow_lattice','hash_tiers','ifc_artifacts','ir_contract','js_string','lowering_arena','lowering_pipeline','module_compatibility_matrix','module_resolver','object_model','parser','parser_api_stability','parser_gap_inventory','security_epoch','signature_preimage','ts_normalization','unified_authority_algebra']
    engine='crates/franken-engine/src/'
    core='crates/franken-core/src/'
    paths=[engine+m+'.rs' for m in mods]+[engine+m for m in mods]+[core+m for m in ['js_string.rs','js_string','deterministic_serde.rs','hash_tiers.rs']]+[engine+'baseline_interpreter.rs',engine+'baseline_interpreter/regexp_syntax.rs',engine+'baseline_interpreter/regexp_backtrack.rs',engine+'baseline_interpreter/regexp_backtrack',engine+'baseline_interpreter/regexp_input.rs',engine+'baseline_interpreter/package_resolution.rs',engine+'baseline_interpreter/iterator_helpers.rs','artifacts/issue6_scoped_qualification_20261027.json','crates/franken-engine/docs/module_compatibility_matrix_v1.json']
    files=subprocess.check_output(['git','ls-tree','-r','--name-only',REV,'--',*paths],cwd=R,text=True).splitlines()
    provenance={}
    for file in files:
     data=subprocess.check_output(['git','show',REV+':'+file],cwd=R)
     target=P/'snapshot'/file;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
     provenance[file]=hashlib.sha256(data).hexdigest()
    S=P/'snapshot'/engine; C=P/'snapshot'/core
    cap=(S/'capability.rs').read_text();assert cap.count('pub mod trust_zone;')==1
    (S/'capability.rs').write_text(cap.replace('pub mod trust_zone;','// Excluded unused capability::trust_zone from diagnostic crate.'))

    def block(text,start,indent=''):
     m=re.search(r'^'+re.escape(indent)+start,text,re.M)
     if not m: raise ValueError(start)
     end=re.search(r'^'+re.escape(indent)+r'}\s*$',text[m.end():],re.M)
     if not end: raise ValueError(start+' ending')
     return text[m.start():m.end()+end.end()].rstrip()+'\n'

    def const(text,name):
     m=re.search(r'^(?:pub\([^)]*\) )?const '+name+r'\b[^;]*;',text,re.M)
     if not m: raise ValueError(name)
     return m.group(0)+'\n'

    base=(S/'baseline_interpreter.rs').read_text(); pkg=(S/'baseline_interpreter/package_resolution.rs').read_text(); inp=(S/'baseline_interpreter/regexp_input.rs').read_text(); ih=(S/'baseline_interpreter/iterator_helpers.rs').read_text()
    metadata='use serde::{Serialize, Deserialize};\nuse regex::RegexBuilder;\nuse std::collections::BTreeSet;\nuse crate::capability::{RuntimeCapability, hostcall_registry_row};\nmod regexp_syntax;\nmod regexp_backtrack;\nuse regexp_backtrack::{BacktrackRegExp, MAX_PATTERN_LEN, PATTERN_TOO_LARGE};\n'
    for n in ['ITERATOR_PROTOTYPE','ARRAY_ITERATOR_PROTOTYPE','MAP_ITERATOR_PROTOTYPE','SET_ITERATOR_PROTOTYPE','GENERATOR_PROTOTYPE','ASYNC_GENERATOR_PROTOTYPE','ASYNC_ITERATOR_PROTOTYPE']: metadata+=const(base,n)
    metadata+='mod iterator_helpers {\n'+''.join(const(ih,n) for n in ['ITERATOR_HELPER_PROTOTYPE','WRAP_FOR_VALID_ITERATOR_PROTOTYPE','REGEXP_STRING_ITERATOR_PROTOTYPE'])+'}\n'
    for name in ['HostcallCapabilityClass','InterpreterError','ModuleResolutionFailureReason']:
     metadata+='#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\n'+block(base,r'(?:pub )?enum '+name+r'\b')
    for name in ['classify_hostcall_capability','live_hostcall_decision','builtin_instanceof_capability_name','canonical_builtin_prototype_name','regexp_literal_early_error']:
     metadata+=block(base,r'(?:pub\(crate\) )?fn '+name+r'\b')
    metadata+=const(pkg,'NODE_CORE_MODULE_NAMES')+block(pkg,r'pub\(crate\) fn is_node_core_module_specifier\b')
    metadata+='// Static method namespace only; no interpreter execution implementation.\nstruct InterpreterCore;\nimpl InterpreterCore {\n'+block(base,r'fn regexp_builder\b','    ')+'}\n'
    metadata+='mod regexp_input {\n'+const(inp,'SURROGATE_BASE')+block(inp,r'pub\(super\) fn encode_code_unit\b')+'}\n'
    (S/'baseline_interpreter_full_source.rs').write_text(base)
    (S/'baseline_interpreter.rs').write_text(metadata)
    (S/'baseline_interpreter_metadata.rs').write_text(metadata)
    (P/'src').mkdir(exist_ok=True)
    lib='#![forbid(unsafe_code)]\n'+''.join(f'pub mod {m};\n' for m in mods)+'mod baseline_interpreter;\n'
    (S/'probe_lib.rs').write_text(lib)
    (P/'core/src').mkdir(parents=True,exist_ok=True)
    (C/'probe_lib.rs').write_text('pub mod js_string;\npub mod deterministic_serde;\npub mod hash_tiers;\n')
    (P/'core/Cargo.toml').write_text('''[package]
    name="frankenengine-core"
    version="0.3.0"
    edition="2024"
    [lib]
    path="../snapshot/crates/franken-core/src/probe_lib.rs"
    [dependencies]
    zeroize="1.8"
    thiserror="2"
    serde={version="1",features=["derive","rc"]}
    serde_json={version="1",features=["float_roundtrip","unbounded_depth"]}
    sha2="0.10"
    hmac="0.12"
    subtle="2.6"
    '''+f'franken-engine-deterministic-trait={{path="{R}/crates/franken-engine-deterministic-trait"}}\nfranken-engine-deterministic-derive={{path="{R}/crates/franken-engine-deterministic-derive"}}\n')
    (P/'Cargo.toml').write_text('''[package]
    name="fe-issue6-native-probe"
    version="0.1.0"
    edition="2024"
    [lib]
    path="snapshot/crates/franken-engine/src/probe_lib.rs"
    [workspace]
    [profile.dev]
    debug=0
    incremental=false
    codegen-units=256
    [dependencies]
    zeroize="1.8"
    thiserror="2"
    serde={version="1",features=["derive","rc"]}
    serde_json={version="1",features=["float_roundtrip","unbounded_depth"]}
    sha2="0.10"
    hmac="0.12"
    subtle="2.6"
    ed25519-dalek="2.1"
    rand="0.8"
    hex="0.4"
    regex="1"
    bumpalo={version="3",features=["collections"]}
    ryu-js="1"
    num-bigint="0.5"
    url="2.5.8"
    frankenengine-core={path="core"}
    '''+f'franken-engine-deterministic-trait={{path="{R}/crates/franken-engine-deterministic-trait"}}\nfranken-engine-deterministic-derive={{path="{R}/crates/franken-engine-deterministic-derive"}}\nfrankenengine-extension-host={{path="{R}/crates/franken-extension-host"}}\n')
    (P/'src/main.rs').write_text('''use fe_issue6_native_probe::{authority_footprint::analyze_authority_footprint,ast::ParseGoal};
    use serde_json::{Value,json};
    fn main() {
        let path=std::env::args().nth(1).expect("input JSON path");
        let cases: Vec<Value>=serde_json::from_slice(&std::fs::read(path).expect("read cases")).expect("case JSON");
        for case in cases {
            let name=case["name"].as_str().unwrap();
            let source=case["source"].as_str().unwrap();
            let goal=if case["goal"].as_str()==Some("module") {ParseGoal::Module} else {ParseGoal::Script};
            let report=analyze_authority_footprint(source,name,goal);
            let replay=analyze_authority_footprint(source,name,goal);
            assert_eq!(report,replay,"deterministic report for {name}");
            println!("{}",json!({"name":name,"source":source,"outcome":format!("{:?}",report.outcome()),"deterministic_replay":true,"report":report}));
        }
    }
    ''')
    e=json.loads((P/'snapshot/artifacts/issue6_scoped_qualification_20261027.json').read_text());(P/'cases33.json').write_text(json.dumps(e['authority_inputs'],indent=2));(P/'case1.json').write_text(json.dumps(e['authority_inputs'][4:5]))
    (P/'provenance.json').write_text(json.dumps({'revision':REV,'source_sha256':provenance,'metadata_sha256':hashlib.sha256(metadata.encode()).hexdigest(),'exclusions':['capability::trust_zone, not used by parser/lowering/analyzer','InterpreterCore runtime; only static regexp_builder namespace plus exact metadata/error/regexp helper source','core crate includes exact js_string, deterministic_serde, hash_tiers only'],'scope':'Actual production parser/lowerer/authority in a diagnostic crate, not native interpreter execution or canonical lib suite'},indent=2))
    print('snapshot files',len(files),'source bytes',sum((P/'snapshot'/f).stat().st_size for f in files),'probe',P)


def add_critical_tests(P):
    from pathlib import Path
    import re,json,hashlib
    S=P/'snapshot/crates/franken-engine/src'
    e=json.loads((P/'snapshot/artifacts/issue6_scoped_qualification_20261027.json').read_text())
    names=list(e['selected_ast_tests']['provenance']['tests']);fs_names=names[:18]
    fs_names=[n.replace('one_escaped_mutated_or_async_alias_preserves_the_whole_original_module','one_escaped_mutated_or_unsupported_alias_preserves_the_whole_original_module') for n in fs_names]
    fs_names += ['direct_promise_reads_use_the_protected_native_completion_intrinsic','deferred_promise_reads_keep_the_full_facade_authority_boundary','promise_reads_keep_handles_options_writes_and_observable_modules_on_the_facade','promise_aliases_preserve_temporal_and_loader_scope_boundaries','direct_promise_reads_share_the_sync_boundary_without_unused_write_authority']
    events_names=[n.replace('once_options_spread_and_invalid_arity_use_the_first_class_helper','every_once_call_uses_the_observable_first_class_helper') for n in names[18:]]+['observable_once_rewrite_preserves_shadowed_require_and_helper_values','events_source_parses_with_every_used_global_shadowed','mixed_stream_reroute_shares_its_events_dependency_bd_305gi_2']
    root_names=['immediate_factory_authority_excludes_uninvoked_methods_and_generators','realm_value_authority_matches_runtime_without_claiming_lexical_shadows']
    authority_names=['first_class_events_initialization_requires_builtin_without_unused_timers','uninvoked_factories_and_shadowed_events_loaders_do_not_add_authority','literal_promise_reads_report_read_authority_without_ambient_require','promise_reads_do_not_hide_ambient_secret_inputs_or_observable_modules','builtin_named_operations_report_their_runtime_authority']
    provenance={}
    def block(src,pat,indent='    '):
     m=re.search(r'^'+re.escape(indent)+pat,src,re.M)
     if not m:raise Exception(pat)
     end=re.search(r'^'+re.escape(indent)+r'}\s*$',src[m.end():],re.M)
     if not end:raise Exception(pat+' end')
     return src[m.start():m.end()+end.end()].rstrip()+'\n'
    def function(src,n):
     s=block(src,r'(?:pub\([^)]*\) )?fn '+n+r'\b')
     provenance[n]=hashlib.sha256(s.encode()).hexdigest();return s

    def runner(names,prefix):
     return '\n    pub(super) fn run() -> usize {\n        let mut failed=0;\n'+''.join('        match std::panic::catch_unwind('+n+') {Ok(())=>println!("PASS '+prefix+'::'+n+'"),Err(_)=>{eprintln!("FAIL '+prefix+'::'+n+'"); failed+=1;}}\n' for n in names)+'        failed\n    }\n'

    fs=S/'lowering_pipeline/fs_module.rs';src=fs.read_text();helpers='    use crate::ast::ParseGoal;\n    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};\n'
    for n in ['parse','parse_goal','require_count']:helpers+=function(src,n)
    helpers+=block(src,r'fn module_source\b','')
    fs.write_text(src+'\nmod scoped_production_tests {\n    use super::*;\n'+helpers+''.join(function(src,n) for n in fs_names)+runner(fs_names,'fs')+'}\npub(super) fn run_scoped_production_tests() -> usize { scoped_production_tests::run() }\n')

    util=S/'lowering_pipeline/util_module.rs';src=util.read_text();start=src.index('mod tests {')+len('mod tests {');end=src.index('    #[test]',start);free_names_helpers=src[start:end]
    events_module=block(src,r'mod events_tests \{','');events_parse=function(events_module,'parse')
    util.write_text(src+'\nmod tests {\n'+free_names_helpers+'}\nmod scoped_events_tests {\n    use super::*;\n'+events_parse+''.join(function(events_module,n) for n in events_names)+runner(events_names,'events')+'}\npub(super) fn run_scoped_module_tests() -> usize { fs_module::run_scoped_production_tests()+scoped_events_tests::run() }\n')

    native_names=['selected_add_abort_listener_carries_its_real_timer_authority','unused_shadowed_reassigned_and_once_helpers_do_not_claim_timer']
    native=S/'lowering_pipeline/native_module_authority.rs';source=native.read_text()
    native.write_text(source+'\nmod scoped_production_tests {\n    use super::*;\n    use crate::{ir_contract::Ir0Module, parser_api_stability::parse_script};\n'+function(source,'capabilities')+''.join(function(source,n) for n in native_names)+runner(native_names,'native_module_authority')+'}\npub(super) fn run_scoped_production_tests() -> usize { scoped_production_tests::run() }\n')
    lower=S/'lowering_pipeline.rs';src=lower.read_text();helpers=function(src,'nested_function_with_body')
    lower.write_text(src+'\nmod scoped_authority_tests {\n    use super::*;\n'+helpers+''.join(function(src,n) for n in root_names)+runner(root_names,'lowering')+'}\npub fn run_scoped_module_tests() -> usize { util_module::run_scoped_module_tests()+scoped_authority_tests::run()+native_module_authority::run_scoped_production_tests() }\n')

    authority=S/'authority_footprint.rs';src=authority.read_text();authority.write_text(src+'\nmod scoped_production_tests {\n    use super::*;\n'+''.join(function(src,n) for n in authority_names)+runner(authority_names,'authority')+'}\npub fn run_scoped_authority_tests() -> usize { scoped_production_tests::run() }\n')
    (P/'selected-test-provenance.json').write_text(json.dumps({'test_bodies_sha256':provenance,'executed_names':fs_names+events_names+root_names+authority_names+native_names,'count':len(fs_names+events_names+root_names+authority_names+native_names),'scope':'Exact production test bodies plus exact supporting test helpers through temporary entrypoints, not canonical cargo test or interpreter execution'},indent=2))
    f=P/'src/main.rs';s=f.read_text();old='    let path=std::env::args().nth(1).expect("input JSON path");';new=old+'''\n    if path=="--selected-tests" {\n        let failures=crate::lowering_pipeline::run_scoped_module_tests()+crate::authority_footprint::run_scoped_authority_tests();\n        println!("SELECTED_TEST_FAILURES={failures}");\n        std::process::exit(if failures==0 {0} else {1});\n    }'''
    if 'SELECTED_TEST_FAILURES' not in s:f.write_text(s.replace(old,new))
    print('Selected unchanged production test bodies',len(fs_names+events_names+root_names+authority_names+native_names))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--toolchain-bin', type=Path)
    parser.add_argument('--cargo-home', type=Path)
    parser.add_argument('--prepare-only', action='store_true')
    args=parser.parse_args()
    R=args.repository.resolve();P=args.work.resolve()
    evidence=args.evidence or R/'artifacts/issue6_scoped_qualification_20261031.json'
    data=json.loads(evidence.read_text())
    if P.exists():raise SystemExit('--work must be a new directory; nothing is deleted')
    for rel,expected in data['source_sha256'].items():
        actual=hashlib.sha256((R/rel).read_bytes()).hexdigest()
        if actual!=expected:raise SystemExit('source hash mismatch: '+rel)
    P.mkdir(parents=True)
    prepare_source_snapshot(P,R)
    for rel in data['source_sha256']:
        dest=P/'snapshot'/rel;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes((R/rel).read_bytes())
        if rel.endswith('/capability.rs'):
            source=dest.read_text();assert source.count('pub mod trust_zone;')==1
            dest.write_text(source.replace('pub mod trust_zone;','// Excluded unused capability::trust_zone from diagnostic crate.'))
    (P/'Cargo.lock').write_text(data['reproduction']['cargo_lock'])
    extra=[{'name':case['name'],'source':case['source']} for case in data['extra_authority_inputs']['cases']]
    (P/'cases-extra.json').write_text(json.dumps(extra,indent=2))
    add_critical_tests(P)
    actual=json.loads((P/'selected-test-provenance.json').read_text())
    assert actual['executed_names']==data['selected_tests']['provenance']['executed_names']
    assert actual['test_bodies_sha256']==data['selected_tests']['provenance']['test_bodies_sha256']
    src=P/'snapshot/crates/franken-engine/src'
    main_source=(P/'src/main.rs').read_text().replace('fe_issue6_native_probe::','crate::')
    (src/'probe_main.rs').write_text((src/'probe_lib.rs').read_text()+main_source)
    cargo=(P/'Cargo.toml').read_text().replace('edition="2024"','edition="2024"\nautolib=false\nautobins=false',1)
    cargo=cargo.replace('[lib]\npath="snapshot/crates/franken-engine/src/probe_lib.rs"\n','')
    cargo=cargo.replace('[workspace]','[[bin]]\nname="fe-issue6-native-probe"\npath="snapshot/crates/franken-engine/src/probe_main.rs"\n[workspace]')
    (P/'Cargo.toml').write_text(cargo)
    print('Prepared exact native source subset and 43 critical test bodies at',P,flush=True)
    if args.prepare_only:return
    env=os.environ.copy();env['RUSTUP_TOOLCHAIN']='nightly-2026-09-21'
    if args.toolchain_bin:env['PATH']=str(args.toolchain_bin.resolve())+os.pathsep+env.get('PATH','')
    if args.cargo_home:env['CARGO_HOME']=str(args.cargo_home.resolve())
    subprocess.run(['cargo','build','--offline','--jobs','1','--bin','fe-issue6-native-probe'],cwd=P,env=env,check=True)
    binary=P/'target/debug/fe-issue6-native-probe'
    for label,argument in [('selected','--selected-tests'),('authority33',str(P/'cases33.json')),('authority14',str(P/'cases-extra.json'))]:
        result=subprocess.run([str(binary),argument],capture_output=True,text=True)
        (P/(label+'.stdout')).write_text(result.stdout);(P/(label+'.stderr')).write_text(result.stderr)
        print(label,'exit',result.returncode,flush=True)
        if result.returncode:raise SystemExit(result.returncode)
        if label!='selected':
            expected=data['authority_comparison']['cases'] if label=='authority33' else data['extra_authority_inputs']['cases']
            observed=[json.loads(line) for line in result.stdout.splitlines()]
            assert [(row['name'],row['outcome']) for row in observed]==[(row['name'],row['outcome']) for row in expected]
            assert [row['report']['required_capabilities'] for row in observed]==[row['requirements'] for row in expected]

if __name__=='__main__':main()
