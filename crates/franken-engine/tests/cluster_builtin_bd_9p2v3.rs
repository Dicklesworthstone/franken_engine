//! bd-9p2v3: hermetic Node `cluster` primary-process facade.

use frankenengine_engine::HybridRouter;

fn eval_console(source: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for {source:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn eval_error(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => panic!("expected eval failure for {source:?}, got {outcome:?}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn fixed_primary_flags_empty_maps_and_linux_scheduling_constants() {
    let output = eval_console(
        r#"
        const cluster = require('cluster');
        console.log(cluster.isPrimary, cluster.isMaster, cluster.isWorker);
        console.log(cluster.worker === undefined);
        console.log(Object.keys(cluster.workers).length, Object.keys(cluster.settings).length);
        console.log(cluster.schedulingPolicy, cluster.SCHED_RR, cluster.SCHED_NONE);
        console.log(typeof cluster.Worker, typeof cluster.fork);
        "#,
    );
    assert_eq!(
        output,
        "true true false\ntrue\n0 0\n2 2 1\nfunction function"
    );
}

#[test]
fn setup_primary_and_legacy_alias_replace_with_shallow_merged_settings() {
    let output = eval_console(
        r#"
        const cluster = require('cluster');
        const initial = cluster.settings;
        console.log(cluster.setupPrimary({ exec: 'first_worker.js' }));
        const first = cluster.settings;
        const args = ['--flag-a', '--flag-b'];
        console.log(cluster.setupMaster({ args }));
        console.log(initial !== first, first !== cluster.settings);
        console.log(cluster.settings.exec.endsWith('first_worker.js'));
        console.log(cluster.settings.args === args, cluster.settings.args.join(','));
        console.log(cluster.setupPrimary === cluster.setupMaster);
        "#,
    );
    assert_eq!(
        output,
        "undefined\nundefined\ntrue true\ntrue\ntrue --flag-a,--flag-b\ntrue"
    );
}

#[test]
fn cluster_uses_shared_event_emitter_order_once_and_boolean_emit_contract() {
    let output = eval_console(
        r#"
        const cluster = require('node:cluster');
        cluster.on('ready', (value) => console.log('on-1:' + value));
        cluster.once('ready', (value) => console.log('once:' + value));
        cluster.on('ready', (value) => console.log('on-2:' + value));
        console.log('first:' + cluster.emit('ready', 7));
        console.log('second:' + cluster.emit('ready', 8));
        console.log('missing:' + cluster.emit('missing'));
        "#,
    );
    assert_eq!(
        output,
        "on-1:7\nonce:7\non-2:7\nfirst:true\non-1:8\non-2:8\nsecond:true\nmissing:false"
    );
}

#[test]
fn disconnect_of_empty_primary_is_asynchronous_and_zero_argument() {
    let output = eval_console(
        r#"
        const cluster = require('cluster');
        cluster.disconnect((value) => console.log('callback-undefined:' + (value === undefined)));
        console.log('called-first');
        "#,
    );
    assert_eq!(output, "called-first\ncallback-undefined:true");
}

#[test]
fn node_and_bare_aliases_share_one_facade_identity_per_compilation_unit() {
    let output = eval_console(
        r#"
        const cluster = require('cluster');
        const nodeCluster = require('node:cluster');
        console.log(cluster.settings === nodeCluster.settings);
        cluster.setupPrimary({ exec: 'shared.js' });
        console.log(nodeCluster.settings.exec);
        "#,
    );
    assert_eq!(output, "true\nshared.js");
}

#[test]
fn node_cluster_fixture_0012_observes_real_event_emitter_identity_bd_dspwz() {
    let output = eval_console(
        r#"
        const cluster = require('cluster');
        const EventEmitter = require('events').EventEmitter;
        console.log('instanceof-ee:' + (cluster instanceof EventEmitter));
        console.log('on:' + typeof cluster.on);
        console.log('once:' + typeof cluster.once);
        console.log('emit:' + typeof cluster.emit);
        "#,
    );
    assert_eq!(
        output,
        "instanceof-ee:true\non:function\nonce:function\nemit:function"
    );
}

#[test]
fn event_emitter_constructor_and_prototype_identity_are_shared_bd_dspwz() {
    let output = eval_console(
        r#"
        const cluster = require('node:cluster');
        const EventEmitter = require('events').EventEmitter;
        const { EventEmitter: NodeEventEmitter } = require('node:events');
        const emitter = new EventEmitter();
        const calledEmitter = EventEmitter();
        console.log(typeof EventEmitter, EventEmitter === NodeEventEmitter);
        console.log(emitter instanceof EventEmitter, calledEmitter instanceof EventEmitter);
        console.log(cluster instanceof EventEmitter);
        console.log(Object.getPrototypeOf(emitter) === NodeEventEmitter.prototype);
        console.log(({ __type: 'Cluster' }) instanceof EventEmitter);
        console.log(({ __type: 'EventEmitter' }) instanceof EventEmitter);
        "#,
    );
    assert_eq!(output, "function true\ntrue true\ntrue\ntrue\nfalse\nfalse");
}

#[test]
fn event_emitter_shadowing_and_unsupported_extraction_remain_bounded_bd_dspwz() {
    for source in [
        "const cluster = require('cluster'); const EventEmitter = require('events').EventEmitter; console.log(cluster instanceof EventEmitter); function probe(EventEmitter) { return cluster instanceof EventEmitter; }",
        "const EventEmitter = require('events')['EventEmitter']; new EventEmitter();",
        "let EventEmitter = require('events').EventEmitter; new EventEmitter();",
        "const EventEmitter = require('events').EventEmitter; new EventEmitter(); const Detached = EventEmitter; new Detached();",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("ambient") || error.contains("Ambient") || error.contains("authority"),
            "unsupported EventEmitter extraction must preserve ambient denial: {source:?}: {error}"
        );
    }
}

#[test]
fn authenticated_alias_reaches_nested_closure_but_parameter_shadow_does_not_spoof_it() {
    let output = eval_console(
        r#"
        const cluster = require('cluster');
        function primary() { return cluster.isPrimary; }
        function shadow(cluster) { return cluster.isPrimary; }
        console.log(primary(), shadow({ isPrimary: 'local' }));
        "#,
    );
    assert_eq!(output, "true local");
}

#[test]
fn fork_and_worker_are_function_shaped_but_invocation_fails_closed() {
    let fork_error = eval_error(
        "const cluster = require('cluster'); console.log(typeof cluster.fork); cluster.fork();",
    );
    assert!(
        fork_error.contains("process_spawn") || fork_error.contains("Capability"),
        "unexpected fork refusal: {fork_error}"
    );

    let worker_error = eval_error(
        "const cluster = require('cluster'); console.log(typeof cluster.Worker); cluster.Worker();",
    );
    assert!(
        worker_error.contains("process_spawn") || worker_error.contains("Capability"),
        "unexpected Worker refusal: {worker_error}"
    );
}

#[test]
fn setup_and_disconnect_reject_forged_cluster_tag_receivers() {
    for source in [
        "const cluster = require('cluster'); cluster.setupPrimary.call({ __type: 'Cluster', settings: {} }, { exec: 'spoof.js' });",
        "const cluster = require('cluster'); cluster.disconnect.call({ __type: 'Cluster' }, () => {});",
    ] {
        let error = eval_error(source);
        let lower_error = error.to_ascii_lowercase();
        assert!(
            error.contains("bound cluster receiver")
                || error.contains("forged receiver")
                || lower_error.contains("type error")
                || lower_error.contains("expected object"),
            "forged receiver must fail closed: {source:?}: {error}"
        );
    }
}

#[test]
fn unsupported_possession_escape_reassignment_and_member_writes_remain_ambient_refused() {
    for source in [
        "const cluster = require('cluster');",
        "const cluster = require('cluster'); console.log(cluster);",
        "let cluster = require('cluster'); console.log(cluster.isPrimary);",
        "const cluster = require('cluster'); cluster = {}; console.log(cluster.isPrimary);",
        "const cluster = require('cluster'); cluster.isPrimary = false; console.log(cluster.isPrimary);",
        "const cluster = require('cluster'); cluster.settings.exec = 'spoof'; console.log(cluster.isPrimary);",
        "const cluster = require('cluster'); const leaked = cluster.on('ready', () => {}); leaked.isPrimary = false; console.log(cluster.isPrimary);",
        "const cluster = require('cluster'); function leak() { return cluster.once('ready', () => {}); } console.log(leak().isPrimary);",
        "const cluster = require('cluster'); function sink(value) { value.isPrimary = false; } sink(cluster.on('ready', () => {})); console.log(cluster.isPrimary);",
        "const cluster = require('cluster'); console.log(cluster['isPrimary']);",
        "const cluster = require('cluster'); console.log(cluster.unsupported);",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("ambient") || error.contains("Ambient") || error.contains("authority"),
            "unsupported cluster possession must preserve ambient denial: {source:?}: {error}"
        );
    }
}

#[test]
fn shadowed_require_is_never_upgraded_to_the_cluster_facade() {
    let error = eval_error(
        r#"
        const require = (name) => ({ isPrimary: 'spoof:' + name });
        const cluster = require('cluster');
        console.log(cluster.isPrimary);
        "#,
    );
    assert!(
        error.contains("ambient") || error.contains("Ambient") || error.contains("authority"),
        "a lexical require shadow must never be upgraded to the authenticated facade: {error}"
    );
}
