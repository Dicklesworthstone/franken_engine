//! Live HTTP and loopback state must not disable the reclaiming collector.
//! These programs exercise real parser/lowering/native execution in both
//! profiles with a 4,096-object heap, including long network callbacks and
//! listener snapshots changed reentrantly. Output is checked against Node.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn run(source: &'static str, expected: &'static str) {
    std::thread::Builder::new()
        .name("network-collection".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let tree = CanonicalEs2020Parser
                .parse_with_options(
                    ParserSource {
                        label: "network-collection.js".into(),
                        text: source.into(),
                    },
                    ParseGoal::Script,
                    &ParserOptions::default(),
                )
                .expect("network collection fixture parses");
            let module = lower_ir0_to_ir3(
                &Ir0Module::from_syntax_tree(tree, "network-collection.js"),
                &LoweringContext::new("network-collection", "bounded-heap", "builtin-only"),
            )
            .expect("network collection fixture lowers")
            .ir3;
            for throughput in [false, true] {
                let mut config = if throughput {
                    InterpreterConfig::v8_defaults()
                } else {
                    InterpreterConfig::quickjs_defaults()
                };
                config.max_heap_objects = 4096;
                config.instruction_budget = 100_000_000;
                config.granted_capabilities = [
                    RuntimeCapability::VmDispatch,
                    RuntimeCapability::HeapAllocate,
                    RuntimeCapability::Builtin,
                    RuntimeCapability::Console,
                ]
                .into_iter()
                .collect();
                let mut core = InterpreterCore::new(config, "network-collection");
                let result = core
                    .execute(&module)
                    .unwrap_or_else(|error| panic!("throughput={throughput}: {error}\n{source}"));
                let actual = result
                    .console_output
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                assert_eq!(actual, expected, "throughput={throughput}");
                assert!(core.gc_stats().collections > 0);
                assert!(core.gc_stats().reclaimed_objects > 0);
                assert_eq!(core.gc_stats().skipped_collections, 0);
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes(),
                    "memory accounting drift, throughput={throughput}"
                );
            }
        })
        .expect("spawn network collection test")
        .join()
        .expect("network collection test panicked");
}

#[test]
fn live_http_request_keeps_its_hidden_response_callback() {
    run(
        r#"
        const http = require('http');
        const net = require('net');
        const server = http.createServer((req, res) => res.end('payload'));
        server.listen(0, '127.0.0.1', () => {
        const request = (() => {
          const captured = { text: 'hidden' };
          return http.request({ host: '127.0.0.1', port: server.address().port }, res => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
              console.log(captured.text, body, total, agent.keepAlive === false,
                          socket instanceof net.Socket);
              server.close();
            });
          });
        })();
        const agent = new http.Agent();
        const socket = new net.Socket();
        let total = 0;
        for (let i = 0; i < 12000; i++) { const o = { i }; total += o.i & 1; }
        request.end();
        });
    "#,
        "hidden payload 6000 true true",
    );
}

#[test]
fn http_callbacks_collect_and_keep_removed_listener_snapshots() {
    run(
        r#"
        const http = require('http');
        let total = 0;
        function churn() {
          for (let i = 0; i < 6000; i++) { const o = { i }; total += o.i & 1; }
        }
        const server = http.createServer();
        let identity;
        server.on('request', (req, res) => {
          identity = res;
          server.removeAllListeners('request');
          churn();
        });
        server.on('request', (() => {
          const captured = { body: 'retained' };
          return (req, res) => {
            churn();
            res.end(captured.body + ':' + (identity === res));
          };
        })());
        server.listen(0, '127.0.0.1', () => {
          churn();
          http.get({ host: '127.0.0.1', port: server.address().port }, res => {
            churn();
            let body = '';
            res.setEncoding('utf8');
            res.on('data', chunk => { churn(); body += chunk; });
            res.once('end', () => {
              churn();
              console.log(body, total);
              server.close();
            });
          });
        });
        churn();
    "#,
        "retained:true 21000",
    );
}

#[test]
fn loopback_connection_and_buffer_survive_collection_inside_callbacks() {
    run(
        r#"
        const net = require('net');
        let total = 0;
        function churn() {
          for (let i = 0; i < 6000; i++) { const o = { i }; total += o.i & 1; }
        }
        const server = net.createServer(socket => {
          churn();
          socket.on('data', chunk => { churn(); socket.end(chunk); });
        });
        server.listen(0, '127.0.0.1', () => {
          churn();
          const client = net.connect({ host: '127.0.0.1', port: server.address().port }, () => {
            churn();
            client.write('ping');
          });
          let body = '';
          client.setEncoding('utf8');
          client.on('data', chunk => { churn(); body += chunk; });
          client.once('end', () => {
            churn();
            console.log(body, total);
            server.close();
          });
        });
    "#,
        "ping 18000",
    );
}

#[test]
fn unused_agents_servers_and_sockets_release_their_host_state() {
    run(
        r#"
        const http = require('http');
        const net = require('net');
        let total = 0;
        for (let i = 0; i < 6000; i++) {
          const agent = new http.Agent();
          const server = http.createServer();
          const socket = new net.Socket();
          total += agent.keepAlive ? 100 : 1;
        }
        console.log(total);
    "#,
        "6000",
    );
}

#[test]
fn closed_internal_port_remains_confined_after_collection() {
    run(
        r#"
        const http = require('http');
        const server = http.createServer();
        server.listen(0, '127.0.0.1', () => {
          const port = server.address().port;
          server.close(() => {
            let total = 0;
            for (let i = 0; i < 12000; i++) { const o = { i }; total += o.i & 1; }
            http.get({ host: '127.0.0.1', port }).on('error', error => {
              console.log(error.code, total);
            });
          });
        });
    "#,
        "ECONNREFUSED 6000",
    );
}
