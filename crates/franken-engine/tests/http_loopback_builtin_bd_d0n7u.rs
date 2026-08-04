//! bd-d0n7u: hermetic Node HTTP/1.1 loopback facade acceptance.
//!
//! The supported server path is entirely interpreter-owned: `listen(0,
//! "127.0.0.1")` allocates a deterministic virtual port, and requests to that
//! listener never bind an operating-system socket or require a host-I/O
//! provider. Non-loopback egress remains on the existing capability-gated
//! `net:request` provider seam. These product-like `HybridRouter::eval` tests
//! pin the finite CommonJS surface and its fail-closed provenance boundary.

use frankenengine_engine::HybridRouter;

fn eval_console(source: &str) -> String {
    let source = source.to_string();
    std::thread::Builder::new()
        .name("http-product-stack".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let mut engine = HybridRouter::default();
            let outcome = engine
                .eval(&source)
                .unwrap_or_else(|error| panic!("eval failed for {source:?}: {error}"));
            outcome
                .console_output
                .iter()
                .map(|entry| entry.message.clone())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .expect("spawn HTTP acceptance thread")
        .join()
        .expect("HTTP acceptance thread must not panic")
}

fn eval_error(source: &str) -> String {
    let source = source.to_string();
    std::thread::Builder::new()
        .name("http-product-error-stack".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let mut engine = HybridRouter::default();
            match engine.eval(&source) {
                Ok(outcome) => panic!("expected eval error for {source:?}, got {outcome:?}"),
                Err(error) => error.to_string(),
            }
        })
        .expect("spawn HTTP error acceptance thread")
        .join()
        .expect("HTTP error acceptance thread must not panic")
}

#[test]
fn get_roundtrip_exposes_request_and_response_metadata() {
    let source = r#"
        const http = require('http');
        const server = http.createServer((req, res) => {
          console.log(req.method, req.url, req.httpVersion);
          console.log(typeof req.headers.host, Array.isArray(req.rawHeaders));
          res.setHeader('X-Trace', 'one');
          res.end('hello-body');
        });
        server.listen(0, '127.0.0.1', () => {
          http.get({
            host: '127.0.0.1',
            port: server.address().port,
            path: '/a/b?k=v&x=1'
          }, res => {
            console.log(res.statusCode, res.statusMessage, res.headers['x-trace']);
            console.log(res.httpVersion, typeof res.socket === 'object');
            let body = '';
            res.setEncoding('utf8');
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
              console.log(body);
              server.close();
            });
          });
        });
    "#;
    assert_eq!(
        eval_console(source),
        "GET /a/b?k=v&x=1 1.1\nstring true\n200 OK one\n1.1 true\nhello-body"
    );
}

#[test]
fn request_streaming_and_late_headers_cover_post_put_delete() {
    let source = r#"
        const http = require('node:http');
        const server = http.createServer((req, res) => {
          let body = '';
          req.setEncoding('utf8');
          req.on('data', chunk => body += chunk);
          req.on('end', () => {
            res.end(req.method + ':' + req.headers['x-late'] + ':' + body);
          });
        });
        server.listen(0, '127.0.0.1', () => {
          const port = server.address().port;
          const send = (method, body, done) => {
            const request = http.request({ host: '127.0.0.1', port, path: '/', method });
            request.setHeader('X-Late', method.toLowerCase());
            request.on('response', res => {
              let reply = '';
              res.on('data', chunk => reply += chunk);
              res.on('end', () => { console.log(reply); done(); });
            });
            request.write(body.slice(0, 1));
            request.end(body.slice(1));
          };
          send('POST', 'alpha', () => send('PUT', 'beta', () => send('DELETE', '', () => server.close())));
        });
    "#;
    assert_eq!(
        eval_console(source),
        "POST:post:alpha\nPUT:put:beta\nDELETE:delete:"
    );
}

#[test]
fn response_header_crud_writehead_and_chunk_order_match_node() {
    let source = r#"
        const http = require('http');
        const server = http.createServer((req, res) => {
          res.setHeader('X-Multi', ['a', 'b']);
          res.setHeader('X-Gone', 'yes');
          console.log(res.getHeader('x-multi').join(','));
          console.log(res.hasHeader('x-gone'), res.hasHeader('missing'));
          res.removeHeader('X-Gone');
          const returned = res.writeHead(201, 'Made Here', { 'X-Head': 'v' });
          console.log(returned === res);
          res.write('one-');
          res.write('two-');
          res.end('three');
        });
        server.listen(0, '127.0.0.1', () => {
          http.get({ host: '127.0.0.1', port: server.address().port, path: '/' }, res => {
            console.log(res.statusCode, res.statusMessage, res.headers['x-head']);
            console.log(res.headers['x-multi'], res.headers['x-gone'] === undefined);
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => { console.log(body); server.close(); });
          });
        });
    "#;
    assert_eq!(
        eval_console(source),
        "a,b\ntrue false\ntrue\n201 Made Here v\na, b true\none-two-three"
    );
}

#[test]
fn head_no_content_empty_and_redirect_responses_do_not_fabricate_bodies() {
    let source = r#"
        const http = require('http');
        let count = 0;
        const server = http.createServer((req, res) => {
          count += 1;
          if (count === 1) {
            res.setHeader('Content-Length', '5');
            res.end(req.method === 'HEAD' ? undefined : '12345');
          } else if (count === 2) {
            res.writeHead(204);
            res.end('must-not-arrive');
          } else {
            res.writeHead(301, { Location: '/elsewhere' });
            res.end();
          }
        });
        server.listen(0, '127.0.0.1', () => {
          const options = { host: '127.0.0.1', port: server.address().port, path: '/' };
          const head = http.request({ host: '127.0.0.1', port: options.port, path: '/', method: 'HEAD' }, res => {
            let size = 0;
            res.on('data', chunk => size += chunk.length);
            res.on('end', () => {
              console.log('head', res.statusCode, res.headers['content-length'], size);
              http.get(options, empty => {
                let second = 0;
                empty.on('data', chunk => second += chunk.length);
                empty.on('end', () => {
                  console.log('empty', empty.statusCode, second);
                  http.get(options, redirect => {
                    console.log('redirect', redirect.statusCode, redirect.headers.location);
                    redirect.resume();
                    redirect.on('end', () => server.close());
                  });
                });
              });
            });
          });
          head.end();
        });
    "#;
    assert_eq!(
        eval_console(source),
        "head 200 5 0\nempty 204 0\nredirect 301 /elsewhere"
    );
}

#[test]
fn binary_and_json_response_bodies_survive_the_loopback_boundary() {
    let source = r#"
        const http = require('http');
        let count = 0;
        const server = http.createServer((req, res) => {
          count += 1;
          if (count === 1) {
            res.end(Buffer.from([0, 1, 2, 250, 251, 252]));
          } else {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify([1, 'two', true, null]));
          }
        });
        server.listen(0, '127.0.0.1', () => {
          const options = { host: '127.0.0.1', port: server.address().port, path: '/' };
          http.get(options, res => {
            const chunks = [];
            res.on('data', chunk => chunks.push(chunk));
            res.on('end', () => {
              console.log(Buffer.concat(chunks).toString('hex'));
              http.get(options, json => {
                let body = '';
                json.on('data', chunk => body += chunk);
                json.on('end', () => {
                  console.log(JSON.parse(body).join('|'));
                  server.close();
                });
              });
            });
          });
        });
    "#;
    assert_eq!(eval_console(source), "000102fafbfc\n1|two|true|");
}

#[test]
fn server_events_address_close_and_multi_request_order_are_deterministic() {
    let source = r#"
        const http = require('http');
        const order = [];
        let count = 0;
        const server = http.createServer();
        server.on('request', (req, res) => {
          count += 1;
          order.push('request-' + count);
          res.end(String(count));
        });
        server.on('listening', () => order.push('listening'));
        server.listen(0, '127.0.0.1', () => {
          const address = server.address();
          console.log(typeof address.port, address.port > 0, address.address, server.listening);
          const one = done => http.get({ host: '127.0.0.1', port: address.port, path: '/' }, res => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => { order.push('response-' + body); done(); });
          });
          one(() => one(() => one(() => server.close(() => {
            order.push('close');
            console.log(order.join(','));
            console.log(server.listening);
          }))));
        });
    "#;
    assert_eq!(
        eval_console(source),
        "number true 127.0.0.1 true\nlistening,request-1,response-1,request-2,response-2,request-3,response-3,close\nfalse"
    );
}

#[test]
fn loopback_listener_ports_and_relisten_generations_are_unambiguous() {
    let relisten = r#"
        const http = require('http');
        const server = http.createServer((req, res) => res.end());
        server.listen(0, '127.0.0.1', () => {
          const first = server.address().port;
          server.close(() => {
            server.listen(0, '127.0.0.1', () => {
              console.log(first !== server.address().port, server.listening);
              server.close(() => console.log('closed-again'));
            });
          });
        });
    "#;
    assert_eq!(eval_console(relisten), "true true\nclosed-again");

    let collision = r#"
        const http = require('http');
        const first = http.createServer((req, res) => res.end());
        const second = http.createServer((req, res) => res.end());
        first.listen(42000, '127.0.0.1');
        second.listen(42000, '127.0.0.1');
    "#;
    let error = eval_error(collision);
    assert!(
        error.contains("EADDRINUSE") || error.contains("address already in use"),
        "a duplicate virtual bind must fail deterministically, got: {error}"
    );
}

#[test]
fn refused_connection_emits_node_shaped_error() {
    let source = r#"
        const http = require('http');
        const server = http.createServer((req, res) => res.end());
        server.listen(0, '127.0.0.1', () => {
          const port = server.address().port;
          server.close(() => {
            const request = http.get({ host: '127.0.0.1', port, path: '/' }, () => {});
            request.on('error', error => console.log(error instanceof Error, error.code));
          });
        });
    "#;
    assert_eq!(eval_console(source), "true ECONNREFUSED");
}

#[test]
fn unknown_external_targets_still_require_network_egress_authority() {
    let source = r#"
        const http = require('http');
        http.get('http://example.com/', () => console.log('must-not-run'));
    "#;
    let error = eval_error(source);
    assert!(
        error.contains("NetworkEgress")
            || error.contains("net:request")
            || error.contains("ambient authority violation")
            || error.contains("capability"),
        "unknown external HTTP targets must stay on the capability-gated provider seam, got: {error}"
    );
}

#[test]
fn non_loopback_host_cannot_alias_a_live_virtual_port() {
    let error = eval_error(
        r#"
        const http = require('http');
        const server = http.createServer((req, res) => res.end('must-not-run'));
        server.listen(0, '127.0.0.1', () => {
          http.get({ host: 'example.com', port: server.address().port, path: '/' });
        });
        "#,
    );
    assert!(
        error.contains("NetworkEgress") || error.contains("net:request"),
        "non-loopback host must cross the external capability seam: {error}"
    );
}

#[test]
fn external_http_framing_rejects_control_bytes_before_egress() {
    for source in [
        "require('http').get({ host: 'example.com', path: '/ok\\r\\nX-Evil: yes' });",
        "require('http').get({ host: 'example.com', path: '/', headers: { X: 'ok\\r\\nInjected: yes' } });",
        "require('http').request({ host: 'example.com', path: '/', method: 'GET\\r\\nX-Evil: yes' });",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("control")
                || error.contains("HTTP token method")
                || error.contains("absolute HTTP path"),
            "wire-unsafe input must fail before provider dispatch: {error}"
        );
        assert!(
            !error.contains("NetworkEgress"),
            "validation must precede the capability/provider seam: {error}"
        );
    }
}

#[test]
fn sparse_header_arrays_are_bounded_before_native_iteration() {
    let error = eval_error(
        r#"
        const http = require('http');
        const values = [];
        values.length = 2147483647;
        const server = http.createServer((req, res) => res.end());
        server.listen(0, '127.0.0.1', () => {
          const request = http.request({ host: '127.0.0.1', port: server.address().port });
          request.setHeader('X-Sparse', values);
        });
        "#,
    );
    assert!(
        error.contains("header array length") || error.contains("128"),
        "sparse header arrays must fail at the bounded-work preflight: {error}"
    );
}

#[test]
fn response_end_precedes_close_when_agent_is_disabled() {
    let source = r#"
        const http = require('http');
        const server = http.createServer((req, res) => res.end('bye'));
        server.listen(0, '127.0.0.1', () => {
          http.get({
            host: '127.0.0.1',
            port: server.address().port,
            path: '/',
            agent: false
          }, res => {
            const order = [];
            res.on('end', () => order.push('end'));
            res.on('close', () => {
              order.push('close');
              console.log(order.join(','));
              server.close();
            });
            res.resume();
          });
        });
    "#;
    assert_eq!(eval_console(source), "end,close");
}

#[test]
fn status_methods_and_agent_are_bounded_pure_compute_surfaces() {
    let source = r#"
        const http = require('node:http');
        const agent = new http.Agent();
        console.log(http.STATUS_CODES[404], http.STATUS_CODES[200]);
        console.log(http.METHODS.includes('GET'), http.METHODS.includes('POST'), http.METHODS.includes('PUT'));
        console.log(agent.keepAlive === false || agent.keepAlive === undefined);
        console.log(typeof agent.protocol === 'string' ? agent.protocol : 'none');
    "#;
    assert_eq!(
        eval_console(source),
        "Not Found OK\ntrue true true\ntrue\nhttp:"
    );
}

#[test]
fn http_module_provenance_and_unknown_surfaces_fail_closed() {
    let rejected = [
        (
            "unused module possession",
            "const http = require('http'); console.log('unreachable');",
        ),
        (
            "unknown member",
            "const http = require('http'); console.log(typeof http.validateHeaderName);",
        ),
        (
            "dynamic specifier",
            "const name = 'http'; const http = require(name); console.log(http.METHODS);",
        ),
        (
            "module alias escape",
            "const http = require('http'); function take(value) { return value; } console.log(take(http));",
        ),
        (
            "consumed method escape",
            "const http = require('http'); const create = http.createServer; console.log(create);",
        ),
        (
            "mutable alias authority confusion",
            "let http = require('http'); http = { get() { return 'local'; } }; console.log(http.get('/'));",
        ),
        (
            "direct module member mutation",
            "const http = require('http'); http.createServer = () => 'forged'; console.log(http.createServer());",
        ),
    ];
    for (label, source) in rejected {
        let error = eval_error(source);
        assert!(
            error.contains("ambient authority violation")
                || error.contains("require")
                || error.contains("lowering"),
            "{label} must stay fail closed, got: {error}"
        );
    }

    let shadowed_error = eval_error(
        r#"
            function probe(require) {
              const http = require('http');
              return http.createServer();
            }
            const marker = { createServer() { return 'local'; } };
            console.log(probe(() => marker));
        "#,
    );
    assert!(
        shadowed_error.contains("ambient authority violation")
            || shadowed_error.contains("require"),
        "a lexically shadowed `require` name must not acquire HTTP builtin provenance, got: {shadowed_error}"
    );
}
