//! bd-7qwej: deterministic same-interpreter `net` loopback acceptance.
//!
//! The engine never opens an operating-system socket for this surface. These
//! tests exercise the product-like `HybridRouter::eval` path and pin the
//! in-memory server/socket lifecycle used by the franken_node compatibility
//! corpus: usage-gated `require('net')` lowering, loopback connection setup,
//! EventEmitter delivery, byte-preserving writes, half-close/close ordering,
//! metadata, backpressure-adjacent chaining, and refused connections.
//!
//! Unknown, unused, and dynamically selected module surfaces remain subject
//! to the ambient-authority refusal instead of silently widening the builtin.

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
        Ok(outcome) => panic!("expected eval error for {source:?}, got {outcome:?}"),
        Err(error) => error.to_string(),
    }
}

fn assert_console_cases(cases: &[(&str, &str, &str)]) {
    for (label, source, expected) in cases {
        assert_eq!(eval_console(source), *expected, "case {label}");
    }
}

#[test]
fn ip_classification_matches_node_shapes() {
    assert_console_cases(&[
        (
            "isIP",
            r#"
                const net = require('net');
                console.log(net.isIP('127.0.0.1'), net.isIP('::1'), net.isIP('not-an-ip'));
            "#,
            "4 6 0",
        ),
        (
            "isIPv4",
            r#"
                const net = require('node:net');
                console.log(net.isIPv4('10.0.0.1'), net.isIPv4('::1'), net.isIPv4('999.1.1.1'));
            "#,
            "true false false",
        ),
        (
            "isIPv6",
            r#"
                const net = require('net');
                console.log(net.isIPv6('::1'), net.isIPv6('fe80::1'), net.isIPv6('127.0.0.1'));
            "#,
            "true true false",
        ),
        (
            "invalid-octets",
            r#"
                const net = require('net');
                console.log(net.isIP('256.0.0.1'), net.isIP('1.2.3.4.5'), net.isIP(''));
            "#,
            "0 0 0",
        ),
        (
            "inline-require",
            "console.log(require('net').isIP('127.0.0.1'));",
            "4",
        ),
    ]);
}

#[test]
fn client_to_server_writes_preserve_order_and_buffer_bytes() {
    let source = r#"
        const net = require('net');
        const server = net.createServer(socket => {
          const chunks = [];
          socket.on('data', chunk => chunks.push(chunk));
          socket.on('end', () => {
            const body = Buffer.concat(chunks);
            console.log('hex:' + body.toString('hex'));
            console.log('read:' + socket.bytesRead);
            socket.end();
            server.close();
          });
        });
        server.listen(0, '127.0.0.1', () => {
          const client = net.connect(server.address().port, '127.0.0.1', () => {
            client.write('aa');
            client.write(Buffer.from([0, 127, 128, 255]));
            client.end('cc');
          });
          client.on('close', () => console.log('written:' + client.bytesWritten));
        });
    "#;
    assert_eq!(
        eval_console(source),
        "hex:6161007f80ff6363\nread:8\nwritten:8"
    );
}

#[test]
fn writes_and_end_before_connect_are_flushed_in_order() {
    let source = r#"
        const net = require('net');
        const server = net.createServer(socket => {
          let body = '';
          socket.setEncoding('utf8');
          socket.on('data', chunk => body += chunk);
          socket.on('end', () => {
            console.log(body);
            server.close(() => console.log('server-close'));
          });
        });
        server.listen(0, '127.0.0.1', () => {
          const client = net.connect(server.address().port, '127.0.0.1');
          client.write('pre');
          client.end('connect');
        });
    "#;
    assert_eq!(eval_console(source), "preconnect\nserver-close");
}

#[test]
fn server_to_client_data_end_close_order_and_encoding() {
    assert_console_cases(&[
        (
            "event-order",
            r#"
                const net = require('net');
                const server = net.createServer(socket => socket.end('D'));
                server.listen(0, '127.0.0.1', () => {
                  const client = net.connect(server.address().port, '127.0.0.1');
                  const order = [];
                  client.on('data', () => order.push('data'));
                  client.on('end', () => order.push('end'));
                  client.on('close', () => {
                    order.push('close');
                    console.log(order.join(','));
                    server.close();
                  });
                });
            "#,
            "data,end,close",
        ),
        (
            "utf8-encoding",
            r#"
                const net = require('net');
                const server = net.createServer(socket => socket.end('text-data'));
                server.listen(0, '127.0.0.1', () => {
                  const client = net.connect(server.address().port, '127.0.0.1');
                  client.setEncoding('utf8');
                  client.on('data', value => console.log(typeof value, value));
                  client.on('close', () => server.close());
                });
            "#,
            "string text-data",
        ),
        (
            "default-buffer",
            r#"
                const net = require('net');
                const server = net.createServer(socket => socket.end(Buffer.from([0, 127, 128, 255])));
                server.listen(0, '127.0.0.1', () => {
                  const client = net.connect(server.address().port, '127.0.0.1');
                  client.on('data', value => console.log(Buffer.isBuffer(value), value.toString('hex')));
                  client.on('close', () => server.close());
                });
            "#,
            "true 007f80ff",
        ),
    ]);
}

#[test]
fn connection_forms_and_server_events_share_the_loopback_kernel() {
    assert_console_cases(&[
        (
            "positional-connect",
            r#"
                const net = require('net');
                const server = net.createServer(socket => socket.end());
                server.listen(0, '127.0.0.1', () => {
                  const client = net.connect(server.address().port, '127.0.0.1', () => {
                    console.log('positional');
                    client.end();
                  });
                  client.on('close', () => server.close());
                });
            "#,
            "positional",
        ),
        (
            "options-createConnection",
            r#"
                const net = require('node:net');
                const server = net.createServer();
                server.on('connection', socket => socket.end('via-alias'));
                server.listen(0, '127.0.0.1', () => {
                  const client = net.createConnection({
                    port: server.address().port,
                    host: '127.0.0.1'
                  });
                  let body = '';
                  client.on('connect', () => console.log('connect-event'));
                  client.on('data', chunk => body += chunk);
                  client.on('close', () => {
                    console.log(body);
                    server.close();
                  });
                });
            "#,
            "connect-event\nvia-alias",
        ),
    ]);
}

#[test]
fn socket_and_server_metadata_are_updated_deterministically() {
    let source = r#"
        const net = require('net');
        const first = net.createServer(socket => socket.end());
        const second = net.createServer(socket => socket.end());
        first.listen(0, '127.0.0.1', () => {
          second.listen(0, '127.0.0.1', () => {
            const address = first.address();
            console.log(address.family, address.address);
            console.log('distinct:' + (address.port !== second.address().port));
            const client = net.connect(address.port, '127.0.0.1', () => {
              console.log('local:' + (typeof client.localAddress === 'string'));
              console.log('remote:' + (client.remotePort === address.port));
              client.end();
            });
            client.on('close', () => {
              first.close();
              second.close();
            });
          });
        });
    "#;
    assert_eq!(
        eval_console(source),
        "IPv4 127.0.0.1\ndistinct:true\nlocal:true\nremote:true"
    );
}

#[test]
fn pause_defers_data_and_end_until_resume() {
    let source = r#"
        const net = require('net');
        const server = net.createServer(socket => socket.end('deferred'));
        server.listen(0, '127.0.0.1', () => {
          const client = net.connect(server.address().port, '127.0.0.1');
          client.pause();
          let body = '';
          client.on('data', chunk => body += chunk);
          client.on('end', () => {
            console.log('after-resume:' + body);
            server.close();
          });
          setTimeout(() => client.resume(), 20);
        });
    "#;
    assert_eq!(eval_console(source), "after-resume:deferred");
}

#[test]
fn refused_connect_emits_error_with_node_code() {
    let source = r#"
        const net = require('net');
        const server = net.createServer(socket => socket.end());
        server.listen(0, '127.0.0.1', () => {
          const port = server.address().port;
          server.close(() => {
            const client = net.connect(port, '127.0.0.1');
            client.on('error', error => console.log(error instanceof Error, error.code));
            client.on('close', hadError => console.log('closed:' + hadError));
          });
        });
    "#;
    assert_eq!(eval_console(source), "true ECONNREFUSED\nclosed:true");
}

#[test]
fn refused_connect_without_error_listener_fails_eval() {
    let source = r#"
        const net = require('net');
        const client = net.connect(65535, '127.0.0.1');
        client.on('close', () => console.log('must-not-close-successfully'));
    "#;
    let error = eval_error(source);
    assert!(
        error.contains("uncaught exception") || error.contains("ECONNREFUSED"),
        "unhandled net error must escape eval, got: {error}"
    );
}

#[test]
fn close_destroy_and_chaining_contracts_hold() {
    let source = r#"
        const net = require('net');
        const server = net.createServer(() => {});
        server.listen(0, '127.0.0.1', () => {
          console.log('listening:' + server.listening);
          const client = net.connect(server.address().port, '127.0.0.1', () => {
            console.log('ref:' + (client.unref().ref() === client));
            console.log('nodelay:' + (client.setNoDelay(true) === client));
            console.log('keepalive:' + (client.setKeepAlive(true, 1000) === client));
            console.log('encoding:' + (client.setEncoding('utf8') === client));
            client.destroy();
          });
          client.on('close', hadError => {
            console.log('closed:' + hadError);
            server.close(() => console.log('listening:' + server.listening));
          });
        });
    "#;
    assert_eq!(
        eval_console(source),
        "listening:true\nref:true\nnodelay:true\nkeepalive:true\nencoding:true\nclosed:false\nlistening:false"
    );
}

#[test]
fn server_close_waits_for_accepted_connections() {
    let source = r#"
        const net = require('net');
        const order = [];
        const server = net.createServer(socket => {
          order.push('connection');
          socket.on('end', () => order.push('socket-end'));
          server.close(() => {
            order.push('server-close');
            console.log(order.join(','));
          });
          order.push('after-close-call');
        });
        server.listen(0, '127.0.0.1', () => {
          const client = net.connect(server.address().port, '127.0.0.1', () => client.end());
        });
    "#;
    assert_eq!(
        eval_console(source),
        "connection,after-close-call,socket-end,server-close"
    );
}

#[test]
fn destroy_suppresses_already_queued_data_and_end() {
    let source = r#"
        const net = require('net');
        const server = net.createServer(socket => socket.end('hidden'));
        server.listen(0, '127.0.0.1', () => {
          const client = net.connect(server.address().port, '127.0.0.1', () => {
            server.close();
            client.destroy();
          });
          client.pause();
          client.on('data', () => console.log('unexpected-data'));
          client.on('end', () => console.log('unexpected-end'));
          client.on('close', () => console.log('close'));
        });
    "#;
    assert_eq!(eval_console(source), "close");
}

#[test]
fn new_socket_exposes_boolean_state_and_can_be_destroyed() {
    let source = r#"
        const net = require('net');
        const socket = new net.Socket();
        console.log(typeof socket.readable, typeof socket.writable, socket.connecting);
        socket.destroy();
    "#;
    assert_eq!(eval_console(source), "boolean boolean false");
}

#[test]
fn write_after_end_returns_false_then_emits_error() {
    let source = r#"
        const net = require('net');
        const server = net.createServer(socket => {
          socket.on('data', () => {});
          socket.on('end', () => socket.end());
        });
        server.listen(0, '127.0.0.1', () => {
          const client = net.connect(server.address().port, '127.0.0.1', () => {
            client.end();
            client.on('error', error => {
              console.log('error:' + (error instanceof Error));
              server.close();
            });
            console.log('write:' + client.write('late'));
          });
        });
    "#;
    assert_eq!(eval_console(source), "write:false\nerror:true");
}

#[test]
fn net_lowering_keeps_unknown_and_dynamic_surfaces_fail_closed() {
    let cases = [
        (
            "unused require",
            "const net = require('net'); console.log('unreachable');",
        ),
        (
            "unknown member",
            "const net = require('net'); console.log(typeof net.lookup);",
        ),
        (
            "dynamic specifier",
            "const name = 'net'; const net = require(name); console.log(net.isIP('127.0.0.1'));",
        ),
    ];
    for (label, source) in cases {
        let error = eval_error(source);
        assert!(
            error.contains("ambient authority violation"),
            "{label} must remain ambient-refused, got: {error}"
        );
    }
}

// =========================================================================
// bd-dmnqx / bd-asw4m.5: net constructor results are finite engine-owned
// aggregates, so implicit-callback introspection observes the pre-fire
// publication state: rawListeners returns the stable once wrapper (never
// the original callable), its .listener property is the original, and
// listeners() reports the original through the wrapper's truthy .listener.
// =========================================================================

#[test]
#[ignore = "bd-dmnqx: closure-captured client binding still types fail-high through the listen CallMethod path; restore when capture labels land"]
fn listen_and_connect_callbacks_expose_stable_wrappers_to_rawlisteners() {
    let source = r#"
        const net = require('net');
        const server = net.createServer(socket => socket.end('ok'));
        let client = null;
        const onConnect = () => { client.end(); };
        const onListening = () => {
          client = net.connect(server.address().port, '127.0.0.1', onConnect);
          console.log('connect-raw-len', client.rawListeners('connect').length);
          console.log('connect-raw-not-original', client.rawListeners('connect')[0] !== onConnect);
          console.log('connect-raw-listener-is-original', client.rawListeners('connect')[0].listener === onConnect);
          console.log('connect-listeners-original', client.listeners('connect')[0] === onConnect);
          client.on('close', () => server.close());
        };
        server.listen(0, '127.0.0.1', onListening);
        console.log('listen-raw-len', server.rawListeners('listening').length);
        console.log('listen-raw-not-original', server.rawListeners('listening')[0] !== onListening);
        console.log('listen-raw-listener-is-original', server.rawListeners('listening')[0].listener === onListening);
        console.log('listen-listeners-original', server.listeners('listening')[0] === onListening);
        console.log('drained');
    "#;
    assert_eq!(
        eval_console(source),
        "listen-raw-len 1\n\
         listen-raw-not-original true\n\
         listen-raw-listener-is-original true\n\
         listen-listeners-original true\n\
         drained\n\
         connect-raw-len 1\n\
         connect-raw-not-original true\n\
         connect-raw-listener-is-original true\n\
         connect-listeners-original true"
    );
}

#[test]
fn close_callback_exposes_stable_wrapper_before_firing() {
    let source = r#"
        const net = require('net');
        const server = net.createServer(socket => socket.end());
        const onClose = () => { console.log('close-fired'); };
        server.listen(0, '127.0.0.1', () => {
          server.close(onClose);
          console.log('close-raw-len', server.rawListeners('close').length);
          console.log('close-raw-not-original', server.rawListeners('close')[0] !== onClose);
          console.log('close-raw-listener-is-original', server.rawListeners('close')[0].listener === onClose);
          console.log('close-listeners-original', server.listeners('close')[0] === onClose);
        });
    "#;
    assert_eq!(
        eval_console(source),
        "close-raw-len 1\n\
         close-raw-not-original true\n\
         close-raw-listener-is-original true\n\
         close-listeners-original true\n\
         close-fired"
    );
}

#[test]
fn socket_end_completion_carrier_is_invisible_and_fires_after_finish() {
    // Node keeps socket.end(callback) out of the EventEmitter finish listener
    // set: neither listeners() nor rawListeners() may observe the pending
    // completion, and it runs once after the finish event with the socket as
    // its receiver.
    let source = r#"
        const net = require('net');
        const server = net.createServer(socket => socket.end());
        let client = null;
        const onClose = () => { server.close(); };
        const onConnect = () => {
          console.log('finish-raw-pending', client.rawListeners('finish').length);
          console.log('finish-listeners-pending', client.listeners('finish').length);
          let finish_seen = false;
          let receiver_was_socket = false;
          client.on('finish', () => { finish_seen = true; });
          client.on('close', onClose);
          client.end(function onEndCallback() {
            receiver_was_socket = this === client;
            console.log('finish-before-endcb', finish_seen);
            console.log('end-receiver-is-socket', receiver_was_socket);
            console.log('finish-raw-after', client.rawListeners('finish').length);
          });
        };
        server.listen(0, '127.0.0.1', () => {
          client = net.connect(server.address().port, '127.0.0.1', onConnect);
        });
    "#;
    assert_eq!(
        eval_console(source),
        "finish-raw-pending 0\n\
         finish-listeners-pending 0\n\
         finish-before-endcb true\n\
         end-receiver-is-socket true\n\
         finish-raw-after 1"
    );
}
