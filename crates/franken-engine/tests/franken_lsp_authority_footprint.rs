//! Integration tests for `franken-lsp` (E5.T3).
//!
//! The server is intentionally a thin LSP wrapper around the E5.T1 authority
//! footprint analyzer. These tests drive the shipped binary over stdio
//! JSON-RPC framing and assert that editor diagnostics, hovers, and code lens
//! output come from the same report fields as `frankenctl check`.
#![forbid(unsafe_code)]

use std::io::{BufRead, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use serde_json::{Value, json};

#[test]
fn lsp_publishes_authority_diagnostics_hover_and_code_lens() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_franken-lsp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("franken-lsp should spawn");
    let mut stdin = child.stdin.take().expect("stdin pipe");
    let stdout = child.stdout.take().expect("stdout pipe");
    let messages = spawn_reader(stdout);

    write_lsp_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {},
                "initializationOptions": {
                    "parse_goal": "script"
                }
            }
        }),
    );
    let initialize = recv_matching(&messages, |message| message["id"] == 1);
    assert_eq!(initialize["result"]["capabilities"]["hoverProvider"], true);

    let uri = "file:///tmp/franken-lsp-fixture.js";
    write_lsp_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": uri,
                    "languageId": "javascript",
                    "version": 1,
                    "text": "const greeting = \"hello\";\nconst secret = process.env.SECRET_KEY;\n"
                }
            }
        }),
    );

    let publish = recv_matching(&messages, |message| {
        message["method"] == "textDocument/publishDiagnostics"
    });
    let diagnostics = publish["params"]["diagnostics"]
        .as_array()
        .expect("diagnostics array");
    assert_eq!(diagnostics.len(), 1);
    let diagnostic = &diagnostics[0];
    assert_eq!(diagnostic["code"], "FE-CAP-0001");
    assert_eq!(diagnostic["source"], "franken-lsp");
    assert_eq!(diagnostic["data"]["confidence"], "definite");
    assert_eq!(diagnostic["data"]["implied_capability"], "EnvRead");
    assert_eq!(
        diagnostic["range"]["start"]["line"], 1,
        "LSP diagnostics are zero-based, so source line 2 is line 1"
    );

    let hover_line = diagnostic["range"]["start"]["line"]
        .as_u64()
        .expect("hover line");
    let hover_character = diagnostic["range"]["start"]["character"]
        .as_u64()
        .expect("hover character");
    write_lsp_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {
                    "uri": uri
                },
                "position": {
                    "line": hover_line,
                    "character": hover_character
                }
            }
        }),
    );
    let hover = recv_matching(&messages, |message| message["id"] == 2);
    let hover_text = hover["result"]["contents"]["value"]
        .as_str()
        .expect("markdown hover text");
    assert!(hover_text.contains("FE-CAP-0001"), "{hover_text}");
    assert!(hover_text.contains("EnvRead"), "{hover_text}");

    write_lsp_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/codeLens",
            "params": {
                "textDocument": {
                    "uri": uri
                }
            }
        }),
    );
    let code_lens = recv_matching(&messages, |message| message["id"] == 3);
    let lenses = code_lens["result"].as_array().expect("code lens array");
    assert_eq!(lenses.len(), 1);
    let title = lenses[0]["command"]["title"]
        .as_str()
        .expect("code lens title");
    assert!(title.contains("Authority footprint"), "{title}");
    assert!(title.contains("EnvRead"), "{title}");
    assert_eq!(
        lenses[0]["command"]["command"],
        "franken-lsp.authorityFootprint"
    );
    let args = lenses[0]["command"]["arguments"]
        .as_array()
        .expect("code lens arguments");
    let report_sha = args[0]["report_sha256"].as_str().expect("report_sha256");
    assert_eq!(report_sha.len(), 64, "{report_sha}");

    shutdown(&mut child, &mut stdin, &messages);
}

fn spawn_reader<R: Read + Send + 'static>(stdout: R) -> Receiver<Value> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        loop {
            match read_lsp_message(&mut reader) {
                Ok(Some(message)) => {
                    if sender.send(message).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => panic!("failed to read LSP message: {error}"),
            }
        }
    });
    receiver
}

fn recv_matching<F>(messages: &Receiver<Value>, predicate: F) -> Value
where
    F: Fn(&Value) -> bool,
{
    let mut seen = Vec::new();
    for _ in 0..20 {
        let message = messages
            .recv_timeout(Duration::from_secs(10))
            .unwrap_or_else(|error| {
                panic!("timed out waiting for LSP message; seen={seen:?}; {error}")
            });
        if predicate(&message) {
            return message;
        }
        seen.push(message);
    }
    panic!("matching LSP message not received; seen={seen:?}");
}

fn shutdown(child: &mut Child, stdin: &mut ChildStdin, messages: &Receiver<Value>) {
    write_lsp_message(
        stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "shutdown",
            "params": null
        }),
    );
    let _ = recv_matching(messages, |message| message["id"] == 4);
    write_lsp_message(
        stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "exit",
            "params": null
        }),
    );
    let status = child
        .wait()
        .expect("franken-lsp exits after exit notification");
    assert!(status.success(), "franken-lsp exited with {status}");
}

fn write_lsp_message(writer: &mut ChildStdin, message: &Value) {
    let body = serde_json::to_vec(message).expect("encode JSON-RPC message");
    write!(writer, "Content-Length: {}\r\n\r\n", body.len()).expect("write LSP header");
    writer.write_all(&body).expect("write LSP body");
    writer.flush().expect("flush LSP body");
}

fn read_lsp_message<R: BufRead>(reader: &mut R) -> Result<Option<Value>, String> {
    let mut content_length = None;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .map_err(|error| format!("failed to read LSP header: {error}"))?;
        if bytes == 0 {
            return Ok(None);
        }
        let header = line.trim_end_matches(&['\r', '\n'][..]);
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|error| format!("invalid Content-Length `{value}`: {error}"))?,
            );
        }
    }

    let Some(content_length) = content_length else {
        return Err("missing Content-Length header".to_string());
    };
    let mut body = vec![0; content_length];
    reader
        .read_exact(&mut body)
        .map_err(|error| format!("failed to read LSP body: {error}"))?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| format!("failed to decode LSP body: {error}"))
}
