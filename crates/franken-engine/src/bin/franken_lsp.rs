#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::authority_footprint::{
    AnalysisCompleteness, AuthorityFootprintReport, CheckFinding, SourceLocation,
    analyze_authority_footprint,
};
use serde_json::{Value, json};

fn main() {
    if let Err(error) = run() {
        eprintln!("franken-lsp: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = io::BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    let mut server = LspServer::default();

    while let Some(message) = read_lsp_message(&mut reader)? {
        let responses = server.handle_message(message);
        for response in responses {
            write_lsp_message(&mut writer, &response)?;
        }
        if server.should_exit {
            break;
        }
    }

    Ok(())
}

struct DocumentState {
    version: Option<i64>,
    parse_goal: ParseGoal,
    report: AuthorityFootprintReport,
}

struct LspServer {
    documents: BTreeMap<String, DocumentState>,
    default_parse_goal: ParseGoal,
    should_exit: bool,
}

impl Default for LspServer {
    fn default() -> Self {
        Self {
            documents: BTreeMap::new(),
            default_parse_goal: ParseGoal::Script,
            should_exit: false,
        }
    }
}

impl LspServer {
    fn handle_message(&mut self, message: Value) -> Vec<Value> {
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let id = message.get("id").cloned();

        match method {
            "initialize" => {
                self.default_parse_goal = parse_goal_from_options(
                    message
                        .pointer("/params/initializationOptions/parse_goal")
                        .or_else(|| message.pointer("/params/initializationOptions/parseGoal"))
                        .and_then(Value::as_str),
                    self.default_parse_goal,
                );
                id.into_iter()
                    .map(|request_id| response(request_id, initialize_result()))
                    .collect()
            }
            "initialized" => Vec::new(),
            "textDocument/didOpen" => self.handle_did_open(&message),
            "textDocument/didChange" => self.handle_did_change(&message),
            "textDocument/didClose" => self.handle_did_close(&message),
            "textDocument/hover" => id
                .into_iter()
                .map(|request_id| response(request_id, self.handle_hover(&message)))
                .collect(),
            "textDocument/codeLens" => id
                .into_iter()
                .map(|request_id| response(request_id, self.handle_code_lens(&message)))
                .collect(),
            "shutdown" => id
                .into_iter()
                .map(|request_id| response(request_id, Value::Null))
                .collect(),
            "exit" => {
                self.should_exit = true;
                Vec::new()
            }
            _ => id
                .into_iter()
                .map(|request_id| error_response(request_id, -32601, "method not found"))
                .collect(),
        }
    }

    fn handle_did_open(&mut self, message: &Value) -> Vec<Value> {
        let Some(uri) = message
            .pointer("/params/textDocument/uri")
            .and_then(Value::as_str)
        else {
            return Vec::new();
        };
        let Some(text) = message
            .pointer("/params/textDocument/text")
            .and_then(Value::as_str)
        else {
            return Vec::new();
        };

        let language_id = message
            .pointer("/params/textDocument/languageId")
            .and_then(Value::as_str);
        let parse_goal = parse_goal_for_document(uri, language_id, text, self.default_parse_goal);
        let version = message
            .pointer("/params/textDocument/version")
            .and_then(Value::as_i64);
        let report = analyze_authority_footprint(text, uri, parse_goal);
        self.documents.insert(
            uri.to_string(),
            DocumentState {
                version,
                parse_goal,
                report,
            },
        );
        vec![self.publish_diagnostics(uri)]
    }

    fn handle_did_change(&mut self, message: &Value) -> Vec<Value> {
        let Some(uri) = message
            .pointer("/params/textDocument/uri")
            .and_then(Value::as_str)
        else {
            return Vec::new();
        };
        let Some(text) = message
            .pointer("/params/contentChanges/0/text")
            .and_then(Value::as_str)
        else {
            return Vec::new();
        };

        let version = message
            .pointer("/params/textDocument/version")
            .and_then(Value::as_i64);
        let parse_goal = self
            .documents
            .get(uri)
            .map(|document| document.parse_goal)
            .unwrap_or_else(|| parse_goal_for_document(uri, None, text, self.default_parse_goal));
        let report = analyze_authority_footprint(text, uri, parse_goal);
        self.documents.insert(
            uri.to_string(),
            DocumentState {
                version,
                parse_goal,
                report,
            },
        );
        vec![self.publish_diagnostics(uri)]
    }

    fn handle_did_close(&mut self, message: &Value) -> Vec<Value> {
        let Some(uri) = message
            .pointer("/params/textDocument/uri")
            .and_then(Value::as_str)
        else {
            return Vec::new();
        };
        self.documents.remove(uri);
        vec![json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {
                "uri": uri,
                "diagnostics": [],
            },
        })]
    }

    fn handle_hover(&self, message: &Value) -> Value {
        let Some(uri) = message
            .pointer("/params/textDocument/uri")
            .and_then(Value::as_str)
        else {
            return Value::Null;
        };
        let Some(document) = self.documents.get(uri) else {
            return Value::Null;
        };
        let line = message
            .pointer("/params/position/line")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let character = message
            .pointer("/params/position/character")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        hover_for_report(&document.report, line, character)
    }

    fn handle_code_lens(&self, message: &Value) -> Value {
        let Some(uri) = message
            .pointer("/params/textDocument/uri")
            .and_then(Value::as_str)
        else {
            return json!([]);
        };
        let Some(document) = self.documents.get(uri) else {
            return json!([]);
        };

        json!([top_of_file_code_lens(&document.report)])
    }

    fn publish_diagnostics(&self, uri: &str) -> Value {
        let Some(document) = self.documents.get(uri) else {
            return json!({
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {
                    "uri": uri,
                    "diagnostics": [],
                },
            });
        };

        let diagnostics = diagnostics_for_report(&document.report);
        let mut params = json!({
            "uri": uri,
            "diagnostics": diagnostics,
        });
        if let Some(version) = document.version {
            params["version"] = json!(version);
        }

        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": params,
        })
    }
}

fn initialize_result() -> Value {
    json!({
        "capabilities": {
            "textDocumentSync": {
                "openClose": true,
                "change": 1
            },
            "hoverProvider": true,
            "codeLensProvider": {
                "resolveProvider": false
            }
        },
        "serverInfo": {
            "name": "franken-lsp",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

fn parse_goal_from_options(value: Option<&str>, fallback: ParseGoal) -> ParseGoal {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "module" => ParseGoal::Module,
        "script" => ParseGoal::Script,
        _ => fallback,
    }
}

fn parse_goal_for_document(
    uri: &str,
    language_id: Option<&str>,
    text: &str,
    fallback: ParseGoal,
) -> ParseGoal {
    if uri.ends_with(".mjs") || matches!(language_id, Some("javascriptreact" | "typescriptreact")) {
        return ParseGoal::Module;
    }
    let trimmed = text.trim_start();
    if trimmed.starts_with("import ") || trimmed.starts_with("export ") {
        return ParseGoal::Module;
    }
    fallback
}

fn diagnostics_for_report(report: &AuthorityFootprintReport) -> Vec<Value> {
    if !report.analyzable {
        return vec![json!({
            "range": zero_width_top_range(),
            "severity": 1,
            "code": "FE-CAP-UNANALYZABLE",
            "source": "franken-lsp",
            "message": report.fail_closed_reason.as_deref().unwrap_or("source is unanalyzable"),
            "data": {
                "analysis_completeness": report.analysis_completeness.as_str(),
                "report_sha256": report.report_sha256.as_str(),
            },
        })];
    }

    report
        .findings
        .iter()
        .map(|finding| diagnostic_for_finding(finding, report.analysis_completeness))
        .collect()
}

fn diagnostic_for_finding(
    finding: &CheckFinding,
    analysis_completeness: AnalysisCompleteness,
) -> Value {
    json!({
        "range": finding
            .location
            .as_ref()
            .map(source_location_to_range)
            .unwrap_or_else(zero_width_top_range),
        "severity": 1,
        "code": finding.error_code.as_str(),
        "source": "franken-lsp",
        "message": finding.message.as_str(),
        "data": {
            "kind": finding.kind,
            "confidence": finding.confidence,
            "accessor": finding.accessor.as_deref(),
            "implied_capability": finding.implied_capability,
            "analysis_completeness": analysis_completeness.as_str(),
        },
    })
}

fn hover_for_report(report: &AuthorityFootprintReport, line: u64, character: u64) -> Value {
    for finding in &report.findings {
        if finding
            .location
            .as_ref()
            .is_some_and(|location| position_in_location(location, line, character))
        {
            let effect = finding
                .implied_capability
                .map(|capability| format!("required capability: {capability:?} ({capability})"))
                .unwrap_or_else(|| "IFC finding from flow-proof artifact".to_string());
            return json!({
                "contents": {
                    "kind": "markdown",
                    "value": format!(
                        "error[{}]\n\n{}\n\n{}",
                        finding.error_code, finding.message, effect
                    ),
                },
                "range": finding
                    .location
                    .as_ref()
                    .map(source_location_to_range)
                    .unwrap_or_else(zero_width_top_range),
            });
        }
    }

    for requirement in &report.required_capabilities {
        for location in &requirement.call_sites {
            if position_in_location(location, line, character) {
                return json!({
                    "contents": {
                        "kind": "markdown",
                        "value": format!(
                            "required capability: {}\n\nEffect set: {}",
                            requirement.capability_tag, requirement.capability_tag
                        ),
                    },
                    "range": source_location_to_range(location),
                });
            }
        }
    }

    json!({
        "contents": {
            "kind": "markdown",
            "value": format!(
                "Authority footprint: {}\n\n{}",
                capability_summary(report), report.least_authority_suggestion
            ),
        },
        "range": zero_width_top_range(),
    })
}

fn top_of_file_code_lens(report: &AuthorityFootprintReport) -> Value {
    json!({
        "range": zero_width_top_range(),
        "command": {
            "title": format!("Authority footprint: {}", capability_summary(report)),
            "command": "franken-lsp.authorityFootprint",
            "arguments": [{
                "schema_version": report.schema_version.as_str(),
                "source_sha256": report.source_sha256.as_str(),
                "report_sha256": report.report_sha256.as_str(),
                "analysis_completeness": report.analysis_completeness.as_str(),
                "required_capabilities": report.required_capabilities.clone(),
            }],
        },
    })
}

fn capability_summary(report: &AuthorityFootprintReport) -> String {
    if report.required_capabilities.is_empty() {
        return "none".to_string();
    }
    report
        .required_capabilities
        .iter()
        .map(|requirement| {
            requirement
                .capability
                .map(|capability| format!("{capability:?} ({})", requirement.capability_tag))
                .unwrap_or_else(|| requirement.capability_tag.clone())
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn source_location_to_range(location: &SourceLocation) -> Value {
    let start_line = location.start_line.saturating_sub(1);
    let start_character = location.start_column.saturating_sub(1);
    let mut end_line = location.end_line.saturating_sub(1);
    let mut end_character = location.end_column.saturating_sub(1);
    if end_line < start_line || (end_line == start_line && end_character <= start_character) {
        end_line = start_line;
        end_character = start_character.saturating_add(1);
    }

    json!({
        "start": {
            "line": start_line,
            "character": start_character,
        },
        "end": {
            "line": end_line,
            "character": end_character,
        },
    })
}

fn zero_width_top_range() -> Value {
    json!({
        "start": {
            "line": 0,
            "character": 0,
        },
        "end": {
            "line": 0,
            "character": 1,
        },
    })
}

fn position_in_location(location: &SourceLocation, line: u64, character: u64) -> bool {
    let start_line = location.start_line.saturating_sub(1);
    let start_character = location.start_column.saturating_sub(1);
    let end_line = location.end_line.saturating_sub(1);
    let end_character = location.end_column.saturating_sub(1);

    if line < start_line || line > end_line {
        return false;
    }
    if line == start_line && character < start_character {
        return false;
    }
    if line == end_line && character > end_character {
        return false;
    }
    true
}

fn response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        },
    })
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
    serde_json::from_slice(&body).map(Some).map_err(|error| {
        format!(
            "failed to decode JSON-RPC message `{}`: {error}",
            String::from_utf8_lossy(&body)
        )
    })
}

fn write_lsp_message<W: Write>(writer: &mut W, message: &Value) -> Result<(), String> {
    let body = serde_json::to_vec(message)
        .map_err(|error| format!("failed to encode JSON-RPC message: {error}"))?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())
        .map_err(|error| format!("failed to write LSP header: {error}"))?;
    writer
        .write_all(&body)
        .map_err(|error| format!("failed to write LSP body: {error}"))?;
    writer
        .flush()
        .map_err(|error| format!("failed to flush LSP output: {error}"))
}
