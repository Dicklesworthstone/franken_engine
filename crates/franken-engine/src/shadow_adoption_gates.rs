//! Shadow daemon adoption gates and mutation policy enforcement.
//!
//! This module provides governance gates to ensure README/documentation claims
//! remain truthful about the shadow daemon's current capabilities and prevents
//! premature claims about autonomous mutation, production status, or operator replacement.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::security_epoch::SecurityEpoch;

/// Gate status for shadow daemon capability verification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GateStatus {
    /// Gate is passing - capability is verified and ready
    Green,
    /// Gate is failing - capability not yet verified
    Red,
    /// Gate status is unknown or indeterminate
    Unknown,
}

/// Individual adoption gate for a specific capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdoptionGate {
    pub gate_id: String,
    pub description: String,
    pub status: GateStatus,
    pub required_for: Vec<String>,
    pub verification_criteria: Vec<String>,
    pub last_check: Option<SecurityEpoch>,
    pub failure_reason: Option<String>,
}

/// Complete set of adoption gates for shadow daemon capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowAdoptionGates {
    pub gates: Vec<AdoptionGate>,
    pub generated_at: SecurityEpoch,
}

impl ShadowAdoptionGates {
    /// Create default adoption gates with current verification status
    pub fn with_default_gates() -> Self {
        Self {
            gates: vec![
                AdoptionGate {
                    gate_id: "no_mock_drill".to_string(),
                    description: "No-mock shadow daemon lifecycle drill completion".to_string(),
                    status: GateStatus::Red, // TODO: Update when bd-djejh.6 completed
                    required_for: vec![
                        "autonomous_live_mutation".to_string(),
                        "production_daemon_status".to_string(),
                        "operator_replacement".to_string(),
                    ],
                    verification_criteria: vec![
                        "Complete shadow daemon lifecycle drill without mocks".to_string(),
                        "Truth gate validation passes".to_string(),
                        "End-to-end integration verified".to_string(),
                    ],
                    last_check: Some(SecurityEpoch::GENESIS),
                    failure_reason: Some("Bead bd-djejh.6 not yet completed".to_string()),
                },
                AdoptionGate {
                    gate_id: "replay_verification".to_string(),
                    description: "Shadow replay and drift verification".to_string(),
                    status: GateStatus::Green, // Completed in bd-djejh.5
                    required_for: vec![
                        "deterministic_replay".to_string(),
                        "drift_detection".to_string(),
                    ],
                    verification_criteria: vec![
                        "Replay verification implementation complete".to_string(),
                        "Drift detection functional".to_string(),
                        "Deterministic replay validated".to_string(),
                    ],
                    last_check: Some(SecurityEpoch::GENESIS),
                    failure_reason: None,
                },
                AdoptionGate {
                    gate_id: "advisory_contract".to_string(),
                    description: "Advisory-only contract enforcement".to_string(),
                    status: GateStatus::Green, // Completed in bd-djejh.1
                    required_for: vec![
                        "safe_operator_ui".to_string(),
                        "bounded_advisory_mode".to_string(),
                    ],
                    verification_criteria: vec![
                        "Advisory contract defined and implemented".to_string(),
                        "No-mutation enforcement verified".to_string(),
                        "Command preview functionality only".to_string(),
                    ],
                    last_check: Some(SecurityEpoch::GENESIS),
                    failure_reason: None,
                },
                AdoptionGate {
                    gate_id: "handoff_contracts".to_string(),
                    description: "Frankentui and fastapi_rust handoff contracts".to_string(),
                    status: GateStatus::Green, // Completed in bd-djejh.7
                    required_for: vec![
                        "ui_integration".to_string(),
                        "service_interface".to_string(),
                    ],
                    verification_criteria: vec![
                        "FrankenTUI panel bundles implemented".to_string(),
                        "FastAPI Rust service interface ready".to_string(),
                        "Advisory-only command surfaces verified".to_string(),
                    ],
                    last_check: Some(SecurityEpoch::GENESIS),
                    failure_reason: None,
                },
                AdoptionGate {
                    gate_id: "mutation_policy_enforcement".to_string(),
                    description: "Mutation policy enforcement and validation".to_string(),
                    status: GateStatus::Green, // Implemented in this bead
                    required_for: vec![
                        "safe_operation".to_string(),
                        "governance_compliance".to_string(),
                    ],
                    verification_criteria: vec![
                        "Mutation policy checker implemented".to_string(),
                        "Command validation enforced".to_string(),
                        "Documentation gates functional".to_string(),
                    ],
                    last_check: Some(SecurityEpoch::GENESIS),
                    failure_reason: None,
                },
            ],
            generated_at: SecurityEpoch::GENESIS,
        }
    }

    /// Check if a specific capability is gated (should not be claimed)
    pub fn is_capability_gated(&self, capability: &str) -> bool {
        self.gates.iter().any(|gate| {
            gate.required_for.contains(&capability.to_string()) && gate.status != GateStatus::Green
        })
    }

    /// Get all gated capabilities that should not be claimed
    pub fn get_gated_capabilities(&self) -> BTreeSet<String> {
        let mut gated = BTreeSet::new();
        for gate in &self.gates {
            if gate.status != GateStatus::Green {
                for capability in &gate.required_for {
                    gated.insert(capability.clone());
                }
            }
        }
        gated
    }

    /// Get status of a specific gate
    pub fn get_gate_status(&self, gate_id: &str) -> Option<&GateStatus> {
        self.gates
            .iter()
            .find(|gate| gate.gate_id == gate_id)
            .map(|gate| &gate.status)
    }

    /// Check if all gates are green
    pub fn all_gates_green(&self) -> bool {
        self.gates
            .iter()
            .all(|gate| gate.status == GateStatus::Green)
    }

    /// Get summary of gate statuses
    pub fn get_summary(&self) -> GateSummary {
        let total = self.gates.len();
        let green = self
            .gates
            .iter()
            .filter(|g| g.status == GateStatus::Green)
            .count();
        let red = self
            .gates
            .iter()
            .filter(|g| g.status == GateStatus::Red)
            .count();
        let unknown = self
            .gates
            .iter()
            .filter(|g| g.status == GateStatus::Unknown)
            .count();

        GateSummary {
            total_gates: total,
            green_gates: green,
            red_gates: red,
            unknown_gates: unknown,
            all_green: green == total,
            gated_capabilities: self.get_gated_capabilities(),
        }
    }
}

/// Summary of adoption gate statuses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateSummary {
    pub total_gates: usize,
    pub green_gates: usize,
    pub red_gates: usize,
    pub unknown_gates: usize,
    pub all_green: bool,
    pub gated_capabilities: BTreeSet<String>,
}

/// Forbidden mutation commands that shadow daemon must never execute
pub const FORBIDDEN_MUTATION_COMMANDS: &[&str] = &[
    "br",
    "beads",
    "rch",
    "remote_compilation_helper",
    "git",
    "agent-mail",
    "mcp-agent-mail",
    "worker",
    "queue",
];

const SHELL_COMMAND_EXECUTORS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "fish",
    "pwsh",
    "powershell",
    "cmd",
];

/// Command validation result
#[derive(Debug, Clone, PartialEq)]
pub enum CommandValidation {
    /// Command is safe - advisory only
    Advisory,
    /// Command would cause forbidden mutation
    ForbiddenMutation { command: String, reason: String },
    /// Command validation failed for other reason
    ValidationFailed { reason: String },
}

#[derive(Debug, Clone, Copy)]
struct ForbiddenCommandUsage {
    command: &'static str,
    direct: bool,
}

fn classify_command_token(
    token: &str,
    at_segment_start: bool,
    saw_separator: bool,
) -> Option<ForbiddenCommandUsage> {
    let executable = token.rsplit('/').next().unwrap_or(token);
    FORBIDDEN_MUTATION_COMMANDS
        .iter()
        .copied()
        .find(|forbidden| executable == *forbidden)
        .map(|command| ForbiddenCommandUsage {
            command,
            direct: at_segment_start && !saw_separator,
        })
}

fn finish_command_token(
    token: &mut String,
    at_segment_start: &mut bool,
    saw_separator: bool,
) -> Option<ForbiddenCommandUsage> {
    if token.is_empty() {
        return None;
    }
    let usage = classify_command_token(token, *at_segment_start, saw_separator);
    token.clear();
    *at_segment_start = false;
    usage
}

fn detect_forbidden_command_usage(command: &str) -> Result<Option<ForbiddenCommandUsage>, String> {
    let mut token = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escaped_in_double_quote = false;
    let mut at_segment_start = true;
    let mut saw_separator = false;
    let mut previous_was_whitespace = true;

    for ch in command.chars() {
        if in_single_quote {
            if ch == '\'' {
                in_single_quote = false;
            }
            continue;
        }

        if in_double_quote {
            if escaped_in_double_quote {
                escaped_in_double_quote = false;
                continue;
            }
            if ch == '\\' {
                escaped_in_double_quote = true;
                continue;
            }
            if ch == '"' {
                in_double_quote = false;
            }
            continue;
        }

        match ch {
            '\'' => in_single_quote = true,
            '"' => in_double_quote = true,
            '#' if token.is_empty() && previous_was_whitespace => break,
            // Shell command separators and operators
            ';' | '|' | '&' | '\n' | '\r' => {
                if let Some(usage) =
                    finish_command_token(&mut token, &mut at_segment_start, saw_separator)
                {
                    return Ok(Some(usage));
                }
                at_segment_start = true;
                saw_separator = true;
                previous_was_whitespace = true;
            }
            // Shell redirections that can separate commands
            '<' | '>' => {
                if let Some(usage) =
                    finish_command_token(&mut token, &mut at_segment_start, saw_separator)
                {
                    return Ok(Some(usage));
                }
                at_segment_start = true;
                saw_separator = true;
                previous_was_whitespace = true;
            }
            // Command substitution and subshell operators
            '$' | '`' | '(' | ')' => {
                if let Some(usage) =
                    finish_command_token(&mut token, &mut at_segment_start, saw_separator)
                {
                    return Ok(Some(usage));
                }
                at_segment_start = true;
                saw_separator = true;
                previous_was_whitespace = true;
            }
            ch if ch.is_whitespace() => {
                if let Some(usage) =
                    finish_command_token(&mut token, &mut at_segment_start, saw_separator)
                {
                    return Ok(Some(usage));
                }
                previous_was_whitespace = true;
            }
            _ => {
                token.push(ch);
                previous_was_whitespace = false;
            }
        }
    }

    if in_single_quote || in_double_quote {
        return Err("Unterminated quote in operator action command".to_string());
    }

    Ok(finish_command_token(
        &mut token,
        &mut at_segment_start,
        saw_separator,
    ))
}

fn shell_command_flag(token: &str) -> bool {
    let token_lower = token.to_ascii_lowercase();
    token_lower == "/c"
        || token_lower == "-command"
        || (token_lower.starts_with('-')
            && !token_lower.starts_with("--")
            && token_lower.chars().skip(1).any(|ch| ch == 'c'))
}

fn segment_invokes_shell_script(tokens: &[String]) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        let executable = token.rsplit('/').next().unwrap_or(token);
        SHELL_COMMAND_EXECUTORS
            .iter()
            .any(|shell| executable.eq_ignore_ascii_case(shell))
            && tokens
                .iter()
                .skip(index + 1)
                .any(|next| shell_command_flag(next))
    })
}

fn finish_shell_token(token: &mut String, tokens: &mut Vec<String>) {
    if !token.is_empty() {
        tokens.push(std::mem::take(token));
    }
}

fn detect_shell_command_execution(command: &str) -> Result<bool, String> {
    let mut token = String::new();
    let mut tokens = Vec::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escaped_in_double_quote = false;
    let mut previous_was_whitespace = true;

    for ch in command.chars() {
        if in_single_quote {
            if ch == '\'' {
                in_single_quote = false;
            } else {
                token.push(ch);
            }
            continue;
        }

        if in_double_quote {
            if escaped_in_double_quote {
                token.push(ch);
                escaped_in_double_quote = false;
                continue;
            }
            if ch == '\\' {
                escaped_in_double_quote = true;
                continue;
            }
            if ch == '"' {
                in_double_quote = false;
            } else {
                token.push(ch);
            }
            continue;
        }

        match ch {
            '\'' => in_single_quote = true,
            '"' => in_double_quote = true,
            '#' if token.is_empty() && previous_was_whitespace => break,
            ';' | '|' | '&' | '\n' | '\r' => {
                finish_shell_token(&mut token, &mut tokens);
                if segment_invokes_shell_script(&tokens) {
                    return Ok(true);
                }
                tokens.clear();
                previous_was_whitespace = true;
            }
            ch if ch.is_whitespace() => {
                finish_shell_token(&mut token, &mut tokens);
                previous_was_whitespace = true;
            }
            _ => {
                token.push(ch);
                previous_was_whitespace = false;
            }
        }
    }

    if in_single_quote || in_double_quote {
        return Err("Unterminated quote in operator action command".to_string());
    }

    finish_shell_token(&mut token, &mut tokens);
    Ok(segment_invokes_shell_script(&tokens))
}

/// Validate that a command string is advisory-only and doesn't contain mutations
pub fn validate_operator_action_command(command: &str) -> CommandValidation {
    let command_trimmed = command.trim();

    match detect_shell_command_execution(command_trimmed) {
        Ok(true) => {
            return CommandValidation::ForbiddenMutation {
                command: "shell_escape".to_string(),
                reason: "Shell command execution is forbidden in operator actions".to_string(),
            };
        }
        Ok(false) => {}
        Err(reason) => {
            return CommandValidation::ValidationFailed { reason };
        }
    }

    match detect_forbidden_command_usage(command_trimmed) {
        Ok(Some(ForbiddenCommandUsage { command, direct })) => {
            let reason = if direct {
                format!("Direct execution of '{command}' is forbidden in shadow daemon context")
            } else {
                format!("Indirect execution of '{command}' is forbidden in shadow daemon context")
            };
            return CommandValidation::ForbiddenMutation {
                command: command.to_string(),
                reason,
            };
        }
        Ok(None) => {}
        Err(reason) => {
            return CommandValidation::ValidationFailed { reason };
        }
    }

    // Check for shell escape attempts
    if command_trimmed.contains("$(") || command_trimmed.contains("`") {
        return CommandValidation::ForbiddenMutation {
            command: "shell_escape".to_string(),
            reason: "Shell command substitution is forbidden in operator actions".to_string(),
        };
    }

    // Check for potentially dangerous flags
    if command_trimmed.contains("--execute")
        || command_trimmed.contains("--force")
        || command_trimmed.contains("--auto")
        || command_trimmed.contains("--yes")
    {
        return CommandValidation::ForbiddenMutation {
            command: "dangerous_flag".to_string(),
            reason: "Commands with auto-execution flags are forbidden".to_string(),
        };
    }

    // Command appears to be advisory-only
    CommandValidation::Advisory
}

/// Documentation claim validator
pub struct DocumentationClaimValidator {
    gates: ShadowAdoptionGates,
}

impl DocumentationClaimValidator {
    pub fn new() -> Self {
        Self {
            gates: ShadowAdoptionGates::with_default_gates(),
        }
    }

    /// Check if documentation text contains gated claims
    pub fn validate_documentation_text(&self, text: &str) -> Vec<GatedClaimViolation> {
        let mut violations = Vec::new();
        let text_lower = text.to_lowercase();

        let gated_capabilities = self.gates.get_gated_capabilities();

        // Check for autonomous mutation claims
        if gated_capabilities.contains("autonomous_live_mutation") {
            if text_lower.contains("autonomous")
                && (text_lower.contains("mutation")
                    || text_lower.contains("execute")
                    || text_lower.contains("modify"))
            {
                violations.push(GatedClaimViolation {
                    claim_type: "autonomous_live_mutation".to_string(),
                    violation_text: extract_violation_context(&text, &["autonomous", "mutation"]),
                    gate_id: "no_mock_drill".to_string(),
                    required_status: GateStatus::Green,
                    actual_status: self.gates.get_gate_status("no_mock_drill").unwrap().clone(),
                });
            }
        }

        // Check for production daemon claims
        if gated_capabilities.contains("production_daemon_status") {
            if text_lower.contains("production") && text_lower.contains("daemon") {
                violations.push(GatedClaimViolation {
                    claim_type: "production_daemon_status".to_string(),
                    violation_text: extract_violation_context(&text, &["production", "daemon"]),
                    gate_id: "no_mock_drill".to_string(),
                    required_status: GateStatus::Green,
                    actual_status: self.gates.get_gate_status("no_mock_drill").unwrap().clone(),
                });
            }
        }

        // Check for operator replacement claims
        if gated_capabilities.contains("operator_replacement") {
            if text_lower.contains("replac") && text_lower.contains("operator") {
                violations.push(GatedClaimViolation {
                    claim_type: "operator_replacement".to_string(),
                    violation_text: extract_violation_context(&text, &["replac", "operator"]),
                    gate_id: "no_mock_drill".to_string(),
                    required_status: GateStatus::Green,
                    actual_status: self.gates.get_gate_status("no_mock_drill").unwrap().clone(),
                });
            }
        }

        violations
    }
}

impl Default for DocumentationClaimValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a violation of gated documentation claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatedClaimViolation {
    pub claim_type: String,
    pub violation_text: String,
    pub gate_id: String,
    pub required_status: GateStatus,
    pub actual_status: GateStatus,
}

/// Extract context around violation for debugging
fn extract_violation_context(text: &str, keywords: &[&str]) -> String {
    for line in text.lines() {
        let line_lower = line.to_lowercase();
        if keywords.iter().any(|&keyword| line_lower.contains(keyword)) {
            return line.trim().to_string();
        }
    }
    "Context not found".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_adoption_gates() {
        let gates = ShadowAdoptionGates::with_default_gates();

        // Should have all required gates
        assert!(gates.gates.len() >= 5);

        // Key gates should exist
        assert!(gates.get_gate_status("no_mock_drill").is_some());
        assert!(gates.get_gate_status("replay_verification").is_some());
        assert!(gates.get_gate_status("advisory_contract").is_some());
        assert!(gates.get_gate_status("handoff_contracts").is_some());
        assert!(
            gates
                .get_gate_status("mutation_policy_enforcement")
                .is_some()
        );
    }

    #[test]
    fn test_gated_capabilities() {
        let gates = ShadowAdoptionGates::with_default_gates();
        let gated = gates.get_gated_capabilities();

        // Should include capabilities blocked by red gates
        assert!(gated.contains("autonomous_live_mutation"));
        assert!(gated.contains("production_daemon_status"));
        assert!(gated.contains("operator_replacement"));
    }

    #[test]
    fn test_command_validation_forbidden_mutations() {
        // Direct command usage
        assert_eq!(
            validate_operator_action_command("br update task-123"),
            CommandValidation::ForbiddenMutation {
                command: "br".to_string(),
                reason: "Direct execution of 'br' is forbidden in shadow daemon context"
                    .to_string()
            }
        );

        assert_eq!(
            validate_operator_action_command("git commit -m 'test'"),
            CommandValidation::ForbiddenMutation {
                command: "git".to_string(),
                reason: "Direct execution of 'git' is forbidden in shadow daemon context"
                    .to_string()
            }
        );

        // Indirect command usage
        assert_eq!(
            validate_operator_action_command("echo 'test' && br status"),
            CommandValidation::ForbiddenMutation {
                command: "br".to_string(),
                reason: "Indirect execution of 'br' is forbidden in shadow daemon context"
                    .to_string()
            }
        );
    }

    #[test]
    fn test_command_validation_shell_separator_bypasses() {
        let commands = [
            ("cmd;br status", "br"),
            ("cmd|br status", "br"),
            ("cmd||br status", "br"),
            ("cmd\nbr status", "br"),
            ("cmd br", "br"),
            ("cmd;git status", "git"),
            ("printf x|rch exec -- cargo check", "rch"),
        ];

        for (command, forbidden) in commands {
            assert_eq!(
                validate_operator_action_command(command),
                CommandValidation::ForbiddenMutation {
                    command: forbidden.to_string(),
                    reason: format!(
                        "Indirect execution of '{forbidden}' is forbidden in shadow daemon context"
                    )
                },
                "should reject command separator bypass: {command}"
            );
        }
    }

    #[test]
    fn test_command_validation_word_boundaries_allow_advisory_mentions() {
        let advisory_commands = [
            "branch status should be reviewed",
            "grep 'br status' logfile.txt",
            "grep 'sh -c br update' logfile.txt",
            "print('Use br status to check')",
            "# br status - run this manually",
        ];

        for command in advisory_commands {
            assert_eq!(
                validate_operator_action_command(command),
                CommandValidation::Advisory,
                "should allow non-executed advisory mention: {command}"
            );
        }
    }

    #[test]
    fn test_command_validation_shell_escapes() {
        assert_eq!(
            validate_operator_action_command("echo $(br status)"),
            CommandValidation::ForbiddenMutation {
                command: "shell_escape".to_string(),
                reason: "Shell command substitution is forbidden in operator actions".to_string()
            }
        );

        assert_eq!(
            validate_operator_action_command("echo `git status`"),
            CommandValidation::ForbiddenMutation {
                command: "shell_escape".to_string(),
                reason: "Shell command substitution is forbidden in operator actions".to_string()
            }
        );
    }

    #[test]
    fn test_command_validation_shell_command_execution() {
        let shell_commands = [
            "sh -c 'br update task-1'",
            "/bin/bash -lc 'git status'",
            "zsh -c \"rch exec -- cargo check\"",
            "pwsh -Command \"agent-mail check\"",
            "cmd /c br update task-1",
        ];

        for command in shell_commands {
            assert_eq!(
                validate_operator_action_command(command),
                CommandValidation::ForbiddenMutation {
                    command: "shell_escape".to_string(),
                    reason: "Shell command execution is forbidden in operator actions".to_string()
                },
                "should reject shell command execution: {command}"
            );
        }
    }

    #[test]
    fn test_command_validation_dangerous_flags() {
        assert_eq!(
            validate_operator_action_command("script.sh --execute"),
            CommandValidation::ForbiddenMutation {
                command: "dangerous_flag".to_string(),
                reason: "Commands with auto-execution flags are forbidden".to_string()
            }
        );

        assert_eq!(
            validate_operator_action_command("cleanup --force"),
            CommandValidation::ForbiddenMutation {
                command: "dangerous_flag".to_string(),
                reason: "Commands with auto-execution flags are forbidden".to_string()
            }
        );
    }

    #[test]
    fn test_command_validation_advisory_commands() {
        assert_eq!(
            validate_operator_action_command("echo 'Check shadow daemon status'"),
            CommandValidation::Advisory
        );

        assert_eq!(
            validate_operator_action_command("shadow-daemon refresh --source evidence-journal"),
            CommandValidation::Advisory
        );

        assert_eq!(
            validate_operator_action_command("cat /path/to/report.json"),
            CommandValidation::Advisory
        );
    }

    #[test]
    fn test_documentation_claim_validator() {
        let validator = DocumentationClaimValidator::new();

        // Should detect gated claims
        let violations = validator.validate_documentation_text(
            "The shadow daemon provides autonomous mutation capabilities for production environments."
        );
        assert!(!violations.is_empty());

        let violation = &violations[0];
        assert_eq!(violation.claim_type, "autonomous_live_mutation");
        assert_eq!(violation.gate_id, "no_mock_drill");
        assert_eq!(violation.required_status, GateStatus::Green);

        // Should allow advisory claims
        let violations = validator.validate_documentation_text(
            "The shadow daemon provides advisory recommendations for operators.",
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn test_gate_summary() {
        let gates = ShadowAdoptionGates::with_default_gates();
        let summary = gates.get_summary();

        assert!(summary.total_gates >= 5);
        assert!(summary.green_gates > 0);
        assert!(summary.red_gates > 0);
        assert!(!summary.all_green); // Should not be all green due to no_mock_drill
        assert!(!summary.gated_capabilities.is_empty());
    }
}
