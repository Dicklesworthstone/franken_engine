//! E8.T5 agent-sandbox mode: run AI-agent-generated code under the engine's
//! containment substrate and hand back the certificate bundle (bd-fqlfw.8.5).
//!
//! The sandbox is the agentic-AI framing of the runtime: an agent framework
//! declares its tool authority as an [`AgentSandboxManifest`] (the thin
//! MCP / tool-runner shim contract), the agent's generated JS/TS executes
//! inside the engine with that authority and nothing more, tool calls route
//! through the capability-typed hostcall membrane, the guardplane watches
//! agent actions as a live behavior firewall (allow → challenge → sandbox →
//! suspend → terminate → quarantine), and on exit the caller receives the
//! E8 certificate bundle (`non_use_certificate` module) plus an
//! [`AgentSandboxReport`] summarizing what the firewall observed.
//!
//! ## The tool-runner shim contract (v1)
//!
//! An agent framework adopts the engine as its execution backend by:
//!
//! 1. writing an `agent_sandbox_manifest.json`
//!    (`franken-engine.agent-sandbox-manifest.v1`) mapping each granted tool
//!    to an engine capability tag,
//! 2. invoking `frankenctl agent-sandbox --manifest <manifest.json> --input
//!    <generated.js> [--data-contract <contract.json>] [--certificate-out
//!    <dir>]`, and
//! 3. consuming the JSON report on stdout plus the certificate bundle files.
//!
//! ## Fail-closed posture
//!
//! - Unknown capability tags are a manifest **error**, never a silent drop
//!   (`RuntimeCapability::from_tag_str` drops unknown tags at the membrane;
//!   the manifest validator refuses them up front so an agent cannot believe
//!   it holds authority it does not).
//! - Host I/O stays [`DenyAll`-postured] unless the manifest declares a
//!   sandbox filesystem root; the network mechanism carries no egress policy
//!   in this repository (that gate lives in the `franken_node` product
//!   layer), so network tool grants remain capability-gated but
//!   policy-unfiltered — the manifest validator requires an explicit
//!   acknowledgement flag before granting network egress.
//! - Guardplane instruction hooks are always enabled for sandbox runs: the
//!   agent is the untrusted principal, so its trust level defaults to
//!   `provisional` and the behavior firewall cannot be opted out of.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::evidence_ledger::{EvidenceEntry, EvidenceVerificationIdentity};
use crate::execution_orchestrator::{ExtensionPackage, OrchestratorResult};

pub const AGENT_SANDBOX_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.agent-sandbox-manifest.v1";
pub const AGENT_SANDBOX_REPORT_SCHEMA_VERSION: &str = "franken-engine.agent-sandbox-report.v2";
/// Trust level assigned to agent code when the manifest does not override it.
/// `provisional` keeps the guardplane's instruction hooks armed.
pub const DEFAULT_AGENT_TRUST_LEVEL: &str = "provisional";

/// Capabilities the interpreter lanes force-grant to every execution
/// (mirrored from `execution_orchestrator::lane_router_for_execution` so the
/// certificate's runtime-granted set matches enforcement reality).
const FORCED_VM_CAPABILITIES: [RuntimeCapability; 3] = [
    RuntimeCapability::VmDispatch,
    RuntimeCapability::HeapAllocate,
    RuntimeCapability::Console,
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentSandboxError {
    UnsupportedSchema {
        expected: &'static str,
        actual: String,
    },
    EmptyField {
        field: &'static str,
    },
    DuplicateToolName {
        tool_name: String,
    },
    UnknownCapabilityTag {
        tool_name: String,
        capability_tag: String,
    },
    NetworkGrantWithoutAcknowledgement {
        tool_name: String,
    },
    DeniedCapabilityAlsoGranted {
        capability_tag: String,
    },
    InvalidTrustLevel {
        trust_level: String,
    },
}

impl fmt::Display for AgentSandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { expected, actual } => write!(
                f,
                "unsupported agent-sandbox manifest schema `{actual}`; expected `{expected}`"
            ),
            Self::EmptyField { field } => {
                write!(
                    f,
                    "agent-sandbox manifest field `{field}` must be non-empty"
                )
            }
            Self::DuplicateToolName { tool_name } => {
                write!(
                    f,
                    "agent-sandbox manifest declares tool `{tool_name}` twice"
                )
            }
            Self::UnknownCapabilityTag {
                tool_name,
                capability_tag,
            } => write!(
                f,
                "tool `{tool_name}` maps to unknown capability tag `{capability_tag}`; \
                 unknown tags are refused fail-closed (the membrane would silently drop \
                 them and the agent would hold less authority than its framework believes)"
            ),
            Self::NetworkGrantWithoutAcknowledgement { tool_name } => write!(
                f,
                "tool `{tool_name}` grants network egress but the manifest does not set \
                 `acknowledge_unfiltered_network: true`; the engine ships the network \
                 mechanism without an egress policy layer, so the grant must be explicit"
            ),
            Self::DeniedCapabilityAlsoGranted { capability_tag } => write!(
                f,
                "capability tag `{capability_tag}` appears in both the effective \
                 runtime-granted set and denied_capability_tags; refusing the \
                 contradictory manifest fail-closed"
            ),
            Self::InvalidTrustLevel { trust_level } => write!(
                f,
                "trust level `{trust_level}` is not a recognised guardplane trust level"
            ),
        }
    }
}

impl std::error::Error for AgentSandboxError {}

// ---------------------------------------------------------------------------
// Manifest (the tool-runner shim input contract)
// ---------------------------------------------------------------------------

/// One tool the agent framework grants: the framework-side tool name mapped
/// to the engine capability tag its calls require.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentToolGrant {
    /// Framework-side tool name (e.g. the MCP tool name).
    pub tool_name: String,
    /// Engine capability tag (parsed via `RuntimeCapability::from_tag_str`;
    /// unknown tags fail manifest validation).
    pub capability_tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The agent-sandbox manifest an agent framework hands the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSandboxManifest {
    pub schema_version: String,
    /// Stable agent identity; becomes the run's extension id.
    pub agent_id: String,
    /// Tool authority the framework grants this run.
    #[serde(default)]
    pub tool_grants: Vec<AgentToolGrant>,
    /// Capability tags the framework explicitly denies (surfaced to the
    /// guardplane as denied capabilities; a tag both runtime-granted and
    /// denied is a manifest error, including capabilities forced by the
    /// execution context).
    #[serde(default)]
    pub denied_capability_tags: Vec<String>,
    /// Guardplane trust level for the agent (defaults to `provisional`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
    /// Sandbox filesystem root for host I/O. Absent ⇒ host I/O stays
    /// deny-all (fail-closed default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_io_root: Option<String>,
    /// Byte ceiling for sandboxed host I/O.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_io_max_bytes: Option<u64>,
    /// Must be `true` for any network-egress tool grant: acknowledges that
    /// the engine-side sandbox provides the network mechanism without an
    /// egress-policy filter (SSRF/allowlist gating is product-layer scope).
    #[serde(default)]
    pub acknowledge_unfiltered_network: bool,
    /// Data-contract purpose the run binds to (defaults to the data-contract
    /// default purpose at the CLI layer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Extra metadata merged into the extension package (guardplane keys
    /// derived from this manifest always win).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

const KNOWN_TRUST_LEVELS: [&str; 9] = [
    "trusted",
    "signed",
    "established",
    "provisional",
    "unknown",
    "unsigned",
    "suspicious",
    "compromised",
    "revoked",
];

impl AgentSandboxManifest {
    /// Validate the manifest fail-closed.
    pub fn validate(&self) -> Result<(), AgentSandboxError> {
        if self.schema_version != AGENT_SANDBOX_MANIFEST_SCHEMA_VERSION {
            return Err(AgentSandboxError::UnsupportedSchema {
                expected: AGENT_SANDBOX_MANIFEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if self.agent_id.trim().is_empty() {
            return Err(AgentSandboxError::EmptyField { field: "agent_id" });
        }

        let mut seen_tools = BTreeSet::new();
        for grant in &self.tool_grants {
            if grant.tool_name.trim().is_empty() {
                return Err(AgentSandboxError::EmptyField {
                    field: "tool_grants[].tool_name",
                });
            }
            if grant.capability_tag.trim().is_empty() {
                return Err(AgentSandboxError::EmptyField {
                    field: "tool_grants[].capability_tag",
                });
            }
            if !seen_tools.insert(grant.tool_name.clone()) {
                return Err(AgentSandboxError::DuplicateToolName {
                    tool_name: grant.tool_name.clone(),
                });
            }
            let Some(capability) = RuntimeCapability::from_tag_str(&grant.capability_tag) else {
                return Err(AgentSandboxError::UnknownCapabilityTag {
                    tool_name: grant.tool_name.clone(),
                    capability_tag: grant.capability_tag.clone(),
                });
            };
            if capability == RuntimeCapability::NetworkEgress
                && !self.acknowledge_unfiltered_network
            {
                return Err(AgentSandboxError::NetworkGrantWithoutAcknowledgement {
                    tool_name: grant.tool_name.clone(),
                });
            }
        }

        // Every sandbox run receives the VM baseline whether or not those
        // capabilities appear in tool_grants. Treat that execution-context
        // authority as granted during validation so a deny cannot be silently
        // overridden later by the lane router.
        let mut always_granted = self.granted_capabilities()?;
        always_granted.extend(FORCED_VM_CAPABILITIES);
        self.reject_denied_capability_overlap(&always_granted)?;

        if let Some(trust_level) = self.trust_level.as_deref()
            && !KNOWN_TRUST_LEVELS.contains(&trust_level)
        {
            return Err(AgentSandboxError::InvalidTrustLevel {
                trust_level: trust_level.to_string(),
            });
        }
        Ok(())
    }

    /// The typed capability set the tool grants denote (before the forced VM
    /// capabilities). Errors on unknown tags rather than dropping them.
    pub fn granted_capabilities(&self) -> Result<BTreeSet<RuntimeCapability>, AgentSandboxError> {
        let mut granted = BTreeSet::new();
        for grant in &self.tool_grants {
            match RuntimeCapability::from_tag_str(&grant.capability_tag) {
                Some(capability) => {
                    granted.insert(capability);
                }
                None => {
                    return Err(AgentSandboxError::UnknownCapabilityTag {
                        tool_name: grant.tool_name.clone(),
                        capability_tag: grant.capability_tag.clone(),
                    });
                }
            }
        }
        Ok(granted)
    }

    /// Reject a deny-list entry that resolves to any capability the run will
    /// actually receive. Unknown deny tags remain conservative metadata, but
    /// empty entries and recognized contradictions fail closed.
    fn reject_denied_capability_overlap(
        &self,
        granted: &BTreeSet<RuntimeCapability>,
    ) -> Result<(), AgentSandboxError> {
        for tag in &self.denied_capability_tags {
            let normalized_tag = tag.trim();
            if normalized_tag.is_empty() {
                return Err(AgentSandboxError::EmptyField {
                    field: "denied_capability_tags[]",
                });
            }
            if let Some(capability) = RuntimeCapability::from_tag_str(normalized_tag)
                && granted.contains(&capability)
            {
                return Err(AgentSandboxError::DeniedCapabilityAlsoGranted {
                    capability_tag: normalized_tag.to_string(),
                });
            }
        }
        Ok(())
    }

    /// The effective runtime-granted set for this sandbox run: the manifest's
    /// tool-grant capabilities plus the interpreter's forced VM capabilities
    /// (and `ModuleLoad` when the run parses as a module). This is the set
    /// the E8 certificate must report as `runtime_granted_capabilities` so
    /// the certificate matches enforcement reality.
    pub fn effective_runtime_capabilities(
        &self,
        module_goal: bool,
    ) -> Result<BTreeSet<RuntimeCapability>, AgentSandboxError> {
        // Report and certificate construction call this method directly, so
        // it must enforce the complete manifest contract rather than assume a
        // package was validated earlier in the process.
        self.validate()?;
        let mut granted = self.granted_capabilities()?;
        granted.extend(FORCED_VM_CAPABILITIES);
        if module_goal {
            granted.insert(RuntimeCapability::ModuleLoad);
        }
        self.reject_denied_capability_overlap(&granted)?;
        Ok(granted)
    }

    /// The guardplane metadata for the extension package: hooks always on,
    /// trust level defaulted to `provisional`, tool authority surfaced as
    /// required/denied capability CSVs. Manifest-supplied metadata is merged
    /// first; the firewall keys derived here always win.
    pub fn guardplane_metadata(&self) -> Result<BTreeMap<String, String>, AgentSandboxError> {
        let mut metadata = self.metadata.clone();
        metadata.insert(
            "guardplane.enable_instruction_hooks".to_string(),
            "true".to_string(),
        );
        metadata.insert(
            "guardplane.trust_level".to_string(),
            self.trust_level
                .clone()
                .unwrap_or_else(|| DEFAULT_AGENT_TRUST_LEVEL.to_string()),
        );
        let granted = self.granted_capabilities()?;
        if !granted.is_empty() {
            metadata.insert(
                "capability_witness.required_capabilities".to_string(),
                granted
                    .iter()
                    .map(|capability| capability.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if !self.denied_capability_tags.is_empty() {
            let mut denied = self.denied_capability_tags.clone();
            denied.sort();
            denied.dedup();
            metadata.insert(
                "capability_witness.denied_capabilities".to_string(),
                denied.join(","),
            );
        }
        Ok(metadata)
    }

    /// Build the extension package for the agent's generated source. The
    /// package's capability tags are the manifest's tool-grant tags (plus
    /// `module_load` for module goals), so the membrane enforces exactly the
    /// declared tool authority.
    pub fn to_extension_package(
        &self,
        source: String,
        source_file: Option<String>,
        engine_version: &str,
        module_goal: bool,
    ) -> Result<ExtensionPackage, AgentSandboxError> {
        // Validate against context-injected authority before publishing the
        // package. In particular, a module goal may not override an explicit
        // module_load denial.
        self.effective_runtime_capabilities(module_goal)?;
        let mut capabilities: Vec<String> = self
            .granted_capabilities()?
            .iter()
            .map(|capability| capability.to_string())
            .collect();
        if module_goal {
            let module_load = RuntimeCapability::ModuleLoad.to_string();
            if !capabilities.contains(&module_load) {
                capabilities.push(module_load);
            }
        }
        Ok(ExtensionPackage {
            extension_id: self.agent_id.clone(),
            source,
            source_file,
            capabilities,
            version: engine_version.to_string(),
            metadata: self.guardplane_metadata()?,
        })
    }
}

// ---------------------------------------------------------------------------
// Report (the tool-runner shim output contract)
// ---------------------------------------------------------------------------

/// Guardplane summary mined from the run's evidence entries: how often the
/// behavior firewall spoke and the most severe action it selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentGuardplaneSummary {
    /// Evidence entries carrying guardplane metadata.
    pub guardplane_evidence_entries: u64,
    /// Most severe guardplane-selected action observed in evidence metadata
    /// (escalation ladder: allow < challenge < sandbox < suspend < terminate
    /// < quarantine), when any was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub most_severe_guardplane_action: Option<String>,
    /// The run-level containment action the orchestrator settled on.
    pub containment_action: String,
    pub expected_loss_millionths: i64,
    pub risk_state: String,
}

/// The sandbox exit report handed back to the agent framework.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSandboxReport {
    pub schema_version: String,
    pub agent_id: String,
    pub trace_id: String,
    pub decision_id: String,
    /// Public evidence identity recorded by the composition root. Verifiers
    /// still authenticate this report out of band before trusting it.
    pub evidence_verification_identity: EvidenceVerificationIdentity,
    pub trust_level: String,
    /// Tool grants the run was executed under (echoed for audit).
    pub tool_grants: Vec<AgentToolGrant>,
    /// The effective runtime-granted capability set (tool grants + forced VM
    /// capabilities), matching the certificate's runtime_granted set.
    pub effective_capabilities: Vec<RuntimeCapability>,
    pub guardplane: AgentGuardplaneSummary,
    pub execution_value: String,
    pub instructions_executed: u64,
    pub console_entries: u64,
    /// Host effects the run performed or was denied (tool calls through the
    /// membrane).
    pub host_effects: u64,
}

const ESCALATION_LADDER: [&str; 6] = [
    "allow",
    "challenge",
    "sandbox",
    "suspend",
    "terminate",
    "quarantine",
];

fn action_severity(action: &str) -> Option<usize> {
    ESCALATION_LADDER
        .iter()
        .position(|candidate| candidate.eq_ignore_ascii_case(action))
}

fn most_severe_guardplane_action(entries: &[EvidenceEntry]) -> (u64, Option<String>) {
    let mut guardplane_entries = 0u64;
    let mut most_severe: Option<(usize, String)> = None;
    for entry in entries {
        let mut saw_guardplane = false;
        for (key, value) in &entry.metadata {
            if !key.starts_with("guardplane") {
                continue;
            }
            saw_guardplane = true;
            if matches!(
                key.as_str(),
                "guardplane_action" | "guardplane_selected_action"
            ) && let Some(severity) = action_severity(value)
                && most_severe
                    .as_ref()
                    .is_none_or(|(current, _)| severity > *current)
            {
                most_severe = Some((severity, value.clone()));
            }
        }
        if saw_guardplane {
            guardplane_entries = guardplane_entries.saturating_add(1);
        }
    }
    (guardplane_entries, most_severe.map(|(_, action)| action))
}

impl AgentSandboxReport {
    /// Summarize a completed sandbox run for the agent framework.
    pub fn from_run(
        manifest: &AgentSandboxManifest,
        result: &OrchestratorResult,
        module_goal: bool,
    ) -> Result<Self, AgentSandboxError> {
        let (guardplane_evidence_entries, most_severe) =
            most_severe_guardplane_action(&result.evidence_entries);
        Ok(Self {
            schema_version: AGENT_SANDBOX_REPORT_SCHEMA_VERSION.to_string(),
            agent_id: manifest.agent_id.clone(),
            trace_id: result.trace_id.clone(),
            decision_id: result.decision_id.clone(),
            evidence_verification_identity: result.evidence_verification_identity.clone(),
            trust_level: manifest
                .trust_level
                .clone()
                .unwrap_or_else(|| DEFAULT_AGENT_TRUST_LEVEL.to_string()),
            tool_grants: manifest.tool_grants.clone(),
            effective_capabilities: manifest
                .effective_runtime_capabilities(module_goal)?
                .into_iter()
                .collect(),
            guardplane: AgentGuardplaneSummary {
                guardplane_evidence_entries,
                most_severe_guardplane_action: most_severe,
                containment_action: result.containment_action.to_string(),
                expected_loss_millionths: result.expected_loss_millionths,
                risk_state: format!("{:?}", result.risk_state),
            },
            execution_value: result.execution_value.clone(),
            instructions_executed: result.instructions_executed,
            console_entries: result.console_output.len() as u64,
            host_effects: result.host_effect_transcript.len() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> AgentSandboxManifest {
        AgentSandboxManifest {
            schema_version: AGENT_SANDBOX_MANIFEST_SCHEMA_VERSION.to_string(),
            agent_id: "agent-e8t5".to_string(),
            tool_grants: vec![
                AgentToolGrant {
                    tool_name: "read_workspace_file".to_string(),
                    capability_tag: "fs:read".to_string(),
                    description: Some("read files under the sandbox root".to_string()),
                },
                AgentToolGrant {
                    tool_name: "log".to_string(),
                    capability_tag: "console".to_string(),
                    description: None,
                },
            ],
            denied_capability_tags: vec!["process_spawn".to_string()],
            trust_level: None,
            host_io_root: Some("/tmp/agent-root".to_string()),
            host_io_max_bytes: Some(1 << 20),
            acknowledge_unfiltered_network: false,
            purpose: Some("agent_sandbox".to_string()),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn valid_manifest_passes_validation() {
        manifest().validate().expect("manifest validates");
    }

    #[test]
    fn wrong_schema_version_fails_closed() {
        let mut bad = manifest();
        bad.schema_version = "franken-engine.agent-sandbox-manifest.v0".to_string();
        assert!(matches!(
            bad.validate(),
            Err(AgentSandboxError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn empty_agent_id_fails_closed() {
        let mut bad = manifest();
        bad.agent_id = "  ".to_string();
        assert!(matches!(
            bad.validate(),
            Err(AgentSandboxError::EmptyField { field: "agent_id" })
        ));
    }

    #[test]
    fn duplicate_tool_names_fail_closed() {
        let mut bad = manifest();
        let duplicate = bad.tool_grants[0].clone();
        bad.tool_grants.push(duplicate);
        assert!(matches!(
            bad.validate(),
            Err(AgentSandboxError::DuplicateToolName { .. })
        ));
    }

    #[test]
    fn unknown_capability_tag_is_an_error_not_a_silent_drop() {
        let mut bad = manifest();
        bad.tool_grants.push(AgentToolGrant {
            tool_name: "teleport".to_string(),
            capability_tag: "quantum_teleport".to_string(),
            description: None,
        });
        assert!(matches!(
            bad.validate(),
            Err(AgentSandboxError::UnknownCapabilityTag { .. })
        ));
    }

    #[test]
    fn network_grant_requires_explicit_acknowledgement() {
        let mut bad = manifest();
        bad.tool_grants.push(AgentToolGrant {
            tool_name: "http_get".to_string(),
            capability_tag: "network".to_string(),
            description: None,
        });
        assert!(matches!(
            bad.validate(),
            Err(AgentSandboxError::NetworkGrantWithoutAcknowledgement { .. })
        ));

        let mut acknowledged = bad.clone();
        acknowledged.acknowledge_unfiltered_network = true;
        acknowledged
            .validate()
            .expect("acknowledged network grant validates");
    }

    #[test]
    fn granted_and_denied_overlap_fails_closed() {
        let mut bad = manifest();
        bad.denied_capability_tags.push("fs:read".to_string());
        assert!(matches!(
            bad.validate(),
            Err(AgentSandboxError::DeniedCapabilityAlsoGranted { .. })
        ));
    }

    #[test]
    fn denied_forced_vm_capability_fails_closed() {
        for capability in FORCED_VM_CAPABILITIES {
            let mut bad = manifest();
            bad.tool_grants
                .retain(|grant| grant.capability_tag != "console");
            bad.denied_capability_tags = vec![capability.to_string()];
            assert!(
                matches!(
                    bad.validate(),
                    Err(AgentSandboxError::DeniedCapabilityAlsoGranted {
                        capability_tag
                    }) if capability_tag == capability.to_string()
                ),
                "forced capability {capability} must not override an explicit deny"
            );
        }
    }

    #[test]
    fn unknown_trust_level_fails_closed() {
        let mut bad = manifest();
        bad.trust_level = Some("galactic".to_string());
        assert!(matches!(
            bad.validate(),
            Err(AgentSandboxError::InvalidTrustLevel { .. })
        ));
    }

    #[test]
    fn granted_capabilities_parse_tool_tags() {
        let granted = manifest().granted_capabilities().expect("grants parse");
        assert_eq!(
            granted,
            BTreeSet::from([RuntimeCapability::FsRead, RuntimeCapability::Console])
        );
    }

    #[test]
    fn effective_capabilities_include_forced_vm_set() {
        let effective = manifest()
            .effective_runtime_capabilities(false)
            .expect("effective set derives");
        for forced in FORCED_VM_CAPABILITIES {
            assert!(effective.contains(&forced), "missing forced {forced:?}");
        }
        assert!(effective.contains(&RuntimeCapability::FsRead));
        assert!(!effective.contains(&RuntimeCapability::ModuleLoad));
    }

    #[test]
    fn module_goal_adds_module_load() {
        let effective = manifest()
            .effective_runtime_capabilities(true)
            .expect("effective set derives");
        assert!(effective.contains(&RuntimeCapability::ModuleLoad));
    }

    #[test]
    fn module_goal_cannot_override_module_load_denial() {
        let mut denied = manifest();
        denied
            .denied_capability_tags
            .push("  module:import  ".to_string());

        denied
            .effective_runtime_capabilities(false)
            .expect("script goal does not inject module_load");
        assert!(matches!(
            denied.effective_runtime_capabilities(true),
            Err(AgentSandboxError::DeniedCapabilityAlsoGranted {
                capability_tag
            }) if capability_tag == "module:import"
        ));
        assert!(matches!(
            denied.to_extension_package("export {};".to_string(), None, "0.1.0", true),
            Err(AgentSandboxError::DeniedCapabilityAlsoGranted {
                capability_tag
            }) if capability_tag == "module:import"
        ));
    }

    #[test]
    fn guardplane_metadata_arms_the_firewall() {
        let metadata = manifest().guardplane_metadata().expect("metadata derives");
        assert_eq!(
            metadata.get("guardplane.enable_instruction_hooks"),
            Some(&"true".to_string())
        );
        assert_eq!(
            metadata.get("guardplane.trust_level"),
            Some(&DEFAULT_AGENT_TRUST_LEVEL.to_string())
        );
        let required = metadata
            .get("capability_witness.required_capabilities")
            .expect("required capabilities surfaced");
        assert!(required.contains("fs_read"));
        assert!(required.contains("console"));
        assert_eq!(
            metadata.get("capability_witness.denied_capabilities"),
            Some(&"process_spawn".to_string())
        );
    }

    #[test]
    fn manifest_metadata_cannot_disarm_the_firewall() {
        let mut sneaky = manifest();
        sneaky.metadata.insert(
            "guardplane.enable_instruction_hooks".to_string(),
            "false".to_string(),
        );
        let metadata = sneaky.guardplane_metadata().expect("metadata derives");
        assert_eq!(
            metadata.get("guardplane.enable_instruction_hooks"),
            Some(&"true".to_string()),
            "derived firewall keys must win over manifest metadata"
        );
    }

    #[test]
    fn to_extension_package_carries_tags_and_metadata() {
        let package = manifest()
            .to_extension_package(
                "const x = 1;".to_string(),
                Some("gen.js".to_string()),
                "0.1.0",
                false,
            )
            .expect("package builds");
        assert_eq!(package.extension_id, "agent-e8t5");
        assert!(package.capabilities.contains(&"fs_read".to_string()));
        assert!(package.capabilities.contains(&"console".to_string()));
        assert_eq!(
            package.metadata.get("guardplane.enable_instruction_hooks"),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn to_extension_package_module_goal_appends_module_load_once() {
        let package = manifest()
            .to_extension_package("export {};".to_string(), None, "0.1.0", true)
            .expect("package builds");
        let module_load_count = package
            .capabilities
            .iter()
            .filter(|tag| tag.as_str() == "module_load")
            .count();
        assert_eq!(module_load_count, 1);
    }

    #[test]
    fn invalid_manifest_refuses_package_construction() {
        let mut bad = manifest();
        bad.agent_id = String::new();
        assert!(
            bad.to_extension_package("x".to_string(), None, "0.1.0", false)
                .is_err()
        );
    }

    #[test]
    fn manifest_round_trips_through_serde() {
        let original = manifest();
        let json = serde_json::to_string(&original).expect("serializes");
        let parsed: AgentSandboxManifest = serde_json::from_str(&json).expect("parses");
        assert_eq!(parsed, original);
    }

    #[test]
    fn escalation_ladder_severity_is_monotonic() {
        let mut previous = None;
        for action in ESCALATION_LADDER {
            let severity = action_severity(action).expect("ladder action has severity");
            if let Some(previous) = previous {
                assert!(severity > previous);
            }
            previous = Some(severity);
        }
        assert_eq!(action_severity("QUARANTINE"), Some(5));
        assert_eq!(action_severity("not-an-action"), None);
    }

    #[test]
    fn guardplane_summary_picks_most_severe_action() {
        use crate::evidence_ledger::{ChosenAction, DecisionType, EvidenceEntryBuilder};
        use crate::security_epoch::SecurityEpoch;

        let build = |action: &str| {
            EvidenceEntryBuilder::new(
                "trace-gp",
                "decision-gp",
                "policy-gp",
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            )
            .timestamp_ns(1)
            .chosen(ChosenAction {
                action_name: action.to_string(),
                expected_loss_millionths: 0,
                rationale: "test".to_string(),
            })
            .meta("guardplane_selected_action", action)
            .build()
            .expect("evidence entry builds")
        };
        let entries = vec![build("allow"), build("sandbox"), build("challenge")];
        let (count, most_severe) = most_severe_guardplane_action(&entries);
        assert_eq!(count, 3);
        assert_eq!(most_severe.as_deref(), Some("sandbox"));
    }

    #[test]
    fn entries_without_guardplane_metadata_are_not_counted() {
        use crate::evidence_ledger::{ChosenAction, DecisionType, EvidenceEntryBuilder};
        use crate::security_epoch::SecurityEpoch;

        let entry = EvidenceEntryBuilder::new(
            "trace-plain",
            "decision-plain",
            "policy-plain",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .timestamp_ns(1)
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "test".to_string(),
        })
        .build()
        .expect("evidence entry builds");
        let (count, most_severe) = most_severe_guardplane_action(&[entry]);
        assert_eq!(count, 0);
        assert_eq!(most_severe, None);
    }
}
