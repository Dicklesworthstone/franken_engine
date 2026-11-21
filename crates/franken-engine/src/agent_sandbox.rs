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
//! - Host I/O stays deny-all unless the manifest declares a sandbox filesystem
//!   root. Network grants require explicit host intent: an exact destination
//!   allowlist, or the existing acknowledgement flag for public-Internet-only
//!   access. Destination policies check all resolved addresses before dialing.
//! - Guardplane instruction hooks are always enabled for sandbox runs: the
//!   agent is the untrusted principal, so its trust level defaults to
//!   `provisional` and the behavior firewall cannot be opted out of.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use frankenengine_extension_host::host_io::budget::{HostIoBudgetLimits, HostIoWorkBudget};
use frankenengine_extension_host::host_io::{
    HostIoProvider, NetworkDestinationAllowlist, NetworkEgressPolicy, SandboxedHostIo,
};
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
    InvalidNetworkAllowlist {
        detail: String,
    },
    InvalidHostIoConfiguration {
        detail: String,
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
                "tool `{tool_name}` grants network egress but the manifest supplies neither \
                 `network_allowlist` nor `acknowledge_unfiltered_network: true`; \
                 destination authority must be explicit"
            ),
            Self::InvalidNetworkAllowlist { detail } => {
                write!(f, "invalid agent-sandbox network allowlist: {detail}")
            }
            Self::InvalidHostIoConfiguration { detail } => {
                write!(f, "invalid agent-sandbox host I/O configuration: {detail}")
            }
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

/// Non-renewable host work credits for one sandbox execution. All limits must
/// be explicit; a misspelled field cannot silently disable an intended limit.
/// These count admitted requests and their owned strings/payloads, not response
/// bytes, disk usage or syscalls. The provider's per-operation cap still applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHostIoBudget {
    pub requests: u64,
    pub request_bytes: u64,
    pub max_in_flight: u64,
}

impl AgentHostIoBudget {
    fn limits(self) -> Result<HostIoBudgetLimits, AgentSandboxError> {
        Ok(HostIoBudgetLimits {
            requests: self.requests,
            request_bytes: self.request_bytes,
            max_in_flight: usize::try_from(self.max_in_flight).map_err(|_| {
                AgentSandboxError::InvalidHostIoConfiguration {
                    detail: "host_io_budget.max_in_flight exceeds the host address space".into(),
                }
            })?,
        })
    }
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
    /// Cumulative work limits shared by every clone of this run's provider.
    /// Zero requests or concurrency denies all host dispatch; zero byte credits
    /// still permits requests with no owned strings/payloads. Omission preserves
    /// the existing per-operation-only behavior. A budget grants no capability
    /// and never enables host I/O without a sandbox root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_io_budget: Option<AgentHostIoBudget>,
    /// Exact numeric IP:port destinations the host authorizes. When present,
    /// only these destinations are allowed, including explicitly listed local
    /// services; an empty list denies every connection. DNS names must resolve
    /// entirely to listed addresses. The list never grants a capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_allowlist: Option<Vec<SocketAddr>>,
    /// Existing explicit network opt-in when no allowlist is supplied. The
    /// historical field name is retained in the manifest schema, but the CLI
    /// applies PublicInternetOnly, never unrestricted egress. An allowlist
    /// takes precedence even when this flag is true.
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
        self.network_egress_policy()?;
        if let Some(budget) = self.host_io_budget {
            budget.limits()?;
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
                && self.network_allowlist.is_none()
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

    /// Construct the destination policy used by the sandbox provider. This
    /// validates the list independently so an embedder cannot accidentally
    /// turn an invalid configuration into unrestricted network access.
    pub fn network_egress_policy(&self) -> Result<NetworkEgressPolicy, AgentSandboxError> {
        match &self.network_allowlist {
            Some(destinations) => NetworkDestinationAllowlist::new(destinations.iter().copied())
                .map(NetworkEgressPolicy::Allowlist)
                .map_err(|error| AgentSandboxError::InvalidNetworkAllowlist {
                    detail: error.to_string(),
                }),
            None => Ok(NetworkEgressPolicy::PublicInternetOnly),
        }
    }

    /// Construct the live provider once at the trusted run boundary. Every
    /// lane receives a clone of this same Arc, so lane changes cannot replenish
    /// cumulative credits. Replay consumes recorded outcomes instead of calling
    /// this constructor or reopening host paths.
    pub fn build_host_io_provider(
        &self,
    ) -> Result<Option<Arc<dyn HostIoProvider>>, AgentSandboxError> {
        self.validate()?;
        let Some(root) = self.host_io_root.as_ref() else {
            return Ok(None);
        };
        let provider = match self.host_io_max_bytes {
            Some(limit) => SandboxedHostIo::with_root_and_limit(root, limit),
            None => SandboxedHostIo::with_root(root),
        }
        .map_err(|error| AgentSandboxError::InvalidHostIoConfiguration {
            detail: error.to_string(),
        })?
        .with_egress_policy(self.network_egress_policy()?);
        let provider: Arc<dyn HostIoProvider> = match self.host_io_budget {
            Some(budget) => {
                Arc::new(provider.with_work_budget(HostIoWorkBudget::new(budget.limits()?)))
            }
            None => Arc::new(provider),
        };
        Ok(Some(provider))
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
            module_root: None,
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
            host_io_budget: None,
            network_allowlist: None,
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
    fn host_io_budget_round_trips_and_preserves_absent_field_encoding() {
        let original = serde_json::to_string(&manifest()).unwrap();
        assert!(!original.contains("host_io_budget"));
        let mut restored: AgentSandboxManifest = serde_json::from_str(&original).unwrap();
        assert_eq!(serde_json::to_string(&restored).unwrap(), original);
        let capabilities = restored.effective_runtime_capabilities(false).unwrap();
        restored.host_io_budget = Some(AgentHostIoBudget {
            requests: 23,
            request_bytes: 4_096,
            max_in_flight: 2,
        });
        restored.validate().unwrap();
        assert_eq!(
            restored.effective_runtime_capabilities(false).unwrap(),
            capabilities,
            "work credits must never grant a capability"
        );
        let json = serde_json::to_value(&restored).unwrap();
        assert_eq!(
            json["host_io_budget"],
            serde_json::json!({"requests": 23, "request_bytes": 4096, "max_in_flight": 2})
        );
        assert_eq!(
            serde_json::from_value::<AgentSandboxManifest>(json).unwrap(),
            restored
        );
    }

    #[test]
    fn host_io_budget_requires_all_limits_and_rejects_unknown_fields() {
        for budget in [
            serde_json::json!({"requests": 1, "request_bytes": 32}),
            serde_json::json!({"request_bytes": 32, "max_in_flight": 1}),
            serde_json::json!({"requests": 1, "max_in_flight": 1}),
            serde_json::json!({
                "requests": 1, "request_bytes": 32, "max_in_flight": 1, "response_bytes": 32
            }),
            serde_json::json!({"requests": -1, "request_bytes": 32, "max_in_flight": 1}),
        ] {
            let mut json = serde_json::to_value(manifest()).unwrap();
            json["host_io_budget"] = budget;
            assert!(serde_json::from_value::<AgentSandboxManifest>(json).is_err());
        }
    }

    #[test]
    fn zero_host_io_budget_is_valid_but_never_opens_an_absent_root() {
        let mut limited = manifest();
        limited.host_io_root = None;
        limited.host_io_budget = Some(AgentHostIoBudget {
            requests: 0,
            request_bytes: 0,
            max_in_flight: 0,
        });
        limited.validate().unwrap();
        assert!(limited.build_host_io_provider().unwrap().is_none());
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
    fn network_allowlist_is_explicit_authority_and_never_grants_a_capability() {
        let mut limited = manifest();
        let destination: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        limited.network_allowlist = Some(vec![destination]);
        limited.validate().unwrap();
        assert!(
            !limited
                .effective_runtime_capabilities(false)
                .unwrap()
                .contains(&RuntimeCapability::NetworkEgress)
        );
        limited.tool_grants.push(AgentToolGrant {
            tool_name: "local_service".to_string(),
            capability_tag: "network".to_string(),
            description: None,
        });
        limited
            .validate()
            .expect("an exact allowlist is explicit network intent");
        for acknowledgement in [false, true] {
            limited.acknowledge_unfiltered_network = acknowledgement;
            let NetworkEgressPolicy::Allowlist(approved) = limited.network_egress_policy().unwrap()
            else {
                panic!("the legacy flag must never broaden an explicit allowlist")
            };
            assert!(approved.contains(&destination));
            assert!(!approved.contains(&"127.0.0.1:8081".parse().unwrap()));
            assert!(!approved.contains(&"8.8.8.8:443".parse().unwrap()));
        }
        limited.network_allowlist = Some(vec![]);
        let NetworkEgressPolicy::Allowlist(approved) = limited.network_egress_policy().unwrap()
        else {
            panic!("an empty list must remain deny-all")
        };
        assert!(!approved.contains(&destination));
    }

    #[test]
    fn invalid_network_allowlist_fails_manifest_validation_before_execution() {
        for destinations in [
            vec!["127.0.0.1:0"],
            vec!["0.0.0.0:80"],
            vec!["[::]:80"],
            vec!["127.0.0.1:8080", "127.0.0.1:8080"],
        ] {
            let mut invalid = manifest();
            invalid.network_allowlist = Some(
                destinations
                    .iter()
                    .map(|value| value.parse().unwrap())
                    .collect(),
            );
            assert!(matches!(
                invalid.to_extension_package("console.log('never')".into(), None, "test", false),
                Err(AgentSandboxError::InvalidNetworkAllowlist { .. })
            ));
        }
    }

    #[test]
    fn network_allowlist_round_trips_without_changing_historical_manifest_bytes() {
        let original = serde_json::to_value(manifest()).unwrap();
        assert!(original.get("network_allowlist").is_none());
        let restored: AgentSandboxManifest = serde_json::from_value(original).unwrap();
        assert_eq!(restored.network_allowlist, None);
        assert_eq!(
            restored.network_egress_policy().unwrap(),
            NetworkEgressPolicy::PublicInternetOnly
        );

        let mut configured = restored;
        configured.network_allowlist = Some(vec!["[::1]:8080".parse().unwrap()]);
        let json = serde_json::to_value(&configured).unwrap();
        assert_eq!(json["network_allowlist"], serde_json::json!(["[::1]:8080"]));
        let restored: AgentSandboxManifest = serde_json::from_value(json).unwrap();
        assert_eq!(restored, configured);
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
