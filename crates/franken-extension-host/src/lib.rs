#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]

pub fn placeholder_extension_host_symbol() {}

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const CURRENT_ENGINE_VERSION: &str = "0.1.0";
pub const MAX_NAME_LEN: usize = 128;
pub const MAX_VERSION_LEN: usize = 64;
pub const MAX_ENTRYPOINT_LEN: usize = 1024;
pub const MAX_TRUST_CHAIN_REF_LEN: usize = 256;

const COMPONENT: &str = "extension_manifest_validation";
const EMPTY_CAPABILITIES: &[Capability] = &[];
const WRITE_IMPLIES: &[Capability] = &[Capability::FsRead];

/// Extension capability identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FsRead,
    FsWrite,
    NetClient,
    HostCall,
    ProcessSpawn,
    Declassify,
}

impl Capability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
            Self::NetClient => "net_client",
            Self::HostCall => "host_call",
            Self::ProcessSpawn => "process_spawn",
            Self::Declassify => "declassify",
        }
    }

    pub const fn implied_capabilities(self) -> &'static [Capability] {
        match self {
            Self::FsWrite => WRITE_IMPLIES,
            Self::FsRead
            | Self::NetClient
            | Self::HostCall
            | Self::ProcessSpawn
            | Self::Declassify => EMPTY_CAPABILITIES,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Extension manifest trust posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestTrustLevel {
    Development,
    SignedSupplyChain,
}

/// Extension manifest from the engine's perspective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionManifest {
    pub name: String,
    pub version: String,
    pub entrypoint: String,
    #[serde(deserialize_with = "deserialize_capability_set")]
    pub capabilities: BTreeSet<Capability>,
    #[serde(default)]
    pub publisher_signature: Option<Vec<u8>>,
    #[serde(default)]
    pub content_hash: [u8; 32],
    #[serde(default)]
    pub trust_chain_ref: Option<String>,
    #[serde(default = "default_min_engine_version")]
    pub min_engine_version: String,
}

impl ExtensionManifest {
    pub fn inferred_trust_level(&self) -> ManifestTrustLevel {
        let has_trust_chain = self
            .trust_chain_ref
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        if has_trust_chain || self.publisher_signature.is_some() {
            ManifestTrustLevel::SignedSupplyChain
        } else {
            ManifestTrustLevel::Development
        }
    }
}

/// Compile-time static manifest representation used for const validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticExtensionManifest {
    pub name: &'static str,
    pub entrypoint: &'static str,
    pub min_engine_version: &'static str,
    pub capabilities: &'static [Capability],
}

/// Const-compatible error model for static manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticManifestValidationError {
    EmptyName,
    EmptyEntrypoint,
    UnsupportedEngineVersion,
    FieldTooLong,
    MissingImpliedCapability {
        declared: Capability,
        missing_implied: Capability,
    },
}

/// Runtime manifest validation error with deterministic codes/messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ManifestValidationError {
    EmptyName,
    EmptyVersion,
    EmptyEntrypoint,
    UnsupportedEngineVersion {
        min_engine_version: String,
        supported_engine_version: &'static str,
    },
    InvalidCapabilityLattice {
        declared: Capability,
        missing_implied: Capability,
    },
    MissingPublisherSignature,
    MissingTrustChainRef,
    InvalidContentHash,
    FieldTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    CanonicalSerialization(String),
}

impl ManifestValidationError {
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::EmptyName => "FE-MANIFEST-0001",
            Self::EmptyVersion => "FE-MANIFEST-0002",
            Self::EmptyEntrypoint => "FE-MANIFEST-0003",
            Self::UnsupportedEngineVersion { .. } => "FE-MANIFEST-0004",
            Self::InvalidCapabilityLattice { .. } => "FE-MANIFEST-0005",
            Self::MissingPublisherSignature => "FE-MANIFEST-0006",
            Self::MissingTrustChainRef => "FE-MANIFEST-0007",
            Self::InvalidContentHash => "FE-MANIFEST-0008",
            Self::CanonicalSerialization(_) => "FE-MANIFEST-0009",
            Self::FieldTooLong { .. } => "FE-MANIFEST-0010",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::EmptyName => "name must not be empty".to_string(),
            Self::EmptyVersion => "version must not be empty".to_string(),
            Self::EmptyEntrypoint => "entrypoint must not be empty".to_string(),
            Self::UnsupportedEngineVersion {
                min_engine_version,
                supported_engine_version,
            } => format!(
                "min_engine_version `{min_engine_version}` is unsupported (max supported `{supported_engine_version}`)"
            ),
            Self::InvalidCapabilityLattice {
                declared,
                missing_implied,
            } => format!("capability `{declared}` requires implied capability `{missing_implied}`"),
            Self::MissingPublisherSignature => {
                "publisher_signature is required for signed supply-chain manifests".to_string()
            }
            Self::MissingTrustChainRef => {
                "trust_chain_ref is required for signed supply-chain manifests".to_string()
            }
            Self::InvalidContentHash => {
                "content_hash does not match canonical manifest bytes".to_string()
            }
            Self::CanonicalSerialization(message) => {
                format!("canonical manifest serialization failed: {message}")
            }
            Self::FieldTooLong { field, max, actual } => {
                format!("field `{field}` exceeds max length {max} (actual {actual})")
            }
        }
    }

    pub fn structured_message(&self, trace_id: &str, extension_id: &str) -> String {
        format!(
            "trace_id={trace_id} extension_id={extension_id} component={COMPONENT} error_code={} message={}",
            self.error_code(),
            self.message()
        )
    }
}

impl fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "manifest validation error [{}]: {}",
            self.error_code(),
            self.message()
        )
    }
}

impl std::error::Error for ManifestValidationError {}

/// Structured context for deterministic validation events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestValidationContext<'a> {
    pub trace_id: &'a str,
    pub decision_id: &'a str,
    pub policy_id: &'a str,
    pub extension_id: &'a str,
}

impl<'a> ManifestValidationContext<'a> {
    pub const fn new(
        trace_id: &'a str,
        decision_id: &'a str,
        policy_id: &'a str,
        extension_id: &'a str,
    ) -> Self {
        Self {
            trace_id,
            decision_id,
            policy_id,
            extension_id,
        }
    }
}

/// Structured deterministic event for manifest validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestValidationEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Validation report with structured event + optional runtime error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestValidationReport {
    pub event: ManifestValidationEvent,
    pub error: Option<ManifestValidationError>,
}

impl ManifestValidationReport {
    pub fn into_result(self) -> Result<(), ManifestValidationError> {
        if let Some(error) = self.error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

fn default_min_engine_version() -> String {
    CURRENT_ENGINE_VERSION.to_string()
}

fn deserialize_capability_set<'de, D>(deserializer: D) -> Result<BTreeSet<Capability>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let capabilities = Vec::<Capability>::deserialize(deserializer)?;
    let mut deduped = BTreeSet::new();
    for capability in capabilities {
        if !deduped.insert(capability) {
            return Err(serde::de::Error::custom(format!(
                "duplicate capability `{capability}`"
            )));
        }
    }
    Ok(deduped)
}

/// Validate a static manifest at compile time.
pub const fn validate_static_manifest(
    manifest: &StaticExtensionManifest,
) -> Result<(), StaticManifestValidationError> {
    if manifest.name.is_empty() {
        return Err(StaticManifestValidationError::EmptyName);
    }
    if manifest.name.len() > MAX_NAME_LEN
        || manifest.entrypoint.len() > MAX_ENTRYPOINT_LEN
        || manifest.min_engine_version.len() > MAX_VERSION_LEN
    {
        return Err(StaticManifestValidationError::FieldTooLong);
    }
    if manifest.entrypoint.is_empty() {
        return Err(StaticManifestValidationError::EmptyEntrypoint);
    }
    if !is_supported_engine_version_const(manifest.min_engine_version) {
        return Err(StaticManifestValidationError::UnsupportedEngineVersion);
    }

    let mut i = 0usize;
    while i < manifest.capabilities.len() {
        let declared = manifest.capabilities[i];
        let implied = declared.implied_capabilities();

        let mut j = 0usize;
        while j < implied.len() {
            if !has_capability_const(manifest.capabilities, implied[j]) {
                return Err(StaticManifestValidationError::MissingImpliedCapability {
                    declared,
                    missing_implied: implied[j],
                });
            }
            j += 1;
        }
        i += 1;
    }

    Ok(())
}

const fn has_capability_const(set: &[Capability], capability: Capability) -> bool {
    let mut idx = 0usize;
    while idx < set.len() {
        if set[idx] as u8 == capability as u8 {
            return true;
        }
        idx += 1;
    }
    false
}

const fn is_supported_engine_version_const(version: &str) -> bool {
    let bytes = version.as_bytes();
    bytes.len() >= 2 && bytes[0] == b'0' && bytes[1] == b'.'
}

/// Validate capability lattice implications.
pub fn validate_capability_lattice(
    capabilities: &BTreeSet<Capability>,
) -> Result<(), ManifestValidationError> {
    for declared in capabilities {
        for implied in declared.implied_capabilities() {
            if !capabilities.contains(implied) {
                return Err(ManifestValidationError::InvalidCapabilityLattice {
                    declared: *declared,
                    missing_implied: *implied,
                });
            }
        }
    }
    Ok(())
}

fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Validate minimum engine-version constraints.
pub fn validate_engine_version(min_engine_version: &str) -> Result<(), ManifestValidationError> {
    let requested = parse_semver(min_engine_version.trim());
    let supported = parse_semver(CURRENT_ENGINE_VERSION).expect("static engine version is valid");
    let Some((requested_major, requested_minor, requested_patch)) = requested else {
        return Err(ManifestValidationError::UnsupportedEngineVersion {
            min_engine_version: min_engine_version.to_string(),
            supported_engine_version: CURRENT_ENGINE_VERSION,
        });
    };
    let (supported_major, supported_minor, supported_patch) = supported;
    if requested_major > supported_major
        || (requested_major == supported_major && requested_minor > supported_minor)
        || (requested_major == supported_major
            && requested_minor == supported_minor
            && requested_patch > supported_patch)
    {
        return Err(ManifestValidationError::UnsupportedEngineVersion {
            min_engine_version: min_engine_version.to_string(),
            supported_engine_version: CURRENT_ENGINE_VERSION,
        });
    }
    Ok(())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

/// Canonical deterministic manifest serialization (sorted keys, compact output).
pub fn canonical_manifest_json(
    manifest: &ExtensionManifest,
) -> Result<String, ManifestValidationError> {
    let mut map = BTreeMap::<String, Value>::new();
    map.insert(
        "capabilities".to_string(),
        Value::Array(
            manifest
                .capabilities
                .iter()
                .map(|capability| Value::String(capability.as_str().to_string()))
                .collect(),
        ),
    );
    map.insert(
        "content_hash".to_string(),
        Value::String(bytes_to_hex(&manifest.content_hash)),
    );
    map.insert(
        "entrypoint".to_string(),
        Value::String(manifest.entrypoint.clone()),
    );
    map.insert(
        "min_engine_version".to_string(),
        Value::String(manifest.min_engine_version.clone()),
    );
    map.insert("name".to_string(), Value::String(manifest.name.clone()));
    map.insert(
        "publisher_signature".to_string(),
        match &manifest.publisher_signature {
            Some(signature) => Value::String(bytes_to_hex(signature)),
            None => Value::Null,
        },
    );
    map.insert(
        "trust_chain_ref".to_string(),
        match &manifest.trust_chain_ref {
            Some(reference) => Value::String(reference.clone()),
            None => Value::Null,
        },
    );
    map.insert(
        "version".to_string(),
        Value::String(manifest.version.clone()),
    );

    serde_json::to_string(&map).map_err(|error| {
        ManifestValidationError::CanonicalSerialization(format!("json encoding failed: {error}"))
    })
}

/// Canonical deterministic bytes for signature/hash workflows.
pub fn canonical_manifest_bytes(
    manifest: &ExtensionManifest,
) -> Result<Vec<u8>, ManifestValidationError> {
    Ok(canonical_manifest_json(manifest)?.into_bytes())
}

/// Compute canonical content hash (SHA-256) over canonical bytes with content_hash zeroed.
pub fn compute_content_hash(
    manifest: &ExtensionManifest,
) -> Result<[u8; 32], ManifestValidationError> {
    let mut to_hash = manifest.clone();
    to_hash.content_hash = [0; 32];
    let bytes = canonical_manifest_bytes(&to_hash)?;
    let digest = Sha256::digest(bytes);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

/// Helper to fill `content_hash` deterministically from canonical bytes.
pub fn with_computed_content_hash(
    mut manifest: ExtensionManifest,
) -> Result<ExtensionManifest, ManifestValidationError> {
    manifest.content_hash = compute_content_hash(&manifest)?;
    Ok(manifest)
}

/// Validate provenance requirements based on trust level.
pub fn validate_provenance(
    manifest: &ExtensionManifest,
    trust_level: ManifestTrustLevel,
) -> Result<(), ManifestValidationError> {
    let has_signature = manifest
        .publisher_signature
        .as_deref()
        .is_some_and(|bytes| !bytes.is_empty());
    let has_trust_chain = manifest
        .trust_chain_ref
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let expected_hash = compute_content_hash(manifest)?;
    let hash_matches = manifest.content_hash == expected_hash;

    match trust_level {
        ManifestTrustLevel::Development => {
            if (has_signature || has_trust_chain) && !hash_matches {
                return Err(ManifestValidationError::InvalidContentHash);
            }
        }
        ManifestTrustLevel::SignedSupplyChain => {
            if !has_signature {
                return Err(ManifestValidationError::MissingPublisherSignature);
            }
            if !has_trust_chain {
                return Err(ManifestValidationError::MissingTrustChainRef);
            }
            if !hash_matches {
                return Err(ManifestValidationError::InvalidContentHash);
            }
        }
    }

    Ok(())
}

/// Validate an extension manifest.
pub fn validate_manifest(manifest: &ExtensionManifest) -> Result<(), ManifestValidationError> {
    if manifest.name.trim().is_empty() {
        return Err(ManifestValidationError::EmptyName);
    }
    if manifest.version.trim().is_empty() {
        return Err(ManifestValidationError::EmptyVersion);
    }
    if manifest.entrypoint.trim().is_empty() {
        return Err(ManifestValidationError::EmptyEntrypoint);
    }
    if manifest.name.len() > MAX_NAME_LEN {
        return Err(ManifestValidationError::FieldTooLong {
            field: "name",
            max: MAX_NAME_LEN,
            actual: manifest.name.len(),
        });
    }
    if manifest.version.len() > MAX_VERSION_LEN {
        return Err(ManifestValidationError::FieldTooLong {
            field: "version",
            max: MAX_VERSION_LEN,
            actual: manifest.version.len(),
        });
    }
    if manifest.min_engine_version.len() > MAX_VERSION_LEN {
        return Err(ManifestValidationError::FieldTooLong {
            field: "min_engine_version",
            max: MAX_VERSION_LEN,
            actual: manifest.min_engine_version.len(),
        });
    }
    if manifest.entrypoint.len() > MAX_ENTRYPOINT_LEN {
        return Err(ManifestValidationError::FieldTooLong {
            field: "entrypoint",
            max: MAX_ENTRYPOINT_LEN,
            actual: manifest.entrypoint.len(),
        });
    }
    if manifest
        .trust_chain_ref
        .as_deref()
        .is_some_and(|value| value.len() > MAX_TRUST_CHAIN_REF_LEN)
    {
        return Err(ManifestValidationError::FieldTooLong {
            field: "trust_chain_ref",
            max: MAX_TRUST_CHAIN_REF_LEN,
            actual: manifest.trust_chain_ref.as_deref().map_or(0, str::len),
        });
    }

    validate_engine_version(&manifest.min_engine_version)?;
    validate_capability_lattice(&manifest.capabilities)?;
    validate_provenance(manifest, manifest.inferred_trust_level())?;
    Ok(())
}

/// Validate and emit a structured deterministic event envelope.
pub fn validate_manifest_with_context(
    manifest: &ExtensionManifest,
    context: &ManifestValidationContext<'_>,
) -> ManifestValidationReport {
    match validate_manifest(manifest) {
        Ok(()) => ManifestValidationReport {
            event: ManifestValidationEvent {
                trace_id: context.trace_id.to_string(),
                decision_id: context.decision_id.to_string(),
                policy_id: context.policy_id.to_string(),
                component: COMPONENT.to_string(),
                event: "manifest_validation".to_string(),
                outcome: "pass".to_string(),
                error_code: None,
            },
            error: None,
        },
        Err(error) => ManifestValidationReport {
            event: ManifestValidationEvent {
                trace_id: context.trace_id.to_string(),
                decision_id: context.decision_id.to_string(),
                policy_id: context.policy_id.to_string(),
                component: COMPONENT.to_string(),
                event: "manifest_validation".to_string(),
                outcome: "fail".to_string(),
                error_code: Some(error.error_code().to_string()),
            },
            error: Some(error),
        },
    }
}

pub const DEFAULT_TERMINATION_GRACE_PERIOD_NS: u64 = 5_000_000_000;
pub const MAX_TERMINATION_GRACE_PERIOD_NS: u64 = 30_000_000_000;
const LIFECYCLE_COMPONENT: &str = "extension_lifecycle_manager";

/// Full extension lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionState {
    Unloaded,
    Validating,
    Loading,
    Starting,
    Running,
    Suspending,
    Suspended,
    Resuming,
    Terminating,
    Terminated,
    Quarantined,
}

impl ExtensionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unloaded => "unloaded",
            Self::Validating => "validating",
            Self::Loading => "loading",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Suspending => "suspending",
            Self::Suspended => "suspended",
            Self::Resuming => "resuming",
            Self::Terminating => "terminating",
            Self::Terminated => "terminated",
            Self::Quarantined => "quarantined",
        }
    }
}

impl fmt::Display for ExtensionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Lifecycle transitions; only valid pairs are accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleTransition {
    Validate,
    Load,
    Start,
    Activate,
    Suspend,
    Freeze,
    Resume,
    Reactivate,
    Terminate,
    Finalize,
    Quarantine,
}

impl LifecycleTransition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validate => "validate",
            Self::Load => "load",
            Self::Start => "start",
            Self::Activate => "activate",
            Self::Suspend => "suspend",
            Self::Freeze => "freeze",
            Self::Resume => "resume",
            Self::Reactivate => "reactivate",
            Self::Terminate => "terminate",
            Self::Finalize => "finalize",
            Self::Quarantine => "quarantine",
        }
    }
}

impl fmt::Display for LifecycleTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Resource-budget action once one dimension reaches zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetExhaustionPolicy {
    Suspend,
    Terminate,
}

impl BudgetExhaustionPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            Self::Terminate => "terminate",
        }
    }
}

impl fmt::Display for BudgetExhaustionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Opaque per-extension budget handle tracked by the lifecycle manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudget {
    pub cpu_time_ns_remaining: u64,
    pub memory_bytes_remaining: u64,
    pub hostcall_count_remaining: u64,
}

impl ResourceBudget {
    pub const fn new(
        cpu_time_ns_remaining: u64,
        memory_bytes_remaining: u64,
        hostcall_count_remaining: u64,
    ) -> Self {
        Self {
            cpu_time_ns_remaining,
            memory_bytes_remaining,
            hostcall_count_remaining,
        }
    }

    fn exhausted_dimension(&self) -> Option<(&'static str, u64)> {
        if self.cpu_time_ns_remaining == 0 {
            Some(("cpu_time_ns_remaining", 0))
        } else if self.memory_bytes_remaining == 0 {
            Some(("memory_bytes_remaining", 0))
        } else if self.hostcall_count_remaining == 0 {
            Some(("hostcall_count_remaining", 0))
        } else {
            None
        }
    }

    fn consume_cpu(&mut self, amount: u64) {
        self.cpu_time_ns_remaining = self.cpu_time_ns_remaining.saturating_sub(amount);
    }

    fn consume_memory(&mut self, amount: u64) {
        self.memory_bytes_remaining = self.memory_bytes_remaining.saturating_sub(amount);
    }

    fn consume_hostcall(&mut self) {
        self.hostcall_count_remaining = self.hostcall_count_remaining.saturating_sub(1);
    }
}

/// Cooperative termination protocol config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationConfig {
    pub grace_period_ns: u64,
}

impl Default for CancellationConfig {
    fn default() -> Self {
        Self {
            grace_period_ns: DEFAULT_TERMINATION_GRACE_PERIOD_NS,
        }
    }
}

impl CancellationConfig {
    pub fn clamped(self) -> Self {
        let grace_period_ns = self
            .grace_period_ns
            .clamp(1, MAX_TERMINATION_GRACE_PERIOD_NS);
        Self { grace_period_ns }
    }
}

/// Structured context keys required by plan-level logging contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleContext<'a> {
    pub trace_id: &'a str,
    pub decision_id: &'a str,
    pub policy_id: &'a str,
}

impl<'a> LifecycleContext<'a> {
    pub const fn new(trace_id: &'a str, decision_id: &'a str, policy_id: &'a str) -> Self {
        Self {
            trace_id,
            decision_id,
            policy_id,
        }
    }
}

/// Monotonic transition log used for deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleTransitionRecord {
    pub monotonic_timestamp_ns: u64,
    pub extension_id: String,
    pub from_state: ExtensionState,
    pub to_state: ExtensionState,
    pub transition: LifecycleTransition,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

/// Structured lifecycle event (stable keys for telemetry/evidence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub extension_id: String,
    pub from_state: String,
    pub to_state: String,
    pub transition: String,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingTermination {
    cancel_token: String,
    started_at_ns: u64,
    deadline_ns: u64,
}

/// Deterministic lifecycle errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleError {
    InvalidTransition {
        extension_id: String,
        current_state: ExtensionState,
        attempted_transition: LifecycleTransition,
    },
    MissingValidatedManifest {
        extension_id: String,
        attempted_transition: LifecycleTransition,
    },
    BudgetExhausted {
        extension_id: String,
        dimension: &'static str,
        remaining: u64,
        attempted_transition: LifecycleTransition,
        action: LifecycleTransition,
    },
    NonMonotonicTimestamp {
        previous: u64,
        current: u64,
    },
    MissingCancelToken {
        extension_id: String,
    },
    TerminationPending {
        extension_id: String,
        now_ns: u64,
        deadline_ns: u64,
    },
}

impl LifecycleError {
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidTransition { .. } => "FE-LIFECYCLE-0001",
            Self::MissingValidatedManifest { .. } => "FE-LIFECYCLE-0002",
            Self::BudgetExhausted { .. } => "FE-LIFECYCLE-0003",
            Self::NonMonotonicTimestamp { .. } => "FE-LIFECYCLE-0004",
            Self::MissingCancelToken { .. } => "FE-LIFECYCLE-0005",
            Self::TerminationPending { .. } => "FE-LIFECYCLE-0006",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::InvalidTransition {
                extension_id,
                current_state,
                attempted_transition,
            } => format!(
                "extension_id={extension_id} current_state={current_state} attempted_transition={attempted_transition}"
            ),
            Self::MissingValidatedManifest {
                extension_id,
                attempted_transition,
            } => format!(
                "extension_id={extension_id} attempted_transition={attempted_transition} requires validated manifest"
            ),
            Self::BudgetExhausted {
                extension_id,
                dimension,
                remaining,
                attempted_transition,
                action,
            } => format!(
                "extension_id={extension_id} dimension={dimension} remaining={remaining} attempted_transition={attempted_transition} action={action}"
            ),
            Self::NonMonotonicTimestamp { previous, current } => {
                format!("non-monotonic timestamp: previous={previous} current={current}")
            }
            Self::MissingCancelToken { extension_id } => {
                format!("extension_id={extension_id} missing cancel token for termination protocol")
            }
            Self::TerminationPending {
                extension_id,
                now_ns,
                deadline_ns,
            } => format!(
                "extension_id={extension_id} termination pending: now_ns={now_ns} deadline_ns={deadline_ns}"
            ),
        }
    }
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "lifecycle error [{}]: {}",
            self.error_code(),
            self.message()
        )
    }
}

impl std::error::Error for LifecycleError {}

/// Compile-active lifecycle manager for a single extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionLifecycleManager {
    extension_id: String,
    state: ExtensionState,
    validated_manifest: Option<ExtensionManifest>,
    resource_budget: ResourceBudget,
    budget_policy: BudgetExhaustionPolicy,
    cancellation: CancellationConfig,
    transition_log: Vec<LifecycleTransitionRecord>,
    telemetry_events: Vec<LifecycleEvent>,
    pending_termination: Option<PendingTermination>,
    last_timestamp_ns: Option<u64>,
}

impl ExtensionLifecycleManager {
    pub fn new(
        extension_id: impl Into<String>,
        resource_budget: ResourceBudget,
        budget_policy: BudgetExhaustionPolicy,
        cancellation: CancellationConfig,
    ) -> Self {
        Self {
            extension_id: extension_id.into(),
            state: ExtensionState::Unloaded,
            validated_manifest: None,
            resource_budget,
            budget_policy,
            cancellation: cancellation.clamped(),
            transition_log: Vec::new(),
            telemetry_events: Vec::new(),
            pending_termination: None,
            last_timestamp_ns: None,
        }
    }

    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }

    pub fn state(&self) -> ExtensionState {
        self.state
    }

    pub fn validated_manifest(&self) -> Option<&ExtensionManifest> {
        self.validated_manifest.as_ref()
    }

    pub fn resource_budget(&self) -> &ResourceBudget {
        &self.resource_budget
    }

    pub fn transition_log(&self) -> &[LifecycleTransitionRecord] {
        &self.transition_log
    }

    pub fn telemetry_events(&self) -> &[LifecycleEvent] {
        &self.telemetry_events
    }

    pub fn pending_cancel_token(&self) -> Option<&str> {
        self.pending_termination
            .as_ref()
            .map(|pending| pending.cancel_token.as_str())
    }

    pub fn set_validated_manifest(
        &mut self,
        manifest: ExtensionManifest,
    ) -> Result<(), ManifestValidationError> {
        validate_manifest(&manifest)?;
        self.validated_manifest = Some(manifest);
        Ok(())
    }

    pub fn apply_transition(
        &mut self,
        transition: LifecycleTransition,
        timestamp_ns: u64,
        context: &LifecycleContext<'_>,
    ) -> Result<LifecycleEvent, LifecycleError> {
        self.ensure_monotonic(timestamp_ns)?;

        if let Some(error) = self.enforce_budget_guard(transition, timestamp_ns, context) {
            return Err(error);
        }

        let Some(target_state) = lifecycle_target_state(self.state, transition) else {
            let error = LifecycleError::InvalidTransition {
                extension_id: self.extension_id.clone(),
                current_state: self.state,
                attempted_transition: transition,
            };
            self.record_failure(self.state, transition, timestamp_ns, context, &error);
            return Err(error);
        };

        if transition_requires_manifest(transition) && self.validated_manifest.is_none() {
            let error = LifecycleError::MissingValidatedManifest {
                extension_id: self.extension_id.clone(),
                attempted_transition: transition,
            };
            self.record_failure(self.state, transition, timestamp_ns, context, &error);
            return Err(error);
        }

        if transition == LifecycleTransition::Terminate {
            self.pending_termination = Some(PendingTermination {
                cancel_token: format!("cancel:{}:{timestamp_ns}", self.extension_id),
                started_at_ns: timestamp_ns,
                deadline_ns: timestamp_ns.saturating_add(self.cancellation.grace_period_ns),
            });
        }

        let from_state = self.state;
        self.state = target_state;
        if matches!(
            transition,
            LifecycleTransition::Finalize | LifecycleTransition::Quarantine
        ) {
            self.pending_termination = None;
        }

        Ok(self.record_success(
            from_state,
            target_state,
            transition,
            timestamp_ns,
            context,
            "pass",
        ))
    }

    /// Complete cooperative termination protocol (9G.2).
    pub fn complete_termination(
        &mut self,
        timestamp_ns: u64,
        context: &LifecycleContext<'_>,
        cooperative_ack: bool,
        quarantine_on_timeout: bool,
    ) -> Result<LifecycleEvent, LifecycleError> {
        self.ensure_monotonic(timestamp_ns)?;
        if self.state != ExtensionState::Terminating {
            let error = LifecycleError::InvalidTransition {
                extension_id: self.extension_id.clone(),
                current_state: self.state,
                attempted_transition: LifecycleTransition::Finalize,
            };
            self.record_failure(
                self.state,
                LifecycleTransition::Finalize,
                timestamp_ns,
                context,
                &error,
            );
            return Err(error);
        }

        let Some(pending) = self.pending_termination.clone() else {
            let error = LifecycleError::MissingCancelToken {
                extension_id: self.extension_id.clone(),
            };
            self.record_failure(
                self.state,
                LifecycleTransition::Finalize,
                timestamp_ns,
                context,
                &error,
            );
            return Err(error);
        };

        if cooperative_ack {
            return self.apply_transition(LifecycleTransition::Finalize, timestamp_ns, context);
        }

        if timestamp_ns < pending.deadline_ns {
            let error = LifecycleError::TerminationPending {
                extension_id: self.extension_id.clone(),
                now_ns: timestamp_ns,
                deadline_ns: pending.deadline_ns,
            };
            self.record_failure(
                self.state,
                LifecycleTransition::Finalize,
                timestamp_ns,
                context,
                &error,
            );
            return Err(error);
        }

        let transition = if quarantine_on_timeout {
            LifecycleTransition::Quarantine
        } else {
            LifecycleTransition::Finalize
        };
        let Some(target_state) = lifecycle_target_state(self.state, transition) else {
            let error = LifecycleError::InvalidTransition {
                extension_id: self.extension_id.clone(),
                current_state: self.state,
                attempted_transition: transition,
            };
            self.record_failure(self.state, transition, timestamp_ns, context, &error);
            return Err(error);
        };
        let from_state = self.state;
        self.state = target_state;
        self.pending_termination = None;
        Ok(self.record_success(
            from_state,
            target_state,
            transition,
            timestamp_ns,
            context,
            "forced",
        ))
    }

    pub fn consume_cpu_time(
        &mut self,
        amount_ns: u64,
        timestamp_ns: u64,
        context: &LifecycleContext<'_>,
    ) -> Result<(), LifecycleError> {
        self.ensure_monotonic(timestamp_ns)?;
        self.resource_budget.consume_cpu(amount_ns);
        if let Some(error) =
            self.enforce_budget_guard(LifecycleTransition::Suspend, timestamp_ns, context)
        {
            return Err(error);
        }
        Ok(())
    }

    pub fn consume_memory_bytes(
        &mut self,
        amount_bytes: u64,
        timestamp_ns: u64,
        context: &LifecycleContext<'_>,
    ) -> Result<(), LifecycleError> {
        self.ensure_monotonic(timestamp_ns)?;
        self.resource_budget.consume_memory(amount_bytes);
        if let Some(error) =
            self.enforce_budget_guard(LifecycleTransition::Suspend, timestamp_ns, context)
        {
            return Err(error);
        }
        Ok(())
    }

    pub fn consume_hostcall(
        &mut self,
        timestamp_ns: u64,
        context: &LifecycleContext<'_>,
    ) -> Result<(), LifecycleError> {
        self.ensure_monotonic(timestamp_ns)?;
        self.resource_budget.consume_hostcall();
        if let Some(error) =
            self.enforce_budget_guard(LifecycleTransition::Suspend, timestamp_ns, context)
        {
            return Err(error);
        }
        Ok(())
    }

    fn ensure_monotonic(&self, timestamp_ns: u64) -> Result<(), LifecycleError> {
        if let Some(previous) = self.last_timestamp_ns {
            if timestamp_ns < previous {
                return Err(LifecycleError::NonMonotonicTimestamp {
                    previous,
                    current: timestamp_ns,
                });
            }
        }
        Ok(())
    }

    fn enforce_budget_guard(
        &mut self,
        attempted_transition: LifecycleTransition,
        timestamp_ns: u64,
        context: &LifecycleContext<'_>,
    ) -> Option<LifecycleError> {
        let (dimension, remaining) = self.resource_budget.exhausted_dimension()?;
        let action = match self.budget_policy {
            BudgetExhaustionPolicy::Suspend
                if matches!(
                    self.state,
                    ExtensionState::Running | ExtensionState::Starting | ExtensionState::Resuming
                ) =>
            {
                LifecycleTransition::Suspend
            }
            _ => LifecycleTransition::Terminate,
        };
        let error = LifecycleError::BudgetExhausted {
            extension_id: self.extension_id.clone(),
            dimension,
            remaining,
            attempted_transition,
            action,
        };

        if let Some(target_state) = lifecycle_target_state(self.state, action) {
            if action == LifecycleTransition::Terminate && self.pending_termination.is_none() {
                self.pending_termination = Some(PendingTermination {
                    cancel_token: format!("cancel:{}:{timestamp_ns}", self.extension_id),
                    started_at_ns: timestamp_ns,
                    deadline_ns: timestamp_ns.saturating_add(self.cancellation.grace_period_ns),
                });
            }
            let from_state = self.state;
            self.state = target_state;
            self.record_event(
                from_state,
                target_state,
                action,
                timestamp_ns,
                context,
                ("fail", Some(error.error_code())),
            );
        }

        Some(error)
    }

    fn record_failure(
        &mut self,
        from_state: ExtensionState,
        transition: LifecycleTransition,
        timestamp_ns: u64,
        context: &LifecycleContext<'_>,
        error: &LifecycleError,
    ) {
        self.record_event(
            from_state,
            from_state,
            transition,
            timestamp_ns,
            context,
            ("fail", Some(error.error_code())),
        );
    }

    fn record_success(
        &mut self,
        from_state: ExtensionState,
        to_state: ExtensionState,
        transition: LifecycleTransition,
        timestamp_ns: u64,
        context: &LifecycleContext<'_>,
        outcome: &str,
    ) -> LifecycleEvent {
        self.record_event(
            from_state,
            to_state,
            transition,
            timestamp_ns,
            context,
            (outcome, None),
        )
    }

    fn record_event(
        &mut self,
        from_state: ExtensionState,
        to_state: ExtensionState,
        transition: LifecycleTransition,
        timestamp_ns: u64,
        context: &LifecycleContext<'_>,
        status: (&str, Option<&str>),
    ) -> LifecycleEvent {
        let (outcome, error_code) = status;
        let event = LifecycleEvent {
            trace_id: context.trace_id.to_string(),
            decision_id: context.decision_id.to_string(),
            policy_id: context.policy_id.to_string(),
            component: LIFECYCLE_COMPONENT.to_string(),
            event: "lifecycle_transition".to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(str::to_string),
            extension_id: self.extension_id.clone(),
            from_state: from_state.as_str().to_string(),
            to_state: to_state.as_str().to_string(),
            transition: transition.as_str().to_string(),
            timestamp_ns,
        };
        self.telemetry_events.push(event.clone());
        if from_state != to_state {
            self.transition_log.push(LifecycleTransitionRecord {
                monotonic_timestamp_ns: timestamp_ns,
                extension_id: self.extension_id.clone(),
                from_state,
                to_state,
                transition,
                trace_id: context.trace_id.to_string(),
                decision_id: context.decision_id.to_string(),
                policy_id: context.policy_id.to_string(),
            });
        }
        self.last_timestamp_ns = Some(timestamp_ns);
        event
    }
}

fn transition_requires_manifest(transition: LifecycleTransition) -> bool {
    !matches!(
        transition,
        LifecycleTransition::Validate
            | LifecycleTransition::Terminate
            | LifecycleTransition::Quarantine
            | LifecycleTransition::Finalize
    )
}

/// Deterministic transition function for compile-active state-machine checking.
pub const fn lifecycle_target_state(
    state: ExtensionState,
    transition: LifecycleTransition,
) -> Option<ExtensionState> {
    use ExtensionState as S;
    use LifecycleTransition as T;
    match (state, transition) {
        (S::Unloaded, T::Validate) => Some(S::Validating),
        (S::Validating, T::Load) => Some(S::Loading),
        (S::Loading, T::Start) => Some(S::Starting),
        (S::Starting, T::Activate) => Some(S::Running),
        (S::Running, T::Suspend) => Some(S::Suspending),
        (S::Suspending, T::Freeze) => Some(S::Suspended),
        (S::Suspended, T::Resume) => Some(S::Resuming),
        (S::Resuming, T::Reactivate) => Some(S::Running),
        (S::Validating, T::Terminate)
        | (S::Loading, T::Terminate)
        | (S::Starting, T::Terminate)
        | (S::Running, T::Terminate)
        | (S::Suspending, T::Terminate)
        | (S::Suspended, T::Terminate)
        | (S::Resuming, T::Terminate) => Some(S::Terminating),
        (S::Terminating, T::Finalize) => Some(S::Terminated),
        (S::Validating, T::Quarantine)
        | (S::Loading, T::Quarantine)
        | (S::Starting, T::Quarantine)
        | (S::Running, T::Quarantine)
        | (S::Suspending, T::Quarantine)
        | (S::Suspended, T::Quarantine)
        | (S::Resuming, T::Quarantine)
        | (S::Terminating, T::Quarantine) => Some(S::Quarantined),
        _ => None,
    }
}

pub fn allowed_lifecycle_transitions(state: ExtensionState) -> &'static [LifecycleTransition] {
    use ExtensionState as S;
    use LifecycleTransition as T;
    match state {
        S::Unloaded => &[T::Validate],
        S::Validating => &[T::Load, T::Terminate, T::Quarantine],
        S::Loading => &[T::Start, T::Terminate, T::Quarantine],
        S::Starting => &[T::Activate, T::Terminate, T::Quarantine],
        S::Running => &[T::Suspend, T::Terminate, T::Quarantine],
        S::Suspending => &[T::Freeze, T::Terminate, T::Quarantine],
        S::Suspended => &[T::Resume, T::Terminate, T::Quarantine],
        S::Resuming => &[T::Reactivate, T::Terminate, T::Quarantine],
        S::Terminating => &[T::Finalize, T::Quarantine],
        S::Terminated => &[],
        S::Quarantined => &[],
    }
}

/// IFC secrecy lattice labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecrecyLevel {
    Public,
    Internal,
    Confidential,
    Secret,
    TopSecret,
}

impl SecrecyLevel {
    pub const fn rank(self) -> u8 {
        self as u8
    }
}

/// IFC integrity lattice labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityLevel {
    Untrusted,
    Validated,
    Verified,
    Trusted,
}

impl IntegrityLevel {
    pub const fn rank(self) -> u8 {
        self as u8
    }
}

/// Runtime flow label carried by hostcall inputs/outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowLabel {
    secrecy: SecrecyLevel,
    integrity: IntegrityLevel,
}

impl FlowLabel {
    pub const fn new(secrecy: SecrecyLevel, integrity: IntegrityLevel) -> Self {
        Self { secrecy, integrity }
    }

    /// Join operation for combined values:
    /// secrecy=max, integrity=min.
    pub fn join(self, other: Self) -> Self {
        let secrecy = if self.secrecy >= other.secrecy {
            self.secrecy
        } else {
            other.secrecy
        };
        let integrity = if self.integrity <= other.integrity {
            self.integrity
        } else {
            other.integrity
        };
        Self { secrecy, integrity }
    }

    pub const fn secrecy(self) -> SecrecyLevel {
        self.secrecy
    }

    pub const fn integrity(self) -> IntegrityLevel {
        self.integrity
    }
}

impl Default for FlowLabel {
    fn default() -> Self {
        // Edge-case default for unlabeled values: maximally restrictive.
        Self::new(SecrecyLevel::TopSecret, IntegrityLevel::Untrusted)
    }
}

/// Sink-level clearance policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SinkClearance {
    pub max_secrecy: SecrecyLevel,
    pub min_integrity: IntegrityLevel,
}

impl SinkClearance {
    pub const fn new(max_secrecy: SecrecyLevel, min_integrity: IntegrityLevel) -> Self {
        Self {
            max_secrecy,
            min_integrity,
        }
    }
}

/// Runtime lattice checks for hostcall boundary enforcement.
pub struct FlowLabelLattice;

impl FlowLabelLattice {
    /// Standard Bell-LaPadula + Biba check.
    pub const fn can_flow(from: &FlowLabel, to: &FlowLabel) -> bool {
        from.secrecy().rank() <= to.secrecy().rank()
            && from.integrity().rank() >= to.integrity().rank()
    }

    pub const fn can_flow_to_sink(from: &FlowLabel, sink: &SinkClearance) -> bool {
        from.secrecy().rank() <= sink.max_secrecy.rank()
            && from.integrity().rank() >= sink.min_integrity.rank()
    }
}

/// Immutable wrapper that preserves flow labels end-to-end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Labeled<T> {
    value: T,
    label: FlowLabel,
}

impl<T> Labeled<T> {
    pub const fn new(value: T, label: FlowLabel) -> Self {
        Self { value, label }
    }

    pub fn system_generated(value: T) -> Self {
        Self {
            value,
            label: FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted),
        }
    }

    pub const fn label(&self) -> FlowLabel {
        self.label
    }

    pub const fn value(&self) -> &T {
        &self.value
    }

    pub fn into_inner(self) -> T {
        self.value
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Labeled<U> {
        Labeled {
            value: f(self.value),
            label: self.label,
        }
    }
}

impl<T> From<T> for Labeled<T> {
    fn from(value: T) -> Self {
        Self {
            value,
            label: FlowLabel::default(),
        }
    }
}

/// Runtime hostcall categories used by flow checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostcallType {
    FsRead,
    FsWrite,
    NetworkSend,
    NetworkRecv,
    ProcessSpawn,
    EnvRead,
    MemAlloc,
    TimerCreate,
    CryptoOp,
    IpcSend,
    IpcRecv,
}

impl HostcallType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
            Self::NetworkSend => "network_send",
            Self::NetworkRecv => "network_recv",
            Self::ProcessSpawn => "process_spawn",
            Self::EnvRead => "env_read",
            Self::MemAlloc => "mem_alloc",
            Self::TimerCreate => "timer_create",
            Self::CryptoOp => "crypto_op",
            Self::IpcSend => "ipc_send",
            Self::IpcRecv => "ipc_recv",
        }
    }

    pub const fn is_sink(self) -> bool {
        matches!(self, Self::FsWrite | Self::NetworkSend | Self::IpcSend)
    }

    pub const fn default_escrow_route(self) -> CapabilityEscrowRoute {
        match self {
            Self::FsWrite | Self::NetworkSend | Self::ProcessSpawn | Self::IpcSend => {
                CapabilityEscrowRoute::Challenge
            }
            Self::FsRead
            | Self::NetworkRecv
            | Self::EnvRead
            | Self::MemAlloc
            | Self::TimerCreate
            | Self::CryptoOp
            | Self::IpcRecv => CapabilityEscrowRoute::Sandbox,
        }
    }
}

impl fmt::Display for HostcallType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenialReason {
    FlowViolation {
        source: FlowLabel,
        sink: SinkClearance,
    },
    CapabilityEscalation {
        attempted: Capability,
    },
    CapabilityEscrowPending {
        attempted: Capability,
        action: CapabilityEscrowRoute,
        escrow_id: String,
    },
    CapabilityEscrowDenied {
        attempted: Capability,
        escrow_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostcallResult {
    Success,
    Denied { reason: DenialReason },
    Error { code: u32 },
    Timeout,
}

/// Deterministic event emitted when runtime IFC denies a hostcall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowViolationEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub extension_id: String,
    pub hostcall_type: HostcallType,
    pub source_label: FlowLabel,
    pub sink_clearance: SinkClearance,
}

/// Evidence item consumed by Guardplane/Bayesian updater.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowViolationEvidence {
    pub extension_id: String,
    pub hostcall_type: HostcallType,
    pub source_label: FlowLabel,
    pub sink_clearance: SinkClearance,
    pub decision_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowEnforcementContext<'a> {
    pub trace_id: &'a str,
    pub decision_id: &'a str,
    pub policy_id: &'a str,
}

impl<'a> FlowEnforcementContext<'a> {
    pub const fn new(trace_id: &'a str, decision_id: &'a str, policy_id: &'a str) -> Self {
        Self {
            trace_id,
            decision_id,
            policy_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallSinkPolicy {
    pub fs_write: SinkClearance,
    pub network_send: SinkClearance,
    pub ipc_send: SinkClearance,
}

impl Default for HostcallSinkPolicy {
    fn default() -> Self {
        Self {
            fs_write: SinkClearance::new(SecrecyLevel::Internal, IntegrityLevel::Validated),
            network_send: SinkClearance::new(SecrecyLevel::Public, IntegrityLevel::Validated),
            ipc_send: SinkClearance::new(SecrecyLevel::Secret, IntegrityLevel::Untrusted),
        }
    }
}

impl HostcallSinkPolicy {
    pub const fn clearance_for(self, hostcall_type: HostcallType) -> Option<SinkClearance> {
        match hostcall_type {
            HostcallType::FsWrite => Some(self.fs_write),
            HostcallType::NetworkSend => Some(self.network_send),
            HostcallType::IpcSend => Some(self.ipc_send),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostcallDispatchOutcome<T> {
    pub result: HostcallResult,
    pub output: Option<Labeled<T>>,
}

const CAPABILITY_ESCROW_COMPONENT: &str = "capability_escrow_gateway";
const ESCROW_CHALLENGE_ERROR_CODE: &str = "FE-ESCROW-0001";
const ESCROW_SANDBOX_ERROR_CODE: &str = "FE-ESCROW-0002";
const ESCROW_FLOOD_ERROR_CODE: &str = "FE-ESCROW-0003";
const ESCROW_MANUAL_DENY_ERROR_CODE: &str = "FE-ESCROW-0004";
const ESCROW_EXPIRED_ERROR_CODE: &str = "FE-ESCROW-0005";
const ESCROW_GRANT_INVALID_ERROR_CODE: &str = "FE-ESCROW-0006";
const ESCROW_GRANT_EXPIRED_ERROR_CODE: &str = "FE-ESCROW-0007";
const ESCROW_GRANT_EXHAUSTED_ERROR_CODE: &str = "FE-ESCROW-0008";
const ESCROW_POST_REVIEW_ERROR_CODE: &str = "FE-ESCROW-0009";
const ESCROW_RECEIPT_EMISSION_ERROR_CODE: &str = "FE-ESCROW-0010";
const DEFAULT_ESCROW_REQUEST_TTL_NS: u64 = 300_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityEscrowRoute {
    Challenge,
    Sandbox,
}

impl CapabilityEscrowRoute {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::Sandbox => "sandbox",
        }
    }
}

impl fmt::Display for CapabilityEscrowRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityEscrowState {
    Requested,
    Challenged,
    Sandboxed,
    Approved,
    Denied,
    Expired,
}

impl CapabilityEscrowState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Challenged => "challenged",
            Self::Sandboxed => "sandboxed",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }
}

impl fmt::Display for CapabilityEscrowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEscrowRequest {
    pub request_id: String,
    pub extension_id: String,
    pub hostcall_type: HostcallType,
    pub capability: Capability,
    pub justification: String,
    pub timestamp_ns: u64,
    pub expires_at_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEscrowRecord {
    pub request_id: String,
    pub extension_id: String,
    pub hostcall_type: HostcallType,
    pub capability: Capability,
    pub justification: String,
    pub state: CapabilityEscrowState,
    pub created_at_ns: u64,
    pub expires_at_ns: u64,
    pub updated_at_ns: u64,
}

impl CapabilityEscrowRecord {
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            CapabilityEscrowState::Denied | CapabilityEscrowState::Expired
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowCondition {
    pub key: String,
    pub value: String,
}

impl EscrowCondition {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityEscrowDecisionKind {
    Challenge,
    Sandbox,
    Approve,
    Deny,
    EmergencyGrant,
    Expire,
}

impl CapabilityEscrowDecisionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::Sandbox => "sandbox",
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::EmergencyGrant => "emergency_grant",
            Self::Expire => "expire",
        }
    }
}

impl fmt::Display for CapabilityEscrowDecisionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEscrowDecisionReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub extension_id: String,
    pub capability: Capability,
    pub decision: CapabilityEscrowDecisionKind,
    pub state: CapabilityEscrowState,
    pub trace_ref: String,
    pub replay_seed: String,
    pub decision_id: String,
    pub policy_id: String,
    pub active_witness_ref: String,
    pub contract_chain: Vec<String>,
    pub conditions: Vec<EscrowCondition>,
    pub outcome: String,
    pub error_code: Option<String>,
    pub timestamp_ns: u64,
    pub signature: [u8; 32],
}

#[derive(Serialize)]
struct CapabilityEscrowReceiptSigningPayload<'a> {
    receipt_id: &'a str,
    request_id: &'a str,
    extension_id: &'a str,
    capability: Capability,
    decision: CapabilityEscrowDecisionKind,
    state: CapabilityEscrowState,
    trace_ref: &'a str,
    replay_seed: &'a str,
    decision_id: &'a str,
    policy_id: &'a str,
    active_witness_ref: &'a str,
    contract_chain: &'a [String],
    conditions: &'a [EscrowCondition],
    outcome: &'a str,
    error_code: &'a Option<String>,
    timestamp_ns: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEscrowReceiptQuery {
    pub extension_id: Option<String>,
    pub capability: Option<Capability>,
    pub decision: Option<CapabilityEscrowDecisionKind>,
    pub outcome: Option<String>,
    pub timestamp_from_ns: Option<u64>,
    pub timestamp_to_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEscrowReplayContext {
    pub receipt: CapabilityEscrowDecisionReceipt,
    pub event: CapabilityEscrowDecisionEvent,
    pub evidence: CapabilityEscrowEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEscrowReceiptCompletenessReport {
    pub complete: bool,
    pub receipts: usize,
    pub events: usize,
    pub evidence: usize,
    pub missing_event_receipt_ids: Vec<String>,
    pub missing_evidence_receipt_ids: Vec<String>,
}

impl CapabilityEscrowDecisionReceipt {
    #[allow(clippy::too_many_arguments)]
    fn new_signed(
        request_id: &str,
        extension_id: &str,
        capability: Capability,
        decision: CapabilityEscrowDecisionKind,
        state: CapabilityEscrowState,
        trace_ref: String,
        replay_seed: String,
        decision_id: &str,
        policy_id: &str,
        active_witness_ref: String,
        contract_chain: Vec<String>,
        conditions: Vec<EscrowCondition>,
        outcome: String,
        error_code: Option<String>,
        timestamp_ns: u64,
        signer: &DecisionSigningKey,
    ) -> Result<Self, CapabilityEscrowError> {
        let receipt_id =
            derive_escrow_receipt_id(request_id, timestamp_ns, decision.as_str(), state.as_str());
        let payload = CapabilityEscrowReceiptSigningPayload {
            receipt_id: &receipt_id,
            request_id,
            extension_id,
            capability,
            decision,
            state,
            trace_ref: &trace_ref,
            replay_seed: &replay_seed,
            decision_id,
            policy_id,
            active_witness_ref: &active_witness_ref,
            contract_chain: &contract_chain,
            conditions: &conditions,
            outcome: &outcome,
            error_code: &error_code,
            timestamp_ns,
        };
        let payload_bytes = serde_json::to_vec(&payload).map_err(|err| {
            CapabilityEscrowError::ReceiptEmissionFailed {
                request_id: request_id.to_string(),
                detail: err.to_string(),
            }
        })?;
        let signature = signer.sign(&payload_bytes);
        Ok(Self {
            receipt_id,
            request_id: request_id.to_string(),
            extension_id: extension_id.to_string(),
            capability,
            decision,
            state,
            trace_ref,
            replay_seed,
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_string(),
            active_witness_ref,
            contract_chain,
            conditions,
            outcome,
            error_code,
            timestamp_ns,
            signature,
        })
    }

    fn signing_payload_bytes(&self) -> Result<Vec<u8>, CapabilityEscrowError> {
        let payload = CapabilityEscrowReceiptSigningPayload {
            receipt_id: &self.receipt_id,
            request_id: &self.request_id,
            extension_id: &self.extension_id,
            capability: self.capability,
            decision: self.decision,
            state: self.state,
            trace_ref: &self.trace_ref,
            replay_seed: &self.replay_seed,
            decision_id: &self.decision_id,
            policy_id: &self.policy_id,
            active_witness_ref: &self.active_witness_ref,
            contract_chain: &self.contract_chain,
            conditions: &self.conditions,
            outcome: &self.outcome,
            error_code: &self.error_code,
            timestamp_ns: self.timestamp_ns,
        };
        serde_json::to_vec(&payload).map_err(|err| CapabilityEscrowError::ReceiptEmissionFailed {
            request_id: self.request_id.clone(),
            detail: err.to_string(),
        })
    }

    pub fn verify(&self, public_key: &DecisionPublicKey) -> bool {
        self.signing_payload_bytes()
            .map(|payload| public_key.verify(&payload, &self.signature))
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEscrowDecisionEvent {
    pub trace_id: String,
    pub trace_ref: String,
    pub replay_seed: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub extension_id: String,
    pub request_id: String,
    pub capability: Capability,
    pub state: CapabilityEscrowState,
    pub receipt_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEscrowEvidence {
    pub extension_id: String,
    pub request_id: String,
    pub capability: Capability,
    pub state: CapabilityEscrowState,
    pub trace_ref: String,
    pub replay_seed: String,
    pub decision_id: String,
    pub receipt_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyGrantArtifact {
    pub grant_id: String,
    pub request_id: String,
    pub extension_id: String,
    pub capability_granted: Capability,
    pub justification: String,
    pub authorized_actor: String,
    pub expiry_timestamp: u64,
    pub max_invocation_count: u32,
    pub mandatory_post_review: bool,
    pub rollback_on_expiry: bool,
    pub issued_at_ns: u64,
    pub signature: [u8; 32],
}

#[derive(Serialize)]
struct EmergencyGrantSigningPayload<'a> {
    grant_id: &'a str,
    request_id: &'a str,
    extension_id: &'a str,
    capability_granted: Capability,
    justification: &'a str,
    authorized_actor: &'a str,
    expiry_timestamp: u64,
    max_invocation_count: u32,
    mandatory_post_review: bool,
    rollback_on_expiry: bool,
    issued_at_ns: u64,
}

impl EmergencyGrantArtifact {
    #[allow(clippy::too_many_arguments)]
    fn new_signed(
        request_id: &str,
        extension_id: &str,
        capability_granted: Capability,
        justification: String,
        authorized_actor: String,
        expiry_timestamp: u64,
        max_invocation_count: u32,
        mandatory_post_review: bool,
        rollback_on_expiry: bool,
        issued_at_ns: u64,
        signer: &DecisionSigningKey,
    ) -> Self {
        let grant_id = derive_emergency_grant_id(request_id, &authorized_actor, issued_at_ns);
        let payload = EmergencyGrantSigningPayload {
            grant_id: &grant_id,
            request_id,
            extension_id,
            capability_granted,
            justification: &justification,
            authorized_actor: &authorized_actor,
            expiry_timestamp,
            max_invocation_count,
            mandatory_post_review,
            rollback_on_expiry,
            issued_at_ns,
        };
        let signature = signer
            .sign(&serde_json::to_vec(&payload).expect("emergency grant payload should serialize"));
        Self {
            grant_id,
            request_id: request_id.to_string(),
            extension_id: extension_id.to_string(),
            capability_granted,
            justification,
            authorized_actor,
            expiry_timestamp,
            max_invocation_count,
            mandatory_post_review,
            rollback_on_expiry,
            issued_at_ns,
            signature,
        }
    }

    fn signing_payload_bytes(&self) -> Vec<u8> {
        let payload = EmergencyGrantSigningPayload {
            grant_id: &self.grant_id,
            request_id: &self.request_id,
            extension_id: &self.extension_id,
            capability_granted: self.capability_granted,
            justification: &self.justification,
            authorized_actor: &self.authorized_actor,
            expiry_timestamp: self.expiry_timestamp,
            max_invocation_count: self.max_invocation_count,
            mandatory_post_review: self.mandatory_post_review,
            rollback_on_expiry: self.rollback_on_expiry,
            issued_at_ns: self.issued_at_ns,
        };
        serde_json::to_vec(&payload).expect("emergency grant payload should serialize")
    }

    pub fn verify(&self, public_key: &DecisionPublicKey) -> bool {
        public_key.verify(&self.signing_payload_bytes(), &self.signature)
    }

    pub const fn is_expired(&self, timestamp_ns: u64) -> bool {
        timestamp_ns >= self.expiry_timestamp
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ActiveEmergencyGrant {
    artifact: EmergencyGrantArtifact,
    invocations_used: u32,
    revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityEscrowError {
    UnknownRequest {
        request_id: String,
    },
    InvalidStateTransition {
        request_id: String,
        from: CapabilityEscrowState,
        to: CapabilityEscrowState,
    },
    RequestNotActionable {
        request_id: String,
        state: CapabilityEscrowState,
    },
    InvalidEmergencyGrant {
        field: &'static str,
        detail: String,
    },
    PostReviewNotPending {
        grant_id: String,
    },
    ReceiptEmissionFailed {
        request_id: String,
        detail: String,
    },
}

impl CapabilityEscrowError {
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::UnknownRequest { .. } => ESCROW_MANUAL_DENY_ERROR_CODE,
            Self::InvalidStateTransition { .. } => ESCROW_MANUAL_DENY_ERROR_CODE,
            Self::RequestNotActionable { .. } => ESCROW_MANUAL_DENY_ERROR_CODE,
            Self::InvalidEmergencyGrant { .. } => ESCROW_GRANT_INVALID_ERROR_CODE,
            Self::PostReviewNotPending { .. } => ESCROW_POST_REVIEW_ERROR_CODE,
            Self::ReceiptEmissionFailed { .. } => ESCROW_RECEIPT_EMISSION_ERROR_CODE,
        }
    }
}

impl fmt::Display for CapabilityEscrowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRequest { request_id } => {
                write!(f, "unknown capability escrow request: {request_id}")
            }
            Self::InvalidStateTransition {
                request_id,
                from,
                to,
            } => write!(
                f,
                "invalid escrow state transition for {request_id}: {from} -> {to}"
            ),
            Self::RequestNotActionable { request_id, state } => write!(
                f,
                "escrow request {request_id} in state {state} cannot be actioned"
            ),
            Self::InvalidEmergencyGrant { field, detail } => {
                write!(f, "invalid emergency grant field `{field}`: {detail}")
            }
            Self::PostReviewNotPending { grant_id } => {
                write!(
                    f,
                    "mandatory post review is not pending for grant {grant_id}"
                )
            }
            Self::ReceiptEmissionFailed { request_id, detail } => {
                write!(
                    f,
                    "failed to emit escrow decision receipt for {request_id}: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for CapabilityEscrowError {}

pub struct CapabilityEscrowEvaluationContext {
    pub open_requests_for_extension: usize,
}

pub enum CapabilityEscrowContractVerdict {
    Continue,
    Challenge { detail: String },
    Sandbox { profile: String },
    Deny { error_code: String, detail: String },
}

pub trait CapabilityEscrowDecisionContract: Send + Sync {
    fn contract_id(&self) -> &'static str;

    fn evaluate(
        &self,
        request: &CapabilityEscrowRequest,
        context: &CapabilityEscrowEvaluationContext,
    ) -> CapabilityEscrowContractVerdict;
}

#[derive(Debug, Clone, Copy)]
pub struct EscrowFloodProtectionContract {
    pub max_open_requests_per_extension: usize,
}

impl Default for EscrowFloodProtectionContract {
    fn default() -> Self {
        Self {
            max_open_requests_per_extension: 16,
        }
    }
}

impl CapabilityEscrowDecisionContract for EscrowFloodProtectionContract {
    fn contract_id(&self) -> &'static str {
        "escrow_flood_protection"
    }

    fn evaluate(
        &self,
        _request: &CapabilityEscrowRequest,
        context: &CapabilityEscrowEvaluationContext,
    ) -> CapabilityEscrowContractVerdict {
        if context.open_requests_for_extension >= self.max_open_requests_per_extension {
            CapabilityEscrowContractVerdict::Deny {
                error_code: ESCROW_FLOOD_ERROR_CODE.to_string(),
                detail: format!(
                    "open capability escrow requests exceed limit {}",
                    self.max_open_requests_per_extension
                ),
            }
        } else {
            CapabilityEscrowContractVerdict::Continue
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EscrowJustificationContract;

impl CapabilityEscrowDecisionContract for EscrowJustificationContract {
    fn contract_id(&self) -> &'static str {
        "escrow_justification"
    }

    fn evaluate(
        &self,
        request: &CapabilityEscrowRequest,
        _context: &CapabilityEscrowEvaluationContext,
    ) -> CapabilityEscrowContractVerdict {
        if request.justification.trim().is_empty() {
            CapabilityEscrowContractVerdict::Challenge {
                detail: "request justification required for out-of-envelope capability".to_string(),
            }
        } else {
            CapabilityEscrowContractVerdict::Continue
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EscrowDefaultRouteContract;

impl CapabilityEscrowDecisionContract for EscrowDefaultRouteContract {
    fn contract_id(&self) -> &'static str {
        "escrow_default_route"
    }

    fn evaluate(
        &self,
        request: &CapabilityEscrowRequest,
        _context: &CapabilityEscrowEvaluationContext,
    ) -> CapabilityEscrowContractVerdict {
        match request.hostcall_type.default_escrow_route() {
            CapabilityEscrowRoute::Challenge => CapabilityEscrowContractVerdict::Challenge {
                detail: "manual challenge required before capability elevation".to_string(),
            },
            CapabilityEscrowRoute::Sandbox => CapabilityEscrowContractVerdict::Sandbox {
                profile: "deterministic_sandbox_v1".to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEscrowDecision {
    pub request_id: String,
    pub state: CapabilityEscrowState,
    pub receipt_id: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

pub enum CapabilityEscrowResolution {
    AuthorizedByApproval {
        request_id: String,
    },
    AuthorizedByEmergencyGrant {
        grant_id: String,
    },
    Escrowed {
        decision: CapabilityEscrowDecision,
        route: CapabilityEscrowRoute,
    },
    Denied {
        decision: CapabilityEscrowDecision,
    },
}

pub struct CapabilityEscrowGateway {
    contracts: Vec<Box<dyn CapabilityEscrowDecisionContract>>,
    signing_key: DecisionSigningKey,
    records: BTreeMap<String, CapabilityEscrowRecord>,
    receipts: Vec<CapabilityEscrowDecisionReceipt>,
    events: Vec<CapabilityEscrowDecisionEvent>,
    evidence: Vec<CapabilityEscrowEvidence>,
    emergency_grants: BTreeMap<String, ActiveEmergencyGrant>,
    pending_post_reviews: BTreeSet<String>,
    emergency_grant_only_requests: BTreeSet<String>,
    request_sequence: u64,
    request_ttl_ns: u64,
}

impl CapabilityEscrowGateway {
    pub fn with_default_contracts(signing_key: DecisionSigningKey) -> Self {
        let contracts: Vec<Box<dyn CapabilityEscrowDecisionContract>> = vec![
            Box::new(EscrowFloodProtectionContract::default()),
            Box::new(EscrowJustificationContract),
            Box::new(EscrowDefaultRouteContract),
        ];
        Self::new(signing_key, contracts)
    }

    pub fn new(
        signing_key: DecisionSigningKey,
        contracts: Vec<Box<dyn CapabilityEscrowDecisionContract>>,
    ) -> Self {
        Self {
            contracts,
            signing_key,
            records: BTreeMap::new(),
            receipts: Vec::new(),
            events: Vec::new(),
            evidence: Vec::new(),
            emergency_grants: BTreeMap::new(),
            pending_post_reviews: BTreeSet::new(),
            emergency_grant_only_requests: BTreeSet::new(),
            request_sequence: 0,
            request_ttl_ns: DEFAULT_ESCROW_REQUEST_TTL_NS,
        }
    }

    pub fn records(&self) -> &BTreeMap<String, CapabilityEscrowRecord> {
        &self.records
    }

    pub fn receipts(&self) -> &[CapabilityEscrowDecisionReceipt] {
        &self.receipts
    }

    pub fn events(&self) -> &[CapabilityEscrowDecisionEvent] {
        &self.events
    }

    pub fn evidence(&self) -> &[CapabilityEscrowEvidence] {
        &self.evidence
    }

    pub fn pending_post_reviews(&self) -> &BTreeSet<String> {
        &self.pending_post_reviews
    }

    pub fn active_emergency_grants(&self) -> Vec<EmergencyGrantArtifact> {
        self.emergency_grants
            .values()
            .filter(|grant| !grant.revoked)
            .map(|grant| grant.artifact.clone())
            .collect()
    }

    pub fn query_receipts(
        &self,
        query: &CapabilityEscrowReceiptQuery,
    ) -> Vec<&CapabilityEscrowDecisionReceipt> {
        self.receipts
            .iter()
            .filter(|receipt| {
                if let Some(extension_id) = query.extension_id.as_deref() {
                    if receipt.extension_id != extension_id {
                        return false;
                    }
                }
                if let Some(capability) = query.capability {
                    if receipt.capability != capability {
                        return false;
                    }
                }
                if let Some(decision) = query.decision {
                    if receipt.decision != decision {
                        return false;
                    }
                }
                if let Some(outcome) = query.outcome.as_deref() {
                    if receipt.outcome != outcome {
                        return false;
                    }
                }
                if let Some(start_ns) = query.timestamp_from_ns {
                    if receipt.timestamp_ns < start_ns {
                        return false;
                    }
                }
                if let Some(end_ns) = query.timestamp_to_ns {
                    if receipt.timestamp_ns > end_ns {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    pub fn replay_context_for_receipt(
        &self,
        receipt_id: &str,
    ) -> Option<CapabilityEscrowReplayContext> {
        let receipt = self
            .receipts
            .iter()
            .find(|item| item.receipt_id == receipt_id)?
            .clone();
        let event = self
            .events
            .iter()
            .find(|item| item.receipt_id == receipt_id)?
            .clone();
        let evidence = self
            .evidence
            .iter()
            .find(|item| item.receipt_id == receipt_id)?
            .clone();
        Some(CapabilityEscrowReplayContext {
            receipt,
            event,
            evidence,
        })
    }

    pub fn receipt_completeness_report(&self) -> CapabilityEscrowReceiptCompletenessReport {
        let event_receipt_ids: BTreeSet<&str> = self
            .events
            .iter()
            .map(|event| event.receipt_id.as_str())
            .collect();
        let evidence_receipt_ids: BTreeSet<&str> = self
            .evidence
            .iter()
            .map(|item| item.receipt_id.as_str())
            .collect();
        let missing_event_receipt_ids: Vec<String> = self
            .receipts
            .iter()
            .filter(|receipt| !event_receipt_ids.contains(receipt.receipt_id.as_str()))
            .map(|receipt| receipt.receipt_id.clone())
            .collect();
        let missing_evidence_receipt_ids: Vec<String> = self
            .receipts
            .iter()
            .filter(|receipt| !evidence_receipt_ids.contains(receipt.receipt_id.as_str()))
            .map(|receipt| receipt.receipt_id.clone())
            .collect();
        CapabilityEscrowReceiptCompletenessReport {
            complete: missing_event_receipt_ids.is_empty()
                && missing_evidence_receipt_ids.is_empty(),
            receipts: self.receipts.len(),
            events: self.events.len(),
            evidence: self.evidence.len(),
            missing_event_receipt_ids,
            missing_evidence_receipt_ids,
        }
    }

    pub fn public_key(&self) -> DecisionPublicKey {
        self.signing_key.public_key()
    }

    pub fn set_request_ttl_ns(&mut self, ttl_ns: u64) {
        self.request_ttl_ns = ttl_ns.max(1);
    }

    pub fn resolve_out_of_envelope_request(
        &mut self,
        extension_id: &str,
        hostcall_type: HostcallType,
        capability: Capability,
        justification: &str,
        timestamp_ns: u64,
        context: &FlowEnforcementContext<'_>,
    ) -> Result<CapabilityEscrowResolution, CapabilityEscrowError> {
        self.expire(timestamp_ns, context)?;

        if let Some(request_id) =
            self.latest_active_approved_request(extension_id, capability, timestamp_ns)
        {
            return Ok(CapabilityEscrowResolution::AuthorizedByApproval { request_id });
        }

        if let Some(grant_id) =
            self.consume_matching_emergency_grant(extension_id, capability, timestamp_ns, context)?
        {
            return Ok(CapabilityEscrowResolution::AuthorizedByEmergencyGrant { grant_id });
        }

        let open_requests_for_extension = self.open_request_count(extension_id);
        self.request_sequence = self.request_sequence.saturating_add(1);
        let request_id = derive_escrow_request_id(
            extension_id,
            capability,
            hostcall_type,
            timestamp_ns,
            self.request_sequence,
        );
        let request = CapabilityEscrowRequest {
            request_id: request_id.clone(),
            extension_id: extension_id.to_string(),
            hostcall_type,
            capability,
            justification: justification.to_string(),
            timestamp_ns,
            expires_at_ns: timestamp_ns.saturating_add(self.request_ttl_ns),
        };
        self.records.insert(
            request_id.clone(),
            CapabilityEscrowRecord {
                request_id: request_id.clone(),
                extension_id: extension_id.to_string(),
                hostcall_type,
                capability,
                justification: request.justification.clone(),
                state: CapabilityEscrowState::Requested,
                created_at_ns: timestamp_ns,
                expires_at_ns: request.expires_at_ns,
                updated_at_ns: timestamp_ns,
            },
        );

        let eval_context = CapabilityEscrowEvaluationContext {
            open_requests_for_extension,
        };

        let mut contract_chain = Vec::new();
        let mut conditions = Vec::new();
        let mut terminal: Option<(CapabilityEscrowState, String, Option<String>)> = None;
        for contract in &self.contracts {
            contract_chain.push(contract.contract_id().to_string());
            match contract.evaluate(&request, &eval_context) {
                CapabilityEscrowContractVerdict::Continue => {}
                CapabilityEscrowContractVerdict::Challenge { detail } => {
                    conditions.push(EscrowCondition::new("escrow_action", "challenge"));
                    conditions.push(EscrowCondition::new("justification_request", detail));
                    terminal = Some((
                        CapabilityEscrowState::Challenged,
                        "challenged".to_string(),
                        Some(ESCROW_CHALLENGE_ERROR_CODE.to_string()),
                    ));
                    break;
                }
                CapabilityEscrowContractVerdict::Sandbox { profile } => {
                    conditions.push(EscrowCondition::new("escrow_action", "sandbox"));
                    conditions.push(EscrowCondition::new("sandbox_config", profile));
                    terminal = Some((
                        CapabilityEscrowState::Sandboxed,
                        "sandboxed".to_string(),
                        Some(ESCROW_SANDBOX_ERROR_CODE.to_string()),
                    ));
                    break;
                }
                CapabilityEscrowContractVerdict::Deny { error_code, detail } => {
                    conditions.push(EscrowCondition::new("escrow_action", "deny"));
                    conditions.push(EscrowCondition::new("denial_reason", detail));
                    conditions.push(EscrowCondition::new(
                        "remediation_guidance",
                        "request policy exception or update active witness envelope",
                    ));
                    terminal = Some((
                        CapabilityEscrowState::Denied,
                        "denied".to_string(),
                        Some(error_code),
                    ));
                    break;
                }
            }
        }

        let (state, outcome, error_code) = terminal.unwrap_or((
            CapabilityEscrowState::Challenged,
            "challenged".to_string(),
            Some(ESCROW_CHALLENGE_ERROR_CODE.to_string()),
        ));
        let decision_kind = match state {
            CapabilityEscrowState::Challenged => CapabilityEscrowDecisionKind::Challenge,
            CapabilityEscrowState::Sandboxed => CapabilityEscrowDecisionKind::Sandbox,
            CapabilityEscrowState::Denied => CapabilityEscrowDecisionKind::Deny,
            _ => CapabilityEscrowDecisionKind::Challenge,
        };
        let decision = match self.transition_record(
            &request_id,
            state,
            decision_kind,
            contract_chain,
            conditions,
            timestamp_ns,
            context,
            outcome,
            error_code,
        ) {
            Ok(decision) => decision,
            Err(err) => {
                // Fail closed: if receipt emission/linking fails, discard the transient request.
                self.records.remove(&request_id);
                self.emergency_grant_only_requests.remove(&request_id);
                return Err(err);
            }
        };

        match state {
            CapabilityEscrowState::Challenged => Ok(CapabilityEscrowResolution::Escrowed {
                decision,
                route: CapabilityEscrowRoute::Challenge,
            }),
            CapabilityEscrowState::Sandboxed => Ok(CapabilityEscrowResolution::Escrowed {
                decision,
                route: CapabilityEscrowRoute::Sandbox,
            }),
            CapabilityEscrowState::Denied => Ok(CapabilityEscrowResolution::Denied { decision }),
            _ => Ok(CapabilityEscrowResolution::Escrowed {
                decision,
                route: CapabilityEscrowRoute::Challenge,
            }),
        }
    }

    pub fn approve_request(
        &mut self,
        request_id: &str,
        timestamp_ns: u64,
        context: &FlowEnforcementContext<'_>,
    ) -> Result<CapabilityEscrowDecisionReceipt, CapabilityEscrowError> {
        self.expire(timestamp_ns, context)?;
        let state = self.current_state(request_id)?;
        if !matches!(
            state,
            CapabilityEscrowState::Requested
                | CapabilityEscrowState::Challenged
                | CapabilityEscrowState::Sandboxed
        ) {
            return Err(CapabilityEscrowError::RequestNotActionable {
                request_id: request_id.to_string(),
                state,
            });
        }

        let decision = self.transition_record(
            request_id,
            CapabilityEscrowState::Approved,
            CapabilityEscrowDecisionKind::Approve,
            vec!["manual_approval".to_string()],
            vec![EscrowCondition::new("approved_by", "operator")],
            timestamp_ns,
            context,
            "approved".to_string(),
            None,
        )?;
        let receipt = self
            .receipts
            .iter()
            .find(|receipt| receipt.receipt_id == decision.receipt_id)
            .cloned()
            .ok_or_else(|| CapabilityEscrowError::UnknownRequest {
                request_id: request_id.to_string(),
            })?;
        self.emergency_grant_only_requests.remove(request_id);
        Ok(receipt)
    }

    pub fn deny_request(
        &mut self,
        request_id: &str,
        reason: impl Into<String>,
        timestamp_ns: u64,
        context: &FlowEnforcementContext<'_>,
    ) -> Result<CapabilityEscrowDecisionReceipt, CapabilityEscrowError> {
        self.expire(timestamp_ns, context)?;
        let state = self.current_state(request_id)?;
        if !matches!(
            state,
            CapabilityEscrowState::Requested
                | CapabilityEscrowState::Challenged
                | CapabilityEscrowState::Sandboxed
        ) {
            return Err(CapabilityEscrowError::RequestNotActionable {
                request_id: request_id.to_string(),
                state,
            });
        }

        let decision = self.transition_record(
            request_id,
            CapabilityEscrowState::Denied,
            CapabilityEscrowDecisionKind::Deny,
            vec!["manual_denial".to_string()],
            vec![
                EscrowCondition::new("escrow_action", "deny"),
                EscrowCondition::new("denial_reason", reason.into()),
                EscrowCondition::new(
                    "remediation_guidance",
                    "request policy exception or update active witness envelope",
                ),
            ],
            timestamp_ns,
            context,
            "denied".to_string(),
            Some(ESCROW_MANUAL_DENY_ERROR_CODE.to_string()),
        )?;
        let receipt = self
            .receipts
            .iter()
            .find(|receipt| receipt.receipt_id == decision.receipt_id)
            .cloned()
            .ok_or_else(|| CapabilityEscrowError::UnknownRequest {
                request_id: request_id.to_string(),
            })?;
        self.emergency_grant_only_requests.remove(request_id);
        Ok(receipt)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_emergency_grant(
        &mut self,
        request_id: &str,
        authorized_actor: &str,
        justification: &str,
        expiry_timestamp: u64,
        max_invocation_count: u32,
        mandatory_post_review: bool,
        rollback_on_expiry: bool,
        timestamp_ns: u64,
        context: &FlowEnforcementContext<'_>,
    ) -> Result<EmergencyGrantArtifact, CapabilityEscrowError> {
        self.expire(timestamp_ns, context)?;
        if authorized_actor.trim().is_empty() {
            return Err(CapabilityEscrowError::InvalidEmergencyGrant {
                field: "authorized_actor",
                detail: "must not be empty".to_string(),
            });
        }
        if justification.trim().is_empty() {
            return Err(CapabilityEscrowError::InvalidEmergencyGrant {
                field: "justification",
                detail: "must not be empty".to_string(),
            });
        }
        if max_invocation_count == 0 {
            return Err(CapabilityEscrowError::InvalidEmergencyGrant {
                field: "max_invocation_count",
                detail: "must be greater than zero".to_string(),
            });
        }
        if expiry_timestamp <= timestamp_ns {
            return Err(CapabilityEscrowError::InvalidEmergencyGrant {
                field: "expiry_timestamp",
                detail: "must be in the future".to_string(),
            });
        }

        let state = self.current_state(request_id)?;
        if !matches!(
            state,
            CapabilityEscrowState::Requested
                | CapabilityEscrowState::Challenged
                | CapabilityEscrowState::Sandboxed
                | CapabilityEscrowState::Approved
        ) {
            return Err(CapabilityEscrowError::RequestNotActionable {
                request_id: request_id.to_string(),
                state,
            });
        }

        if state != CapabilityEscrowState::Approved {
            self.transition_record(
                request_id,
                CapabilityEscrowState::Approved,
                CapabilityEscrowDecisionKind::Approve,
                vec!["pre_grant_approval".to_string()],
                vec![EscrowCondition::new("approved_by", authorized_actor)],
                timestamp_ns,
                context,
                "approved".to_string(),
                None,
            )?;
        }

        let record = self.records.get(request_id).cloned().ok_or_else(|| {
            CapabilityEscrowError::UnknownRequest {
                request_id: request_id.to_string(),
            }
        })?;

        let artifact = EmergencyGrantArtifact::new_signed(
            request_id,
            &record.extension_id,
            record.capability,
            justification.to_string(),
            authorized_actor.to_string(),
            expiry_timestamp,
            max_invocation_count,
            mandatory_post_review,
            rollback_on_expiry,
            timestamp_ns,
            &self.signing_key,
        );
        let grant_id = artifact.grant_id.clone();
        self.emergency_grants.insert(
            grant_id.clone(),
            ActiveEmergencyGrant {
                artifact: artifact.clone(),
                invocations_used: 0,
                revoked: false,
            },
        );
        self.emergency_grant_only_requests
            .insert(request_id.to_string());
        if mandatory_post_review {
            self.pending_post_reviews.insert(grant_id.clone());
        }
        let review_obligation_id = if mandatory_post_review {
            format!("post-review-{grant_id}")
        } else {
            "none".to_string()
        };
        self.transition_record(
            request_id,
            CapabilityEscrowState::Approved,
            CapabilityEscrowDecisionKind::EmergencyGrant,
            vec!["emergency_grant_contract".to_string()],
            vec![
                EscrowCondition::new("escrow_action", "emergency_grant"),
                EscrowCondition::new("grant_id", grant_id),
                EscrowCondition::new("authorized_actor", authorized_actor.to_string()),
                EscrowCondition::new("justification", justification.to_string()),
                EscrowCondition::new("expiry_timestamp", expiry_timestamp.to_string()),
                EscrowCondition::new("max_invocation_count", max_invocation_count.to_string()),
                EscrowCondition::new("rollback_on_expiry", rollback_on_expiry.to_string()),
                EscrowCondition::new("mandatory_post_review", mandatory_post_review.to_string()),
                EscrowCondition::new("review_obligation_id", review_obligation_id),
            ],
            timestamp_ns,
            context,
            "emergency_granted".to_string(),
            None,
        )?;
        Ok(artifact)
    }

    pub fn complete_post_review(&mut self, grant_id: &str) -> Result<(), CapabilityEscrowError> {
        if self.pending_post_reviews.remove(grant_id) {
            Ok(())
        } else {
            Err(CapabilityEscrowError::PostReviewNotPending {
                grant_id: grant_id.to_string(),
            })
        }
    }

    pub fn expire(
        &mut self,
        timestamp_ns: u64,
        context: &FlowEnforcementContext<'_>,
    ) -> Result<(), CapabilityEscrowError> {
        let expiring_requests: Vec<String> = self
            .records
            .iter()
            .filter(|(_, record)| {
                matches!(
                    record.state,
                    CapabilityEscrowState::Requested
                        | CapabilityEscrowState::Challenged
                        | CapabilityEscrowState::Sandboxed
                        | CapabilityEscrowState::Approved
                ) && timestamp_ns >= record.expires_at_ns
            })
            .map(|(request_id, _)| request_id.clone())
            .collect();
        for request_id in expiring_requests {
            self.transition_record(
                &request_id,
                CapabilityEscrowState::Expired,
                CapabilityEscrowDecisionKind::Expire,
                vec!["expiry_timer".to_string()],
                vec![EscrowCondition::new("expired_at", timestamp_ns.to_string())],
                timestamp_ns,
                context,
                "expired".to_string(),
                Some(ESCROW_EXPIRED_ERROR_CODE.to_string()),
            )?;
        }

        let expiring_grants: Vec<String> = self
            .emergency_grants
            .iter()
            .filter(|(_, grant)| {
                !grant.revoked
                    && (grant.artifact.is_expired(timestamp_ns)
                        || grant.invocations_used >= grant.artifact.max_invocation_count)
            })
            .map(|(grant_id, _)| grant_id.clone())
            .collect();
        for grant_id in expiring_grants {
            let expired_payload = if let Some(grant) = self.emergency_grants.get_mut(&grant_id) {
                grant.revoked = true;
                let error_code = if grant.artifact.is_expired(timestamp_ns) {
                    ESCROW_GRANT_EXPIRED_ERROR_CODE.to_string()
                } else {
                    ESCROW_GRANT_EXHAUSTED_ERROR_CODE.to_string()
                };
                Some((
                    grant.artifact.request_id.clone(),
                    grant.artifact.rollback_on_expiry,
                    error_code,
                ))
            } else {
                None
            };
            if let Some((request_id, rollback_on_expiry, error_code)) = expired_payload {
                self.transition_record(
                    &request_id,
                    CapabilityEscrowState::Expired,
                    CapabilityEscrowDecisionKind::Expire,
                    vec!["emergency_grant_expiry".to_string()],
                    vec![
                        EscrowCondition::new("grant_id", grant_id),
                        EscrowCondition::new("rollback_on_expiry", rollback_on_expiry.to_string()),
                    ],
                    timestamp_ns,
                    context,
                    "expired".to_string(),
                    Some(error_code),
                )?;
            }
        }
        Ok(())
    }

    fn consume_matching_emergency_grant(
        &mut self,
        extension_id: &str,
        capability: Capability,
        timestamp_ns: u64,
        context: &FlowEnforcementContext<'_>,
    ) -> Result<Option<String>, CapabilityEscrowError> {
        let matching_grant_id = self
            .emergency_grants
            .iter()
            .find(|(_, grant)| {
                !grant.revoked
                    && grant.artifact.extension_id == extension_id
                    && grant.artifact.capability_granted == capability
            })
            .map(|(grant_id, _)| grant_id.clone());

        let Some(grant_id) = matching_grant_id else {
            return Ok(None);
        };
        self.expire(timestamp_ns, context)?;
        let Some(grant) = self.emergency_grants.get_mut(&grant_id) else {
            return Ok(None);
        };
        if grant.revoked {
            return Ok(None);
        }
        if grant.artifact.is_expired(timestamp_ns) {
            grant.revoked = true;
            return Ok(None);
        }
        if grant.invocations_used >= grant.artifact.max_invocation_count {
            grant.revoked = true;
            return Ok(None);
        }
        grant.invocations_used = grant.invocations_used.saturating_add(1);
        Ok(Some(grant_id))
    }

    fn latest_active_approved_request(
        &self,
        extension_id: &str,
        capability: Capability,
        timestamp_ns: u64,
    ) -> Option<String> {
        self.records
            .values()
            .filter(|record| {
                record.extension_id == extension_id
                    && record.capability == capability
                    && record.state == CapabilityEscrowState::Approved
                    && timestamp_ns < record.expires_at_ns
                    && !self
                        .emergency_grant_only_requests
                        .contains(record.request_id.as_str())
            })
            .max_by_key(|record| record.updated_at_ns)
            .map(|record| record.request_id.clone())
    }

    fn open_request_count(&self, extension_id: &str) -> usize {
        self.records
            .values()
            .filter(|record| {
                record.extension_id == extension_id
                    && !matches!(
                        record.state,
                        CapabilityEscrowState::Denied | CapabilityEscrowState::Expired
                    )
            })
            .count()
    }

    fn current_state(
        &self,
        request_id: &str,
    ) -> Result<CapabilityEscrowState, CapabilityEscrowError> {
        self.records
            .get(request_id)
            .map(|record| record.state)
            .ok_or_else(|| CapabilityEscrowError::UnknownRequest {
                request_id: request_id.to_string(),
            })
    }

    fn validate_receipt_context(
        request_id: &str,
        context: &FlowEnforcementContext<'_>,
    ) -> Result<(), CapabilityEscrowError> {
        if context.trace_id.trim().is_empty() {
            return Err(CapabilityEscrowError::ReceiptEmissionFailed {
                request_id: request_id.to_string(),
                detail: "trace_id must not be empty".to_string(),
            });
        }
        if context.decision_id.trim().is_empty() {
            return Err(CapabilityEscrowError::ReceiptEmissionFailed {
                request_id: request_id.to_string(),
                detail: "decision_id must not be empty".to_string(),
            });
        }
        if context.policy_id.trim().is_empty() {
            return Err(CapabilityEscrowError::ReceiptEmissionFailed {
                request_id: request_id.to_string(),
                detail: "policy_id must not be empty".to_string(),
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_receipt(
        &self,
        request_id: &str,
        extension_id: &str,
        capability: Capability,
        decision_kind: CapabilityEscrowDecisionKind,
        next_state: CapabilityEscrowState,
        contract_chain: Vec<String>,
        conditions: Vec<EscrowCondition>,
        timestamp_ns: u64,
        context: &FlowEnforcementContext<'_>,
        outcome: String,
        error_code: Option<String>,
    ) -> Result<CapabilityEscrowDecisionReceipt, CapabilityEscrowError> {
        Self::validate_receipt_context(request_id, context)?;
        let trace_ref = format!(
            "trace:{}#decision:{}",
            context.trace_id, context.decision_id
        );
        let replay_seed = derive_escrow_replay_seed(
            request_id,
            context.trace_id,
            context.decision_id,
            context.policy_id,
            decision_kind.as_str(),
            next_state.as_str(),
            timestamp_ns,
        );
        CapabilityEscrowDecisionReceipt::new_signed(
            request_id,
            extension_id,
            capability,
            decision_kind,
            next_state,
            trace_ref.clone(),
            replay_seed,
            context.decision_id,
            context.policy_id,
            context.policy_id.to_string(),
            contract_chain,
            conditions,
            outcome,
            error_code,
            timestamp_ns,
            &self.signing_key,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transition_record(
        &mut self,
        request_id: &str,
        next_state: CapabilityEscrowState,
        decision_kind: CapabilityEscrowDecisionKind,
        contract_chain: Vec<String>,
        conditions: Vec<EscrowCondition>,
        timestamp_ns: u64,
        context: &FlowEnforcementContext<'_>,
        outcome: String,
        error_code: Option<String>,
    ) -> Result<CapabilityEscrowDecision, CapabilityEscrowError> {
        let (extension_id, capability, current_state) = self
            .records
            .get(request_id)
            .map(|record| (record.extension_id.clone(), record.capability, record.state))
            .ok_or_else(|| CapabilityEscrowError::UnknownRequest {
                request_id: request_id.to_string(),
            })?;
        if current_state != next_state && !escrow_transition_allowed(current_state, next_state) {
            return Err(CapabilityEscrowError::InvalidStateTransition {
                request_id: request_id.to_string(),
                from: current_state,
                to: next_state,
            });
        }

        let receipt = self.build_receipt(
            request_id,
            &extension_id,
            capability,
            decision_kind,
            next_state,
            contract_chain,
            conditions,
            timestamp_ns,
            context,
            outcome.clone(),
            error_code.clone(),
        )?;

        let record = self.records.get_mut(request_id).ok_or_else(|| {
            CapabilityEscrowError::UnknownRequest {
                request_id: request_id.to_string(),
            }
        })?;
        record.state = next_state;
        record.updated_at_ns = timestamp_ns;
        self.receipts.push(receipt.clone());
        self.events.push(CapabilityEscrowDecisionEvent {
            trace_id: context.trace_id.to_string(),
            trace_ref: receipt.trace_ref.clone(),
            replay_seed: receipt.replay_seed.clone(),
            decision_id: context.decision_id.to_string(),
            policy_id: context.policy_id.to_string(),
            component: CAPABILITY_ESCROW_COMPONENT.to_string(),
            event: "capability_escrow_decision".to_string(),
            outcome: outcome.clone(),
            error_code: error_code.clone(),
            extension_id: record.extension_id.clone(),
            request_id: request_id.to_string(),
            capability: record.capability,
            state: next_state,
            receipt_id: receipt.receipt_id.clone(),
        });
        self.evidence.push(CapabilityEscrowEvidence {
            extension_id: record.extension_id.clone(),
            request_id: request_id.to_string(),
            capability: record.capability,
            state: next_state,
            trace_ref: receipt.trace_ref.clone(),
            replay_seed: receipt.replay_seed.clone(),
            decision_id: context.decision_id.to_string(),
            receipt_id: receipt.receipt_id.clone(),
        });

        Ok(CapabilityEscrowDecision {
            request_id: request_id.to_string(),
            state: next_state,
            receipt_id: receipt.receipt_id,
            outcome,
            error_code,
        })
    }
}

impl Default for CapabilityEscrowGateway {
    fn default() -> Self {
        Self::with_default_contracts(DecisionSigningKey::default())
    }
}

/// Runtime dispatcher that enforces flow-label checks at hostcall boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallDispatcher {
    sink_policy: HostcallSinkPolicy,
    violation_events: Vec<FlowViolationEvent>,
    guardplane_evidence: Vec<FlowViolationEvidence>,
}

impl HostcallDispatcher {
    pub fn new(sink_policy: HostcallSinkPolicy) -> Self {
        Self {
            sink_policy,
            violation_events: Vec::new(),
            guardplane_evidence: Vec::new(),
        }
    }

    pub fn violation_events(&self) -> &[FlowViolationEvent] {
        &self.violation_events
    }

    pub fn guardplane_evidence(&self) -> &[FlowViolationEvidence] {
        &self.guardplane_evidence
    }

    pub fn dispatch<T: Clone>(
        &mut self,
        extension_id: &str,
        hostcall_type: HostcallType,
        declared_capabilities: &BTreeSet<Capability>,
        attempted_capability: Capability,
        argument: Labeled<T>,
        context: &FlowEnforcementContext<'_>,
    ) -> HostcallDispatchOutcome<T> {
        if !declared_capabilities.contains(&attempted_capability) {
            return HostcallDispatchOutcome {
                result: HostcallResult::Denied {
                    reason: DenialReason::CapabilityEscalation {
                        attempted: attempted_capability,
                    },
                },
                output: None,
            };
        }

        if let Some(clearance) = self.sink_policy.clearance_for(hostcall_type) {
            if !FlowLabelLattice::can_flow_to_sink(&argument.label, &clearance) {
                let event = FlowViolationEvent {
                    trace_id: context.trace_id.to_string(),
                    decision_id: context.decision_id.to_string(),
                    policy_id: context.policy_id.to_string(),
                    component: "runtime_flow_enforcement".to_string(),
                    event: "hostcall_flow_violation".to_string(),
                    outcome: "blocked".to_string(),
                    error_code: "FE-FLOW-0001".to_string(),
                    extension_id: extension_id.to_string(),
                    hostcall_type,
                    source_label: argument.label,
                    sink_clearance: clearance,
                };
                self.violation_events.push(event);
                self.guardplane_evidence.push(FlowViolationEvidence {
                    extension_id: extension_id.to_string(),
                    hostcall_type,
                    source_label: argument.label,
                    sink_clearance: clearance,
                    decision_id: context.decision_id.to_string(),
                });

                return HostcallDispatchOutcome {
                    result: HostcallResult::Denied {
                        reason: DenialReason::FlowViolation {
                            source: argument.label,
                            sink: clearance,
                        },
                    },
                    output: None,
                };
            }
        }

        HostcallDispatchOutcome {
            result: HostcallResult::Success,
            output: Some(argument),
        }
    }
}

const DECLASSIFICATION_COMPONENT: &str = "declassification_gateway";

/// Stable reference to data targeted by a declassification request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataRef {
    pub namespace: String,
    pub key: String,
}

impl DataRef {
    pub fn new(namespace: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            key: key.into(),
        }
    }
}

/// Explicit purpose attached to a declassification request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclassificationPurpose {
    UserConsent,
    AggregationAnonymization,
    PublicApiResponse,
    DiagnosticExport,
    OperatorOverride,
    Custom(String),
}

impl DeclassificationPurpose {
    pub fn as_str(&self) -> &str {
        match self {
            Self::UserConsent => "user_consent",
            Self::AggregationAnonymization => "aggregation_anonymization",
            Self::PublicApiResponse => "public_api_response",
            Self::DiagnosticExport => "diagnostic_export",
            Self::OperatorOverride => "operator_override",
            Self::Custom(_) => "custom",
        }
    }
}

impl fmt::Display for DeclassificationPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(value) => write!(f, "custom:{value}"),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// Mandatory input contract for declassification gateway evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationRequest {
    pub request_id: String,
    pub requester: String,
    pub data_ref: DataRef,
    pub current_label: FlowLabel,
    pub target_label: FlowLabel,
    pub purpose: DeclassificationPurpose,
    pub justification: String,
    pub timestamp_ns: u64,
}

/// Condition attached to an approved contract step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationCondition {
    pub key: String,
    pub value: String,
}

impl DeclassificationCondition {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Deferred-decision challenge descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationChallenge {
    pub challenge_type: String,
    pub detail: String,
}

/// Deterministic denial taxonomy for declassification requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeclassificationDenialReason {
    MissingCapability {
        capability: Capability,
    },
    LabelDistanceTooLarge {
        secrecy_distance: u8,
        integrity_distance: u8,
    },
    InvalidPurpose {
        purpose: DeclassificationPurpose,
        target: SecrecyLevel,
    },
    RateLimited {
        max_requests: u32,
        window_ns: u64,
    },
    NoDeclassificationRequired,
    EmptyJustification,
    ContractRejected {
        contract_id: String,
        detail: String,
    },
}

impl DeclassificationDenialReason {
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::MissingCapability { .. } => "FE-DECLASS-0001",
            Self::LabelDistanceTooLarge { .. } => "FE-DECLASS-0002",
            Self::InvalidPurpose { .. } => "FE-DECLASS-0003",
            Self::RateLimited { .. } => "FE-DECLASS-0004",
            Self::NoDeclassificationRequired => "FE-DECLASS-0005",
            Self::EmptyJustification => "FE-DECLASS-0006",
            Self::ContractRejected { .. } => "FE-DECLASS-0007",
        }
    }
}

impl fmt::Display for DeclassificationDenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCapability { capability } => {
                write!(f, "missing required capability: {capability}")
            }
            Self::LabelDistanceTooLarge {
                secrecy_distance,
                integrity_distance,
            } => write!(
                f,
                "label distance too large: secrecy_distance={secrecy_distance}, integrity_distance={integrity_distance}"
            ),
            Self::InvalidPurpose { purpose, target } => {
                write!(
                    f,
                    "purpose '{purpose}' is invalid for target secrecy {target:?}"
                )
            }
            Self::RateLimited {
                max_requests,
                window_ns,
            } => write!(
                f,
                "rate limit exceeded: max_requests={max_requests}, window_ns={window_ns}"
            ),
            Self::NoDeclassificationRequired => f.write_str("flow is already lattice-legal"),
            Self::EmptyJustification => f.write_str("justification must not be empty"),
            Self::ContractRejected {
                contract_id,
                detail,
            } => {
                write!(f, "contract '{contract_id}' rejected request: {detail}")
            }
        }
    }
}

/// Decision-contract verdict for one contract evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionVerdict {
    Approved {
        conditions: Vec<DeclassificationCondition>,
    },
    Denied {
        reason: DeclassificationDenialReason,
    },
    Deferred {
        challenge: DeclassificationChallenge,
    },
}

/// Evaluation context passed into decision contracts.
#[derive(Debug, Clone, Copy)]
pub struct DeclassificationEvaluationContext<'a> {
    requester_capabilities: &'a BTreeSet<Capability>,
    request_history: Option<&'a [u64]>,
    request_timestamp_ns: u64,
}

impl<'a> DeclassificationEvaluationContext<'a> {
    pub const fn new(
        requester_capabilities: &'a BTreeSet<Capability>,
        request_history: Option<&'a [u64]>,
        request_timestamp_ns: u64,
    ) -> Self {
        Self {
            requester_capabilities,
            request_history,
            request_timestamp_ns,
        }
    }

    pub fn has_capability(&self, capability: Capability) -> bool {
        self.requester_capabilities.contains(&capability)
    }

    pub fn request_count_within_window(&self, window_ns: u64) -> u32 {
        let lower_bound = self.request_timestamp_ns.saturating_sub(window_ns);
        self.request_history.map_or(0, |history| {
            history
                .iter()
                .filter(|timestamp| {
                    **timestamp >= lower_bound && **timestamp <= self.request_timestamp_ns
                })
                .count() as u32
        })
    }
}

/// Contract interface for composable declassification decisions.
pub trait DecisionContract: Send + Sync {
    fn contract_id(&self) -> &'static str;

    fn evaluate(
        &self,
        request: &DeclassificationRequest,
        context: &DeclassificationEvaluationContext<'_>,
    ) -> DecisionVerdict;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RequesterCapabilityContract;

impl DecisionContract for RequesterCapabilityContract {
    fn contract_id(&self) -> &'static str {
        "requester_capability"
    }

    fn evaluate(
        &self,
        _request: &DeclassificationRequest,
        context: &DeclassificationEvaluationContext<'_>,
    ) -> DecisionVerdict {
        if context.has_capability(Capability::Declassify) {
            DecisionVerdict::Approved {
                conditions: vec![DeclassificationCondition::new("capability", "declassify")],
            }
        } else {
            DecisionVerdict::Denied {
                reason: DeclassificationDenialReason::MissingCapability {
                    capability: Capability::Declassify,
                },
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LabelDistanceContract;

impl DecisionContract for LabelDistanceContract {
    fn contract_id(&self) -> &'static str {
        "label_distance"
    }

    fn evaluate(
        &self,
        request: &DeclassificationRequest,
        _context: &DeclassificationEvaluationContext<'_>,
    ) -> DecisionVerdict {
        let secrecy_distance = secrecy_drop_levels(request.current_label, request.target_label);
        let integrity_distance =
            integrity_raise_levels(request.current_label, request.target_label);
        let max_distance = secrecy_distance.max(integrity_distance);

        if max_distance == 0 {
            return DecisionVerdict::Denied {
                reason: DeclassificationDenialReason::NoDeclassificationRequired,
            };
        }

        if max_distance > 1 && !matches!(request.purpose, DeclassificationPurpose::OperatorOverride)
        {
            return DecisionVerdict::Denied {
                reason: DeclassificationDenialReason::LabelDistanceTooLarge {
                    secrecy_distance,
                    integrity_distance,
                },
            };
        }

        DecisionVerdict::Approved {
            conditions: vec![DeclassificationCondition::new(
                "label_distance",
                max_distance.to_string(),
            )],
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PurposeValidityContract;

impl DecisionContract for PurposeValidityContract {
    fn contract_id(&self) -> &'static str {
        "purpose_validity"
    }

    fn evaluate(
        &self,
        request: &DeclassificationRequest,
        _context: &DeclassificationEvaluationContext<'_>,
    ) -> DecisionVerdict {
        if purpose_allowed_for_target(&request.purpose, request.target_label.secrecy()) {
            DecisionVerdict::Approved {
                conditions: vec![DeclassificationCondition::new(
                    "purpose",
                    request.purpose.to_string(),
                )],
            }
        } else {
            DecisionVerdict::Denied {
                reason: DeclassificationDenialReason::InvalidPurpose {
                    purpose: request.purpose.clone(),
                    target: request.target_label.secrecy(),
                },
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitContract {
    pub max_requests: u32,
    pub window_ns: u64,
}

impl RateLimitContract {
    pub const fn new(max_requests: u32, window_ns: u64) -> Self {
        Self {
            max_requests,
            window_ns,
        }
    }
}

impl DecisionContract for RateLimitContract {
    fn contract_id(&self) -> &'static str {
        "rate_limit"
    }

    fn evaluate(
        &self,
        _request: &DeclassificationRequest,
        context: &DeclassificationEvaluationContext<'_>,
    ) -> DecisionVerdict {
        let count = context.request_count_within_window(self.window_ns);
        if count >= self.max_requests {
            DecisionVerdict::Denied {
                reason: DeclassificationDenialReason::RateLimited {
                    max_requests: self.max_requests,
                    window_ns: self.window_ns,
                },
            }
        } else {
            DecisionVerdict::Approved {
                conditions: vec![DeclassificationCondition::new(
                    "rate_limit_remaining",
                    (self.max_requests - count - 1).to_string(),
                )],
            }
        }
    }
}

/// Symmetric key used for deterministic decision receipt signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionSigningKey {
    bytes: [u8; 32],
}

impl Default for DecisionSigningKey {
    fn default() -> Self {
        Self { bytes: [0x42; 32] }
    }
}

impl DecisionSigningKey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub const fn public_key(self) -> DecisionPublicKey {
        DecisionPublicKey { bytes: self.bytes }
    }

    pub fn sign(&self, payload: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.bytes);
        hasher.update(payload);
        let digest = hasher.finalize();
        let mut signature = [0u8; 32];
        signature.copy_from_slice(&digest);
        signature
    }
}

/// Offline-verifiable public key counterpart for decision receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionPublicKey {
    bytes: [u8; 32],
}

impl DecisionPublicKey {
    pub fn verify(&self, payload: &[u8], signature: &[u8; 32]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.bytes);
        hasher.update(payload);
        let digest = hasher.finalize();
        digest.as_slice() == signature
    }
}

/// Signed decision receipt for approved/denied/deferred declassification outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptographicDecisionReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub verdict: DecisionVerdict,
    pub contract_chain: Vec<String>,
    pub conditions: Vec<DeclassificationCondition>,
    pub posterior_at_decision_micros: u64,
    pub timestamp_ns: u64,
    pub signature: [u8; 32],
}

#[derive(Serialize)]
struct ReceiptSigningPayload<'a> {
    receipt_id: &'a str,
    request_id: &'a str,
    verdict: &'a DecisionVerdict,
    contract_chain: &'a [String],
    conditions: &'a [DeclassificationCondition],
    posterior_at_decision_micros: u64,
    timestamp_ns: u64,
}

impl CryptographicDecisionReceipt {
    fn new_signed(
        request_id: &str,
        verdict: DecisionVerdict,
        contract_chain: Vec<String>,
        conditions: Vec<DeclassificationCondition>,
        posterior_at_decision_micros: u64,
        timestamp_ns: u64,
        signer: &DecisionSigningKey,
    ) -> Self {
        let outcome_tag = match &verdict {
            DecisionVerdict::Approved { .. } => "approved",
            DecisionVerdict::Denied { .. } => "denied",
            DecisionVerdict::Deferred { .. } => "deferred",
        };
        let receipt_id = derive_receipt_id(request_id, timestamp_ns, outcome_tag);
        let payload = ReceiptSigningPayload {
            receipt_id: &receipt_id,
            request_id,
            verdict: &verdict,
            contract_chain: &contract_chain,
            conditions: &conditions,
            posterior_at_decision_micros,
            timestamp_ns,
        };
        let signature = signer
            .sign(&serde_json::to_vec(&payload).expect("receipt signing payload should serialize"));
        Self {
            receipt_id,
            request_id: request_id.to_string(),
            verdict,
            contract_chain,
            conditions,
            posterior_at_decision_micros,
            timestamp_ns,
            signature,
        }
    }

    fn signing_payload_bytes(&self) -> Vec<u8> {
        let payload = ReceiptSigningPayload {
            receipt_id: &self.receipt_id,
            request_id: &self.request_id,
            verdict: &self.verdict,
            contract_chain: &self.contract_chain,
            conditions: &self.conditions,
            posterior_at_decision_micros: self.posterior_at_decision_micros,
            timestamp_ns: self.timestamp_ns,
        };
        serde_json::to_vec(&payload).expect("receipt signing payload should serialize")
    }

    pub fn verify(&self, public_key: &DecisionPublicKey) -> bool {
        public_key.verify(&self.signing_payload_bytes(), &self.signature)
    }
}

/// Append-only receipt log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceiptLog {
    receipts: Vec<CryptographicDecisionReceipt>,
}

impl DecisionReceiptLog {
    pub fn append(&mut self, receipt: CryptographicDecisionReceipt) {
        self.receipts.push(receipt);
    }

    pub fn receipts(&self) -> &[CryptographicDecisionReceipt] {
        &self.receipts
    }
}

/// Structured stable event for declassification contract outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationDecisionEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub request_id: String,
    pub requester: String,
    pub receipt_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclassificationEvidenceSeverity {
    High,
    Critical,
}

/// Guardplane evidence emitted on denied declassification requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationDeniedEvidence {
    pub request_id: String,
    pub requester: String,
    pub reason: DeclassificationDenialReason,
    pub severity: DeclassificationEvidenceSeverity,
    pub label_distance: u8,
    pub decision_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeclassificationOutcome {
    Approved {
        new_label: FlowLabel,
        receipt: CryptographicDecisionReceipt,
    },
    Denied {
        reason: DeclassificationDenialReason,
        receipt: CryptographicDecisionReceipt,
    },
    Deferred {
        challenge: DeclassificationChallenge,
        receipt: CryptographicDecisionReceipt,
    },
}

/// Mandatory gateway for all runtime declassification requests.
pub struct DeclassificationGateway {
    contracts: Vec<Box<dyn DecisionContract>>,
    signing_key: DecisionSigningKey,
    receipt_log: DecisionReceiptLog,
    events: Vec<DeclassificationDecisionEvent>,
    denied_evidence: Vec<DeclassificationDeniedEvidence>,
    request_history_by_requester: BTreeMap<String, Vec<u64>>,
}

impl DeclassificationGateway {
    pub fn with_default_contracts(signing_key: DecisionSigningKey) -> Self {
        let contracts: Vec<Box<dyn DecisionContract>> = vec![
            Box::new(RequesterCapabilityContract),
            Box::new(LabelDistanceContract),
            Box::new(PurposeValidityContract),
            Box::new(RateLimitContract::new(8, 60_000_000_000)),
        ];
        Self::new(signing_key, contracts)
    }

    pub fn new(signing_key: DecisionSigningKey, contracts: Vec<Box<dyn DecisionContract>>) -> Self {
        Self {
            contracts,
            signing_key,
            receipt_log: DecisionReceiptLog::default(),
            events: Vec::new(),
            denied_evidence: Vec::new(),
            request_history_by_requester: BTreeMap::new(),
        }
    }

    pub fn receipt_log(&self) -> &DecisionReceiptLog {
        &self.receipt_log
    }

    pub fn events(&self) -> &[DeclassificationDecisionEvent] {
        &self.events
    }

    pub fn denied_evidence(&self) -> &[DeclassificationDeniedEvidence] {
        &self.denied_evidence
    }

    pub fn public_key(&self) -> DecisionPublicKey {
        self.signing_key.public_key()
    }

    pub fn evaluate_request(
        &mut self,
        request: DeclassificationRequest,
        requester_capabilities: &BTreeSet<Capability>,
        posterior_at_decision_micros: u64,
        context: &FlowEnforcementContext<'_>,
    ) -> DeclassificationOutcome {
        let mut contract_chain = Vec::new();
        let mut conditions = Vec::new();
        let mut verdict_override = None;

        if request.justification.trim().is_empty() {
            verdict_override = Some(DecisionVerdict::Denied {
                reason: DeclassificationDenialReason::EmptyJustification,
            });
        } else if FlowLabelLattice::can_flow(&request.current_label, &request.target_label) {
            verdict_override = Some(DecisionVerdict::Denied {
                reason: DeclassificationDenialReason::NoDeclassificationRequired,
            });
        }

        let verdict = if let Some(verdict) = verdict_override {
            verdict
        } else {
            let request_history = self
                .request_history_by_requester
                .get(request.requester.as_str())
                .map(Vec::as_slice);
            let eval_context = DeclassificationEvaluationContext::new(
                requester_capabilities,
                request_history,
                request.timestamp_ns,
            );
            let mut terminal_verdict = None;

            for contract in &self.contracts {
                contract_chain.push(contract.contract_id().to_string());
                match contract.evaluate(&request, &eval_context) {
                    DecisionVerdict::Approved {
                        conditions: contract_conditions,
                    } => {
                        conditions.extend(contract_conditions);
                    }
                    DecisionVerdict::Denied { reason } => {
                        terminal_verdict = Some(DecisionVerdict::Denied { reason });
                        break;
                    }
                    DecisionVerdict::Deferred { challenge } => {
                        terminal_verdict = Some(DecisionVerdict::Deferred { challenge });
                        break;
                    }
                }
            }

            terminal_verdict.unwrap_or_else(|| DecisionVerdict::Approved {
                conditions: conditions.clone(),
            })
        };

        let receipt = CryptographicDecisionReceipt::new_signed(
            &request.request_id,
            verdict.clone(),
            contract_chain,
            conditions,
            posterior_at_decision_micros,
            request.timestamp_ns,
            &self.signing_key,
        );
        self.receipt_log.append(receipt.clone());
        self.request_history_by_requester
            .entry(request.requester.clone())
            .or_default()
            .push(request.timestamp_ns);

        let (outcome, error_code) = match verdict {
            DecisionVerdict::Approved { .. } => {
                self.events.push(DeclassificationDecisionEvent {
                    trace_id: context.trace_id.to_string(),
                    decision_id: context.decision_id.to_string(),
                    policy_id: context.policy_id.to_string(),
                    component: DECLASSIFICATION_COMPONENT.to_string(),
                    event: "declassification_request".to_string(),
                    outcome: "approved".to_string(),
                    error_code: None,
                    request_id: request.request_id,
                    requester: request.requester,
                    receipt_id: receipt.receipt_id.clone(),
                });
                (
                    DeclassificationOutcome::Approved {
                        new_label: request.target_label,
                        receipt,
                    },
                    None,
                )
            }
            DecisionVerdict::Denied { reason } => {
                let label_distance =
                    declassification_label_distance(request.current_label, request.target_label);
                self.denied_evidence.push(DeclassificationDeniedEvidence {
                    request_id: request.request_id.clone(),
                    requester: request.requester.clone(),
                    reason: reason.clone(),
                    severity: denial_severity(label_distance),
                    label_distance,
                    decision_id: context.decision_id.to_string(),
                });
                let error_code_value = reason.error_code().to_string();
                self.events.push(DeclassificationDecisionEvent {
                    trace_id: context.trace_id.to_string(),
                    decision_id: context.decision_id.to_string(),
                    policy_id: context.policy_id.to_string(),
                    component: DECLASSIFICATION_COMPONENT.to_string(),
                    event: "declassification_request".to_string(),
                    outcome: "denied".to_string(),
                    error_code: Some(error_code_value.clone()),
                    request_id: request.request_id,
                    requester: request.requester,
                    receipt_id: receipt.receipt_id.clone(),
                });
                (
                    DeclassificationOutcome::Denied { reason, receipt },
                    Some(error_code_value),
                )
            }
            DecisionVerdict::Deferred { challenge } => {
                self.events.push(DeclassificationDecisionEvent {
                    trace_id: context.trace_id.to_string(),
                    decision_id: context.decision_id.to_string(),
                    policy_id: context.policy_id.to_string(),
                    component: DECLASSIFICATION_COMPONENT.to_string(),
                    event: "declassification_request".to_string(),
                    outcome: "deferred".to_string(),
                    error_code: Some("FE-DECLASS-0008".to_string()),
                    request_id: request.request_id,
                    requester: request.requester,
                    receipt_id: receipt.receipt_id.clone(),
                });
                (
                    DeclassificationOutcome::Deferred { challenge, receipt },
                    Some("FE-DECLASS-0008".to_string()),
                )
            }
        };

        let _ = error_code;
        outcome
    }
}

impl Default for DeclassificationGateway {
    fn default() -> Self {
        Self::with_default_contracts(DecisionSigningKey::default())
    }
}

fn purpose_allowed_for_target(purpose: &DeclassificationPurpose, target: SecrecyLevel) -> bool {
    match target {
        SecrecyLevel::Public => matches!(
            purpose,
            DeclassificationPurpose::UserConsent
                | DeclassificationPurpose::AggregationAnonymization
                | DeclassificationPurpose::PublicApiResponse
                | DeclassificationPurpose::DiagnosticExport
                | DeclassificationPurpose::OperatorOverride
                | DeclassificationPurpose::Custom(_)
        ),
        SecrecyLevel::Internal => matches!(
            purpose,
            DeclassificationPurpose::UserConsent
                | DeclassificationPurpose::AggregationAnonymization
                | DeclassificationPurpose::DiagnosticExport
                | DeclassificationPurpose::OperatorOverride
                | DeclassificationPurpose::Custom(_)
        ),
        SecrecyLevel::Confidential => matches!(
            purpose,
            DeclassificationPurpose::UserConsent
                | DeclassificationPurpose::AggregationAnonymization
                | DeclassificationPurpose::DiagnosticExport
                | DeclassificationPurpose::OperatorOverride
        ),
        SecrecyLevel::Secret => matches!(
            purpose,
            DeclassificationPurpose::UserConsent | DeclassificationPurpose::OperatorOverride
        ),
        SecrecyLevel::TopSecret => matches!(purpose, DeclassificationPurpose::OperatorOverride),
    }
}

const fn secrecy_drop_levels(current: FlowLabel, target: FlowLabel) -> u8 {
    current
        .secrecy()
        .rank()
        .saturating_sub(target.secrecy().rank())
}

const fn integrity_raise_levels(current: FlowLabel, target: FlowLabel) -> u8 {
    target
        .integrity()
        .rank()
        .saturating_sub(current.integrity().rank())
}

const fn declassification_label_distance(current: FlowLabel, target: FlowLabel) -> u8 {
    let secrecy_distance = secrecy_drop_levels(current, target);
    let integrity_distance = integrity_raise_levels(current, target);
    if secrecy_distance > integrity_distance {
        secrecy_distance
    } else {
        integrity_distance
    }
}

const fn denial_severity(distance: u8) -> DeclassificationEvidenceSeverity {
    if distance >= 3 {
        DeclassificationEvidenceSeverity::Critical
    } else {
        DeclassificationEvidenceSeverity::High
    }
}

const fn escrow_transition_allowed(from: CapabilityEscrowState, to: CapabilityEscrowState) -> bool {
    matches!(
        (from, to),
        (
            CapabilityEscrowState::Requested,
            CapabilityEscrowState::Challenged
        ) | (
            CapabilityEscrowState::Requested,
            CapabilityEscrowState::Sandboxed
        ) | (
            CapabilityEscrowState::Requested,
            CapabilityEscrowState::Approved
        ) | (
            CapabilityEscrowState::Requested,
            CapabilityEscrowState::Denied
        ) | (
            CapabilityEscrowState::Requested,
            CapabilityEscrowState::Expired
        ) | (
            CapabilityEscrowState::Challenged,
            CapabilityEscrowState::Sandboxed
        ) | (
            CapabilityEscrowState::Challenged,
            CapabilityEscrowState::Approved
        ) | (
            CapabilityEscrowState::Challenged,
            CapabilityEscrowState::Denied
        ) | (
            CapabilityEscrowState::Challenged,
            CapabilityEscrowState::Expired
        ) | (
            CapabilityEscrowState::Sandboxed,
            CapabilityEscrowState::Challenged
        ) | (
            CapabilityEscrowState::Sandboxed,
            CapabilityEscrowState::Approved
        ) | (
            CapabilityEscrowState::Sandboxed,
            CapabilityEscrowState::Denied
        ) | (
            CapabilityEscrowState::Sandboxed,
            CapabilityEscrowState::Expired
        ) | (
            CapabilityEscrowState::Approved,
            CapabilityEscrowState::Expired
        ) | (
            CapabilityEscrowState::Approved,
            CapabilityEscrowState::Approved
        ) | (CapabilityEscrowState::Denied, CapabilityEscrowState::Denied)
            | (
                CapabilityEscrowState::Expired,
                CapabilityEscrowState::Expired
            )
    )
}

fn derive_escrow_receipt_id(
    request_id: &str,
    timestamp_ns: u64,
    decision_tag: &str,
    state_tag: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request_id.as_bytes());
    hasher.update(timestamp_ns.to_le_bytes());
    hasher.update(decision_tag.as_bytes());
    hasher.update(state_tag.as_bytes());
    let digest = hasher.finalize();
    format!("escr-{}", to_hex(&digest[..12]))
}

#[allow(clippy::too_many_arguments)]
fn derive_escrow_replay_seed(
    request_id: &str,
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    decision_tag: &str,
    state_tag: &str,
    timestamp_ns: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request_id.as_bytes());
    hasher.update(trace_id.as_bytes());
    hasher.update(decision_id.as_bytes());
    hasher.update(policy_id.as_bytes());
    hasher.update(decision_tag.as_bytes());
    hasher.update(state_tag.as_bytes());
    hasher.update(timestamp_ns.to_le_bytes());
    let digest = hasher.finalize();
    format!("replay-{}", to_hex(&digest[..16]))
}

fn derive_escrow_request_id(
    extension_id: &str,
    capability: Capability,
    hostcall_type: HostcallType,
    timestamp_ns: u64,
    sequence: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(extension_id.as_bytes());
    hasher.update(capability.as_str().as_bytes());
    hasher.update(hostcall_type.as_str().as_bytes());
    hasher.update(timestamp_ns.to_le_bytes());
    hasher.update(sequence.to_le_bytes());
    let digest = hasher.finalize();
    format!("esc-{}", to_hex(&digest[..12]))
}

fn derive_emergency_grant_id(request_id: &str, actor: &str, issued_at_ns: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request_id.as_bytes());
    hasher.update(actor.as_bytes());
    hasher.update(issued_at_ns.to_le_bytes());
    let digest = hasher.finalize();
    format!("egrant-{}", to_hex(&digest[..12]))
}

fn derive_receipt_id(request_id: &str, timestamp_ns: u64, outcome_tag: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request_id.as_bytes());
    hasher.update(timestamp_ns.to_le_bytes());
    hasher.update(outcome_tag.as_bytes());
    let digest = hasher.finalize();
    format!("dcr-{}", to_hex(&digest[..12]))
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub const MAX_DELEGATE_LIFETIME_NS: u64 = 86_400_000_000_000;
pub const MAX_DELEGATE_CPU_BUDGET_NS: u64 = 60_000_000_000;
pub const MAX_DELEGATE_MEMORY_BUDGET_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_DELEGATE_HOSTCALL_BUDGET: u64 = 100_000;
const DELEGATE_COMPONENT: &str = "delegate_cell_policy";

/// Delegate-cell scope authorizing specific runtime-internal operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationScope {
    ModuleReplacement,
    ConfigUpdate,
    DiagnosticCollection,
    TrustChainRotation,
    Custom(String),
}

impl DelegationScope {
    pub fn as_str(&self) -> &str {
        match self {
            Self::ModuleReplacement => "module_replacement",
            Self::ConfigUpdate => "config_update",
            Self::DiagnosticCollection => "diagnostic_collection",
            Self::TrustChainRotation => "trust_chain_rotation",
            Self::Custom(_) => "custom",
        }
    }
}

impl fmt::Display for DelegationScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(value) => write!(f, "custom:{value}"),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// Extension manifest extension for delegate-cell creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateCellManifest {
    pub base_manifest: ExtensionManifest,
    pub delegation_scope: DelegationScope,
    pub delegator_id: String,
    pub max_lifetime_ns: u64,
}

/// Configurable guardplane tuning for delegate-cell risk updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateCellPolicy {
    pub initial_posterior_micros: u64,
    pub capability_escalation_penalty_micros: u64,
    pub flow_violation_penalty_micros: u64,
    pub declassification_denial_penalty_micros: u64,
    pub false_positive_cost_micros: u64,
    pub false_negative_cost_micros: u64,
}

const GUARDPLANE_MAX_POSTERIOR_MICROS: u64 = 1_000_000;
const GUARDPLANE_CHALLENGE_THRESHOLD_MICROS: u64 = 250_000;
const GUARDPLANE_SANDBOX_THRESHOLD_MICROS: u64 = 400_000;
const GUARDPLANE_SUSPEND_THRESHOLD_MICROS: u64 = 550_000;
const GUARDPLANE_TERMINATE_THRESHOLD_MICROS: u64 = 700_000;
const GUARDPLANE_QUARANTINE_THRESHOLD_MICROS: u64 = 850_000;
const GUARDPLANE_DECISION_LOG_SCHEMA_VERSION: &str = "franken-engine.guardplane-decision-log.v1";
const CONTAINMENT_WORKFLOW_LOG_SCHEMA_VERSION: &str = "franken-engine.containment-workflow-log.v1";
const DELEGATE_MESH_PROPAGATION_DEGRADED_ERROR_CODE: &str = "FE-DELEGATE-0008";

impl Default for DelegateCellPolicy {
    fn default() -> Self {
        Self {
            initial_posterior_micros: 200_000,
            capability_escalation_penalty_micros: 220_000,
            flow_violation_penalty_micros: 150_000,
            declassification_denial_penalty_micros: 110_000,
            false_positive_cost_micros: 400_000,
            false_negative_cost_micros: 850_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateGuardplaneState {
    pub delegate_id: String,
    pub posterior_micros: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardplanePolicyAction {
    Allow,
    Challenge,
    Sandbox,
    Suspend,
    Terminate,
    Quarantine,
}

impl GuardplanePolicyAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Challenge => "challenge",
            Self::Sandbox => "sandbox",
            Self::Suspend => "suspend",
            Self::Terminate => "terminate",
            Self::Quarantine => "quarantine",
        }
    }

    pub const fn fail_closed_fallback(self) -> Self {
        match self {
            Self::Allow | Self::Challenge => Self::Sandbox,
            Self::Sandbox => Self::Suspend,
            Self::Suspend => Self::Terminate,
            Self::Terminate | Self::Quarantine => Self::Quarantine,
        }
    }

    pub const fn is_containment_action(self) -> bool {
        matches!(
            self,
            Self::Sandbox | Self::Suspend | Self::Terminate | Self::Quarantine
        )
    }
}

impl fmt::Display for GuardplanePolicyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardplaneDecisionLogEntry {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub source_event: String,
    pub delegate_id: String,
    pub timestamp_ns: u64,
    pub posterior_micros: u64,
    pub action: GuardplanePolicyAction,
    pub safe_mode_fallback: bool,
    pub lifecycle_transition: Option<LifecycleTransition>,
    pub resulting_state: ExtensionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentWorkflowLogEntry {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub source_event: String,
    pub delegate_id: String,
    pub timestamp_ns: u64,
    pub action: GuardplanePolicyAction,
    pub lifecycle_transition: Option<LifecycleTransition>,
    pub resulting_state: ExtensionState,
    pub mesh_attempted_targets: Vec<String>,
    pub mesh_targets: Vec<String>,
    pub mesh_failed_targets: Vec<String>,
    pub mesh_propagated: bool,
}

/// Stable structured event for delegate-cell operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateCellEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub delegate_id: String,
    pub delegation_scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegateCellEvidence {
    FlowViolation(FlowViolationEvidence),
    CapabilityEscalation {
        delegate_id: String,
        attempted: Capability,
        decision_id: String,
    },
    CapabilityEscrow(CapabilityEscrowEvidence),
    DeclassificationDenied(DeclassificationDeniedEvidence),
    ContainmentAction {
        delegate_id: String,
        action: GuardplanePolicyAction,
        lifecycle_transition: Option<LifecycleTransition>,
        mesh_attempted_targets: Vec<String>,
        mesh_targets: Vec<String>,
        mesh_failed_targets: Vec<String>,
        mesh_propagated: bool,
        timestamp_ns: u64,
    },
    LifetimeExpired {
        delegate_id: String,
        expired_at_ns: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegateCellError {
    InvalidDelegateId,
    InvalidDelegatorId,
    InvalidMaxLifetime {
        requested_ns: u64,
    },
    MissingCapabilities,
    InvalidBudget {
        field: &'static str,
        value: u64,
        max_allowed: u64,
    },
    ManifestValidation(ManifestValidationError),
    Lifecycle(LifecycleError),
    CapabilityEscrow(CapabilityEscrowError),
    InactiveState {
        delegate_id: String,
        state: ExtensionState,
        action: &'static str,
    },
    LifetimeExpired {
        delegate_id: String,
        expired_at_ns: u64,
    },
}

impl fmt::Display for DelegateCellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDelegateId => f.write_str("delegate_id must not be empty"),
            Self::InvalidDelegatorId => f.write_str("delegator_id must not be empty"),
            Self::InvalidMaxLifetime { requested_ns } => write!(
                f,
                "max_lifetime_ns must be in 1..={MAX_DELEGATE_LIFETIME_NS}, got {requested_ns}"
            ),
            Self::MissingCapabilities => f.write_str("delegate manifest must declare capabilities"),
            Self::InvalidBudget {
                field,
                value,
                max_allowed,
            } => write!(
                f,
                "delegate budget {field} out of bounds: value={value}, max_allowed={max_allowed}"
            ),
            Self::ManifestValidation(error) => {
                write!(f, "delegate manifest validation failed: {error}")
            }
            Self::Lifecycle(error) => write!(f, "delegate lifecycle error: {error}"),
            Self::CapabilityEscrow(error) => {
                write!(f, "delegate capability escrow error: {error}")
            }
            Self::InactiveState {
                delegate_id,
                state,
                action,
            } => write!(
                f,
                "delegate '{delegate_id}' cannot {action} while in {state}"
            ),
            Self::LifetimeExpired {
                delegate_id,
                expired_at_ns,
            } => write!(
                f,
                "delegate '{delegate_id}' exceeded max lifetime at {expired_at_ns}"
            ),
        }
    }
}

impl std::error::Error for DelegateCellError {}

impl From<ManifestValidationError> for DelegateCellError {
    fn from(value: ManifestValidationError) -> Self {
        Self::ManifestValidation(value)
    }
}

impl From<LifecycleError> for DelegateCellError {
    fn from(value: LifecycleError) -> Self {
        Self::Lifecycle(value)
    }
}

impl From<CapabilityEscrowError> for DelegateCellError {
    fn from(value: CapabilityEscrowError) -> Self {
        Self::CapabilityEscrow(value)
    }
}

impl DelegateCellManifest {
    pub fn validate(&self) -> Result<(), DelegateCellError> {
        if self.delegator_id.trim().is_empty() {
            return Err(DelegateCellError::InvalidDelegatorId);
        }
        if self.max_lifetime_ns == 0 || self.max_lifetime_ns > MAX_DELEGATE_LIFETIME_NS {
            return Err(DelegateCellError::InvalidMaxLifetime {
                requested_ns: self.max_lifetime_ns,
            });
        }
        if self.base_manifest.capabilities.is_empty() {
            return Err(DelegateCellError::MissingCapabilities);
        }
        validate_manifest(&self.base_manifest)?;
        Ok(())
    }
}

/// Runtime representation of a delegate cell that must follow extension security policy.
pub struct DelegateCell {
    delegate_id: String,
    manifest: DelegateCellManifest,
    lifecycle_manager: ExtensionLifecycleManager,
    hostcall_dispatcher: HostcallDispatcher,
    capability_escrow_gateway: CapabilityEscrowGateway,
    declassification_gateway: DeclassificationGateway,
    guardplane_state: DelegateGuardplaneState,
    policy: DelegateCellPolicy,
    created_at_ns: u64,
    expires_at_ns: u64,
    lifetime_expired_recorded: bool,
    events: Vec<DelegateCellEvent>,
    quarantine_mesh_peers: BTreeSet<String>,
    quarantine_mesh_unreachable_peers: BTreeSet<String>,
    guardplane_decision_log: Vec<GuardplaneDecisionLogEntry>,
    containment_workflow_log: Vec<ContainmentWorkflowLogEntry>,
    evidence: Vec<DelegateCellEvidence>,
    capability_escrow_evidence_cursor: usize,
    adaptive_components_available: bool,
}

impl DelegateCell {
    pub fn delegate_id(&self) -> &str {
        &self.delegate_id
    }

    pub fn manifest(&self) -> &DelegateCellManifest {
        &self.manifest
    }

    pub const fn created_at_ns(&self) -> u64 {
        self.created_at_ns
    }

    pub const fn expires_at_ns(&self) -> u64 {
        self.expires_at_ns
    }

    pub fn state(&self) -> ExtensionState {
        self.lifecycle_manager.state()
    }

    pub fn guardplane_state(&self) -> &DelegateGuardplaneState {
        &self.guardplane_state
    }

    pub fn lifecycle_manager(&self) -> &ExtensionLifecycleManager {
        &self.lifecycle_manager
    }

    pub fn hostcall_violation_events(&self) -> &[FlowViolationEvent] {
        self.hostcall_dispatcher.violation_events()
    }

    pub fn declassification_receipts(&self) -> &[CryptographicDecisionReceipt] {
        self.declassification_gateway.receipt_log().receipts()
    }

    pub fn capability_escrow_records(&self) -> &BTreeMap<String, CapabilityEscrowRecord> {
        self.capability_escrow_gateway.records()
    }

    pub fn capability_escrow_receipts(&self) -> &[CapabilityEscrowDecisionReceipt] {
        self.capability_escrow_gateway.receipts()
    }

    pub fn capability_escrow_events(&self) -> &[CapabilityEscrowDecisionEvent] {
        self.capability_escrow_gateway.events()
    }

    pub fn query_capability_escrow_receipts(
        &self,
        query: &CapabilityEscrowReceiptQuery,
    ) -> Vec<&CapabilityEscrowDecisionReceipt> {
        self.capability_escrow_gateway.query_receipts(query)
    }

    pub fn capability_escrow_replay_context(
        &self,
        receipt_id: &str,
    ) -> Option<CapabilityEscrowReplayContext> {
        self.capability_escrow_gateway
            .replay_context_for_receipt(receipt_id)
    }

    pub fn capability_escrow_receipt_completeness(
        &self,
    ) -> CapabilityEscrowReceiptCompletenessReport {
        self.capability_escrow_gateway.receipt_completeness_report()
    }

    pub fn capability_escrow_public_key(&self) -> DecisionPublicKey {
        self.capability_escrow_gateway.public_key()
    }

    pub fn active_emergency_grants(&self) -> Vec<EmergencyGrantArtifact> {
        self.capability_escrow_gateway.active_emergency_grants()
    }

    pub fn pending_emergency_post_reviews(&self) -> &BTreeSet<String> {
        self.capability_escrow_gateway.pending_post_reviews()
    }

    pub fn approve_capability_escrow_request(
        &mut self,
        request_id: &str,
        timestamp_ns: u64,
        flow_context: &FlowEnforcementContext<'_>,
    ) -> Result<CapabilityEscrowDecisionReceipt, DelegateCellError> {
        let receipt = self.capability_escrow_gateway.approve_request(
            request_id,
            timestamp_ns,
            flow_context,
        )?;
        self.sync_capability_escrow_evidence();
        Ok(receipt)
    }

    pub fn deny_capability_escrow_request(
        &mut self,
        request_id: &str,
        reason: impl Into<String>,
        timestamp_ns: u64,
        flow_context: &FlowEnforcementContext<'_>,
    ) -> Result<CapabilityEscrowDecisionReceipt, DelegateCellError> {
        let receipt = self.capability_escrow_gateway.deny_request(
            request_id,
            reason,
            timestamp_ns,
            flow_context,
        )?;
        self.sync_capability_escrow_evidence();
        Ok(receipt)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_emergency_capability_grant(
        &mut self,
        request_id: &str,
        authorized_actor: &str,
        justification: &str,
        expiry_timestamp: u64,
        max_invocation_count: u32,
        mandatory_post_review: bool,
        rollback_on_expiry: bool,
        timestamp_ns: u64,
        flow_context: &FlowEnforcementContext<'_>,
    ) -> Result<EmergencyGrantArtifact, DelegateCellError> {
        let artifact = self.capability_escrow_gateway.issue_emergency_grant(
            request_id,
            authorized_actor,
            justification,
            expiry_timestamp,
            max_invocation_count,
            mandatory_post_review,
            rollback_on_expiry,
            timestamp_ns,
            flow_context,
        )?;
        self.sync_capability_escrow_evidence();
        Ok(artifact)
    }

    pub fn complete_emergency_post_review(
        &mut self,
        grant_id: &str,
    ) -> Result<(), DelegateCellError> {
        self.capability_escrow_gateway
            .complete_post_review(grant_id)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_capability_emergency_grant(
        &mut self,
        request_id: &str,
        authorized_actor: &str,
        justification: &str,
        expiry_timestamp: u64,
        max_invocation_count: u32,
        mandatory_post_review: bool,
        rollback_on_expiry: bool,
        timestamp_ns: u64,
        flow_context: &FlowEnforcementContext<'_>,
    ) -> Result<EmergencyGrantArtifact, DelegateCellError> {
        self.issue_emergency_capability_grant(
            request_id,
            authorized_actor,
            justification,
            expiry_timestamp,
            max_invocation_count,
            mandatory_post_review,
            rollback_on_expiry,
            timestamp_ns,
            flow_context,
        )
    }

    pub fn complete_capability_post_review(
        &mut self,
        grant_id: &str,
    ) -> Result<(), DelegateCellError> {
        self.complete_emergency_post_review(grant_id)
    }

    pub fn capability_escrow_pending_post_reviews(&self) -> &BTreeSet<String> {
        self.pending_emergency_post_reviews()
    }

    pub fn capability_escrow_active_emergency_grants(&self) -> Vec<EmergencyGrantArtifact> {
        self.active_emergency_grants()
    }

    pub fn expire_capability_escrow(
        &mut self,
        timestamp_ns: u64,
        flow_context: &FlowEnforcementContext<'_>,
    ) -> Result<(), DelegateCellError> {
        self.capability_escrow_gateway
            .expire(timestamp_ns, flow_context)?;
        self.sync_capability_escrow_evidence();
        Ok(())
    }

    pub fn events(&self) -> &[DelegateCellEvent] {
        &self.events
    }

    pub fn guardplane_decision_log(&self) -> &[GuardplaneDecisionLogEntry] {
        &self.guardplane_decision_log
    }

    pub fn containment_workflow_log(&self) -> &[ContainmentWorkflowLogEntry] {
        &self.containment_workflow_log
    }

    pub fn quarantine_mesh_peers(&self) -> &BTreeSet<String> {
        &self.quarantine_mesh_peers
    }

    pub fn quarantine_mesh_unreachable_peers(&self) -> &BTreeSet<String> {
        &self.quarantine_mesh_unreachable_peers
    }

    pub fn set_quarantine_mesh_peers<I, S>(&mut self, peers: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut normalized = BTreeSet::new();
        for peer in peers {
            let peer = peer.into();
            if !peer.trim().is_empty() {
                normalized.insert(peer);
            }
        }
        self.quarantine_mesh_peers = normalized;
        self.quarantine_mesh_unreachable_peers
            .retain(|peer| self.quarantine_mesh_peers.contains(peer));
    }

    pub fn set_quarantine_mesh_unreachable_peers<I, S>(&mut self, peers: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut normalized = BTreeSet::new();
        for peer in peers {
            let peer = peer.into();
            if !peer.trim().is_empty() && self.quarantine_mesh_peers.contains(&peer) {
                normalized.insert(peer);
            }
        }
        self.quarantine_mesh_unreachable_peers = normalized;
    }

    pub const fn adaptive_components_available(&self) -> bool {
        self.adaptive_components_available
    }

    pub fn set_adaptive_components_available(&mut self, available: bool) {
        self.adaptive_components_available = available;
    }

    pub fn evidence(&self) -> &[DelegateCellEvidence] {
        &self.evidence
    }

    pub fn apply_transition(
        &mut self,
        transition: LifecycleTransition,
        timestamp_ns: u64,
        context: &LifecycleContext<'_>,
    ) -> Result<LifecycleEvent, DelegateCellError> {
        self.check_lifetime(timestamp_ns, context)?;
        let event = self
            .lifecycle_manager
            .apply_transition(transition, timestamp_ns, context)?;
        self.record_event(
            context.trace_id,
            context.decision_id,
            context.policy_id,
            "delegate_lifecycle_transition",
            "ok",
            None,
        );
        Ok(event)
    }

    pub fn check_lifetime(
        &mut self,
        timestamp_ns: u64,
        context: &LifecycleContext<'_>,
    ) -> Result<(), DelegateCellError> {
        if timestamp_ns < self.expires_at_ns {
            return Ok(());
        }
        if self.lifetime_expired_recorded {
            return Err(DelegateCellError::LifetimeExpired {
                delegate_id: self.delegate_id.clone(),
                expired_at_ns: self.expires_at_ns,
            });
        }

        let state = self.lifecycle_manager.state();
        if !matches!(
            state,
            ExtensionState::Terminated | ExtensionState::Quarantined
        ) {
            if lifecycle_target_state(state, LifecycleTransition::Terminate).is_some() {
                let _ = self.lifecycle_manager.apply_transition(
                    LifecycleTransition::Terminate,
                    timestamp_ns,
                    context,
                );
            } else if lifecycle_target_state(state, LifecycleTransition::Quarantine).is_some() {
                let _ = self.lifecycle_manager.apply_transition(
                    LifecycleTransition::Quarantine,
                    timestamp_ns,
                    context,
                );
            }

            if self.lifecycle_manager.state() == ExtensionState::Terminating {
                let forced_completion_timestamp = timestamp_ns
                    .saturating_add(self.lifecycle_manager.cancellation.grace_period_ns)
                    .saturating_add(1);
                let _ = self.lifecycle_manager.complete_termination(
                    forced_completion_timestamp,
                    context,
                    false,
                    false,
                );
            }
        }

        self.lifetime_expired_recorded = true;
        self.evidence.push(DelegateCellEvidence::LifetimeExpired {
            delegate_id: self.delegate_id.clone(),
            expired_at_ns: self.expires_at_ns,
        });
        self.record_event(
            context.trace_id,
            context.decision_id,
            context.policy_id,
            "delegate_lifetime_expired",
            "forced_containment",
            Some("FE-DELEGATE-0004"),
        );
        Err(DelegateCellError::LifetimeExpired {
            delegate_id: self.delegate_id.clone(),
            expired_at_ns: self.expires_at_ns,
        })
    }

    pub fn dispatch_hostcall<T: Clone>(
        &mut self,
        hostcall_type: HostcallType,
        attempted_capability: Capability,
        argument: Labeled<T>,
        timestamp_ns: u64,
        flow_context: &FlowEnforcementContext<'_>,
        lifecycle_context: &LifecycleContext<'_>,
    ) -> Result<HostcallDispatchOutcome<T>, DelegateCellError> {
        self.dispatch_hostcall_with_escrow(
            hostcall_type,
            attempted_capability,
            argument,
            timestamp_ns,
            flow_context,
            lifecycle_context,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_hostcall_with_escrow<T: Clone>(
        &mut self,
        hostcall_type: HostcallType,
        attempted_capability: Capability,
        argument: Labeled<T>,
        timestamp_ns: u64,
        flow_context: &FlowEnforcementContext<'_>,
        lifecycle_context: &LifecycleContext<'_>,
        escrow_justification: Option<&str>,
    ) -> Result<HostcallDispatchOutcome<T>, DelegateCellError> {
        self.check_lifetime(timestamp_ns, lifecycle_context)?;
        self.ensure_running_for("dispatch_hostcall")?;
        self.lifecycle_manager
            .consume_hostcall(timestamp_ns, lifecycle_context)?;

        let mut effective_capabilities = self.manifest.base_manifest.capabilities.clone();
        let in_envelope = effective_capabilities.contains(&attempted_capability);
        if !in_envelope {
            let justification = escrow_justification.unwrap_or("delegate out-of-envelope hostcall");
            let resolution = self
                .capability_escrow_gateway
                .resolve_out_of_envelope_request(
                    &self.delegate_id,
                    hostcall_type,
                    attempted_capability,
                    justification,
                    timestamp_ns,
                    flow_context,
                )?;
            self.sync_capability_escrow_evidence();
            match resolution {
                CapabilityEscrowResolution::AuthorizedByApproval { request_id: _ } => {
                    effective_capabilities.insert(attempted_capability);
                    self.record_event(
                        flow_context.trace_id,
                        flow_context.decision_id,
                        flow_context.policy_id,
                        "delegate_capability_escrow",
                        "approved",
                        None,
                    );
                    self.record_event(
                        flow_context.trace_id,
                        flow_context.decision_id,
                        flow_context.policy_id,
                        "delegate_capability_escrow_authorization",
                        "approved",
                        None,
                    );
                }
                CapabilityEscrowResolution::AuthorizedByEmergencyGrant { grant_id: _ } => {
                    effective_capabilities.insert(attempted_capability);
                    self.record_event(
                        flow_context.trace_id,
                        flow_context.decision_id,
                        flow_context.policy_id,
                        "delegate_capability_escrow",
                        "emergency_granted",
                        None,
                    );
                }
                CapabilityEscrowResolution::Escrowed { decision, route } => {
                    self.evidence
                        .push(DelegateCellEvidence::CapabilityEscalation {
                            delegate_id: self.delegate_id.clone(),
                            attempted: attempted_capability,
                            decision_id: flow_context.decision_id.to_string(),
                        });
                    self.apply_guardplane_penalty(self.policy.capability_escalation_penalty_micros);
                    self.record_event(
                        flow_context.trace_id,
                        flow_context.decision_id,
                        flow_context.policy_id,
                        "delegate_capability_escrow",
                        route.as_str(),
                        decision.error_code.as_deref(),
                    );
                    self.record_event(
                        flow_context.trace_id,
                        flow_context.decision_id,
                        flow_context.policy_id,
                        "delegate_hostcall",
                        "blocked",
                        decision.error_code.as_deref(),
                    );
                    self.evaluate_guardplane_policy_action(
                        "delegate_capability_escrow",
                        timestamp_ns,
                        flow_context,
                        lifecycle_context,
                    );
                    return Ok(HostcallDispatchOutcome {
                        result: HostcallResult::Denied {
                            reason: DenialReason::CapabilityEscrowPending {
                                attempted: attempted_capability,
                                action: route,
                                escrow_id: decision.request_id,
                            },
                        },
                        output: None,
                    });
                }
                CapabilityEscrowResolution::Denied { decision } => {
                    self.evidence
                        .push(DelegateCellEvidence::CapabilityEscalation {
                            delegate_id: self.delegate_id.clone(),
                            attempted: attempted_capability,
                            decision_id: flow_context.decision_id.to_string(),
                        });
                    self.apply_guardplane_penalty(self.policy.capability_escalation_penalty_micros);
                    self.record_event(
                        flow_context.trace_id,
                        flow_context.decision_id,
                        flow_context.policy_id,
                        "delegate_capability_escrow",
                        "denied",
                        decision.error_code.as_deref(),
                    );
                    self.record_event(
                        flow_context.trace_id,
                        flow_context.decision_id,
                        flow_context.policy_id,
                        "delegate_hostcall",
                        "blocked",
                        decision.error_code.as_deref(),
                    );
                    self.evaluate_guardplane_policy_action(
                        "delegate_capability_escrow",
                        timestamp_ns,
                        flow_context,
                        lifecycle_context,
                    );
                    return Ok(HostcallDispatchOutcome {
                        result: HostcallResult::Denied {
                            reason: DenialReason::CapabilityEscrowDenied {
                                attempted: attempted_capability,
                                escrow_id: decision.request_id,
                            },
                        },
                        output: None,
                    });
                }
            }
        }

        let outcome = self.hostcall_dispatcher.dispatch(
            &self.delegate_id,
            hostcall_type,
            &effective_capabilities,
            attempted_capability,
            argument,
            flow_context,
        );

        match &outcome.result {
            HostcallResult::Denied {
                reason: DenialReason::FlowViolation { .. },
            } => {
                if let Some(last_evidence) = self
                    .hostcall_dispatcher
                    .guardplane_evidence()
                    .last()
                    .cloned()
                {
                    self.evidence
                        .push(DelegateCellEvidence::FlowViolation(last_evidence));
                }
                self.apply_guardplane_penalty(self.policy.flow_violation_penalty_micros);
                self.record_event(
                    flow_context.trace_id,
                    flow_context.decision_id,
                    flow_context.policy_id,
                    "delegate_hostcall",
                    "blocked",
                    Some("FE-FLOW-0001"),
                );
            }
            HostcallResult::Denied {
                reason: DenialReason::CapabilityEscalation { attempted },
            } => {
                self.evidence
                    .push(DelegateCellEvidence::CapabilityEscalation {
                        delegate_id: self.delegate_id.clone(),
                        attempted: *attempted,
                        decision_id: flow_context.decision_id.to_string(),
                    });
                self.apply_guardplane_penalty(self.policy.capability_escalation_penalty_micros);
                self.record_event(
                    flow_context.trace_id,
                    flow_context.decision_id,
                    flow_context.policy_id,
                    "delegate_hostcall",
                    "blocked",
                    Some("FE-DELEGATE-0003"),
                );
            }
            HostcallResult::Denied {
                reason:
                    DenialReason::CapabilityEscrowPending {
                        attempted: _,
                        action: _,
                        escrow_id: _,
                    }
                    | DenialReason::CapabilityEscrowDenied {
                        attempted: _,
                        escrow_id: _,
                    },
            } => {
                self.apply_guardplane_penalty(self.policy.capability_escalation_penalty_micros);
                self.record_event(
                    flow_context.trace_id,
                    flow_context.decision_id,
                    flow_context.policy_id,
                    "delegate_hostcall",
                    "blocked",
                    Some("FE-DELEGATE-0003"),
                );
            }
            HostcallResult::Success => {
                self.record_event(
                    flow_context.trace_id,
                    flow_context.decision_id,
                    flow_context.policy_id,
                    "delegate_hostcall",
                    "allowed",
                    None,
                );
            }
            HostcallResult::Error { .. } | HostcallResult::Timeout => {
                self.record_event(
                    flow_context.trace_id,
                    flow_context.decision_id,
                    flow_context.policy_id,
                    "delegate_hostcall",
                    "failed",
                    Some("FE-DELEGATE-0005"),
                );
            }
        }

        self.evaluate_guardplane_policy_action(
            "delegate_hostcall",
            timestamp_ns,
            flow_context,
            lifecycle_context,
        );

        Ok(outcome)
    }

    pub fn request_declassification(
        &mut self,
        request: DeclassificationRequest,
        flow_context: &FlowEnforcementContext<'_>,
        lifecycle_context: &LifecycleContext<'_>,
    ) -> Result<DeclassificationOutcome, DelegateCellError> {
        self.check_lifetime(request.timestamp_ns, lifecycle_context)?;
        self.ensure_running_for("request_declassification")?;
        let timestamp_ns = request.timestamp_ns;
        let outcome = self.declassification_gateway.evaluate_request(
            request,
            &self.manifest.base_manifest.capabilities,
            self.guardplane_state.posterior_micros,
            flow_context,
        );

        match &outcome {
            DeclassificationOutcome::Approved { .. } => {
                self.record_event(
                    flow_context.trace_id,
                    flow_context.decision_id,
                    flow_context.policy_id,
                    "delegate_declassification",
                    "approved",
                    None,
                );
            }
            DeclassificationOutcome::Denied { reason, .. } => {
                if let Some(last) = self
                    .declassification_gateway
                    .denied_evidence()
                    .last()
                    .cloned()
                {
                    self.evidence
                        .push(DelegateCellEvidence::DeclassificationDenied(last));
                }
                self.apply_guardplane_penalty(self.policy.declassification_denial_penalty_micros);
                self.record_event(
                    flow_context.trace_id,
                    flow_context.decision_id,
                    flow_context.policy_id,
                    "delegate_declassification",
                    "denied",
                    Some(reason.error_code()),
                );
            }
            DeclassificationOutcome::Deferred { .. } => {
                self.record_event(
                    flow_context.trace_id,
                    flow_context.decision_id,
                    flow_context.policy_id,
                    "delegate_declassification",
                    "deferred",
                    Some("FE-DECLASS-0008"),
                );
            }
        }

        self.evaluate_guardplane_policy_action(
            "delegate_declassification",
            timestamp_ns,
            flow_context,
            lifecycle_context,
        );

        Ok(outcome)
    }

    fn sync_capability_escrow_evidence(&mut self) {
        let evidence = self.capability_escrow_gateway.evidence();
        if self.capability_escrow_evidence_cursor >= evidence.len() {
            return;
        }
        self.evidence.extend(
            evidence[self.capability_escrow_evidence_cursor..]
                .iter()
                .cloned()
                .map(DelegateCellEvidence::CapabilityEscrow),
        );
        self.capability_escrow_evidence_cursor = evidence.len();
    }

    fn apply_guardplane_penalty(&mut self, penalty_micros: u64) {
        self.guardplane_state.posterior_micros = (self.guardplane_state.posterior_micros
            + penalty_micros)
            .min(GUARDPLANE_MAX_POSTERIOR_MICROS);
    }

    fn ensure_running_for(&self, action: &'static str) -> Result<(), DelegateCellError> {
        let state = self.lifecycle_manager.state();
        if state == ExtensionState::Running {
            Ok(())
        } else {
            Err(DelegateCellError::InactiveState {
                delegate_id: self.delegate_id.clone(),
                state,
                action,
            })
        }
    }

    fn evaluate_guardplane_policy_action(
        &mut self,
        source_event: &str,
        timestamp_ns: u64,
        flow_context: &FlowEnforcementContext<'_>,
        lifecycle_context: &LifecycleContext<'_>,
    ) {
        let (action, safe_mode_fallback) = self.select_guardplane_policy_action();
        let lifecycle_transition =
            self.apply_guardplane_lifecycle_action(action, timestamp_ns, lifecycle_context);
        let resulting_state = self.lifecycle_manager.state();
        self.record_event(
            flow_context.trace_id,
            flow_context.decision_id,
            flow_context.policy_id,
            "delegate_guardplane_action",
            action.as_str(),
            None,
        );
        self.guardplane_decision_log
            .push(GuardplaneDecisionLogEntry {
                schema_version: GUARDPLANE_DECISION_LOG_SCHEMA_VERSION.to_string(),
                trace_id: flow_context.trace_id.to_string(),
                decision_id: flow_context.decision_id.to_string(),
                policy_id: flow_context.policy_id.to_string(),
                component: DELEGATE_COMPONENT.to_string(),
                event: "delegate_guardplane_action".to_string(),
                outcome: action.as_str().to_string(),
                error_code: None,
                source_event: source_event.to_string(),
                delegate_id: self.delegate_id.clone(),
                timestamp_ns,
                posterior_micros: self.guardplane_state.posterior_micros,
                action,
                safe_mode_fallback,
                lifecycle_transition,
                resulting_state,
            });
        self.record_containment_workflow(
            source_event,
            timestamp_ns,
            flow_context,
            action,
            lifecycle_transition,
            resulting_state,
        );
    }

    fn select_guardplane_policy_action(&self) -> (GuardplanePolicyAction, bool) {
        let nominal = guardplane_action_from_posterior(self.guardplane_state.posterior_micros);
        if self.adaptive_components_available {
            (nominal, false)
        } else {
            (nominal.fail_closed_fallback(), true)
        }
    }

    fn apply_guardplane_lifecycle_action(
        &mut self,
        action: GuardplanePolicyAction,
        timestamp_ns: u64,
        context: &LifecycleContext<'_>,
    ) -> Option<LifecycleTransition> {
        let transition = match action {
            GuardplanePolicyAction::Suspend => Some(LifecycleTransition::Suspend),
            GuardplanePolicyAction::Terminate => Some(LifecycleTransition::Terminate),
            GuardplanePolicyAction::Quarantine => Some(LifecycleTransition::Quarantine),
            GuardplanePolicyAction::Allow
            | GuardplanePolicyAction::Challenge
            | GuardplanePolicyAction::Sandbox => None,
        }?;

        let current_state = self.lifecycle_manager.state();
        lifecycle_target_state(current_state, transition)?;

        if self
            .lifecycle_manager
            .apply_transition(transition, timestamp_ns, context)
            .is_ok()
        {
            Some(transition)
        } else {
            None
        }
    }

    fn record_containment_workflow(
        &mut self,
        source_event: &str,
        timestamp_ns: u64,
        flow_context: &FlowEnforcementContext<'_>,
        action: GuardplanePolicyAction,
        lifecycle_transition: Option<LifecycleTransition>,
        resulting_state: ExtensionState,
    ) {
        if !action.is_containment_action() {
            return;
        }

        let mesh_attempted_targets = if action == GuardplanePolicyAction::Quarantine {
            self.quarantine_mesh_peers
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mesh_failed_targets = if action == GuardplanePolicyAction::Quarantine {
            mesh_attempted_targets
                .iter()
                .filter(|peer| self.quarantine_mesh_unreachable_peers.contains(*peer))
                .cloned()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mesh_targets = if action == GuardplanePolicyAction::Quarantine {
            mesh_attempted_targets
                .iter()
                .filter(|peer| !self.quarantine_mesh_unreachable_peers.contains(*peer))
                .cloned()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mesh_propagated =
            action == GuardplanePolicyAction::Quarantine && !mesh_targets.is_empty();
        let (event_name, outcome, error_code) = if action == GuardplanePolicyAction::Quarantine {
            if !mesh_failed_targets.is_empty() {
                if mesh_propagated {
                    (
                        "delegate_quarantine_mesh_partial_propagation",
                        "degraded",
                        Some(DELEGATE_MESH_PROPAGATION_DEGRADED_ERROR_CODE),
                    )
                } else {
                    (
                        "delegate_quarantine_mesh_propagation_failed",
                        "degraded",
                        Some(DELEGATE_MESH_PROPAGATION_DEGRADED_ERROR_CODE),
                    )
                }
            } else if mesh_propagated {
                ("delegate_quarantine_mesh_propagated", "ok", None)
            } else {
                ("delegate_quarantine_mesh_local_only", "ok", None)
            }
        } else {
            ("delegate_containment_action", "ok", None)
        };
        self.record_event(
            flow_context.trace_id,
            flow_context.decision_id,
            flow_context.policy_id,
            event_name,
            outcome,
            error_code,
        );
        self.evidence.push(DelegateCellEvidence::ContainmentAction {
            delegate_id: self.delegate_id.clone(),
            action,
            lifecycle_transition,
            mesh_attempted_targets: mesh_attempted_targets.clone(),
            mesh_targets: mesh_targets.clone(),
            mesh_failed_targets: mesh_failed_targets.clone(),
            mesh_propagated,
            timestamp_ns,
        });
        self.containment_workflow_log
            .push(ContainmentWorkflowLogEntry {
                schema_version: CONTAINMENT_WORKFLOW_LOG_SCHEMA_VERSION.to_string(),
                trace_id: flow_context.trace_id.to_string(),
                decision_id: flow_context.decision_id.to_string(),
                policy_id: flow_context.policy_id.to_string(),
                component: DELEGATE_COMPONENT.to_string(),
                event: event_name.to_string(),
                outcome: outcome.to_string(),
                error_code: error_code.map(str::to_string),
                source_event: source_event.to_string(),
                delegate_id: self.delegate_id.clone(),
                timestamp_ns,
                action,
                lifecycle_transition,
                resulting_state,
                mesh_attempted_targets,
                mesh_targets,
                mesh_failed_targets,
                mesh_propagated,
            });
    }

    fn record_event(
        &mut self,
        trace_id: &str,
        decision_id: &str,
        policy_id: &str,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
    ) {
        self.events.push(DelegateCellEvent {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_string(),
            component: DELEGATE_COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(str::to_string),
            delegate_id: self.delegate_id.clone(),
            delegation_scope: self.manifest.delegation_scope.to_string(),
        });
    }
}

/// Factory ensuring delegate cells are created through full security policy path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DelegateCellFactory {
    pub sink_policy: HostcallSinkPolicy,
    pub cancellation_config: CancellationConfig,
    pub policy: DelegateCellPolicy,
    pub decision_signing_key: DecisionSigningKey,
}

impl DelegateCellFactory {
    pub fn create_delegate_cell(
        &self,
        delegate_id: impl Into<String>,
        manifest: DelegateCellManifest,
        budget: ResourceBudget,
        budget_policy: BudgetExhaustionPolicy,
        created_at_ns: u64,
        lifecycle_context: &LifecycleContext<'_>,
    ) -> Result<DelegateCell, DelegateCellError> {
        let delegate_id = delegate_id.into();
        if delegate_id.trim().is_empty() {
            return Err(DelegateCellError::InvalidDelegateId);
        }
        manifest.validate()?;
        validate_delegate_budget(&budget)?;

        let mut lifecycle_manager = ExtensionLifecycleManager::new(
            delegate_id.clone(),
            budget,
            budget_policy,
            self.cancellation_config,
        );
        lifecycle_manager.set_validated_manifest(manifest.base_manifest.clone())?;
        lifecycle_manager.apply_transition(
            LifecycleTransition::Validate,
            created_at_ns.saturating_add(1),
            lifecycle_context,
        )?;
        lifecycle_manager.apply_transition(
            LifecycleTransition::Load,
            created_at_ns.saturating_add(2),
            lifecycle_context,
        )?;
        lifecycle_manager.apply_transition(
            LifecycleTransition::Start,
            created_at_ns.saturating_add(3),
            lifecycle_context,
        )?;
        lifecycle_manager.apply_transition(
            LifecycleTransition::Activate,
            created_at_ns.saturating_add(4),
            lifecycle_context,
        )?;

        let mut delegate = DelegateCell {
            delegate_id: delegate_id.clone(),
            lifecycle_manager,
            hostcall_dispatcher: HostcallDispatcher::new(self.sink_policy),
            capability_escrow_gateway: CapabilityEscrowGateway::with_default_contracts(
                self.decision_signing_key,
            ),
            declassification_gateway: DeclassificationGateway::with_default_contracts(
                self.decision_signing_key,
            ),
            guardplane_state: DelegateGuardplaneState {
                delegate_id: delegate_id.clone(),
                posterior_micros: self.policy.initial_posterior_micros,
            },
            policy: self.policy.clone(),
            created_at_ns,
            expires_at_ns: created_at_ns.saturating_add(manifest.max_lifetime_ns),
            lifetime_expired_recorded: false,
            events: Vec::new(),
            quarantine_mesh_peers: BTreeSet::new(),
            quarantine_mesh_unreachable_peers: BTreeSet::new(),
            guardplane_decision_log: Vec::new(),
            containment_workflow_log: Vec::new(),
            evidence: Vec::new(),
            capability_escrow_evidence_cursor: 0,
            adaptive_components_available: true,
            manifest,
        };
        delegate.record_event(
            lifecycle_context.trace_id,
            lifecycle_context.decision_id,
            lifecycle_context.policy_id,
            "delegate_cell_created",
            "ok",
            None,
        );

        Ok(delegate)
    }
}

fn validate_delegate_budget(budget: &ResourceBudget) -> Result<(), DelegateCellError> {
    if budget.cpu_time_ns_remaining == 0
        || budget.cpu_time_ns_remaining > MAX_DELEGATE_CPU_BUDGET_NS
    {
        return Err(DelegateCellError::InvalidBudget {
            field: "cpu_time_ns_remaining",
            value: budget.cpu_time_ns_remaining,
            max_allowed: MAX_DELEGATE_CPU_BUDGET_NS,
        });
    }
    if budget.memory_bytes_remaining == 0
        || budget.memory_bytes_remaining > MAX_DELEGATE_MEMORY_BUDGET_BYTES
    {
        return Err(DelegateCellError::InvalidBudget {
            field: "memory_bytes_remaining",
            value: budget.memory_bytes_remaining,
            max_allowed: MAX_DELEGATE_MEMORY_BUDGET_BYTES,
        });
    }
    if budget.hostcall_count_remaining == 0
        || budget.hostcall_count_remaining > MAX_DELEGATE_HOSTCALL_BUDGET
    {
        return Err(DelegateCellError::InvalidBudget {
            field: "hostcall_count_remaining",
            value: budget.hostcall_count_remaining,
            max_allowed: MAX_DELEGATE_HOSTCALL_BUDGET,
        });
    }
    Ok(())
}

const fn guardplane_action_from_posterior(posterior_micros: u64) -> GuardplanePolicyAction {
    if posterior_micros >= GUARDPLANE_QUARANTINE_THRESHOLD_MICROS {
        GuardplanePolicyAction::Quarantine
    } else if posterior_micros >= GUARDPLANE_TERMINATE_THRESHOLD_MICROS {
        GuardplanePolicyAction::Terminate
    } else if posterior_micros >= GUARDPLANE_SUSPEND_THRESHOLD_MICROS {
        GuardplanePolicyAction::Suspend
    } else if posterior_micros >= GUARDPLANE_SANDBOX_THRESHOLD_MICROS {
        GuardplanePolicyAction::Sandbox
    } else if posterior_micros >= GUARDPLANE_CHALLENGE_THRESHOLD_MICROS {
        GuardplanePolicyAction::Challenge
    } else {
        GuardplanePolicyAction::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_set(values: &[Capability]) -> BTreeSet<Capability> {
        values.iter().copied().collect()
    }

    fn signed_manifest(capabilities: &[Capability]) -> ExtensionManifest {
        let mut manifest = ExtensionManifest {
            name: "weather-ext".to_string(),
            version: "1.2.3".to_string(),
            entrypoint: "dist/index.js".to_string(),
            capabilities: capability_set(capabilities),
            publisher_signature: Some(vec![1, 2, 3, 4]),
            content_hash: [0; 32],
            trust_chain_ref: Some("chain/weather-team".to_string()),
            min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
        };
        manifest.content_hash = compute_content_hash(&manifest).expect("content hash");
        manifest
    }

    #[test]
    fn signed_manifest_validates_with_matching_hash() {
        let manifest = signed_manifest(&[Capability::FsRead, Capability::FsWrite]);
        assert_eq!(validate_manifest(&manifest), Ok(()));
    }

    #[test]
    fn fs_write_requires_fs_read() {
        let manifest = signed_manifest(&[Capability::FsWrite]);
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::InvalidCapabilityLattice {
                declared: Capability::FsWrite,
                missing_implied: Capability::FsRead,
            })
        );
    }

    #[test]
    fn signed_supply_chain_requires_signature() {
        let mut manifest = signed_manifest(&[Capability::FsRead]);
        manifest.publisher_signature = None;
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::MissingPublisherSignature)
        );
    }

    #[test]
    fn invalid_content_hash_is_rejected() {
        let mut manifest = signed_manifest(&[Capability::FsRead]);
        manifest.content_hash[0] ^= 0xFF;
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::InvalidContentHash)
        );
    }

    #[test]
    fn unsupported_engine_version_is_rejected() {
        let mut manifest = signed_manifest(&[Capability::FsRead]);
        manifest.min_engine_version = "0.2.0".to_string();
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::UnsupportedEngineVersion {
                min_engine_version: "0.2.0".to_string(),
                supported_engine_version: CURRENT_ENGINE_VERSION,
            })
        );
    }

    #[test]
    fn overly_long_name_is_rejected() {
        let mut manifest = signed_manifest(&[Capability::FsRead]);
        manifest.name = "x".repeat(MAX_NAME_LEN + 1);
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::FieldTooLong {
                field: "name",
                max: MAX_NAME_LEN,
                actual: MAX_NAME_LEN + 1,
            })
        );
    }

    #[test]
    fn canonical_serialization_is_deterministic_and_compact() {
        let manifest_a = signed_manifest(&[Capability::FsRead, Capability::FsWrite]);
        let manifest_b = signed_manifest(&[Capability::FsWrite, Capability::FsRead]);

        let json_a = canonical_manifest_json(&manifest_a).expect("canonical json");
        let json_b = canonical_manifest_json(&manifest_b).expect("canonical json");
        assert_eq!(json_a, json_b);
        assert!(!json_a.contains('\n'));
        assert!(!json_a.contains(": "));
        assert!(json_a.contains("\"capabilities\""));
    }

    #[test]
    fn validation_report_emits_pass_event() {
        let context = ManifestValidationContext::new(
            "trace-001",
            "decision-001",
            "policy-001",
            "weather-ext",
        );
        let manifest = signed_manifest(&[Capability::FsRead, Capability::FsWrite]);
        let report = validate_manifest_with_context(&manifest, &context);

        assert_eq!(report.error, None);
        assert_eq!(report.event.outcome, "pass");
        assert_eq!(report.event.error_code, None);
    }

    #[test]
    fn validation_report_emits_fail_event_with_stable_error_code() {
        let context = ManifestValidationContext::new(
            "trace-002",
            "decision-002",
            "policy-002",
            "weather-ext",
        );
        let manifest = signed_manifest(&[Capability::FsWrite]);
        let report = validate_manifest_with_context(&manifest, &context);

        assert!(report.error.is_some());
        assert_eq!(report.event.outcome, "fail");
        assert_eq!(report.event.error_code.as_deref(), Some("FE-MANIFEST-0005"));
    }

    const STATIC_VALID_MANIFEST: StaticExtensionManifest = StaticExtensionManifest {
        name: "static-ext",
        entrypoint: "index.js",
        min_engine_version: "0.1.0",
        capabilities: &[Capability::FsRead, Capability::FsWrite],
    };
    const STATIC_VALID_RESULT: Result<(), StaticManifestValidationError> =
        validate_static_manifest(&STATIC_VALID_MANIFEST);

    const STATIC_INVALID_MANIFEST: StaticExtensionManifest = StaticExtensionManifest {
        name: "static-ext",
        entrypoint: "index.js",
        min_engine_version: "0.1.0",
        capabilities: &[Capability::FsWrite],
    };
    const STATIC_INVALID_RESULT: Result<(), StaticManifestValidationError> =
        validate_static_manifest(&STATIC_INVALID_MANIFEST);

    #[test]
    fn const_validation_path_is_const_evaluable() {
        assert_eq!(STATIC_VALID_RESULT, Ok(()));
        assert_eq!(
            STATIC_INVALID_RESULT,
            Err(StaticManifestValidationError::MissingImpliedCapability {
                declared: Capability::FsWrite,
                missing_implied: Capability::FsRead,
            })
        );
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::thread;

    fn lifecycle_manifest() -> ExtensionManifest {
        let mut manifest = ExtensionManifest {
            name: "lifecycle-ext".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "dist/main.js".to_string(),
            capabilities: [Capability::FsRead, Capability::FsWrite]
                .into_iter()
                .collect(),
            publisher_signature: Some(vec![1, 2, 3, 4]),
            content_hash: [0; 32],
            trust_chain_ref: Some("chain/lifecycle".to_string()),
            min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
        };
        manifest.content_hash = compute_content_hash(&manifest).expect("content hash");
        manifest
    }

    fn context() -> LifecycleContext<'static> {
        LifecycleContext::new("trace-life", "decision-life", "policy-life")
    }

    fn manager_in_running_state(
        extension_id: &str,
        budget_policy: BudgetExhaustionPolicy,
        hostcall_budget: u64,
    ) -> ExtensionLifecycleManager {
        let mut manager = ExtensionLifecycleManager::new(
            extension_id.to_string(),
            ResourceBudget::new(5_000_000_000, 1024 * 1024, hostcall_budget),
            budget_policy,
            CancellationConfig::default(),
        );
        manager
            .set_validated_manifest(lifecycle_manifest())
            .expect("validated manifest");
        let cx = context();
        manager
            .apply_transition(LifecycleTransition::Validate, 10, &cx)
            .expect("validate");
        manager
            .apply_transition(LifecycleTransition::Load, 20, &cx)
            .expect("load");
        manager
            .apply_transition(LifecycleTransition::Start, 30, &cx)
            .expect("start");
        manager
            .apply_transition(LifecycleTransition::Activate, 40, &cx)
            .expect("activate");
        manager
    }

    #[test]
    fn full_lifecycle_path_transitions_and_protocol_complete() {
        let cx = context();
        let mut manager =
            manager_in_running_state("ext-full", BudgetExhaustionPolicy::Suspend, 100);
        assert_eq!(manager.state(), ExtensionState::Running);

        manager
            .apply_transition(LifecycleTransition::Suspend, 50, &cx)
            .expect("suspend");
        manager
            .apply_transition(LifecycleTransition::Freeze, 60, &cx)
            .expect("freeze");
        manager
            .apply_transition(LifecycleTransition::Resume, 70, &cx)
            .expect("resume");
        manager
            .apply_transition(LifecycleTransition::Reactivate, 80, &cx)
            .expect("reactivate");
        manager
            .apply_transition(LifecycleTransition::Terminate, 90, &cx)
            .expect("terminate");
        assert!(manager.pending_cancel_token().is_some());

        manager
            .complete_termination(95, &cx, true, false)
            .expect("cooperative finalize");
        assert_eq!(manager.state(), ExtensionState::Terminated);
        assert!(manager.pending_cancel_token().is_none());
    }

    #[test]
    fn invalid_transition_rejected_with_deterministic_context() {
        let cx = context();
        let mut manager = ExtensionLifecycleManager::new(
            "ext-invalid",
            ResourceBudget::new(1, 1, 1),
            BudgetExhaustionPolicy::Suspend,
            CancellationConfig::default(),
        );
        let error = manager
            .apply_transition(LifecycleTransition::Resume, 1, &cx)
            .expect_err("invalid transition");
        assert_eq!(
            error,
            LifecycleError::InvalidTransition {
                extension_id: "ext-invalid".to_string(),
                current_state: ExtensionState::Unloaded,
                attempted_transition: LifecycleTransition::Resume,
            }
        );
        let last_event = manager.telemetry_events().last().expect("event");
        assert_eq!(last_event.outcome, "fail");
        assert_eq!(last_event.error_code.as_deref(), Some("FE-LIFECYCLE-0001"));
    }

    #[test]
    fn budget_exhaustion_triggers_configured_containment_action() {
        let cx = context();

        let mut suspend_manager =
            manager_in_running_state("ext-budget-suspend", BudgetExhaustionPolicy::Suspend, 2);
        suspend_manager
            .consume_hostcall(41, &cx)
            .expect("first hostcall");
        let err = suspend_manager
            .consume_hostcall(42, &cx)
            .expect_err("budget exhaustion");
        assert!(matches!(err, LifecycleError::BudgetExhausted { .. }));
        assert_eq!(suspend_manager.state(), ExtensionState::Suspending);

        let mut terminate_manager =
            manager_in_running_state("ext-budget-terminate", BudgetExhaustionPolicy::Terminate, 2);
        terminate_manager
            .consume_hostcall(41, &cx)
            .expect("first hostcall");
        let err = terminate_manager
            .consume_hostcall(42, &cx)
            .expect_err("budget exhaustion");
        assert!(matches!(err, LifecycleError::BudgetExhausted { .. }));
        assert_eq!(terminate_manager.state(), ExtensionState::Terminating);
        assert!(terminate_manager.pending_cancel_token().is_some());
    }

    #[test]
    fn termination_timeout_forces_finalize_or_quarantine() {
        let cx = context();

        let mut forced_finalize =
            manager_in_running_state("ext-timeout-finalize", BudgetExhaustionPolicy::Suspend, 10);
        forced_finalize
            .apply_transition(LifecycleTransition::Terminate, 100, &cx)
            .expect("terminate");
        let event = forced_finalize
            .complete_termination(
                100 + DEFAULT_TERMINATION_GRACE_PERIOD_NS + 1,
                &cx,
                false,
                false,
            )
            .expect("forced finalize");
        assert_eq!(event.outcome, "forced");
        assert_eq!(forced_finalize.state(), ExtensionState::Terminated);

        let mut forced_quarantine = manager_in_running_state(
            "ext-timeout-quarantine",
            BudgetExhaustionPolicy::Suspend,
            10,
        );
        forced_quarantine
            .apply_transition(LifecycleTransition::Terminate, 200, &cx)
            .expect("terminate");
        let event = forced_quarantine
            .complete_termination(
                200 + DEFAULT_TERMINATION_GRACE_PERIOD_NS + 1,
                &cx,
                false,
                true,
            )
            .expect("forced quarantine");
        assert_eq!(event.outcome, "forced");
        assert_eq!(forced_quarantine.state(), ExtensionState::Quarantined);
    }

    #[test]
    fn state_machine_exhaustiveness_matches_allowed_transition_table() {
        let states = [
            ExtensionState::Unloaded,
            ExtensionState::Validating,
            ExtensionState::Loading,
            ExtensionState::Starting,
            ExtensionState::Running,
            ExtensionState::Suspending,
            ExtensionState::Suspended,
            ExtensionState::Resuming,
            ExtensionState::Terminating,
            ExtensionState::Terminated,
            ExtensionState::Quarantined,
        ];
        let transitions = [
            LifecycleTransition::Validate,
            LifecycleTransition::Load,
            LifecycleTransition::Start,
            LifecycleTransition::Activate,
            LifecycleTransition::Suspend,
            LifecycleTransition::Freeze,
            LifecycleTransition::Resume,
            LifecycleTransition::Reactivate,
            LifecycleTransition::Terminate,
            LifecycleTransition::Finalize,
            LifecycleTransition::Quarantine,
        ];

        for state in states {
            let allowed = allowed_lifecycle_transitions(state);
            for transition in transitions {
                let expected = allowed.contains(&transition);
                let actual = lifecycle_target_state(state, transition).is_some();
                assert_eq!(
                    actual, expected,
                    "state={} transition={} mismatch",
                    state, transition
                );
            }
        }
    }

    #[test]
    fn deterministic_replay_produces_identical_logs_and_events() {
        let cx = context();
        let sequence = [
            (LifecycleTransition::Validate, 10),
            (LifecycleTransition::Load, 20),
            (LifecycleTransition::Start, 30),
            (LifecycleTransition::Activate, 40),
            (LifecycleTransition::Suspend, 50),
            (LifecycleTransition::Freeze, 60),
            (LifecycleTransition::Resume, 70),
            (LifecycleTransition::Reactivate, 80),
            (LifecycleTransition::Terminate, 90),
        ];

        let mut first = ExtensionLifecycleManager::new(
            "ext-replay",
            ResourceBudget::new(5_000_000_000, 1_000_000, 100),
            BudgetExhaustionPolicy::Suspend,
            CancellationConfig::default(),
        );
        first
            .set_validated_manifest(lifecycle_manifest())
            .expect("manifest");
        for (transition, ts) in sequence {
            first
                .apply_transition(transition, ts, &cx)
                .expect("transition");
        }
        first
            .complete_termination(95, &cx, true, false)
            .expect("finalize");
        let first_log = first.transition_log().to_vec();
        let first_events = first.telemetry_events().to_vec();

        let mut second = ExtensionLifecycleManager::new(
            "ext-replay",
            ResourceBudget::new(5_000_000_000, 1_000_000, 100),
            BudgetExhaustionPolicy::Suspend,
            CancellationConfig::default(),
        );
        second
            .set_validated_manifest(lifecycle_manifest())
            .expect("manifest");
        for (transition, ts) in sequence {
            second
                .apply_transition(transition, ts, &cx)
                .expect("transition");
        }
        second
            .complete_termination(95, &cx, true, false)
            .expect("finalize");

        assert_eq!(first_log, second.transition_log());
        assert_eq!(first_events, second.telemetry_events());
    }

    #[test]
    fn non_monotonic_timestamps_are_rejected() {
        let cx = context();
        let mut manager = ExtensionLifecycleManager::new(
            "ext-time",
            ResourceBudget::new(5_000_000_000, 1_000_000, 100),
            BudgetExhaustionPolicy::Suspend,
            CancellationConfig::default(),
        );
        manager
            .set_validated_manifest(lifecycle_manifest())
            .expect("manifest");
        manager
            .apply_transition(LifecycleTransition::Validate, 10, &cx)
            .expect("validate");

        let error = manager
            .apply_transition(LifecycleTransition::Load, 9, &cx)
            .expect_err("non-monotonic");
        assert_eq!(
            error,
            LifecycleError::NonMonotonicTimestamp {
                previous: 10,
                current: 9,
            }
        );
    }

    #[test]
    fn multiple_managers_run_independently_in_parallel() {
        let handle_a = thread::spawn(|| {
            let cx = LifecycleContext::new("trace-a", "decision-a", "policy-a");
            let mut manager =
                manager_in_running_state("ext-a", BudgetExhaustionPolicy::Suspend, 100);
            manager
                .apply_transition(LifecycleTransition::Terminate, 90, &cx)
                .expect("terminate");
            manager
                .complete_termination(95, &cx, true, false)
                .expect("complete");
            (
                manager.extension_id().to_string(),
                manager.state(),
                manager.transition_log().len(),
            )
        });
        let handle_b = thread::spawn(|| {
            let cx = LifecycleContext::new("trace-b", "decision-b", "policy-b");
            let mut manager =
                manager_in_running_state("ext-b", BudgetExhaustionPolicy::Terminate, 2);
            manager.consume_hostcall(41, &cx).expect("hostcall1");
            let _ = manager.consume_hostcall(42, &cx);
            (
                manager.extension_id().to_string(),
                manager.state(),
                manager.transition_log().len(),
            )
        });

        let (id_a, state_a, log_a) = handle_a.join().expect("thread a");
        let (id_b, state_b, log_b) = handle_b.join().expect("thread b");
        assert_eq!(id_a, "ext-a");
        assert_eq!(state_a, ExtensionState::Terminated);
        assert!(log_a >= 5);

        assert_eq!(id_b, "ext-b");
        assert_eq!(state_b, ExtensionState::Terminating);
        assert!(log_b >= 5);
    }

    #[test]
    fn lifecycle_manager_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ExtensionLifecycleManager>();
    }
}

#[cfg(test)]
mod flow_label_tests {
    use super::*;
    use std::hint::black_box;
    use std::time::Instant;

    fn flow_context() -> FlowEnforcementContext<'static> {
        FlowEnforcementContext::new("trace-flow", "decision-flow", "policy-flow")
    }

    fn declared_caps() -> BTreeSet<Capability> {
        [
            Capability::FsRead,
            Capability::FsWrite,
            Capability::NetClient,
            Capability::HostCall,
            Capability::ProcessSpawn,
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn lattice_can_flow_and_rejects_unauthorized_paths() {
        let public_trusted = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
        let secret_untrusted = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Untrusted);
        let internal_validated = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated);

        assert!(FlowLabelLattice::can_flow(
            &public_trusted,
            &internal_validated
        ));
        assert!(!FlowLabelLattice::can_flow(
            &secret_untrusted,
            &internal_validated
        ));
    }

    #[test]
    fn join_semantics_use_max_secrecy_and_min_integrity() {
        let a = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Trusted);
        let b = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated);
        let joined = a.join(b);
        assert_eq!(
            joined,
            FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated)
        );
    }

    #[test]
    fn sink_clearance_blocks_secret_to_public_network_egress() {
        let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
        let payload = Labeled::new(
            "token".to_string(),
            FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
        );
        let outcome = dispatcher.dispatch(
            "ext-a",
            HostcallType::NetworkSend,
            &declared_caps(),
            Capability::NetClient,
            payload,
            &flow_context(),
        );

        assert!(matches!(
            outcome.result,
            HostcallResult::Denied {
                reason: DenialReason::FlowViolation { .. }
            }
        ));
        assert!(outcome.output.is_none());
        assert_eq!(dispatcher.violation_events().len(), 1);
        assert_eq!(dispatcher.guardplane_evidence().len(), 1);
    }

    #[test]
    fn sink_clearance_allows_public_to_secret_sink() {
        let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
        let payload = Labeled::new(
            "log-line".to_string(),
            FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted),
        );
        let outcome = dispatcher.dispatch(
            "ext-a",
            HostcallType::IpcSend,
            &declared_caps(),
            Capability::HostCall,
            payload.clone(),
            &flow_context(),
        );

        assert_eq!(outcome.result, HostcallResult::Success);
        assert_eq!(outcome.output, Some(payload));
        assert!(dispatcher.violation_events().is_empty());
    }

    #[test]
    fn capability_escalation_is_denied() {
        let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
        let declared: BTreeSet<Capability> = [Capability::FsRead].into_iter().collect();
        let payload = Labeled::system_generated("diag".to_string());
        let outcome = dispatcher.dispatch(
            "ext-a",
            HostcallType::ProcessSpawn,
            &declared,
            Capability::ProcessSpawn,
            payload,
            &flow_context(),
        );

        assert!(matches!(
            outcome.result,
            HostcallResult::Denied {
                reason: DenialReason::CapabilityEscalation { .. }
            }
        ));
        assert!(outcome.output.is_none());
    }

    #[test]
    fn ipc_propagation_preserves_labels_and_blocks_follow_on_exfiltration() {
        let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
        let ipc_payload = Labeled::new(
            vec![1u8, 2, 3],
            FlowLabel::new(SecrecyLevel::Confidential, IntegrityLevel::Validated),
        );

        let ipc_outcome = dispatcher.dispatch(
            "ext-a",
            HostcallType::IpcSend,
            &declared_caps(),
            Capability::HostCall,
            ipc_payload,
            &flow_context(),
        );
        assert_eq!(ipc_outcome.result, HostcallResult::Success);
        let inherited = ipc_outcome.output.expect("ipc output");
        assert_eq!(
            inherited.label(),
            FlowLabel::new(SecrecyLevel::Confidential, IntegrityLevel::Validated)
        );

        let net_outcome = dispatcher.dispatch(
            "ext-b",
            HostcallType::NetworkSend,
            &declared_caps(),
            Capability::NetClient,
            inherited,
            &flow_context(),
        );
        assert!(matches!(
            net_outcome.result,
            HostcallResult::Denied {
                reason: DenialReason::FlowViolation { .. }
            }
        ));
    }

    #[test]
    fn violation_event_contains_required_stable_fields() {
        let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
        let payload = Labeled::new(
            "secret".to_string(),
            FlowLabel::new(SecrecyLevel::TopSecret, IntegrityLevel::Validated),
        );
        let _ = dispatcher.dispatch(
            "ext-a",
            HostcallType::NetworkSend,
            &declared_caps(),
            Capability::NetClient,
            payload,
            &flow_context(),
        );
        let event = dispatcher
            .violation_events()
            .last()
            .expect("violation event emitted");
        assert_eq!(event.trace_id, "trace-flow");
        assert_eq!(event.decision_id, "decision-flow");
        assert_eq!(event.policy_id, "policy-flow");
        assert_eq!(event.component, "runtime_flow_enforcement");
        assert_eq!(event.event, "hostcall_flow_violation");
        assert_eq!(event.outcome, "blocked");
        assert_eq!(event.error_code, "FE-FLOW-0001");
    }

    #[test]
    fn default_and_system_labels_match_edge_case_policy() {
        let unlabeled: Labeled<&str> = "unlabeled".into();
        assert_eq!(
            unlabeled.label(),
            FlowLabel::new(SecrecyLevel::TopSecret, IntegrityLevel::Untrusted)
        );

        let system = Labeled::system_generated("system");
        assert_eq!(
            system.label(),
            FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted)
        );
    }

    #[test]
    fn hostcall_flow_check_has_low_runtime_overhead() {
        let source = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated);
        let sink = SinkClearance::new(SecrecyLevel::Secret, IntegrityLevel::Untrusted);
        let iterations = 200_000u128;
        let start = Instant::now();
        let mut count = 0u64;
        for _ in 0..iterations {
            if black_box(FlowLabelLattice::can_flow_to_sink(&source, &sink)) {
                count += 1;
            }
        }
        let elapsed_ns = start.elapsed().as_nanos();
        let avg_ns = elapsed_ns / iterations;
        assert_eq!(count, iterations as u64);
        // Debug test environments are noisy; keep this as a sanity guard.
        assert!(avg_ns < 50_000, "avg flow-check cost too high: {avg_ns}ns");
    }
}

#[cfg(test)]
mod declassification_tests {
    use super::*;

    fn declass_context() -> FlowEnforcementContext<'static> {
        FlowEnforcementContext::new("trace-declass", "decision-declass", "policy-declass")
    }

    fn requester_capabilities(with_declassify: bool) -> BTreeSet<Capability> {
        let mut capabilities: BTreeSet<Capability> = [
            Capability::FsRead,
            Capability::NetClient,
            Capability::HostCall,
        ]
        .into_iter()
        .collect();
        if with_declassify {
            capabilities.insert(Capability::Declassify);
        }
        capabilities
    }

    fn make_request(
        request_id: &str,
        requester: &str,
        current_label: FlowLabel,
        target_label: FlowLabel,
        purpose: DeclassificationPurpose,
        timestamp_ns: u64,
    ) -> DeclassificationRequest {
        DeclassificationRequest {
            request_id: request_id.to_string(),
            requester: requester.to_string(),
            data_ref: DataRef::new("memory", "payload"),
            current_label,
            target_label,
            purpose,
            justification: "operator approved transition".to_string(),
            timestamp_ns,
        }
    }

    #[test]
    fn requester_capability_contract_denies_without_declassify() {
        let mut gateway = DeclassificationGateway::default();
        let request = make_request(
            "req-cap-1",
            "ext-a",
            FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
            FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated),
            DeclassificationPurpose::DiagnosticExport,
            10,
        );

        let outcome = gateway.evaluate_request(
            request,
            &requester_capabilities(false),
            450_000,
            &declass_context(),
        );

        match outcome {
            DeclassificationOutcome::Denied { reason, receipt } => {
                assert!(matches!(
                    reason,
                    DeclassificationDenialReason::MissingCapability {
                        capability: Capability::Declassify
                    }
                ));
                assert!(receipt.verify(&gateway.public_key()));
            }
            other => panic!("expected denied outcome, got {other:?}"),
        }

        assert_eq!(gateway.denied_evidence().len(), 1);
        assert_eq!(
            gateway.denied_evidence()[0].severity,
            DeclassificationEvidenceSeverity::High
        );
    }

    #[test]
    fn label_distance_contract_requires_operator_override_for_multi_level_drop() {
        let current = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated);
        let target = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Validated);
        let caps = requester_capabilities(true);

        let mut denied_gateway = DeclassificationGateway::default();
        let denied = denied_gateway.evaluate_request(
            make_request(
                "req-distance-denied",
                "ext-a",
                current,
                target,
                DeclassificationPurpose::PublicApiResponse,
                20,
            ),
            &caps,
            500_000,
            &declass_context(),
        );
        assert!(matches!(
            denied,
            DeclassificationOutcome::Denied {
                reason: DeclassificationDenialReason::LabelDistanceTooLarge { .. },
                ..
            }
        ));

        let mut approved_gateway = DeclassificationGateway::default();
        let approved = approved_gateway.evaluate_request(
            make_request(
                "req-distance-approved",
                "ext-a",
                current,
                target,
                DeclassificationPurpose::OperatorOverride,
                30,
            ),
            &caps,
            500_000,
            &declass_context(),
        );
        assert!(matches!(approved, DeclassificationOutcome::Approved { .. }));
    }

    #[test]
    fn purpose_validity_contract_enforces_target_level_constraints() {
        let mut gateway = DeclassificationGateway::default();
        let outcome = gateway.evaluate_request(
            make_request(
                "req-purpose-1",
                "ext-a",
                FlowLabel::new(SecrecyLevel::TopSecret, IntegrityLevel::Validated),
                FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
                DeclassificationPurpose::PublicApiResponse,
                40,
            ),
            &requester_capabilities(true),
            500_000,
            &declass_context(),
        );

        assert!(matches!(
            outcome,
            DeclassificationOutcome::Denied {
                reason: DeclassificationDenialReason::InvalidPurpose { .. },
                ..
            }
        ));
    }

    #[test]
    fn rate_limit_contract_denies_after_threshold() {
        let contracts: Vec<Box<dyn DecisionContract>> = vec![
            Box::new(RequesterCapabilityContract),
            Box::new(LabelDistanceContract),
            Box::new(PurposeValidityContract),
            Box::new(RateLimitContract::new(2, 1_000)),
        ];
        let mut gateway = DeclassificationGateway::new(DecisionSigningKey::default(), contracts);
        let caps = requester_capabilities(true);
        let base_current = FlowLabel::new(SecrecyLevel::Confidential, IntegrityLevel::Validated);
        let base_target = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated);

        let first = gateway.evaluate_request(
            make_request(
                "req-rate-1",
                "ext-a",
                base_current,
                base_target,
                DeclassificationPurpose::DiagnosticExport,
                100,
            ),
            &caps,
            500_000,
            &declass_context(),
        );
        let second = gateway.evaluate_request(
            make_request(
                "req-rate-2",
                "ext-a",
                base_current,
                base_target,
                DeclassificationPurpose::DiagnosticExport,
                200,
            ),
            &caps,
            500_000,
            &declass_context(),
        );
        let third = gateway.evaluate_request(
            make_request(
                "req-rate-3",
                "ext-a",
                base_current,
                base_target,
                DeclassificationPurpose::DiagnosticExport,
                300,
            ),
            &caps,
            500_000,
            &declass_context(),
        );

        assert!(matches!(first, DeclassificationOutcome::Approved { .. }));
        assert!(matches!(second, DeclassificationOutcome::Approved { .. }));
        assert!(matches!(
            third,
            DeclassificationOutcome::Denied {
                reason: DeclassificationDenialReason::RateLimited { .. },
                ..
            }
        ));
    }

    #[derive(Debug)]
    struct AlwaysDenyContract;

    impl DecisionContract for AlwaysDenyContract {
        fn contract_id(&self) -> &'static str {
            "always_deny"
        }

        fn evaluate(
            &self,
            _request: &DeclassificationRequest,
            _context: &DeclassificationEvaluationContext<'_>,
        ) -> DecisionVerdict {
            DecisionVerdict::Denied {
                reason: DeclassificationDenialReason::ContractRejected {
                    contract_id: self.contract_id().to_string(),
                    detail: "forced deny".to_string(),
                },
            }
        }
    }

    #[test]
    fn contract_chain_short_circuits_on_first_denial() {
        let contracts: Vec<Box<dyn DecisionContract>> = vec![
            Box::new(RequesterCapabilityContract),
            Box::new(AlwaysDenyContract),
            Box::new(PurposeValidityContract),
        ];
        let mut gateway = DeclassificationGateway::new(DecisionSigningKey::default(), contracts);
        let outcome = gateway.evaluate_request(
            make_request(
                "req-chain-1",
                "ext-a",
                FlowLabel::new(SecrecyLevel::Confidential, IntegrityLevel::Validated),
                FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated),
                DeclassificationPurpose::DiagnosticExport,
                500,
            ),
            &requester_capabilities(true),
            500_000,
            &declass_context(),
        );

        let receipt = match outcome {
            DeclassificationOutcome::Denied { receipt, .. } => receipt,
            other => panic!("expected denied outcome, got {other:?}"),
        };
        assert_eq!(
            receipt.contract_chain,
            vec![
                "requester_capability".to_string(),
                "always_deny".to_string()
            ]
        );
        assert!(receipt.verify(&gateway.public_key()));
    }

    #[test]
    fn decision_receipts_are_signed_and_append_only() {
        let mut gateway = DeclassificationGateway::default();
        let caps = requester_capabilities(true);
        let current = FlowLabel::new(SecrecyLevel::Confidential, IntegrityLevel::Validated);
        let target = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated);

        let first = gateway.evaluate_request(
            make_request(
                "req-receipt-1",
                "ext-a",
                current,
                target,
                DeclassificationPurpose::DiagnosticExport,
                600,
            ),
            &caps,
            500_000,
            &declass_context(),
        );
        let second = gateway.evaluate_request(
            make_request(
                "req-receipt-2",
                "ext-a",
                current,
                target,
                DeclassificationPurpose::DiagnosticExport,
                700,
            ),
            &caps,
            500_000,
            &declass_context(),
        );
        assert!(matches!(first, DeclassificationOutcome::Approved { .. }));
        assert!(matches!(second, DeclassificationOutcome::Approved { .. }));

        let receipts = gateway.receipt_log().receipts();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].request_id, "req-receipt-1");
        assert_eq!(receipts[1].request_id, "req-receipt-2");
        assert!(receipts
            .iter()
            .all(|receipt| receipt.verify(&gateway.public_key())));
    }

    #[test]
    fn integration_declassification_then_hostcall_egress() {
        let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
        let mut gateway = DeclassificationGateway::default();
        let caps = requester_capabilities(true);

        let secret_payload = Labeled::new(
            "token-123".to_string(),
            FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
        );
        let blocked = dispatcher.dispatch(
            "ext-a",
            HostcallType::NetworkSend,
            &caps,
            Capability::NetClient,
            secret_payload.clone(),
            &declass_context(),
        );
        assert!(matches!(
            blocked.result,
            HostcallResult::Denied {
                reason: DenialReason::FlowViolation { .. }
            }
        ));

        let decision = gateway.evaluate_request(
            make_request(
                "req-int-1",
                "ext-a",
                secret_payload.label(),
                FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Validated),
                DeclassificationPurpose::OperatorOverride,
                800,
            ),
            &caps,
            500_000,
            &declass_context(),
        );
        let (new_label, receipt) = match decision {
            DeclassificationOutcome::Approved { new_label, receipt } => (new_label, receipt),
            other => panic!("expected approved outcome, got {other:?}"),
        };
        assert!(receipt.verify(&gateway.public_key()));

        let relabeled_payload = Labeled::new(secret_payload.into_inner(), new_label);
        let allowed = dispatcher.dispatch(
            "ext-a",
            HostcallType::NetworkSend,
            &caps,
            Capability::NetClient,
            relabeled_payload,
            &declass_context(),
        );
        assert_eq!(allowed.result, HostcallResult::Success);
    }

    #[test]
    fn declassification_events_emit_required_stable_fields() {
        let mut gateway = DeclassificationGateway::default();
        let _ = gateway.evaluate_request(
            make_request(
                "req-event-1",
                "ext-a",
                FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
                FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated),
                DeclassificationPurpose::DiagnosticExport,
                900,
            ),
            &requester_capabilities(false),
            500_000,
            &declass_context(),
        );

        let event = gateway.events().last().expect("declassification event");
        assert_eq!(event.trace_id, "trace-declass");
        assert_eq!(event.decision_id, "decision-declass");
        assert_eq!(event.policy_id, "policy-declass");
        assert_eq!(event.component, "declassification_gateway");
        assert_eq!(event.event, "declassification_request");
        assert_eq!(event.outcome, "denied");
        assert_eq!(event.error_code.as_deref(), Some("FE-DECLASS-0001"));
    }
}

#[cfg(test)]
mod delegate_cell_tests {
    use super::*;

    const GUARDPLANE_REPLAY_COMMAND_SPACE_SENTINEL: &str = "__FRANKEN_ENGINE_SPACE__";

    fn delegate_base_manifest(capabilities: &[Capability]) -> ExtensionManifest {
        let mut manifest = ExtensionManifest {
            name: "delegate-ext".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "dist/delegate.js".to_string(),
            capabilities: capabilities.iter().copied().collect(),
            publisher_signature: Some(vec![1, 2, 3, 4]),
            content_hash: [0; 32],
            trust_chain_ref: Some("chain/delegate".to_string()),
            min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
        };
        manifest.content_hash = compute_content_hash(&manifest).expect("content hash");
        manifest
    }

    fn delegate_manifest(
        capabilities: &[Capability],
        max_lifetime_ns: u64,
    ) -> DelegateCellManifest {
        DelegateCellManifest {
            base_manifest: delegate_base_manifest(capabilities),
            delegation_scope: DelegationScope::DiagnosticCollection,
            delegator_id: "engine-core".to_string(),
            max_lifetime_ns,
        }
    }

    fn lifecycle_context() -> LifecycleContext<'static> {
        LifecycleContext::new("trace-delegate", "decision-delegate", "policy-delegate")
    }

    fn flow_context() -> FlowEnforcementContext<'static> {
        FlowEnforcementContext::new(
            "trace-flow-delegate",
            "decision-flow-delegate",
            "policy-flow-delegate",
        )
    }

    fn guardplane_replay_command_from_env() -> String {
        if let Ok(encoded) = std::env::var("FE_GUARDPLANE_REPLAY_COMMAND_ENCODED") {
            return encoded.replace(GUARDPLANE_REPLAY_COMMAND_SPACE_SENTINEL, " ");
        }
        std::env::var("FE_GUARDPLANE_REPLAY_COMMAND")
            .unwrap_or_else(|_| "./scripts/run_guardplane_policy_actions_suite.sh ci".to_string())
    }

    #[test]
    fn delegate_manifest_validation_rejects_invalid_configuration() {
        let empty_delegator = DelegateCellManifest {
            base_manifest: delegate_base_manifest(&[Capability::FsRead]),
            delegation_scope: DelegationScope::DiagnosticCollection,
            delegator_id: "".to_string(),
            max_lifetime_ns: 10,
        };
        assert!(matches!(
            empty_delegator.validate(),
            Err(DelegateCellError::InvalidDelegatorId)
        ));

        let no_caps = DelegateCellManifest {
            base_manifest: delegate_base_manifest(&[]),
            delegation_scope: DelegationScope::DiagnosticCollection,
            delegator_id: "engine-core".to_string(),
            max_lifetime_ns: 10,
        };
        assert!(matches!(
            no_caps.validate(),
            Err(DelegateCellError::MissingCapabilities)
        ));

        let invalid_lifetime = delegate_manifest(&[Capability::FsRead], 0);
        assert!(matches!(
            invalid_lifetime.validate(),
            Err(DelegateCellError::InvalidMaxLifetime { .. })
        ));
    }

    #[test]
    fn factory_creates_delegate_with_full_lifecycle_and_guardplane_registration() {
        let factory = DelegateCellFactory::default();
        let delegate = factory
            .create_delegate_cell(
                "delegate-a",
                delegate_manifest(
                    &[
                        Capability::FsRead,
                        Capability::HostCall,
                        Capability::NetClient,
                        Capability::Declassify,
                    ],
                    1_000_000,
                ),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 1_000),
                BudgetExhaustionPolicy::Suspend,
                100,
                &lifecycle_context(),
            )
            .expect("delegate created");

        assert_eq!(delegate.state(), ExtensionState::Running);
        assert_eq!(delegate.guardplane_state().delegate_id, "delegate-a");
        assert_eq!(
            delegate.guardplane_state().posterior_micros,
            DelegateCellPolicy::default().initial_posterior_micros
        );
        assert!(delegate
            .lifecycle_manager()
            .transition_log()
            .iter()
            .any(|record| record.to_state == ExtensionState::Running));
        assert!(!delegate.events().is_empty());
    }

    #[test]
    fn out_of_envelope_hostcall_enters_escrow_and_updates_guardplane() {
        let factory = DelegateCellFactory::default();
        let mut delegate = factory
            .create_delegate_cell(
                "delegate-b",
                delegate_manifest(&[Capability::FsRead, Capability::NetClient], 1_000_000),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                200,
                &lifecycle_context(),
            )
            .expect("delegate created");
        let baseline = delegate.guardplane_state().posterior_micros;

        let outcome = delegate
            .dispatch_hostcall(
                HostcallType::ProcessSpawn,
                Capability::ProcessSpawn,
                Labeled::system_generated("diag".to_string()),
                250,
                &flow_context(),
                &lifecycle_context(),
            )
            .expect("hostcall dispatch");

        assert!(matches!(
            outcome.result,
            HostcallResult::Denied {
                reason: DenialReason::CapabilityEscrowPending {
                    attempted: Capability::ProcessSpawn,
                    action: CapabilityEscrowRoute::Challenge,
                    ..
                }
            }
        ));
        assert!(delegate
            .evidence()
            .iter()
            .any(|item| matches!(item, DelegateCellEvidence::CapabilityEscrow(_))));
        assert!(delegate.guardplane_state().posterior_micros > baseline);
    }

    #[test]
    fn delegate_flow_violation_matches_extension_flow_enforcement_shape() {
        let factory = DelegateCellFactory::default();
        let mut delegate = factory
            .create_delegate_cell(
                "delegate-c",
                delegate_manifest(&[Capability::FsRead, Capability::NetClient], 1_000_000),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                300,
                &lifecycle_context(),
            )
            .expect("delegate created");
        let payload = Labeled::new(
            "secret".to_string(),
            FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
        );

        let outcome = delegate
            .dispatch_hostcall(
                HostcallType::NetworkSend,
                Capability::NetClient,
                payload,
                350,
                &flow_context(),
                &lifecycle_context(),
            )
            .expect("hostcall dispatch");

        assert!(matches!(
            outcome.result,
            HostcallResult::Denied {
                reason: DenialReason::FlowViolation { .. }
            }
        ));
        let violation = delegate
            .hostcall_violation_events()
            .last()
            .expect("flow violation event");
        assert_eq!(violation.component, "runtime_flow_enforcement");
        assert_eq!(violation.event, "hostcall_flow_violation");
        assert_eq!(violation.error_code, "FE-FLOW-0001");
        assert!(delegate
            .evidence()
            .iter()
            .any(|item| matches!(item, DelegateCellEvidence::FlowViolation(_))));
    }

    #[test]
    fn delegate_lifetime_expiry_forces_containment() {
        let factory = DelegateCellFactory::default();
        let mut delegate = factory
            .create_delegate_cell(
                "delegate-d",
                delegate_manifest(&[Capability::FsRead, Capability::NetClient], 50),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                400,
                &lifecycle_context(),
            )
            .expect("delegate created");

        let err = delegate
            .check_lifetime(500, &lifecycle_context())
            .expect_err("lifetime should expire");
        assert!(matches!(err, DelegateCellError::LifetimeExpired { .. }));
        assert!(matches!(
            delegate.state(),
            ExtensionState::Terminated | ExtensionState::Quarantined
        ));
        assert!(delegate
            .lifecycle_manager()
            .pending_cancel_token()
            .is_none());
        assert!(delegate
            .evidence()
            .iter()
            .any(|item| matches!(item, DelegateCellEvidence::LifetimeExpired { .. })));
    }

    #[test]
    fn escrow_flood_denial_reports_hard_denial_to_callers() {
        let factory = DelegateCellFactory::default();
        let mut delegate = factory
            .create_delegate_cell(
                "delegate-flood",
                delegate_manifest(&[Capability::FsRead, Capability::NetClient], 1_000_000),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                450,
                &lifecycle_context(),
            )
            .expect("delegate created");

        let mut terminal_outcome = None;
        for index in 0..17 {
            let outcome = delegate
                .dispatch_hostcall(
                    HostcallType::ProcessSpawn,
                    Capability::ProcessSpawn,
                    Labeled::system_generated(format!("diag-{index}")),
                    500 + index as u64,
                    &flow_context(),
                    &lifecycle_context(),
                )
                .expect("hostcall dispatch");
            terminal_outcome = Some(outcome);
        }

        let outcome = terminal_outcome.expect("final outcome");
        let escrow_id = match outcome.result {
            HostcallResult::Denied {
                reason:
                    DenialReason::CapabilityEscrowDenied {
                        attempted: Capability::ProcessSpawn,
                        escrow_id,
                    },
            } => escrow_id,
            other => panic!("expected hard escrow denial, got {other:?}"),
        };

        let receipt = delegate
            .capability_escrow_receipts()
            .last()
            .expect("capability escrow receipt");
        assert_eq!(receipt.request_id, escrow_id);
        assert_eq!(receipt.state, CapabilityEscrowState::Denied);
        assert_eq!(receipt.error_code.as_deref(), Some(ESCROW_FLOOD_ERROR_CODE));
    }

    #[test]
    fn delegate_declassification_path_produces_receipts_and_denial_evidence() {
        let factory = DelegateCellFactory::default();
        let mut allowed_delegate = factory
            .create_delegate_cell(
                "delegate-e",
                delegate_manifest(
                    &[
                        Capability::FsRead,
                        Capability::NetClient,
                        Capability::Declassify,
                        Capability::HostCall,
                    ],
                    1_000_000,
                ),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                500,
                &lifecycle_context(),
            )
            .expect("delegate created");

        let approved = allowed_delegate
            .request_declassification(
                DeclassificationRequest {
                    request_id: "delegate-dec-1".to_string(),
                    requester: "delegate-e".to_string(),
                    data_ref: DataRef::new("memory", "token"),
                    current_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
                    target_label: FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Validated),
                    purpose: DeclassificationPurpose::OperatorOverride,
                    justification: "approved escalation".to_string(),
                    timestamp_ns: 550,
                },
                &flow_context(),
                &lifecycle_context(),
            )
            .expect("declassification outcome");

        match approved {
            DeclassificationOutcome::Approved { receipt, .. } => {
                assert!(receipt.verify(&allowed_delegate.declassification_gateway.public_key()));
            }
            other => panic!("expected approved declassification, got {other:?}"),
        }

        let mut denied_delegate = factory
            .create_delegate_cell(
                "delegate-f",
                delegate_manifest(&[Capability::FsRead, Capability::NetClient], 1_000_000),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                600,
                &lifecycle_context(),
            )
            .expect("delegate created");

        let denied = denied_delegate
            .request_declassification(
                DeclassificationRequest {
                    request_id: "delegate-dec-2".to_string(),
                    requester: "delegate-f".to_string(),
                    data_ref: DataRef::new("memory", "token"),
                    current_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
                    target_label: FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated),
                    purpose: DeclassificationPurpose::DiagnosticExport,
                    justification: "attempted".to_string(),
                    timestamp_ns: 650,
                },
                &flow_context(),
                &lifecycle_context(),
            )
            .expect("declassification outcome");

        assert!(matches!(
            denied,
            DeclassificationOutcome::Denied {
                reason: DeclassificationDenialReason::MissingCapability { .. },
                ..
            }
        ));
        assert!(denied_delegate
            .evidence()
            .iter()
            .any(|item| matches!(item, DelegateCellEvidence::DeclassificationDenied(_))));
    }

    #[test]
    fn non_running_delegate_cannot_dispatch_hostcalls() {
        let factory = DelegateCellFactory::default();
        let mut delegate = factory
            .create_delegate_cell(
                "delegate-inactive-hostcall",
                delegate_manifest(&[Capability::FsRead, Capability::NetClient], 1_000_000),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                675,
                &lifecycle_context(),
            )
            .expect("delegate created");

        delegate
            .apply_transition(LifecycleTransition::Terminate, 700, &lifecycle_context())
            .expect("terminate");

        let err = delegate
            .dispatch_hostcall(
                HostcallType::FsRead,
                Capability::FsRead,
                Labeled::system_generated("probe".to_string()),
                701,
                &flow_context(),
                &lifecycle_context(),
            )
            .expect_err("hostcall should fail-closed outside running state");
        assert!(matches!(
            err,
            DelegateCellError::InactiveState {
                state: ExtensionState::Terminating,
                action: "dispatch_hostcall",
                ..
            }
        ));
    }

    #[test]
    fn non_running_delegate_cannot_request_declassification() {
        let factory = DelegateCellFactory::default();
        let mut delegate = factory
            .create_delegate_cell(
                "delegate-inactive-declass",
                delegate_manifest(
                    &[
                        Capability::FsRead,
                        Capability::NetClient,
                        Capability::Declassify,
                    ],
                    1_000_000,
                ),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                725,
                &lifecycle_context(),
            )
            .expect("delegate created");

        delegate
            .apply_transition(LifecycleTransition::Quarantine, 750, &lifecycle_context())
            .expect("quarantine");

        let err = delegate
            .request_declassification(
                DeclassificationRequest {
                    request_id: "delegate-inactive-declass-request".to_string(),
                    requester: "delegate-inactive-declass".to_string(),
                    data_ref: DataRef::new("memory", "token"),
                    current_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
                    target_label: FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated),
                    purpose: DeclassificationPurpose::DiagnosticExport,
                    justification: "should fail closed outside running state".to_string(),
                    timestamp_ns: 751,
                },
                &flow_context(),
                &lifecycle_context(),
            )
            .expect_err("declassification should fail-closed outside running state");
        assert!(matches!(
            err,
            DelegateCellError::InactiveState {
                state: ExtensionState::Quarantined,
                action: "request_declassification",
                ..
            }
        ));
    }

    #[test]
    fn guardplane_action_thresholds_are_deterministic() {
        assert_eq!(
            guardplane_action_from_posterior(0),
            GuardplanePolicyAction::Allow
        );
        assert_eq!(
            guardplane_action_from_posterior(250_000),
            GuardplanePolicyAction::Challenge
        );
        assert_eq!(
            guardplane_action_from_posterior(400_000),
            GuardplanePolicyAction::Sandbox
        );
        assert_eq!(
            guardplane_action_from_posterior(550_000),
            GuardplanePolicyAction::Suspend
        );
        assert_eq!(
            guardplane_action_from_posterior(700_000),
            GuardplanePolicyAction::Terminate
        );
        assert_eq!(
            guardplane_action_from_posterior(850_000),
            GuardplanePolicyAction::Quarantine
        );
    }

    #[test]
    fn guardplane_policy_actions_progress_from_challenge_to_quarantine() {
        let factory = DelegateCellFactory::default();
        let mut delegate = factory
            .create_delegate_cell(
                "delegate-g",
                delegate_manifest(&[Capability::FsRead, Capability::NetClient], 1_000_000),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                700,
                &lifecycle_context(),
            )
            .expect("delegate created");
        let expected_actions = [
            GuardplanePolicyAction::Challenge,
            GuardplanePolicyAction::Sandbox,
            GuardplanePolicyAction::Sandbox,
            GuardplanePolicyAction::Suspend,
            GuardplanePolicyAction::Terminate,
            GuardplanePolicyAction::Quarantine,
        ];

        for (index, expected_action) in expected_actions.iter().enumerate() {
            let outcome = delegate
                .request_declassification(
                    DeclassificationRequest {
                        request_id: format!("delegate-dec-denied-{index}"),
                        requester: "delegate-g".to_string(),
                        data_ref: DataRef::new("memory", "token"),
                        current_label: FlowLabel::new(
                            SecrecyLevel::Secret,
                            IntegrityLevel::Validated,
                        ),
                        target_label: FlowLabel::new(
                            SecrecyLevel::Internal,
                            IntegrityLevel::Validated,
                        ),
                        purpose: DeclassificationPurpose::DiagnosticExport,
                        justification: "expected denial".to_string(),
                        timestamp_ns: 710 + index as u64,
                    },
                    &flow_context(),
                    &lifecycle_context(),
                )
                .expect("declassification outcome");

            assert!(matches!(
                outcome,
                DeclassificationOutcome::Denied {
                    reason: DeclassificationDenialReason::MissingCapability { .. },
                    ..
                }
            ));
            let decision = delegate
                .guardplane_decision_log()
                .last()
                .expect("guardplane decision");
            assert_eq!(decision.action, *expected_action);
            assert_eq!(decision.source_event, "delegate_declassification");
            assert_eq!(
                decision.posterior_micros,
                310_000 + (index as u64 * 110_000)
            );
            assert_eq!(
                decision.schema_version,
                GUARDPLANE_DECISION_LOG_SCHEMA_VERSION
            );
            assert_eq!(decision.event, "delegate_guardplane_action");
            assert_eq!(decision.outcome, expected_action.as_str());
            assert!(decision.error_code.is_none());
        }

        assert_eq!(delegate.state(), ExtensionState::Quarantined);
        let transitions: Vec<_> = delegate
            .guardplane_decision_log()
            .iter()
            .filter_map(|entry| entry.lifecycle_transition)
            .collect();
        assert_eq!(
            transitions,
            vec![
                LifecycleTransition::Suspend,
                LifecycleTransition::Terminate,
                LifecycleTransition::Quarantine
            ]
        );
        let containment_actions: Vec<_> = delegate
            .containment_workflow_log()
            .iter()
            .map(|entry| entry.action)
            .collect();
        assert_eq!(
            containment_actions,
            vec![
                GuardplanePolicyAction::Sandbox,
                GuardplanePolicyAction::Sandbox,
                GuardplanePolicyAction::Suspend,
                GuardplanePolicyAction::Terminate,
                GuardplanePolicyAction::Quarantine
            ]
        );
        let last_containment = delegate
            .containment_workflow_log()
            .last()
            .expect("quarantine containment record");
        assert_eq!(
            last_containment.schema_version,
            CONTAINMENT_WORKFLOW_LOG_SCHEMA_VERSION
        );
        assert_eq!(last_containment.outcome, "ok");
        assert!(last_containment.error_code.is_none());
        assert!(last_containment.mesh_attempted_targets.is_empty());
        assert!(last_containment.mesh_targets.is_empty());
        assert!(last_containment.mesh_failed_targets.is_empty());
        assert!(!last_containment.mesh_propagated);
    }

    #[test]
    fn quarantine_mesh_targets_are_sorted_and_recorded() {
        let factory = DelegateCellFactory::default();
        let mut delegate = factory
            .create_delegate_cell(
                "delegate-mesh",
                delegate_manifest(&[Capability::FsRead, Capability::NetClient], 1_000_000),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                750,
                &lifecycle_context(),
            )
            .expect("delegate created");
        delegate.set_quarantine_mesh_peers(["peer-z", "peer-a", "peer-m", "peer-a"]);

        for index in 0..6 {
            let _ = delegate
                .request_declassification(
                    DeclassificationRequest {
                        request_id: format!("delegate-mesh-denied-{index}"),
                        requester: "delegate-mesh".to_string(),
                        data_ref: DataRef::new("memory", "token"),
                        current_label: FlowLabel::new(
                            SecrecyLevel::Secret,
                            IntegrityLevel::Validated,
                        ),
                        target_label: FlowLabel::new(
                            SecrecyLevel::Internal,
                            IntegrityLevel::Validated,
                        ),
                        purpose: DeclassificationPurpose::DiagnosticExport,
                        justification: "expected denial".to_string(),
                        timestamp_ns: 760 + index as u64,
                    },
                    &flow_context(),
                    &lifecycle_context(),
                )
                .expect("declassification outcome");
        }

        let expected_targets = vec![
            "peer-a".to_string(),
            "peer-m".to_string(),
            "peer-z".to_string(),
        ];
        let quarantine_record = delegate
            .containment_workflow_log()
            .iter()
            .find(|entry| entry.action == GuardplanePolicyAction::Quarantine)
            .expect("quarantine containment record");
        assert_eq!(quarantine_record.mesh_attempted_targets, expected_targets);
        assert_eq!(quarantine_record.mesh_targets, expected_targets);
        assert!(quarantine_record.mesh_failed_targets.is_empty());
        assert!(quarantine_record.mesh_propagated);
        assert_eq!(
            quarantine_record.resulting_state,
            ExtensionState::Quarantined
        );
        assert_eq!(
            quarantine_record.lifecycle_transition,
            Some(LifecycleTransition::Quarantine)
        );
        assert_eq!(quarantine_record.source_event, "delegate_declassification");
        assert_eq!(
            quarantine_record.schema_version,
            CONTAINMENT_WORKFLOW_LOG_SCHEMA_VERSION
        );
        assert_eq!(
            quarantine_record.event,
            "delegate_quarantine_mesh_propagated"
        );
        assert_eq!(quarantine_record.outcome, "ok");
        assert!(quarantine_record.error_code.is_none());
        assert!(delegate
            .events()
            .iter()
            .any(|event| event.event == "delegate_quarantine_mesh_propagated"
                && event.outcome == "ok"));
        let quarantine_evidence_targets = delegate
            .evidence()
            .iter()
            .find_map(|item| {
                if let DelegateCellEvidence::ContainmentAction {
                    action,
                    mesh_targets,
                    ..
                } = item
                {
                    (*action == GuardplanePolicyAction::Quarantine).then(|| mesh_targets.clone())
                } else {
                    None
                }
            })
            .expect("quarantine evidence");
        assert_eq!(quarantine_evidence_targets, expected_targets);
    }

    #[test]
    fn quarantine_mesh_partial_failures_are_recorded() {
        let factory = DelegateCellFactory::default();
        let mut delegate = factory
            .create_delegate_cell(
                "delegate-mesh-partial",
                delegate_manifest(&[Capability::FsRead, Capability::NetClient], 1_000_000),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                775,
                &lifecycle_context(),
            )
            .expect("delegate created");
        delegate.set_quarantine_mesh_peers(["peer-z", "peer-a", "peer-m"]);
        delegate.set_quarantine_mesh_unreachable_peers(["peer-m", "peer-ghost"]);

        for index in 0..6 {
            let _ = delegate
                .request_declassification(
                    DeclassificationRequest {
                        request_id: format!("delegate-mesh-partial-denied-{index}"),
                        requester: "delegate-mesh-partial".to_string(),
                        data_ref: DataRef::new("memory", "token"),
                        current_label: FlowLabel::new(
                            SecrecyLevel::Secret,
                            IntegrityLevel::Validated,
                        ),
                        target_label: FlowLabel::new(
                            SecrecyLevel::Internal,
                            IntegrityLevel::Validated,
                        ),
                        purpose: DeclassificationPurpose::DiagnosticExport,
                        justification: "expected denial".to_string(),
                        timestamp_ns: 780 + index as u64,
                    },
                    &flow_context(),
                    &lifecycle_context(),
                )
                .expect("declassification outcome");
        }

        let quarantine_record = delegate
            .containment_workflow_log()
            .iter()
            .find(|entry| entry.action == GuardplanePolicyAction::Quarantine)
            .expect("quarantine containment record");
        assert_eq!(
            quarantine_record.mesh_attempted_targets,
            vec![
                "peer-a".to_string(),
                "peer-m".to_string(),
                "peer-z".to_string(),
            ]
        );
        assert_eq!(
            quarantine_record.mesh_targets,
            vec!["peer-a".to_string(), "peer-z".to_string()]
        );
        assert_eq!(
            quarantine_record.mesh_failed_targets,
            vec!["peer-m".to_string()]
        );
        assert!(quarantine_record.mesh_propagated);
        assert_eq!(
            quarantine_record.event,
            "delegate_quarantine_mesh_partial_propagation"
        );
        assert_eq!(quarantine_record.outcome, "degraded");
        assert_eq!(
            quarantine_record.error_code.as_deref(),
            Some(DELEGATE_MESH_PROPAGATION_DEGRADED_ERROR_CODE)
        );
        assert!(delegate.events().iter().any(|event| {
            event.event == "delegate_quarantine_mesh_partial_propagation"
                && event.outcome == "degraded"
                && event.error_code.as_deref()
                    == Some(DELEGATE_MESH_PROPAGATION_DEGRADED_ERROR_CODE)
        }));
    }

    #[test]
    fn quarantine_mesh_total_failure_is_recorded() {
        let factory = DelegateCellFactory::default();
        let mut delegate = factory
            .create_delegate_cell(
                "delegate-mesh-failed",
                delegate_manifest(&[Capability::FsRead, Capability::NetClient], 1_000_000),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                790,
                &lifecycle_context(),
            )
            .expect("delegate created");
        delegate.set_quarantine_mesh_peers(["peer-a", "peer-m"]);
        delegate.set_quarantine_mesh_unreachable_peers(["peer-a", "peer-m"]);

        for index in 0..6 {
            let _ = delegate
                .request_declassification(
                    DeclassificationRequest {
                        request_id: format!("delegate-mesh-failed-denied-{index}"),
                        requester: "delegate-mesh-failed".to_string(),
                        data_ref: DataRef::new("memory", "token"),
                        current_label: FlowLabel::new(
                            SecrecyLevel::Secret,
                            IntegrityLevel::Validated,
                        ),
                        target_label: FlowLabel::new(
                            SecrecyLevel::Internal,
                            IntegrityLevel::Validated,
                        ),
                        purpose: DeclassificationPurpose::DiagnosticExport,
                        justification: "expected denial".to_string(),
                        timestamp_ns: 795 + index as u64,
                    },
                    &flow_context(),
                    &lifecycle_context(),
                )
                .expect("declassification outcome");
        }

        let quarantine_record = delegate
            .containment_workflow_log()
            .iter()
            .find(|entry| entry.action == GuardplanePolicyAction::Quarantine)
            .expect("quarantine containment record");
        assert_eq!(
            quarantine_record.mesh_attempted_targets,
            vec!["peer-a".to_string(), "peer-m".to_string()]
        );
        assert!(quarantine_record.mesh_targets.is_empty());
        assert_eq!(
            quarantine_record.mesh_failed_targets,
            vec!["peer-a".to_string(), "peer-m".to_string()]
        );
        assert!(!quarantine_record.mesh_propagated);
        assert_eq!(
            quarantine_record.event,
            "delegate_quarantine_mesh_propagation_failed"
        );
        assert_eq!(quarantine_record.outcome, "degraded");
        assert_eq!(
            quarantine_record.error_code.as_deref(),
            Some(DELEGATE_MESH_PROPAGATION_DEGRADED_ERROR_CODE)
        );
    }

    #[test]
    fn guardplane_safe_mode_fallback_is_fail_closed() {
        let factory = DelegateCellFactory::default();
        let mut delegate = factory
            .create_delegate_cell(
                "delegate-h",
                delegate_manifest(&[Capability::FsRead], 1_000_000),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                800,
                &lifecycle_context(),
            )
            .expect("delegate created");
        delegate.set_adaptive_components_available(false);

        let outcome = delegate
            .dispatch_hostcall(
                HostcallType::FsRead,
                Capability::FsRead,
                Labeled::system_generated("probe".to_string()),
                805,
                &flow_context(),
                &lifecycle_context(),
            )
            .expect("hostcall dispatch");

        assert_eq!(outcome.result, HostcallResult::Success);
        let decision = delegate
            .guardplane_decision_log()
            .last()
            .expect("guardplane decision");
        assert_eq!(decision.action, GuardplanePolicyAction::Sandbox);
        assert_eq!(
            decision.schema_version,
            GUARDPLANE_DECISION_LOG_SCHEMA_VERSION
        );
        assert_eq!(decision.event, "delegate_guardplane_action");
        assert_eq!(decision.outcome, "sandbox");
        assert!(decision.error_code.is_none());
        assert!(decision.safe_mode_fallback);
        assert_eq!(decision.lifecycle_transition, None);
        assert_eq!(decision.resulting_state, ExtensionState::Running);
        assert_eq!(decision.source_event, "delegate_hostcall");
    }

    #[test]
    fn guardplane_policy_action_logs_can_emit_jsonl_artifacts() {
        let factory = DelegateCellFactory::default();
        let mut delegate = factory
            .create_delegate_cell(
                "delegate-artifacts",
                delegate_manifest(&[Capability::FsRead, Capability::NetClient], 1_000_000),
                ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 100),
                BudgetExhaustionPolicy::Suspend,
                900,
                &lifecycle_context(),
            )
            .expect("delegate created");
        delegate.set_quarantine_mesh_peers(["peer-z", "peer-a", "peer-m"]);

        for index in 0..6 {
            let outcome = delegate
                .request_declassification(
                    DeclassificationRequest {
                        request_id: format!("delegate-artifacts-denied-{index}"),
                        requester: "delegate-artifacts".to_string(),
                        data_ref: DataRef::new("memory", "token"),
                        current_label: FlowLabel::new(
                            SecrecyLevel::Secret,
                            IntegrityLevel::Validated,
                        ),
                        target_label: FlowLabel::new(
                            SecrecyLevel::Internal,
                            IntegrityLevel::Validated,
                        ),
                        purpose: DeclassificationPurpose::DiagnosticExport,
                        justification: "expected denial".to_string(),
                        timestamp_ns: 901 + index as u64,
                    },
                    &flow_context(),
                    &lifecycle_context(),
                )
                .expect("declassification outcome");
            assert!(matches!(
                outcome,
                DeclassificationOutcome::Denied {
                    reason: DeclassificationDenialReason::MissingCapability { .. },
                    ..
                }
            ));
        }

        assert_eq!(delegate.state(), ExtensionState::Quarantined);
        assert!(!delegate.guardplane_decision_log().is_empty());
        assert!(!delegate.containment_workflow_log().is_empty());

        let replay_command = guardplane_replay_command_from_env();

        let mut guardplane_lines = Vec::new();
        for entry in delegate.guardplane_decision_log() {
            let mut value = serde_json::to_value(entry).expect("serialize guardplane entry");
            value
                .as_object_mut()
                .expect("guardplane entry object")
                .insert(
                    "replay_command".to_string(),
                    serde_json::Value::String(replay_command.clone()),
                );
            guardplane_lines
                .push(serde_json::to_string(&value).expect("encode guardplane json line"));
        }

        let mut containment_lines = Vec::new();
        for entry in delegate.containment_workflow_log() {
            let mut value = serde_json::to_value(entry).expect("serialize containment entry");
            value
                .as_object_mut()
                .expect("containment entry object")
                .insert(
                    "replay_command".to_string(),
                    serde_json::Value::String(replay_command.clone()),
                );
            containment_lines
                .push(serde_json::to_string(&value).expect("encode containment json line"));
        }

        if std::env::var_os("FE_GUARDPLANE_EMIT_STDOUT_MARKERS").is_some() {
            println!("__FE_GUARDPLANE_DECISION_LOG_BEGIN__");
            for line in &guardplane_lines {
                println!("{line}");
            }
            println!("__FE_GUARDPLANE_DECISION_LOG_END__");
            println!("__FE_CONTAINMENT_WORKFLOW_LOG_BEGIN__");
            for line in &containment_lines {
                println!("{line}");
            }
            println!("__FE_CONTAINMENT_WORKFLOW_LOG_END__");
        }

        if let Ok(path) = std::env::var("FE_GUARDPLANE_DECISION_LOG_PATH") {
            let path = std::path::PathBuf::from(path);
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).expect("create guardplane decision log parent");
            }
            std::fs::write(&path, guardplane_lines.join("\n") + "\n")
                .expect("write guardplane decision log");
        }

        if let Ok(path) = std::env::var("FE_CONTAINMENT_WORKFLOW_LOG_PATH") {
            let path = std::path::PathBuf::from(path);
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).expect("create containment workflow log parent");
            }
            std::fs::write(&path, containment_lines.join("\n") + "\n")
                .expect("write containment workflow log");
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Enrichment test module: serde round-trips, display/as_str, lattice,
// signing, error-code stability, boundary conditions.
// ────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod enrichment_tests {
    use super::*;

    // ── Capability ──────────────────────────────────────────────────────

    #[test]
    fn capability_serde_round_trip_all_variants() {
        let variants = [
            Capability::FsRead,
            Capability::FsWrite,
            Capability::NetClient,
            Capability::HostCall,
            Capability::ProcessSpawn,
            Capability::Declassify,
        ];
        for cap in &variants {
            let json = serde_json::to_string(cap).expect("serialize");
            let back: Capability = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*cap, back);
        }
    }

    #[test]
    fn capability_as_str_display_agree() {
        let variants = [
            Capability::FsRead,
            Capability::FsWrite,
            Capability::NetClient,
            Capability::HostCall,
            Capability::ProcessSpawn,
            Capability::Declassify,
        ];
        for cap in &variants {
            assert_eq!(cap.as_str(), cap.to_string());
        }
    }

    #[test]
    fn capability_serde_matches_as_str() {
        let variants = [
            Capability::FsRead,
            Capability::FsWrite,
            Capability::NetClient,
            Capability::HostCall,
            Capability::ProcessSpawn,
            Capability::Declassify,
        ];
        for cap in &variants {
            let json = serde_json::to_string(cap).expect("serialize");
            let expected = format!("\"{}\"", cap.as_str());
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn capability_implied_capabilities_coverage() {
        assert_eq!(
            Capability::FsWrite.implied_capabilities(),
            &[Capability::FsRead]
        );
        assert!(Capability::FsRead.implied_capabilities().is_empty());
        assert!(Capability::NetClient.implied_capabilities().is_empty());
        assert!(Capability::HostCall.implied_capabilities().is_empty());
        assert!(Capability::ProcessSpawn.implied_capabilities().is_empty());
        assert!(Capability::Declassify.implied_capabilities().is_empty());
    }

    // ── ManifestTrustLevel ──────────────────────────────────────────────

    #[test]
    fn manifest_trust_level_serde_round_trip() {
        for level in [
            ManifestTrustLevel::Development,
            ManifestTrustLevel::SignedSupplyChain,
        ] {
            let json = serde_json::to_string(&level).expect("serialize");
            let back: ManifestTrustLevel = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(level, back);
        }
    }

    // ── ExtensionState ──────────────────────────────────────────────────

    #[test]
    fn extension_state_serde_round_trip_all_variants() {
        let variants = [
            ExtensionState::Unloaded,
            ExtensionState::Validating,
            ExtensionState::Loading,
            ExtensionState::Starting,
            ExtensionState::Running,
            ExtensionState::Suspending,
            ExtensionState::Suspended,
            ExtensionState::Resuming,
            ExtensionState::Terminating,
            ExtensionState::Terminated,
            ExtensionState::Quarantined,
        ];
        for state in &variants {
            let json = serde_json::to_string(state).expect("serialize");
            let back: ExtensionState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*state, back);
        }
    }

    #[test]
    fn extension_state_as_str_display_agree() {
        let variants = [
            ExtensionState::Unloaded,
            ExtensionState::Validating,
            ExtensionState::Loading,
            ExtensionState::Starting,
            ExtensionState::Running,
            ExtensionState::Suspending,
            ExtensionState::Suspended,
            ExtensionState::Resuming,
            ExtensionState::Terminating,
            ExtensionState::Terminated,
            ExtensionState::Quarantined,
        ];
        for state in &variants {
            assert_eq!(state.as_str(), state.to_string());
        }
    }

    #[test]
    fn extension_state_serde_matches_as_str() {
        let variants = [
            ExtensionState::Unloaded,
            ExtensionState::Validating,
            ExtensionState::Loading,
            ExtensionState::Starting,
            ExtensionState::Running,
            ExtensionState::Suspending,
            ExtensionState::Suspended,
            ExtensionState::Resuming,
            ExtensionState::Terminating,
            ExtensionState::Terminated,
            ExtensionState::Quarantined,
        ];
        for state in &variants {
            let json = serde_json::to_string(state).expect("serialize");
            let expected = format!("\"{}\"", state.as_str());
            assert_eq!(json, expected);
        }
    }

    // ── LifecycleTransition ─────────────────────────────────────────────

    #[test]
    fn lifecycle_transition_serde_round_trip_all_variants() {
        let variants = [
            LifecycleTransition::Validate,
            LifecycleTransition::Load,
            LifecycleTransition::Start,
            LifecycleTransition::Activate,
            LifecycleTransition::Suspend,
            LifecycleTransition::Freeze,
            LifecycleTransition::Resume,
            LifecycleTransition::Reactivate,
            LifecycleTransition::Terminate,
            LifecycleTransition::Finalize,
            LifecycleTransition::Quarantine,
        ];
        for t in &variants {
            let json = serde_json::to_string(t).expect("serialize");
            let back: LifecycleTransition = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*t, back);
        }
    }

    #[test]
    fn lifecycle_transition_as_str_display_agree() {
        let variants = [
            LifecycleTransition::Validate,
            LifecycleTransition::Load,
            LifecycleTransition::Start,
            LifecycleTransition::Activate,
            LifecycleTransition::Suspend,
            LifecycleTransition::Freeze,
            LifecycleTransition::Resume,
            LifecycleTransition::Reactivate,
            LifecycleTransition::Terminate,
            LifecycleTransition::Finalize,
            LifecycleTransition::Quarantine,
        ];
        for t in &variants {
            assert_eq!(t.as_str(), t.to_string());
        }
    }

    // ── BudgetExhaustionPolicy ──────────────────────────────────────────

    #[test]
    fn budget_exhaustion_policy_serde_round_trip() {
        for p in [
            BudgetExhaustionPolicy::Suspend,
            BudgetExhaustionPolicy::Terminate,
        ] {
            let json = serde_json::to_string(&p).expect("serialize");
            let back: BudgetExhaustionPolicy = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(p, back);
        }
    }

    #[test]
    fn budget_exhaustion_policy_as_str_display_agree() {
        for p in [
            BudgetExhaustionPolicy::Suspend,
            BudgetExhaustionPolicy::Terminate,
        ] {
            assert_eq!(p.as_str(), p.to_string());
        }
    }

    // ── ResourceBudget ──────────────────────────────────────────────────

    #[test]
    fn resource_budget_serde_round_trip() {
        let budget = ResourceBudget::new(1_000_000, 512 * 1024, 100);
        let json = serde_json::to_string(&budget).expect("serialize");
        let back: ResourceBudget = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(budget, back);
    }

    #[test]
    fn resource_budget_exhausted_dimension_cpu() {
        let budget = ResourceBudget::new(0, 1024, 10);
        assert_eq!(
            budget.exhausted_dimension(),
            Some(("cpu_time_ns_remaining", 0))
        );
    }

    #[test]
    fn resource_budget_exhausted_dimension_memory() {
        let budget = ResourceBudget::new(1, 0, 10);
        assert_eq!(
            budget.exhausted_dimension(),
            Some(("memory_bytes_remaining", 0))
        );
    }

    #[test]
    fn resource_budget_exhausted_dimension_hostcall() {
        let budget = ResourceBudget::new(1, 1, 0);
        assert_eq!(
            budget.exhausted_dimension(),
            Some(("hostcall_count_remaining", 0))
        );
    }

    #[test]
    fn resource_budget_exhausted_dimension_none() {
        let budget = ResourceBudget::new(1, 1, 1);
        assert_eq!(budget.exhausted_dimension(), None);
    }

    #[test]
    fn resource_budget_consume_saturates_at_zero() {
        let mut budget = ResourceBudget::new(10, 10, 2);
        budget.consume_cpu(100);
        assert_eq!(budget.cpu_time_ns_remaining, 0);
        budget.consume_memory(100);
        assert_eq!(budget.memory_bytes_remaining, 0);
        budget.consume_hostcall();
        budget.consume_hostcall();
        budget.consume_hostcall();
        assert_eq!(budget.hostcall_count_remaining, 0);
    }

    // ── CancellationConfig ──────────────────────────────────────────────

    #[test]
    fn cancellation_config_default_matches_constant() {
        let config = CancellationConfig::default();
        assert_eq!(config.grace_period_ns, DEFAULT_TERMINATION_GRACE_PERIOD_NS);
    }

    #[test]
    fn cancellation_config_clamped_zero_becomes_one() {
        let config = CancellationConfig { grace_period_ns: 0 };
        let clamped = config.clamped();
        assert_eq!(clamped.grace_period_ns, 1);
    }

    #[test]
    fn cancellation_config_clamped_above_max() {
        let config = CancellationConfig {
            grace_period_ns: MAX_TERMINATION_GRACE_PERIOD_NS + 1,
        };
        let clamped = config.clamped();
        assert_eq!(clamped.grace_period_ns, MAX_TERMINATION_GRACE_PERIOD_NS);
    }

    #[test]
    fn cancellation_config_clamped_within_range_unchanged() {
        let config = CancellationConfig {
            grace_period_ns: 1_000,
        };
        let clamped = config.clamped();
        assert_eq!(clamped.grace_period_ns, 1_000);
    }

    #[test]
    fn cancellation_config_serde_round_trip() {
        let config = CancellationConfig {
            grace_period_ns: 7_500_000,
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let back: CancellationConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, back);
    }

    // ── SecrecyLevel / IntegrityLevel ───────────────────────────────────

    #[test]
    fn secrecy_level_serde_round_trip() {
        let variants = [
            SecrecyLevel::Public,
            SecrecyLevel::Internal,
            SecrecyLevel::Confidential,
            SecrecyLevel::Secret,
            SecrecyLevel::TopSecret,
        ];
        for level in &variants {
            let json = serde_json::to_string(level).expect("serialize");
            let back: SecrecyLevel = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*level, back);
        }
    }

    #[test]
    fn secrecy_level_rank_is_monotonically_increasing() {
        let ordered = [
            SecrecyLevel::Public,
            SecrecyLevel::Internal,
            SecrecyLevel::Confidential,
            SecrecyLevel::Secret,
            SecrecyLevel::TopSecret,
        ];
        for window in ordered.windows(2) {
            assert!(window[0].rank() < window[1].rank());
        }
    }

    #[test]
    fn integrity_level_serde_round_trip() {
        let variants = [
            IntegrityLevel::Untrusted,
            IntegrityLevel::Validated,
            IntegrityLevel::Verified,
            IntegrityLevel::Trusted,
        ];
        for level in &variants {
            let json = serde_json::to_string(level).expect("serialize");
            let back: IntegrityLevel = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*level, back);
        }
    }

    #[test]
    fn integrity_level_rank_is_monotonically_increasing() {
        let ordered = [
            IntegrityLevel::Untrusted,
            IntegrityLevel::Validated,
            IntegrityLevel::Verified,
            IntegrityLevel::Trusted,
        ];
        for window in ordered.windows(2) {
            assert!(window[0].rank() < window[1].rank());
        }
    }

    // ── FlowLabel ───────────────────────────────────────────────────────

    #[test]
    fn flow_label_serde_round_trip() {
        let label = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Verified);
        let json = serde_json::to_string(&label).expect("serialize");
        let back: FlowLabel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(label, back);
    }

    #[test]
    fn flow_label_default_is_maximally_restrictive() {
        let label = FlowLabel::default();
        assert_eq!(label.secrecy(), SecrecyLevel::TopSecret);
        assert_eq!(label.integrity(), IntegrityLevel::Untrusted);
    }

    #[test]
    fn flow_label_join_takes_max_secrecy_min_integrity() {
        let a = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Verified);
        let b = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Trusted);
        let joined = a.join(b);
        assert_eq!(joined.secrecy(), SecrecyLevel::Secret);
        assert_eq!(joined.integrity(), IntegrityLevel::Verified);
    }

    #[test]
    fn flow_label_join_is_commutative() {
        let a = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
        let b = FlowLabel::new(SecrecyLevel::Confidential, IntegrityLevel::Untrusted);
        assert_eq!(a.join(b), b.join(a));
    }

    #[test]
    fn flow_label_join_identity_same_label() {
        let a = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated);
        assert_eq!(a.join(a), a);
    }

    #[test]
    fn flow_label_join_default_is_absorbing() {
        let specific = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
        let joined = specific.join(FlowLabel::default());
        assert_eq!(joined.secrecy(), SecrecyLevel::TopSecret);
        assert_eq!(joined.integrity(), IntegrityLevel::Untrusted);
    }

    // ── FlowLabelLattice ────────────────────────────────────────────────

    #[test]
    fn can_flow_same_label_is_allowed() {
        let label = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated);
        assert!(FlowLabelLattice::can_flow(&label, &label));
    }

    #[test]
    fn can_flow_upward_secrecy_is_allowed() {
        let from = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Validated);
        let to = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated);
        assert!(FlowLabelLattice::can_flow(&from, &to));
    }

    #[test]
    fn can_flow_downward_secrecy_is_blocked() {
        let from = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated);
        let to = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Validated);
        assert!(!FlowLabelLattice::can_flow(&from, &to));
    }

    #[test]
    fn can_flow_downward_integrity_is_allowed() {
        let from = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Trusted);
        let to = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Untrusted);
        assert!(FlowLabelLattice::can_flow(&from, &to));
    }

    #[test]
    fn can_flow_upward_integrity_is_blocked() {
        let from = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Untrusted);
        let to = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Trusted);
        assert!(!FlowLabelLattice::can_flow(&from, &to));
    }

    #[test]
    fn can_flow_to_sink_respects_max_secrecy() {
        let public_data = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Validated);
        let secret_data = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated);
        let sink = SinkClearance::new(SecrecyLevel::Internal, IntegrityLevel::Validated);
        assert!(FlowLabelLattice::can_flow_to_sink(&public_data, &sink));
        assert!(!FlowLabelLattice::can_flow_to_sink(&secret_data, &sink));
    }

    #[test]
    fn can_flow_to_sink_respects_min_integrity() {
        let trusted_data = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
        let untrusted_data = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Untrusted);
        let sink = SinkClearance::new(SecrecyLevel::Secret, IntegrityLevel::Validated);
        assert!(FlowLabelLattice::can_flow_to_sink(&trusted_data, &sink));
        assert!(!FlowLabelLattice::can_flow_to_sink(&untrusted_data, &sink));
    }

    // ── Labeled<T> ──────────────────────────────────────────────────────

    #[test]
    fn labeled_new_preserves_value_and_label() {
        let label = FlowLabel::new(SecrecyLevel::Confidential, IntegrityLevel::Verified);
        let labeled = Labeled::new(42u64, label);
        assert_eq!(*labeled.value(), 42);
        assert_eq!(labeled.label(), label);
    }

    #[test]
    fn labeled_system_generated_uses_public_trusted() {
        let labeled = Labeled::system_generated("hello".to_string());
        assert_eq!(labeled.label().secrecy(), SecrecyLevel::Public);
        assert_eq!(labeled.label().integrity(), IntegrityLevel::Trusted);
    }

    #[test]
    fn labeled_from_uses_default_label() {
        let labeled: Labeled<i32> = 99.into();
        assert_eq!(*labeled.value(), 99);
        assert_eq!(labeled.label(), FlowLabel::default());
    }

    #[test]
    fn labeled_into_inner_extracts_value() {
        let labeled = Labeled::system_generated(vec![1, 2, 3]);
        let inner = labeled.into_inner();
        assert_eq!(inner, vec![1, 2, 3]);
    }

    #[test]
    fn labeled_map_transforms_value_preserves_label() {
        let label = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Trusted);
        let labeled = Labeled::new(10u32, label);
        let mapped = labeled.map(|v| v * 2);
        assert_eq!(*mapped.value(), 20);
        assert_eq!(mapped.label(), label);
    }

    #[test]
    fn labeled_serde_round_trip() {
        let labeled = Labeled::new(
            "test".to_string(),
            FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated),
        );
        let json = serde_json::to_string(&labeled).expect("serialize");
        let back: Labeled<String> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(labeled, back);
    }

    // ── HostcallType ────────────────────────────────────────────────────

    #[test]
    fn hostcall_type_serde_round_trip_all_variants() {
        let variants = [
            HostcallType::FsRead,
            HostcallType::FsWrite,
            HostcallType::NetworkSend,
            HostcallType::NetworkRecv,
            HostcallType::ProcessSpawn,
            HostcallType::EnvRead,
            HostcallType::MemAlloc,
            HostcallType::TimerCreate,
            HostcallType::CryptoOp,
            HostcallType::IpcSend,
            HostcallType::IpcRecv,
        ];
        for ht in &variants {
            let json = serde_json::to_string(ht).expect("serialize");
            let back: HostcallType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*ht, back);
        }
    }

    #[test]
    fn hostcall_type_as_str_display_agree() {
        let variants = [
            HostcallType::FsRead,
            HostcallType::FsWrite,
            HostcallType::NetworkSend,
            HostcallType::NetworkRecv,
            HostcallType::ProcessSpawn,
            HostcallType::EnvRead,
            HostcallType::MemAlloc,
            HostcallType::TimerCreate,
            HostcallType::CryptoOp,
            HostcallType::IpcSend,
            HostcallType::IpcRecv,
        ];
        for ht in &variants {
            assert_eq!(ht.as_str(), ht.to_string());
        }
    }

    #[test]
    fn hostcall_type_is_sink_exactly_three() {
        let sinks: Vec<_> = [
            HostcallType::FsRead,
            HostcallType::FsWrite,
            HostcallType::NetworkSend,
            HostcallType::NetworkRecv,
            HostcallType::ProcessSpawn,
            HostcallType::EnvRead,
            HostcallType::MemAlloc,
            HostcallType::TimerCreate,
            HostcallType::CryptoOp,
            HostcallType::IpcSend,
            HostcallType::IpcRecv,
        ]
        .iter()
        .filter(|ht| ht.is_sink())
        .collect();
        assert_eq!(sinks.len(), 3);
        assert!(HostcallType::FsWrite.is_sink());
        assert!(HostcallType::NetworkSend.is_sink());
        assert!(HostcallType::IpcSend.is_sink());
    }

    #[test]
    fn hostcall_type_default_escrow_route_sinks_get_challenge() {
        assert_eq!(
            HostcallType::FsWrite.default_escrow_route(),
            CapabilityEscrowRoute::Challenge
        );
        assert_eq!(
            HostcallType::NetworkSend.default_escrow_route(),
            CapabilityEscrowRoute::Challenge
        );
        assert_eq!(
            HostcallType::ProcessSpawn.default_escrow_route(),
            CapabilityEscrowRoute::Challenge
        );
        assert_eq!(
            HostcallType::IpcSend.default_escrow_route(),
            CapabilityEscrowRoute::Challenge
        );
    }

    #[test]
    fn hostcall_type_default_escrow_route_sources_get_sandbox() {
        assert_eq!(
            HostcallType::FsRead.default_escrow_route(),
            CapabilityEscrowRoute::Sandbox
        );
        assert_eq!(
            HostcallType::NetworkRecv.default_escrow_route(),
            CapabilityEscrowRoute::Sandbox
        );
        assert_eq!(
            HostcallType::EnvRead.default_escrow_route(),
            CapabilityEscrowRoute::Sandbox
        );
        assert_eq!(
            HostcallType::MemAlloc.default_escrow_route(),
            CapabilityEscrowRoute::Sandbox
        );
        assert_eq!(
            HostcallType::TimerCreate.default_escrow_route(),
            CapabilityEscrowRoute::Sandbox
        );
        assert_eq!(
            HostcallType::CryptoOp.default_escrow_route(),
            CapabilityEscrowRoute::Sandbox
        );
        assert_eq!(
            HostcallType::IpcRecv.default_escrow_route(),
            CapabilityEscrowRoute::Sandbox
        );
    }

    // ── HostcallSinkPolicy ──────────────────────────────────────────────

    #[test]
    fn hostcall_sink_policy_default_clearances() {
        let policy = HostcallSinkPolicy::default();
        assert_eq!(
            policy.fs_write,
            SinkClearance::new(SecrecyLevel::Internal, IntegrityLevel::Validated)
        );
        assert_eq!(
            policy.network_send,
            SinkClearance::new(SecrecyLevel::Public, IntegrityLevel::Validated)
        );
        assert_eq!(
            policy.ipc_send,
            SinkClearance::new(SecrecyLevel::Secret, IntegrityLevel::Untrusted)
        );
    }

    #[test]
    fn hostcall_sink_policy_clearance_for_sinks() {
        let policy = HostcallSinkPolicy::default();
        assert_eq!(
            policy.clearance_for(HostcallType::FsWrite),
            Some(policy.fs_write)
        );
        assert_eq!(
            policy.clearance_for(HostcallType::NetworkSend),
            Some(policy.network_send)
        );
        assert_eq!(
            policy.clearance_for(HostcallType::IpcSend),
            Some(policy.ipc_send)
        );
    }

    #[test]
    fn hostcall_sink_policy_clearance_for_non_sinks_is_none() {
        let policy = HostcallSinkPolicy::default();
        assert_eq!(policy.clearance_for(HostcallType::FsRead), None);
        assert_eq!(policy.clearance_for(HostcallType::NetworkRecv), None);
        assert_eq!(policy.clearance_for(HostcallType::EnvRead), None);
        assert_eq!(policy.clearance_for(HostcallType::MemAlloc), None);
        assert_eq!(policy.clearance_for(HostcallType::TimerCreate), None);
        assert_eq!(policy.clearance_for(HostcallType::CryptoOp), None);
        assert_eq!(policy.clearance_for(HostcallType::ProcessSpawn), None);
        assert_eq!(policy.clearance_for(HostcallType::IpcRecv), None);
    }

    #[test]
    fn hostcall_sink_policy_serde_round_trip() {
        let policy = HostcallSinkPolicy::default();
        let json = serde_json::to_string(&policy).expect("serialize");
        let back: HostcallSinkPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, back);
    }

    // ── CapabilityEscrowRoute ───────────────────────────────────────────

    #[test]
    fn capability_escrow_route_serde_round_trip() {
        for route in [
            CapabilityEscrowRoute::Challenge,
            CapabilityEscrowRoute::Sandbox,
        ] {
            let json = serde_json::to_string(&route).expect("serialize");
            let back: CapabilityEscrowRoute = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(route, back);
        }
    }

    #[test]
    fn capability_escrow_route_as_str_display_agree() {
        for route in [
            CapabilityEscrowRoute::Challenge,
            CapabilityEscrowRoute::Sandbox,
        ] {
            assert_eq!(route.as_str(), route.to_string());
        }
    }

    // ── CapabilityEscrowState ───────────────────────────────────────────

    #[test]
    fn capability_escrow_state_serde_round_trip_all_variants() {
        let variants = [
            CapabilityEscrowState::Requested,
            CapabilityEscrowState::Challenged,
            CapabilityEscrowState::Sandboxed,
            CapabilityEscrowState::Approved,
            CapabilityEscrowState::Denied,
            CapabilityEscrowState::Expired,
        ];
        for state in &variants {
            let json = serde_json::to_string(state).expect("serialize");
            let back: CapabilityEscrowState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*state, back);
        }
    }

    #[test]
    fn capability_escrow_state_as_str_display_agree() {
        let variants = [
            CapabilityEscrowState::Requested,
            CapabilityEscrowState::Challenged,
            CapabilityEscrowState::Sandboxed,
            CapabilityEscrowState::Approved,
            CapabilityEscrowState::Denied,
            CapabilityEscrowState::Expired,
        ];
        for state in &variants {
            assert_eq!(state.as_str(), state.to_string());
        }
    }

    #[test]
    fn capability_escrow_state_terminal_only_denied_and_expired() {
        let record_with_state = |state: CapabilityEscrowState| CapabilityEscrowRecord {
            request_id: "r".to_string(),
            extension_id: "e".to_string(),
            hostcall_type: HostcallType::FsRead,
            capability: Capability::FsRead,
            justification: "j".to_string(),
            state,
            created_at_ns: 0,
            expires_at_ns: 1000,
            updated_at_ns: 0,
        };

        assert!(record_with_state(CapabilityEscrowState::Denied).is_terminal());
        assert!(record_with_state(CapabilityEscrowState::Expired).is_terminal());
        assert!(!record_with_state(CapabilityEscrowState::Requested).is_terminal());
        assert!(!record_with_state(CapabilityEscrowState::Challenged).is_terminal());
        assert!(!record_with_state(CapabilityEscrowState::Sandboxed).is_terminal());
        assert!(!record_with_state(CapabilityEscrowState::Approved).is_terminal());
    }

    // ── CapabilityEscrowDecisionKind ────────────────────────────────────

    #[test]
    fn capability_escrow_decision_kind_serde_round_trip() {
        let variants = [
            CapabilityEscrowDecisionKind::Challenge,
            CapabilityEscrowDecisionKind::Sandbox,
            CapabilityEscrowDecisionKind::Approve,
            CapabilityEscrowDecisionKind::Deny,
            CapabilityEscrowDecisionKind::EmergencyGrant,
            CapabilityEscrowDecisionKind::Expire,
        ];
        for kind in &variants {
            let json = serde_json::to_string(kind).expect("serialize");
            let back: CapabilityEscrowDecisionKind =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn capability_escrow_decision_kind_as_str_display_agree() {
        let variants = [
            CapabilityEscrowDecisionKind::Challenge,
            CapabilityEscrowDecisionKind::Sandbox,
            CapabilityEscrowDecisionKind::Approve,
            CapabilityEscrowDecisionKind::Deny,
            CapabilityEscrowDecisionKind::EmergencyGrant,
            CapabilityEscrowDecisionKind::Expire,
        ];
        for kind in &variants {
            assert_eq!(kind.as_str(), kind.to_string());
        }
    }

    // ── DeclassificationPurpose ─────────────────────────────────────────

    #[test]
    fn declassification_purpose_serde_round_trip() {
        let variants = [
            DeclassificationPurpose::UserConsent,
            DeclassificationPurpose::AggregationAnonymization,
            DeclassificationPurpose::PublicApiResponse,
            DeclassificationPurpose::DiagnosticExport,
            DeclassificationPurpose::OperatorOverride,
            DeclassificationPurpose::Custom("audit_export".to_string()),
        ];
        for purpose in &variants {
            let json = serde_json::to_string(purpose).expect("serialize");
            let back: DeclassificationPurpose = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*purpose, back);
        }
    }

    #[test]
    fn declassification_purpose_display_custom_includes_value() {
        let custom = DeclassificationPurpose::Custom("my_reason".to_string());
        assert_eq!(custom.to_string(), "custom:my_reason");
    }

    #[test]
    fn declassification_purpose_as_str_non_custom_agrees_with_display() {
        let standard = [
            DeclassificationPurpose::UserConsent,
            DeclassificationPurpose::AggregationAnonymization,
            DeclassificationPurpose::PublicApiResponse,
            DeclassificationPurpose::DiagnosticExport,
            DeclassificationPurpose::OperatorOverride,
        ];
        for purpose in &standard {
            assert_eq!(purpose.as_str(), purpose.to_string());
        }
    }

    // ── DeclassificationDenialReason ────────────────────────────────────

    #[test]
    fn declassification_denial_reason_error_codes_stable() {
        assert_eq!(
            DeclassificationDenialReason::MissingCapability {
                capability: Capability::Declassify
            }
            .error_code(),
            "FE-DECLASS-0001"
        );
        assert_eq!(
            DeclassificationDenialReason::LabelDistanceTooLarge {
                secrecy_distance: 2,
                integrity_distance: 0
            }
            .error_code(),
            "FE-DECLASS-0002"
        );
        assert_eq!(
            DeclassificationDenialReason::InvalidPurpose {
                purpose: DeclassificationPurpose::DiagnosticExport,
                target: SecrecyLevel::Public
            }
            .error_code(),
            "FE-DECLASS-0003"
        );
        assert_eq!(
            DeclassificationDenialReason::RateLimited {
                max_requests: 8,
                window_ns: 60_000_000_000
            }
            .error_code(),
            "FE-DECLASS-0004"
        );
        assert_eq!(
            DeclassificationDenialReason::NoDeclassificationRequired.error_code(),
            "FE-DECLASS-0005"
        );
        assert_eq!(
            DeclassificationDenialReason::EmptyJustification.error_code(),
            "FE-DECLASS-0006"
        );
        assert_eq!(
            DeclassificationDenialReason::ContractRejected {
                contract_id: "c".to_string(),
                detail: "d".to_string()
            }
            .error_code(),
            "FE-DECLASS-0007"
        );
    }

    #[test]
    fn declassification_denial_reason_serde_round_trip() {
        let variants: Vec<DeclassificationDenialReason> = vec![
            DeclassificationDenialReason::MissingCapability {
                capability: Capability::Declassify,
            },
            DeclassificationDenialReason::LabelDistanceTooLarge {
                secrecy_distance: 3,
                integrity_distance: 1,
            },
            DeclassificationDenialReason::NoDeclassificationRequired,
            DeclassificationDenialReason::EmptyJustification,
            DeclassificationDenialReason::RateLimited {
                max_requests: 5,
                window_ns: 1_000_000,
            },
            DeclassificationDenialReason::ContractRejected {
                contract_id: "test".to_string(),
                detail: "rejected".to_string(),
            },
        ];
        for reason in &variants {
            let json = serde_json::to_string(reason).expect("serialize");
            let back: DeclassificationDenialReason =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*reason, back);
        }
    }

    // ── DecisionSigningKey / DecisionPublicKey ──────────────────────────

    #[test]
    fn signing_key_default_is_deterministic() {
        let a = DecisionSigningKey::default();
        let b = DecisionSigningKey::default();
        assert_eq!(a, b);
    }

    #[test]
    fn signing_key_sign_verify_round_trip() {
        let key = DecisionSigningKey::new([0xAB; 32]);
        let payload = b"test payload";
        let signature = key.sign(payload);
        let pubkey = key.public_key();
        assert!(pubkey.verify(payload, &signature));
    }

    #[test]
    fn signing_key_verify_rejects_tampered_payload() {
        let key = DecisionSigningKey::new([0x01; 32]);
        let signature = key.sign(b"original");
        let pubkey = key.public_key();
        assert!(!pubkey.verify(b"tampered", &signature));
    }

    #[test]
    fn signing_key_verify_rejects_tampered_signature() {
        let key = DecisionSigningKey::new([0x02; 32]);
        let payload = b"some data";
        let mut signature = key.sign(payload);
        signature[0] ^= 0xFF;
        let pubkey = key.public_key();
        assert!(!pubkey.verify(payload, &signature));
    }

    #[test]
    fn signing_key_different_keys_produce_different_signatures() {
        let key_a = DecisionSigningKey::new([0x01; 32]);
        let key_b = DecisionSigningKey::new([0x02; 32]);
        let payload = b"same payload";
        let sig_a = key_a.sign(payload);
        let sig_b = key_b.sign(payload);
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn signing_key_serde_round_trip() {
        let key = DecisionSigningKey::new([0x55; 32]);
        let json = serde_json::to_string(&key).expect("serialize");
        let back: DecisionSigningKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(key, back);
    }

    #[test]
    fn public_key_serde_round_trip() {
        let pubkey = DecisionSigningKey::new([0x77; 32]).public_key();
        let json = serde_json::to_string(&pubkey).expect("serialize");
        let back: DecisionPublicKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pubkey, back);
    }

    // ── ManifestValidationError ─────────────────────────────────────────

    #[test]
    fn manifest_validation_error_codes_stable() {
        assert_eq!(
            ManifestValidationError::EmptyName.error_code(),
            "FE-MANIFEST-0001"
        );
        assert_eq!(
            ManifestValidationError::EmptyVersion.error_code(),
            "FE-MANIFEST-0002"
        );
        assert_eq!(
            ManifestValidationError::EmptyEntrypoint.error_code(),
            "FE-MANIFEST-0003"
        );
        assert_eq!(
            ManifestValidationError::UnsupportedEngineVersion {
                min_engine_version: "9.9.9".to_string(),
                supported_engine_version: "0.1.0",
            }
            .error_code(),
            "FE-MANIFEST-0004"
        );
        assert_eq!(
            ManifestValidationError::InvalidCapabilityLattice {
                declared: Capability::FsWrite,
                missing_implied: Capability::FsRead,
            }
            .error_code(),
            "FE-MANIFEST-0005"
        );
        assert_eq!(
            ManifestValidationError::MissingPublisherSignature.error_code(),
            "FE-MANIFEST-0006"
        );
        assert_eq!(
            ManifestValidationError::MissingTrustChainRef.error_code(),
            "FE-MANIFEST-0007"
        );
        assert_eq!(
            ManifestValidationError::InvalidContentHash.error_code(),
            "FE-MANIFEST-0008"
        );
        assert_eq!(
            ManifestValidationError::CanonicalSerialization("err".to_string()).error_code(),
            "FE-MANIFEST-0009"
        );
        assert_eq!(
            ManifestValidationError::FieldTooLong {
                field: "name",
                max: 128,
                actual: 200,
            }
            .error_code(),
            "FE-MANIFEST-0010"
        );
    }

    #[test]
    fn manifest_validation_error_display_includes_code_and_message() {
        let error = ManifestValidationError::EmptyName;
        let display = error.to_string();
        assert!(display.contains("FE-MANIFEST-0001"));
        assert!(display.contains("name must not be empty"));
    }

    #[test]
    fn manifest_validation_error_structured_message_includes_trace_context() {
        let error = ManifestValidationError::EmptyName;
        let msg = error.structured_message("trace-abc", "ext-xyz");
        assert!(msg.contains("trace_id=trace-abc"));
        assert!(msg.contains("extension_id=ext-xyz"));
        assert!(msg.contains("FE-MANIFEST-0001"));
    }

    // ── LifecycleError ──────────────────────────────────────────────────

    #[test]
    fn lifecycle_error_codes_stable() {
        assert_eq!(
            LifecycleError::InvalidTransition {
                extension_id: "e".to_string(),
                current_state: ExtensionState::Running,
                attempted_transition: LifecycleTransition::Load,
            }
            .error_code(),
            "FE-LIFECYCLE-0001"
        );
        assert_eq!(
            LifecycleError::MissingValidatedManifest {
                extension_id: "e".to_string(),
                attempted_transition: LifecycleTransition::Start,
            }
            .error_code(),
            "FE-LIFECYCLE-0002"
        );
        assert_eq!(
            LifecycleError::BudgetExhausted {
                extension_id: "e".to_string(),
                dimension: "cpu_time_ns_remaining",
                remaining: 0,
                attempted_transition: LifecycleTransition::Suspend,
                action: LifecycleTransition::Suspend,
            }
            .error_code(),
            "FE-LIFECYCLE-0003"
        );
        assert_eq!(
            LifecycleError::NonMonotonicTimestamp {
                previous: 100,
                current: 50,
            }
            .error_code(),
            "FE-LIFECYCLE-0004"
        );
        assert_eq!(
            LifecycleError::MissingCancelToken {
                extension_id: "e".to_string(),
            }
            .error_code(),
            "FE-LIFECYCLE-0005"
        );
        assert_eq!(
            LifecycleError::TerminationPending {
                extension_id: "e".to_string(),
                now_ns: 50,
                deadline_ns: 100,
            }
            .error_code(),
            "FE-LIFECYCLE-0006"
        );
    }

    #[test]
    fn lifecycle_error_display_includes_code_and_message() {
        let error = LifecycleError::NonMonotonicTimestamp {
            previous: 200,
            current: 100,
        };
        let display = error.to_string();
        assert!(display.contains("FE-LIFECYCLE-0004"));
        assert!(display.contains("previous=200"));
        assert!(display.contains("current=100"));
    }

    // ── CapabilityEscrowError ───────────────────────────────────────────

    #[test]
    fn capability_escrow_error_codes_stable() {
        assert_eq!(
            CapabilityEscrowError::UnknownRequest {
                request_id: "r".to_string()
            }
            .error_code(),
            "FE-ESCROW-0004"
        );
        assert_eq!(
            CapabilityEscrowError::InvalidEmergencyGrant {
                field: "f",
                detail: "d".to_string()
            }
            .error_code(),
            "FE-ESCROW-0006"
        );
        assert_eq!(
            CapabilityEscrowError::PostReviewNotPending {
                grant_id: "g".to_string()
            }
            .error_code(),
            "FE-ESCROW-0009"
        );
        assert_eq!(
            CapabilityEscrowError::ReceiptEmissionFailed {
                request_id: "r".to_string(),
                detail: "d".to_string()
            }
            .error_code(),
            "FE-ESCROW-0010"
        );
    }

    #[test]
    fn capability_escrow_error_display_all_variants() {
        let variants: Vec<CapabilityEscrowError> = vec![
            CapabilityEscrowError::UnknownRequest {
                request_id: "req-1".to_string(),
            },
            CapabilityEscrowError::InvalidStateTransition {
                request_id: "req-2".to_string(),
                from: CapabilityEscrowState::Denied,
                to: CapabilityEscrowState::Approved,
            },
            CapabilityEscrowError::RequestNotActionable {
                request_id: "req-3".to_string(),
                state: CapabilityEscrowState::Expired,
            },
            CapabilityEscrowError::InvalidEmergencyGrant {
                field: "actor",
                detail: "empty".to_string(),
            },
            CapabilityEscrowError::PostReviewNotPending {
                grant_id: "g-1".to_string(),
            },
            CapabilityEscrowError::ReceiptEmissionFailed {
                request_id: "req-4".to_string(),
                detail: "serialize failed".to_string(),
            },
        ];
        for err in &variants {
            let display = err.to_string();
            assert!(!display.is_empty());
        }
    }

    // ── DeclassificationEvidenceSeverity ────────────────────────────────

    #[test]
    fn declassification_evidence_severity_serde_round_trip() {
        for sev in [
            DeclassificationEvidenceSeverity::High,
            DeclassificationEvidenceSeverity::Critical,
        ] {
            let json = serde_json::to_string(&sev).expect("serialize");
            let back: DeclassificationEvidenceSeverity =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(sev, back);
        }
    }

    // ── lifecycle_target_state exhaustive ────────────────────────────────

    #[test]
    fn lifecycle_target_state_happy_path_chain() {
        assert_eq!(
            lifecycle_target_state(ExtensionState::Unloaded, LifecycleTransition::Validate),
            Some(ExtensionState::Validating)
        );
        assert_eq!(
            lifecycle_target_state(ExtensionState::Validating, LifecycleTransition::Load),
            Some(ExtensionState::Loading)
        );
        assert_eq!(
            lifecycle_target_state(ExtensionState::Loading, LifecycleTransition::Start),
            Some(ExtensionState::Starting)
        );
        assert_eq!(
            lifecycle_target_state(ExtensionState::Starting, LifecycleTransition::Activate),
            Some(ExtensionState::Running)
        );
        assert_eq!(
            lifecycle_target_state(ExtensionState::Running, LifecycleTransition::Suspend),
            Some(ExtensionState::Suspending)
        );
        assert_eq!(
            lifecycle_target_state(ExtensionState::Suspending, LifecycleTransition::Freeze),
            Some(ExtensionState::Suspended)
        );
        assert_eq!(
            lifecycle_target_state(ExtensionState::Suspended, LifecycleTransition::Resume),
            Some(ExtensionState::Resuming)
        );
        assert_eq!(
            lifecycle_target_state(ExtensionState::Resuming, LifecycleTransition::Reactivate),
            Some(ExtensionState::Running)
        );
    }

    #[test]
    fn lifecycle_target_state_terminate_from_most_states() {
        let terminable = [
            ExtensionState::Validating,
            ExtensionState::Loading,
            ExtensionState::Starting,
            ExtensionState::Running,
            ExtensionState::Suspending,
            ExtensionState::Suspended,
            ExtensionState::Resuming,
        ];
        for state in &terminable {
            assert_eq!(
                lifecycle_target_state(*state, LifecycleTransition::Terminate),
                Some(ExtensionState::Terminating),
                "terminate from {state:?}"
            );
        }
    }

    #[test]
    fn lifecycle_target_state_quarantine_from_most_states() {
        let quarantinable = [
            ExtensionState::Validating,
            ExtensionState::Loading,
            ExtensionState::Starting,
            ExtensionState::Running,
            ExtensionState::Suspending,
            ExtensionState::Suspended,
            ExtensionState::Resuming,
            ExtensionState::Terminating,
        ];
        for state in &quarantinable {
            assert_eq!(
                lifecycle_target_state(*state, LifecycleTransition::Quarantine),
                Some(ExtensionState::Quarantined),
                "quarantine from {state:?}"
            );
        }
    }

    #[test]
    fn lifecycle_target_state_terminal_states_reject_all() {
        let terminal = [ExtensionState::Terminated, ExtensionState::Quarantined];
        let all_transitions = [
            LifecycleTransition::Validate,
            LifecycleTransition::Load,
            LifecycleTransition::Start,
            LifecycleTransition::Activate,
            LifecycleTransition::Suspend,
            LifecycleTransition::Freeze,
            LifecycleTransition::Resume,
            LifecycleTransition::Reactivate,
            LifecycleTransition::Terminate,
            LifecycleTransition::Finalize,
            LifecycleTransition::Quarantine,
        ];
        for state in &terminal {
            for transition in &all_transitions {
                assert_eq!(
                    lifecycle_target_state(*state, *transition),
                    None,
                    "{state:?} + {transition:?} should be None"
                );
            }
        }
    }

    // ── allowed_lifecycle_transitions ────────────────────────────────────

    #[test]
    fn allowed_transitions_terminal_states_are_empty() {
        assert!(allowed_lifecycle_transitions(ExtensionState::Terminated).is_empty());
        assert!(allowed_lifecycle_transitions(ExtensionState::Quarantined).is_empty());
    }

    #[test]
    fn allowed_transitions_running_includes_suspend_terminate_quarantine() {
        let allowed = allowed_lifecycle_transitions(ExtensionState::Running);
        assert!(allowed.contains(&LifecycleTransition::Suspend));
        assert!(allowed.contains(&LifecycleTransition::Terminate));
        assert!(allowed.contains(&LifecycleTransition::Quarantine));
    }

    // ── DataRef ─────────────────────────────────────────────────────────

    #[test]
    fn data_ref_serde_round_trip() {
        let data_ref = DataRef::new("memory", "token");
        let json = serde_json::to_string(&data_ref).expect("serialize");
        let back: DataRef = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(data_ref, back);
    }

    // ── ManifestValidationEvent ─────────────────────────────────────────

    #[test]
    fn manifest_validation_event_serde_round_trip() {
        let event = ManifestValidationEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let back: ManifestValidationEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, back);
    }

    // ── ManifestValidationReport ────────────────────────────────────────

    #[test]
    fn manifest_validation_report_into_result_ok() {
        let report = ManifestValidationReport {
            event: ManifestValidationEvent {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                component: "c".to_string(),
                event: "e".to_string(),
                outcome: "pass".to_string(),
                error_code: None,
            },
            error: None,
        };
        assert!(report.into_result().is_ok());
    }

    #[test]
    fn manifest_validation_report_into_result_err() {
        let report = ManifestValidationReport {
            event: ManifestValidationEvent {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                component: "c".to_string(),
                event: "e".to_string(),
                outcome: "fail".to_string(),
                error_code: Some("FE-MANIFEST-0001".to_string()),
            },
            error: Some(ManifestValidationError::EmptyName),
        };
        assert_eq!(
            report.into_result(),
            Err(ManifestValidationError::EmptyName)
        );
    }

    // ── ExtensionManifest ───────────────────────────────────────────────

    #[test]
    fn extension_manifest_inferred_trust_level_with_signature() {
        let manifest = ExtensionManifest {
            name: "ext".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "index.js".to_string(),
            capabilities: BTreeSet::new(),
            publisher_signature: Some(vec![1, 2]),
            content_hash: [0; 32],
            trust_chain_ref: None,
            min_engine_version: "0.1.0".to_string(),
        };
        assert_eq!(
            manifest.inferred_trust_level(),
            ManifestTrustLevel::SignedSupplyChain
        );
    }

    #[test]
    fn extension_manifest_inferred_trust_level_with_trust_chain() {
        let manifest = ExtensionManifest {
            name: "ext".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "index.js".to_string(),
            capabilities: BTreeSet::new(),
            publisher_signature: None,
            content_hash: [0; 32],
            trust_chain_ref: Some("chain/pub".to_string()),
            min_engine_version: "0.1.0".to_string(),
        };
        assert_eq!(
            manifest.inferred_trust_level(),
            ManifestTrustLevel::SignedSupplyChain
        );
    }

    #[test]
    fn extension_manifest_inferred_trust_level_development() {
        let manifest = ExtensionManifest {
            name: "ext".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "index.js".to_string(),
            capabilities: BTreeSet::new(),
            publisher_signature: None,
            content_hash: [0; 32],
            trust_chain_ref: None,
            min_engine_version: "0.1.0".to_string(),
        };
        assert_eq!(
            manifest.inferred_trust_level(),
            ManifestTrustLevel::Development
        );
    }

    #[test]
    fn extension_manifest_inferred_trust_level_empty_trust_chain_is_development() {
        let manifest = ExtensionManifest {
            name: "ext".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "index.js".to_string(),
            capabilities: BTreeSet::new(),
            publisher_signature: None,
            content_hash: [0; 32],
            trust_chain_ref: Some("   ".to_string()),
            min_engine_version: "0.1.0".to_string(),
        };
        assert_eq!(
            manifest.inferred_trust_level(),
            ManifestTrustLevel::Development
        );
    }

    // ── Manifest validation edge cases ──────────────────────────────────

    #[test]
    fn validate_manifest_rejects_empty_version() {
        let manifest = ExtensionManifest {
            name: "ext".to_string(),
            version: "".to_string(),
            entrypoint: "index.js".to_string(),
            capabilities: BTreeSet::new(),
            publisher_signature: None,
            content_hash: [0; 32],
            trust_chain_ref: None,
            min_engine_version: "0.1.0".to_string(),
        };
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::EmptyVersion)
        );
    }

    #[test]
    fn validate_manifest_rejects_empty_entrypoint() {
        let manifest = ExtensionManifest {
            name: "ext".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "".to_string(),
            capabilities: BTreeSet::new(),
            publisher_signature: None,
            content_hash: [0; 32],
            trust_chain_ref: None,
            min_engine_version: "0.1.0".to_string(),
        };
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::EmptyEntrypoint)
        );
    }

    #[test]
    fn validate_manifest_rejects_oversized_version() {
        let manifest = ExtensionManifest {
            name: "ext".to_string(),
            version: "x".repeat(MAX_VERSION_LEN + 1),
            entrypoint: "index.js".to_string(),
            capabilities: BTreeSet::new(),
            publisher_signature: None,
            content_hash: [0; 32],
            trust_chain_ref: None,
            min_engine_version: "0.1.0".to_string(),
        };
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::FieldTooLong {
                field: "version",
                ..
            })
        ));
    }

    #[test]
    fn validate_manifest_rejects_oversized_entrypoint() {
        let manifest = ExtensionManifest {
            name: "ext".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "x".repeat(MAX_ENTRYPOINT_LEN + 1),
            capabilities: BTreeSet::new(),
            publisher_signature: None,
            content_hash: [0; 32],
            trust_chain_ref: None,
            min_engine_version: "0.1.0".to_string(),
        };
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::FieldTooLong {
                field: "entrypoint",
                ..
            })
        ));
    }

    #[test]
    fn validate_manifest_rejects_oversized_trust_chain_ref() {
        let mut manifest = ExtensionManifest {
            name: "ext".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "index.js".to_string(),
            capabilities: [Capability::FsRead].into_iter().collect(),
            publisher_signature: Some(vec![1]),
            content_hash: [0; 32],
            trust_chain_ref: Some("x".repeat(MAX_TRUST_CHAIN_REF_LEN + 1)),
            min_engine_version: "0.1.0".to_string(),
        };
        manifest.content_hash = compute_content_hash(&manifest).unwrap_or([0; 32]);
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::FieldTooLong {
                field: "trust_chain_ref",
                ..
            })
        ));
    }

    #[test]
    fn validate_manifest_rejects_oversized_min_engine_version() {
        let manifest = ExtensionManifest {
            name: "ext".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "index.js".to_string(),
            capabilities: BTreeSet::new(),
            publisher_signature: None,
            content_hash: [0; 32],
            trust_chain_ref: None,
            min_engine_version: "x".repeat(MAX_VERSION_LEN + 1),
        };
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::FieldTooLong {
                field: "min_engine_version",
                ..
            })
        ));
    }

    // ── parse_semver ────────────────────────────────────────────────────

    #[test]
    fn validate_engine_version_rejects_malformed() {
        assert!(matches!(
            validate_engine_version("not.a.semver.really"),
            Err(ManifestValidationError::UnsupportedEngineVersion { .. })
        ));
        assert!(matches!(
            validate_engine_version("1"),
            Err(ManifestValidationError::UnsupportedEngineVersion { .. })
        ));
    }

    #[test]
    fn validate_engine_version_accepts_current() {
        assert_eq!(validate_engine_version(CURRENT_ENGINE_VERSION), Ok(()));
    }

    #[test]
    fn validate_engine_version_accepts_lower() {
        assert_eq!(validate_engine_version("0.0.0"), Ok(()));
    }

    // ── EscrowCondition ─────────────────────────────────────────────────

    #[test]
    fn escrow_condition_serde_round_trip() {
        let cond = EscrowCondition::new("key", "value");
        let json = serde_json::to_string(&cond).expect("serialize");
        let back: EscrowCondition = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cond, back);
    }

    // ── DeclassificationCondition ───────────────────────────────────────

    #[test]
    fn declassification_condition_serde_round_trip() {
        let cond = DeclassificationCondition::new("key", "value");
        let json = serde_json::to_string(&cond).expect("serialize");
        let back: DeclassificationCondition = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cond, back);
    }

    // ── SinkClearance ───────────────────────────────────────────────────

    #[test]
    fn sink_clearance_serde_round_trip() {
        let clearance = SinkClearance::new(SecrecyLevel::Confidential, IntegrityLevel::Verified);
        let json = serde_json::to_string(&clearance).expect("serialize");
        let back: SinkClearance = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(clearance, back);
    }

    // ── HostcallResult ──────────────────────────────────────────────────

    #[test]
    fn hostcall_result_serde_round_trip() {
        let variants = [
            HostcallResult::Success,
            HostcallResult::Denied {
                reason: DenialReason::CapabilityEscalation {
                    attempted: Capability::ProcessSpawn,
                },
            },
            HostcallResult::Error { code: 42 },
            HostcallResult::Timeout,
        ];
        for result in &variants {
            let json = serde_json::to_string(result).expect("serialize");
            let back: HostcallResult = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*result, back);
        }
    }

    // ── DenialReason ────────────────────────────────────────────────────

    #[test]
    fn denial_reason_serde_round_trip() {
        let variants = [
            DenialReason::FlowViolation {
                source: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
                sink: SinkClearance::new(SecrecyLevel::Public, IntegrityLevel::Validated),
            },
            DenialReason::CapabilityEscalation {
                attempted: Capability::FsWrite,
            },
            DenialReason::CapabilityEscrowPending {
                attempted: Capability::NetClient,
                action: CapabilityEscrowRoute::Challenge,
                escrow_id: "esc-1".to_string(),
            },
            DenialReason::CapabilityEscrowDenied {
                attempted: Capability::ProcessSpawn,
                escrow_id: "esc-2".to_string(),
            },
        ];
        for reason in &variants {
            let json = serde_json::to_string(reason).expect("serialize");
            let back: DenialReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*reason, back);
        }
    }

    // ── RateLimitContract ───────────────────────────────────────────────

    #[test]
    fn rate_limit_contract_serde_round_trip() {
        let contract = RateLimitContract::new(10, 1_000_000_000);
        let json = serde_json::to_string(&contract).expect("serialize");
        let back: RateLimitContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, back);
    }

    // ── DecisionReceiptLog ──────────────────────────────────────────────

    #[test]
    fn decision_receipt_log_append_and_retrieve() {
        let mut log = DecisionReceiptLog::default();
        assert!(log.receipts().is_empty());
        let key = DecisionSigningKey::default();
        let receipt = CryptographicDecisionReceipt::new_signed(
            "req-1",
            DecisionVerdict::Approved {
                conditions: vec![DeclassificationCondition::new("k", "v")],
            },
            vec!["contract-a".to_string()],
            vec![DeclassificationCondition::new("c", "d")],
            500_000,
            1000,
            &key,
        );
        log.append(receipt.clone());
        assert_eq!(log.receipts().len(), 1);
        assert_eq!(log.receipts()[0], receipt);
    }

    // ── CryptographicDecisionReceipt sign/verify ────────────────────────

    #[test]
    fn cryptographic_decision_receipt_sign_verify_round_trip() {
        let key = DecisionSigningKey::new([0xDE; 32]);
        let receipt = CryptographicDecisionReceipt::new_signed(
            "req-sign-test",
            DecisionVerdict::Denied {
                reason: DeclassificationDenialReason::EmptyJustification,
            },
            vec!["cap_contract".to_string()],
            vec![],
            750_000,
            2000,
            &key,
        );
        let pubkey = key.public_key();
        assert!(receipt.verify(&pubkey));
    }

    #[test]
    fn cryptographic_decision_receipt_verify_rejects_wrong_key() {
        let key_a = DecisionSigningKey::new([0xAA; 32]);
        let key_b = DecisionSigningKey::new([0xBB; 32]);
        let receipt = CryptographicDecisionReceipt::new_signed(
            "req-wrong-key",
            DecisionVerdict::Approved { conditions: vec![] },
            vec![],
            vec![],
            100_000,
            3000,
            &key_a,
        );
        assert!(!receipt.verify(&key_b.public_key()));
    }

    // ── LifecycleTransitionRecord ───────────────────────────────────────

    #[test]
    fn lifecycle_transition_record_serde_round_trip() {
        let record = LifecycleTransitionRecord {
            monotonic_timestamp_ns: 42,
            extension_id: "ext-a".to_string(),
            from_state: ExtensionState::Running,
            to_state: ExtensionState::Suspending,
            transition: LifecycleTransition::Suspend,
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let back: LifecycleTransitionRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }

    // ── LifecycleEvent ──────────────────────────────────────────────────

    #[test]
    fn lifecycle_event_serde_round_trip() {
        let event = LifecycleEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "lifecycle_transition".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            extension_id: "ext".to_string(),
            from_state: "running".to_string(),
            to_state: "suspending".to_string(),
            transition: "suspend".to_string(),
            timestamp_ns: 100,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let back: LifecycleEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, back);
    }

    // ── FlowViolationEvent ──────────────────────────────────────────────

    #[test]
    fn flow_violation_event_serde_round_trip() {
        let event = FlowViolationEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "runtime_flow_enforcement".to_string(),
            event: "hostcall_flow_violation".to_string(),
            outcome: "blocked".to_string(),
            error_code: "FE-FLOW-0001".to_string(),
            extension_id: "ext".to_string(),
            hostcall_type: HostcallType::NetworkSend,
            source_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
            sink_clearance: SinkClearance::new(SecrecyLevel::Public, IntegrityLevel::Validated),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let back: FlowViolationEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, back);
    }

    // ── ExtensionManifest serde round-trip ──────────────────────────────

    #[test]
    fn extension_manifest_serde_round_trip() {
        let manifest = ExtensionManifest {
            name: "test-ext".to_string(),
            version: "2.0.0".to_string(),
            entrypoint: "dist/main.js".to_string(),
            capabilities: [Capability::FsRead, Capability::FsWrite]
                .into_iter()
                .collect(),
            publisher_signature: Some(vec![0xAB, 0xCD]),
            content_hash: [0x42; 32],
            trust_chain_ref: Some("chain/test".to_string()),
            min_engine_version: "0.1.0".to_string(),
        };
        let json = serde_json::to_string(&manifest).expect("serialize");
        let back: ExtensionManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(manifest, back);
    }

    // ── with_computed_content_hash ──────────────────────────────────────

    #[test]
    fn with_computed_content_hash_makes_manifest_valid() {
        let manifest = ExtensionManifest {
            name: "hash-ext".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "dist/index.js".to_string(),
            capabilities: [Capability::FsRead].into_iter().collect(),
            publisher_signature: Some(vec![1, 2, 3]),
            content_hash: [0; 32],
            trust_chain_ref: Some("chain/hash".to_string()),
            min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
        };
        let hashed = with_computed_content_hash(manifest).expect("compute hash");
        assert_ne!(hashed.content_hash, [0; 32]);
        assert_eq!(validate_manifest(&hashed), Ok(()));
    }

    // ── CapabilityEscrowReceiptQuery ────────────────────────────────────

    #[test]
    fn capability_escrow_receipt_query_default_is_unfiltered() {
        let query = CapabilityEscrowReceiptQuery::default();
        assert!(query.extension_id.is_none());
        assert!(query.capability.is_none());
        assert!(query.decision.is_none());
        assert!(query.outcome.is_none());
        assert!(query.timestamp_from_ns.is_none());
        assert!(query.timestamp_to_ns.is_none());
    }

    #[test]
    fn capability_escrow_receipt_query_serde_round_trip() {
        let query = CapabilityEscrowReceiptQuery {
            extension_id: Some("ext-a".to_string()),
            capability: Some(Capability::FsRead),
            decision: Some(CapabilityEscrowDecisionKind::Approve),
            outcome: Some("approved".to_string()),
            timestamp_from_ns: Some(100),
            timestamp_to_ns: Some(200),
        };
        let json = serde_json::to_string(&query).expect("serialize");
        let back: CapabilityEscrowReceiptQuery = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(query, back);
    }

    // ── DeclassificationRequest ─────────────────────────────────────────

    #[test]
    fn declassification_request_serde_round_trip() {
        let request = DeclassificationRequest {
            request_id: "dr-1".to_string(),
            requester: "ext-a".to_string(),
            data_ref: DataRef::new("ns", "k"),
            current_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
            target_label: FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated),
            purpose: DeclassificationPurpose::UserConsent,
            justification: "user approved".to_string(),
            timestamp_ns: 42,
        };
        let json = serde_json::to_string(&request).expect("serialize");
        let back: DeclassificationRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(request, back);
    }

    // ── DeclassificationChallenge ───────────────────────────────────────

    #[test]
    fn declassification_challenge_serde_round_trip() {
        let challenge = DeclassificationChallenge {
            challenge_type: "operator_approval".to_string(),
            detail: "requires sign-off".to_string(),
        };
        let json = serde_json::to_string(&challenge).expect("serialize");
        let back: DeclassificationChallenge = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(challenge, back);
    }

    // ── DecisionVerdict ─────────────────────────────────────────────────

    #[test]
    fn decision_verdict_serde_round_trip() {
        let verdicts = [
            DecisionVerdict::Approved {
                conditions: vec![DeclassificationCondition::new("k", "v")],
            },
            DecisionVerdict::Denied {
                reason: DeclassificationDenialReason::EmptyJustification,
            },
            DecisionVerdict::Deferred {
                challenge: DeclassificationChallenge {
                    challenge_type: "review".to_string(),
                    detail: "pending".to_string(),
                },
            },
        ];
        for verdict in &verdicts {
            let json = serde_json::to_string(verdict).expect("serialize");
            let back: DecisionVerdict = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*verdict, back);
        }
    }

    // ── DeclassificationDecisionEvent ───────────────────────────────────

    #[test]
    fn declassification_decision_event_serde_round_trip() {
        let event = DeclassificationDecisionEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "declassification_request".to_string(),
            outcome: "approved".to_string(),
            error_code: None,
            request_id: "r".to_string(),
            requester: "ext".to_string(),
            receipt_id: "rec".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let back: DeclassificationDecisionEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, back);
    }

    // ── DeclassificationDeniedEvidence ──────────────────────────────────

    #[test]
    fn declassification_denied_evidence_serde_round_trip() {
        let evidence = DeclassificationDeniedEvidence {
            request_id: "r".to_string(),
            requester: "ext".to_string(),
            reason: DeclassificationDenialReason::EmptyJustification,
            severity: DeclassificationEvidenceSeverity::High,
            label_distance: 2,
            decision_id: "d".to_string(),
        };
        let json = serde_json::to_string(&evidence).expect("serialize");
        let back: DeclassificationDeniedEvidence =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(evidence, back);
    }

    // ── CapabilityEscrowRecord ──────────────────────────────────────────

    #[test]
    fn capability_escrow_record_serde_round_trip() {
        let record = CapabilityEscrowRecord {
            request_id: "r".to_string(),
            extension_id: "e".to_string(),
            hostcall_type: HostcallType::FsWrite,
            capability: Capability::FsWrite,
            justification: "needed for log rotation".to_string(),
            state: CapabilityEscrowState::Challenged,
            created_at_ns: 100,
            expires_at_ns: 200,
            updated_at_ns: 150,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let back: CapabilityEscrowRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }

    // ── EmergencyGrantArtifact ──────────────────────────────────────────

    #[test]
    fn emergency_grant_artifact_is_expired() {
        let key = DecisionSigningKey::default();
        let artifact = EmergencyGrantArtifact::new_signed(
            "req-1",
            "ext-a",
            Capability::ProcessSpawn,
            "incident response".to_string(),
            "ops-lead".to_string(),
            1000,
            5,
            true,
            false,
            500,
            &key,
        );
        assert!(!artifact.is_expired(999));
        assert!(artifact.is_expired(1000));
        assert!(artifact.is_expired(1001));
    }

    #[test]
    fn emergency_grant_artifact_sign_verify() {
        let key = DecisionSigningKey::new([0xCC; 32]);
        let artifact = EmergencyGrantArtifact::new_signed(
            "req-2",
            "ext-b",
            Capability::FsWrite,
            "emergency write".to_string(),
            "admin".to_string(),
            5000,
            3,
            false,
            true,
            100,
            &key,
        );
        assert!(artifact.verify(&key.public_key()));
        let wrong_key = DecisionSigningKey::new([0xDD; 32]);
        assert!(!artifact.verify(&wrong_key.public_key()));
    }

    // ── HostcallDispatcher flow enforcement ─────────────────────────────

    #[test]
    fn hostcall_dispatcher_allows_non_sink_calls() {
        let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
        let caps: BTreeSet<Capability> = [Capability::FsRead].into_iter().collect();
        let context = FlowEnforcementContext::new("t", "d", "p");
        let outcome = dispatcher.dispatch(
            "ext-a",
            HostcallType::FsRead,
            &caps,
            Capability::FsRead,
            Labeled::system_generated("data".to_string()),
            &context,
        );
        assert_eq!(outcome.result, HostcallResult::Success);
        assert!(outcome.output.is_some());
    }

    #[test]
    fn hostcall_dispatcher_blocks_missing_capability() {
        let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
        let caps: BTreeSet<Capability> = [Capability::FsRead].into_iter().collect();
        let context = FlowEnforcementContext::new("t", "d", "p");
        let outcome = dispatcher.dispatch(
            "ext-a",
            HostcallType::FsWrite,
            &caps,
            Capability::FsWrite,
            Labeled::system_generated("data".to_string()),
            &context,
        );
        assert!(matches!(
            outcome.result,
            HostcallResult::Denied {
                reason: DenialReason::CapabilityEscalation { .. }
            }
        ));
    }

    #[test]
    fn hostcall_dispatcher_blocks_flow_violation() {
        let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
        let caps: BTreeSet<Capability> = [Capability::FsRead, Capability::NetClient]
            .into_iter()
            .collect();
        let secret_data = Labeled::new(
            "secret".to_string(),
            FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
        );
        let context = FlowEnforcementContext::new("t", "d", "p");
        let outcome = dispatcher.dispatch(
            "ext-a",
            HostcallType::NetworkSend,
            &caps,
            Capability::NetClient,
            secret_data,
            &context,
        );
        assert!(matches!(
            outcome.result,
            HostcallResult::Denied {
                reason: DenialReason::FlowViolation { .. }
            }
        ));
        assert_eq!(dispatcher.violation_events().len(), 1);
        assert_eq!(dispatcher.guardplane_evidence().len(), 1);
    }

    #[test]
    fn hostcall_dispatcher_allows_flow_compliant_sink() {
        let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
        let caps: BTreeSet<Capability> = [Capability::FsRead, Capability::FsWrite]
            .into_iter()
            .collect();
        let internal_data = Labeled::new(
            "log".to_string(),
            FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Validated),
        );
        let context = FlowEnforcementContext::new("t", "d", "p");
        let outcome = dispatcher.dispatch(
            "ext-a",
            HostcallType::FsWrite,
            &caps,
            Capability::FsWrite,
            internal_data,
            &context,
        );
        assert_eq!(outcome.result, HostcallResult::Success);
        assert!(dispatcher.violation_events().is_empty());
    }

    // ── DeclassificationEvaluationContext ────────────────────────────────

    #[test]
    fn declassification_eval_context_has_capability() {
        let caps: BTreeSet<Capability> = [Capability::Declassify, Capability::FsRead]
            .into_iter()
            .collect();
        let ctx = DeclassificationEvaluationContext::new(&caps, None, 1000);
        assert!(ctx.has_capability(Capability::Declassify));
        assert!(ctx.has_capability(Capability::FsRead));
        assert!(!ctx.has_capability(Capability::NetClient));
    }

    #[test]
    fn declassification_eval_context_request_count_within_window() {
        let caps = BTreeSet::new();
        let history = vec![100, 200, 300, 400, 500];
        let ctx = DeclassificationEvaluationContext::new(&caps, Some(&history), 500);
        assert_eq!(ctx.request_count_within_window(200), 3); // 300, 400, 500
        assert_eq!(ctx.request_count_within_window(500), 5); // all
        assert_eq!(ctx.request_count_within_window(0), 1); // just 500
    }

    #[test]
    fn declassification_eval_context_no_history_returns_zero() {
        let caps = BTreeSet::new();
        let ctx = DeclassificationEvaluationContext::new(&caps, None, 1000);
        assert_eq!(ctx.request_count_within_window(999_999), 0);
    }
}
