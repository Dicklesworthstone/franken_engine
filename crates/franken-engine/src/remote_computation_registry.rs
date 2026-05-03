//! Named remote computation registry with deterministic input encoding
//! and schema validation.
//!
//! All remote computations must be pre-registered with named identifiers,
//! typed input/output schemas, and deterministic serialization. Shipping
//! closures or opaque payloads to remote endpoints is explicitly rejected.
//!
//! The registry validates inputs against declared schemas before dispatch,
//! produces deterministic input hashes for idempotency-key derivation and
//! evidence linking, and supports version negotiation with remote endpoints.
//!
//! Plan references: Section 10.11 item 21, 9G.7 (remote-effects contract),
//! Top-10 #5 (supply-chain trust), #10 (provenance + revocation fabric).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityProfile, ProfileKind, RuntimeCapability};
use crate::deterministic_serde::{CanonicalValue, SchemaHash, encode_value};
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// ComputationName — validated unique identifier
// ---------------------------------------------------------------------------

/// A validated unique identifier for a named remote computation.
///
/// Names must be non-empty, ASCII-only, lowercase with underscores and dots.
/// Examples: `"revocation_propagate"`, `"evidence_sync"`, `"checkpoint_publish"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ComputationName(String);

impl ComputationName {
    /// Create a validated computation name.
    pub fn new(name: &str) -> Result<Self, RegistryError> {
        if name.is_empty() {
            return Err(RegistryError::InvalidComputationName {
                name: name.to_string(),
                reason: "name is empty".to_string(),
            });
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
        {
            return Err(RegistryError::InvalidComputationName {
                name: name.to_string(),
                reason: "must be ASCII lowercase, digits, underscores, or dots".to_string(),
            });
        }
        Ok(Self(name.to_string()))
    }

    /// Access the raw string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ComputationName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

use crate::control_plane::SchemaVersion;

pub trait SchemaVersionExt {
    fn is_compatible_with(&self, other: &Self) -> bool;
}

impl SchemaVersionExt for SchemaVersion {
    fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && other.minor >= self.minor
    }
}

// ---------------------------------------------------------------------------
// IdempotencyClass — idempotency semantics for computations
// ---------------------------------------------------------------------------

/// Whether a computation is naturally idempotent or requires explicit
/// idempotency-key management.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IdempotencyClass {
    /// Safe to retry without side effects (reads, lookups).
    NaturallyIdempotent,
    /// Requires an explicit idempotency key derived from (computation_name,
    /// input_hash) to prevent duplicate execution.
    RequiresKey,
}

impl fmt::Display for IdempotencyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NaturallyIdempotent => f.write_str("naturally_idempotent"),
            Self::RequiresKey => f.write_str("requires_key"),
        }
    }
}

// ---------------------------------------------------------------------------
// ComputationSchema — typed input/output schema
// ---------------------------------------------------------------------------

/// Schema description for a computation's input or output.
///
/// The schema hash is derived from the definition bytes, binding the
/// encoding format to its version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputationSchema {
    /// Human-readable description of the schema fields.
    pub description: String,
    /// Content-addressed hash of the schema definition.
    pub schema_hash: SchemaHash,
    /// Expected top-level field names in lexicographic order.
    pub expected_fields: Vec<String>,
}

impl ComputationSchema {
    /// Create a schema from its definition bytes and field list.
    pub fn new(description: &str, definition: &[u8], expected_fields: Vec<String>) -> Self {
        Self {
            description: description.to_string(),
            schema_hash: SchemaHash::from_definition(definition),
            expected_fields,
        }
    }
}

// ---------------------------------------------------------------------------
// ComputationRegistration — full registration record
// ---------------------------------------------------------------------------

/// A registered named remote computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputationRegistration {
    /// Unique computation name.
    pub name: ComputationName,
    /// Schema for the computation input.
    pub input_schema: ComputationSchema,
    /// Schema for the computation output.
    pub output_schema: ComputationSchema,
    /// Schema version for backward compatibility.
    pub version: SchemaVersion,
    /// Minimum capability profile required for invocation.
    pub capability_required: ProfileKind,
    /// Idempotency semantics.
    pub idempotency_class: IdempotencyClass,
}

// ---------------------------------------------------------------------------
// RegistryEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured event emitted by the computation registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEvent {
    /// Trace identifier for correlation.
    pub trace_id: String,
    /// Component that triggered the event.
    pub component: String,
    /// The computation name involved (if applicable).
    pub computation_name: String,
    /// Schema version (if applicable).
    pub version: String,
    /// Content hash of the input (if applicable).
    pub input_hash: String,
    /// Event type.
    pub event: String,
    /// Outcome: "success", "validation_failed", "denied", etc.
    pub outcome: String,
}

// ---------------------------------------------------------------------------
// RegistryError — typed error enum
// ---------------------------------------------------------------------------

/// Errors from the remote computation registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryError {
    /// Computation name failed validation.
    InvalidComputationName { name: String, reason: String },
    /// A computation with this name is already registered.
    DuplicateRegistration { name: String },
    /// No computation with this name is registered.
    ComputationNotFound { name: String },
    /// Input schema validation failed.
    SchemaValidationFailed {
        computation_name: String,
        reason: String,
    },
    /// The caller lacks the required capability profile.
    CapabilityDenied {
        computation_name: String,
        required: ProfileKind,
        held: ProfileKind,
    },
    /// Version negotiation failed (incompatible schema version).
    VersionIncompatible {
        computation_name: String,
        registered: SchemaVersion,
        requested: SchemaVersion,
    },
    /// Attempted to register a closure or untyped payload.
    ClosureRejected { reason: String },
    /// Hot-registration denied (requires EvidenceEmit capability).
    HotRegistrationDenied { reason: String },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidComputationName { name, reason } => {
                write!(f, "invalid computation name '{name}': {reason}")
            }
            Self::DuplicateRegistration { name } => {
                write!(f, "computation '{name}' already registered")
            }
            Self::ComputationNotFound { name } => {
                write!(f, "computation '{name}' not found")
            }
            Self::SchemaValidationFailed {
                computation_name,
                reason,
            } => {
                write!(
                    f,
                    "schema validation failed for '{computation_name}': {reason}"
                )
            }
            Self::CapabilityDenied {
                computation_name,
                required,
                held,
            } => {
                write!(
                    f,
                    "capability denied for '{computation_name}': requires {required}, held {held}"
                )
            }
            Self::VersionIncompatible {
                computation_name,
                registered,
                requested,
            } => {
                write!(
                    f,
                    "version incompatible for '{computation_name}': registered {registered}, requested {requested}"
                )
            }
            Self::ClosureRejected { reason } => {
                write!(f, "closure/untyped payload rejected: {reason}")
            }
            Self::HotRegistrationDenied { reason } => {
                write!(f, "hot-registration denied: {reason}")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

// ---------------------------------------------------------------------------
// VersionNegotiationResult — version check outcome
// ---------------------------------------------------------------------------

/// Result of version negotiation between local and remote schemas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionNegotiationResult {
    /// The computation name checked.
    pub computation_name: ComputationName,
    /// Whether versions are compatible.
    pub compatible: bool,
    /// Local (registered) version.
    pub local_version: SchemaVersion,
    /// Remote (requested) version.
    pub remote_version: SchemaVersion,
}

// ---------------------------------------------------------------------------
// RemoteComputationRegistry — the registry
// ---------------------------------------------------------------------------

/// Registry of named remote computations.
///
/// Maintains a catalog of pre-registered computations with typed schemas,
/// deterministic input encoding, and capability enforcement. Acts as a
/// singleton per runtime instance.
///
/// Uses `BTreeMap` for deterministic iteration ordering.
#[derive(Debug)]
pub struct RemoteComputationRegistry {
    /// Registered computations by name.
    computations: BTreeMap<String, ComputationRegistration>,
    /// Accumulated audit events.
    events: Vec<RegistryEvent>,
    /// Counters by event type.
    event_counts: BTreeMap<String, u64>,
}

impl Default for RemoteComputationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteComputationRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            computations: BTreeMap::new(),
            events: Vec::new(),
            event_counts: BTreeMap::new(),
        }
    }

    /// Register a named computation (static registration at startup).
    pub fn register(&mut self, registration: ComputationRegistration) -> Result<(), RegistryError> {
        let name_str = registration.name.as_str().to_string();
        if self.computations.contains_key(&name_str) {
            return Err(RegistryError::DuplicateRegistration { name: name_str });
        }
        self.computations.insert(name_str.clone(), registration);
        self.record_event_count("registration");
        Ok(())
    }

    /// Hot-register a computation at runtime (requires EvidenceEmit capability).
    ///
    /// Hot-registration emits evidence and requires a policy-governed profile.
    pub fn hot_register(
        &mut self,
        registration: ComputationRegistration,
        profile: &CapabilityProfile,
        trace_id: &str,
    ) -> Result<(), RegistryError> {
        if !profile.has(RuntimeCapability::EvidenceEmit) {
            self.emit_event(RegistryEvent {
                trace_id: trace_id.to_string(),
                component: "registry".to_string(),
                computation_name: registration.name.as_str().to_string(),
                version: registration.version.to_string(),
                input_hash: String::new(),
                event: "hot_registration_denied".to_string(),
                outcome: "denied".to_string(),
            });
            return Err(RegistryError::HotRegistrationDenied {
                reason: format!(
                    "profile {} lacks EvidenceEmit for hot-registration",
                    profile.kind()
                ),
            });
        }

        let name_str = registration.name.as_str().to_string();
        if self.computations.contains_key(&name_str) {
            return Err(RegistryError::DuplicateRegistration { name: name_str });
        }

        self.emit_event(RegistryEvent {
            trace_id: trace_id.to_string(),
            component: "registry".to_string(),
            computation_name: name_str.clone(),
            version: registration.version.to_string(),
            input_hash: String::new(),
            event: "hot_registration".to_string(),
            outcome: "success".to_string(),
        });

        self.computations.insert(name_str, registration);
        self.record_event_count("hot_registration");
        Ok(())
    }

    /// Look up a registered computation by name.
    pub fn lookup(&self, name: &ComputationName) -> Option<&ComputationRegistration> {
        self.computations.get(name.as_str())
    }

    /// Number of registered computations.
    pub fn len(&self) -> usize {
        self.computations.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.computations.is_empty()
    }

    /// List all registered computation names (deterministic order).
    pub fn computation_names(&self) -> Vec<&str> {
        self.computations.keys().map(|s| s.as_str()).collect()
    }

    /// Validate an input against a computation's declared input schema.
    ///
    /// Returns the deterministic content hash of the validated input.
    pub fn validate_input(
        &mut self,
        name: &ComputationName,
        input: &CanonicalValue,
        trace_id: &str,
    ) -> Result<ContentHash, RegistryError> {
        let registration = self.computations.get(name.as_str()).ok_or_else(|| {
            RegistryError::ComputationNotFound {
                name: name.as_str().to_string(),
            }
        })?;

        // Validate that input is a Map with the expected fields.
        let validation_result = validate_input_against_schema(input, &registration.input_schema);

        if let Err(reason) = validation_result {
            self.emit_event(RegistryEvent {
                trace_id: trace_id.to_string(),
                component: "registry".to_string(),
                computation_name: name.as_str().to_string(),
                version: registration.version.to_string(),
                input_hash: String::new(),
                event: "schema_validation".to_string(),
                outcome: "validation_failed".to_string(),
            });
            self.record_event_count("validation_failed");
            return Err(RegistryError::SchemaValidationFailed {
                computation_name: name.as_str().to_string(),
                reason,
            });
        }

        // Compute deterministic input hash.
        let encoded = encode_value(input);
        let input_hash = ContentHash::compute(&encoded);

        self.emit_event(RegistryEvent {
            trace_id: trace_id.to_string(),
            component: "registry".to_string(),
            computation_name: name.as_str().to_string(),
            version: registration.version.to_string(),
            input_hash: input_hash.to_hex(),
            event: "schema_validation".to_string(),
            outcome: "success".to_string(),
        });
        self.record_event_count("validation_success");

        Ok(input_hash)
    }

    /// Check that the caller's profile grants the required capabilities
    /// for invoking a computation.
    pub fn check_capability(
        &mut self,
        name: &ComputationName,
        profile: &CapabilityProfile,
        trace_id: &str,
    ) -> Result<(), RegistryError> {
        let registration = self.computations.get(name.as_str()).ok_or_else(|| {
            RegistryError::ComputationNotFound {
                name: name.as_str().to_string(),
            }
        })?;

        // Extract values we need before releasing the immutable borrow.
        let capability_required = registration.capability_required;
        let version_str = registration.version.to_string();

        let required_profile = match capability_required {
            ProfileKind::Full => CapabilityProfile::full(),
            ProfileKind::EngineCore => CapabilityProfile::engine_core(),
            ProfileKind::Policy => CapabilityProfile::policy(),
            ProfileKind::Remote => CapabilityProfile::remote(),
            ProfileKind::ComputeOnly => CapabilityProfile::compute_only(),
        };

        if !profile.subsumes(&required_profile) {
            self.emit_event(RegistryEvent {
                trace_id: trace_id.to_string(),
                component: "registry".to_string(),
                computation_name: name.as_str().to_string(),
                version: version_str,
                input_hash: String::new(),
                event: "capability_check".to_string(),
                outcome: "denied".to_string(),
            });
            self.record_event_count("capability_denied");
            return Err(RegistryError::CapabilityDenied {
                computation_name: name.as_str().to_string(),
                required: capability_required,
                held: profile.kind(),
            });
        }

        self.record_event_count("capability_granted");
        Ok(())
    }

    /// Negotiate schema version compatibility with a remote endpoint.
    ///
    /// Returns a negotiation result indicating whether the remote's version
    /// is compatible with the locally registered schema.
    pub fn negotiate_version(
        &self,
        name: &ComputationName,
        remote_version: SchemaVersion,
    ) -> Result<VersionNegotiationResult, RegistryError> {
        let registration = self.computations.get(name.as_str()).ok_or_else(|| {
            RegistryError::ComputationNotFound {
                name: name.as_str().to_string(),
            }
        })?;

        let compatible = registration.version.is_compatible_with(&remote_version);

        Ok(VersionNegotiationResult {
            computation_name: name.clone(),
            compatible,
            local_version: registration.version,
            remote_version,
        })
    }

    /// Reject an attempt to register a closure or untyped payload.
    ///
    /// This is an explicit API surface that makes the security policy
    /// clear: no opaque function pointers, closures, or untyped blobs.
    pub fn reject_closure(reason: &str) -> RegistryError {
        RegistryError::ClosureRejected {
            reason: reason.to_string(),
        }
    }

    /// Compute the deterministic input hash for a validated input.
    ///
    /// The hash can be used for idempotency-key derivation:
    /// `idempotency_key = hash(computation_name || input_hash)`.
    pub fn compute_input_hash(name: &ComputationName, input: &CanonicalValue) -> ContentHash {
        let encoded = encode_value(input);
        // Include computation name in hash for domain separation.
        let mut preimage = Vec::new();
        let name_bytes = name.as_str().as_bytes();
        preimage.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
        preimage.extend_from_slice(name_bytes);
        preimage.extend_from_slice(&encoded);
        ContentHash::compute(&preimage)
    }

    /// Drain accumulated audit events.
    pub fn drain_events(&mut self) -> Vec<RegistryEvent> {
        std::mem::take(&mut self.events)
    }

    /// Per-event-type counters (deterministic ordering).
    pub fn event_counts(&self) -> &BTreeMap<String, u64> {
        &self.event_counts
    }

    // -- Internal helpers --

    fn emit_event(&mut self, event: RegistryEvent) {
        self.events.push(event);
    }

    fn record_event_count(&mut self, event_type: &str) {
        *self.event_counts.entry(event_type.to_string()).or_insert(0) += 1;
    }
}

// ---------------------------------------------------------------------------
// Schema validation helpers
// ---------------------------------------------------------------------------

/// Validate that a `CanonicalValue` conforms to the declared schema.
///
/// Currently checks:
/// 1. Input must be a Map (not a raw scalar/array).
/// 2. All expected fields must be present.
/// 3. No undeclared fields (strict schema enforcement).
fn validate_input_against_schema(
    input: &CanonicalValue,
    schema: &ComputationSchema,
) -> Result<(), String> {
    let map = match input {
        CanonicalValue::Map(m) => m,
        _ => return Err("input must be a Map, not a scalar or array".to_string()),
    };

    // Check for missing required fields.
    for field in &schema.expected_fields {
        if !map.contains_key(field) {
            return Err(format!("missing required field: '{field}'"));
        }
    }

    // Check for undeclared fields.
    for key in map.keys() {
        if !schema.expected_fields.contains(key) {
            return Err(format!("undeclared field: '{key}'"));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // -- Test helpers --

    fn test_input_schema() -> ComputationSchema {
        ComputationSchema::new(
            "test input schema",
            b"test-input-schema-def-v1",
            vec!["action".to_string(), "target".to_string()],
        )
    }

    fn test_output_schema() -> ComputationSchema {
        ComputationSchema::new(
            "test output schema",
            b"test-output-schema-def-v1",
            vec!["status".to_string(), "result".to_string()],
        )
    }

    fn test_registration(name: &str) -> ComputationRegistration {
        ComputationRegistration {
            name: ComputationName::new(name).expect("serde deserialization should succeed"),
            input_schema: test_input_schema(),
            output_schema: test_output_schema(),
            version: SchemaVersion::new(1, 0, 0),
            capability_required: ProfileKind::Remote,
            idempotency_class: IdempotencyClass::RequiresKey,
        }
    }

    fn valid_input() -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "action".to_string(),
            CanonicalValue::String("propagate".to_string()),
        );
        map.insert(
            "target".to_string(),
            CanonicalValue::String("node-1".to_string()),
        );
        CanonicalValue::Map(map)
    }

    fn remote_profile() -> CapabilityProfile {
        CapabilityProfile::remote()
    }

    fn full_profile() -> CapabilityProfile {
        CapabilityProfile::full()
    }

    fn compute_only_profile() -> CapabilityProfile {
        CapabilityProfile::compute_only()
    }

    // -- ComputationName validation --

    #[test]
    fn valid_computation_name() {
        let name = ComputationName::new("revocation_propagate")
            .expect("serde deserialization should succeed");
        assert_eq!(name.as_str(), "revocation_propagate");
        assert_eq!(name.to_string(), "revocation_propagate");
    }

    #[test]
    fn computation_name_with_dots() {
        let name =
            ComputationName::new("evidence.sync.v2").expect("serde deserialization should succeed");
        assert_eq!(name.as_str(), "evidence.sync.v2");
    }

    #[test]
    fn computation_name_with_digits() {
        let name = ComputationName::new("checkpoint_publish_3")
            .expect("serde deserialization should succeed");
        assert_eq!(name.as_str(), "checkpoint_publish_3");
    }

    #[test]
    fn computation_name_empty_rejected() {
        assert!(matches!(
            ComputationName::new(""),
            Err(RegistryError::InvalidComputationName { .. })
        ));
    }

    #[test]
    fn computation_name_uppercase_rejected() {
        assert!(matches!(
            ComputationName::new("MyComputation"),
            Err(RegistryError::InvalidComputationName { .. })
        ));
    }

    #[test]
    fn computation_name_spaces_rejected() {
        assert!(matches!(
            ComputationName::new("my computation"),
            Err(RegistryError::InvalidComputationName { .. })
        ));
    }

    #[test]
    fn computation_name_special_chars_rejected() {
        assert!(matches!(
            ComputationName::new("my-computation"),
            Err(RegistryError::InvalidComputationName { .. })
        ));
    }

    // -- SchemaVersion --

    #[test]
    fn schema_version_compatible_same() {
        let v = SchemaVersion::new(1, 0, 0);
        assert!(v.is_compatible_with(&SchemaVersion::new(1, 0, 0)));
    }

    #[test]
    fn schema_version_compatible_minor_bump() {
        let v = SchemaVersion::new(1, 0, 0);
        assert!(v.is_compatible_with(&SchemaVersion::new(1, 2, 0)));
    }

    #[test]
    fn schema_version_incompatible_major_bump() {
        let v = SchemaVersion::new(1, 0, 0);
        assert!(!v.is_compatible_with(&SchemaVersion::new(2, 0, 0)));
    }

    #[test]
    fn schema_version_incompatible_lower_minor() {
        let v = SchemaVersion::new(1, 3, 0);
        assert!(!v.is_compatible_with(&SchemaVersion::new(1, 2, 0)));
    }

    #[test]
    fn schema_version_display() {
        assert_eq!(SchemaVersion::new(2, 5, 0).to_string(), "2.5.0");
    }

    // -- IdempotencyClass --

    #[test]
    fn idempotency_class_display() {
        assert_eq!(
            IdempotencyClass::NaturallyIdempotent.to_string(),
            "naturally_idempotent"
        );
        assert_eq!(IdempotencyClass::RequiresKey.to_string(), "requires_key");
    }

    // -- Registry: registration --

    #[test]
    fn register_computation() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("revocation_propagate"))
            .expect("serde deserialization should succeed");
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
    }

    #[test]
    fn register_duplicate_rejected() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("evidence_sync"))
            .expect("serde deserialization should succeed");
        assert!(matches!(
            reg.register(test_registration("evidence_sync")),
            Err(RegistryError::DuplicateRegistration { .. })
        ));
    }

    #[test]
    fn register_multiple_computations() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("alpha"))
            .expect("serde deserialization should succeed");
        reg.register(test_registration("beta"))
            .expect("serde deserialization should succeed");
        reg.register(test_registration("gamma"))
            .expect("serde deserialization should succeed");
        assert_eq!(reg.len(), 3);
    }

    #[test]
    fn computation_names_are_sorted() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("gamma"))
            .expect("serde deserialization should succeed");
        reg.register(test_registration("alpha"))
            .expect("serde deserialization should succeed");
        reg.register(test_registration("beta"))
            .expect("serde deserialization should succeed");
        assert_eq!(reg.computation_names(), vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn lookup_registered_computation() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("evidence_sync"))
            .expect("serde deserialization should succeed");
        let name =
            ComputationName::new("evidence_sync").expect("serde deserialization should succeed");
        let found = reg
            .lookup(&name)
            .expect("serde deserialization should succeed");
        assert_eq!(found.name.as_str(), "evidence_sync");
        assert_eq!(found.version, SchemaVersion::new(1, 0, 0));
    }

    #[test]
    fn lookup_missing_computation() {
        let reg = RemoteComputationRegistry::new();
        let name =
            ComputationName::new("nonexistent").expect("serde deserialization should succeed");
        assert!(reg.lookup(&name).is_none());
    }

    // -- Registry: hot registration --

    #[test]
    fn hot_register_with_evidence_emit() {
        let mut reg = RemoteComputationRegistry::new();
        let profile = CapabilityProfile::policy(); // has EvidenceEmit
        reg.hot_register(test_registration("late_addition"), &profile, "trace-hot")
            .expect("serde deserialization should succeed");
        assert_eq!(reg.len(), 1);
        let events = reg.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "hot_registration");
        assert_eq!(events[0].outcome, "success");
    }

    #[test]
    fn hot_register_without_evidence_emit_denied() {
        let mut reg = RemoteComputationRegistry::new();
        let profile = compute_only_profile();
        let err = reg
            .hot_register(test_registration("blocked"), &profile, "trace-denied")
            .unwrap_err();
        assert!(matches!(err, RegistryError::HotRegistrationDenied { .. }));
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn hot_register_duplicate_rejected() {
        let mut reg = RemoteComputationRegistry::new();
        let profile = CapabilityProfile::policy();
        reg.hot_register(test_registration("dup_hot"), &profile, "t1")
            .expect("serde deserialization should succeed");
        assert!(matches!(
            reg.hot_register(test_registration("dup_hot"), &profile, "t2"),
            Err(RegistryError::DuplicateRegistration { .. })
        ));
    }

    // -- Schema validation --

    #[test]
    fn validate_valid_input() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");
        let hash = reg
            .validate_input(&name, &valid_input(), "trace-v")
            .expect("serde deserialization should succeed");
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn validate_input_missing_field() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");

        let mut map = BTreeMap::new();
        map.insert(
            "action".to_string(),
            CanonicalValue::String("propagate".to_string()),
        );
        // Missing "target" field.
        let input = CanonicalValue::Map(map);

        let err = reg.validate_input(&name, &input, "trace-m").unwrap_err();
        assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
    }

    #[test]
    fn validate_input_undeclared_field() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");

        let mut map = BTreeMap::new();
        map.insert(
            "action".to_string(),
            CanonicalValue::String("propagate".to_string()),
        );
        map.insert(
            "target".to_string(),
            CanonicalValue::String("node-1".to_string()),
        );
        map.insert(
            "extra".to_string(),
            CanonicalValue::String("sneaky".to_string()),
        );
        let input = CanonicalValue::Map(map);

        let err = reg.validate_input(&name, &input, "trace-e").unwrap_err();
        assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
    }

    #[test]
    fn validate_input_not_a_map() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");

        let input = CanonicalValue::String("not a map".to_string());
        let err = reg.validate_input(&name, &input, "trace-s").unwrap_err();
        assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
    }

    #[test]
    fn validate_input_computation_not_found() {
        let mut reg = RemoteComputationRegistry::new();
        let name =
            ComputationName::new("nonexistent").expect("serde deserialization should succeed");
        assert!(matches!(
            reg.validate_input(&name, &valid_input(), "trace-nf"),
            Err(RegistryError::ComputationNotFound { .. })
        ));
    }

    // -- Deterministic input encoding --

    #[test]
    fn input_hash_is_deterministic() {
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");
        let input = valid_input();
        let h1 = RemoteComputationRegistry::compute_input_hash(&name, &input);
        let h2 = RemoteComputationRegistry::compute_input_hash(&name, &input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn input_hash_differs_for_different_inputs() {
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");

        let mut map1 = BTreeMap::new();
        map1.insert(
            "action".to_string(),
            CanonicalValue::String("a".to_string()),
        );
        map1.insert(
            "target".to_string(),
            CanonicalValue::String("x".to_string()),
        );

        let mut map2 = BTreeMap::new();
        map2.insert(
            "action".to_string(),
            CanonicalValue::String("b".to_string()),
        );
        map2.insert(
            "target".to_string(),
            CanonicalValue::String("y".to_string()),
        );

        let h1 = RemoteComputationRegistry::compute_input_hash(&name, &CanonicalValue::Map(map1));
        let h2 = RemoteComputationRegistry::compute_input_hash(&name, &CanonicalValue::Map(map2));
        assert_ne!(h1, h2);
    }

    #[test]
    fn input_hash_differs_for_different_computation_names() {
        let name_a = ComputationName::new("comp_a").expect("serde deserialization should succeed");
        let name_b = ComputationName::new("comp_b").expect("serde deserialization should succeed");
        let input = valid_input();
        let h1 = RemoteComputationRegistry::compute_input_hash(&name_a, &input);
        let h2 = RemoteComputationRegistry::compute_input_hash(&name_b, &input);
        assert_ne!(h1, h2);
    }

    // -- Capability enforcement --

    #[test]
    fn capability_check_passes_with_sufficient_profile() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");
        // Remote profile has all capabilities needed for RemoteCaps
        assert!(
            reg.check_capability(&name, &remote_profile(), "trace-cap")
                .is_ok()
        );
    }

    #[test]
    fn capability_check_passes_with_full_profile() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");
        assert!(
            reg.check_capability(&name, &full_profile(), "trace-full")
                .is_ok()
        );
    }

    #[test]
    fn capability_check_denied_with_compute_only() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");
        let err = reg
            .check_capability(&name, &compute_only_profile(), "trace-co")
            .unwrap_err();
        assert!(matches!(err, RegistryError::CapabilityDenied { .. }));
    }

    #[test]
    fn capability_check_computation_not_found() {
        let mut reg = RemoteComputationRegistry::new();
        let name = ComputationName::new("missing").expect("serde deserialization should succeed");
        assert!(matches!(
            reg.check_capability(&name, &remote_profile(), "trace-nf"),
            Err(RegistryError::ComputationNotFound { .. })
        ));
    }

    // -- Version negotiation --

    #[test]
    fn version_negotiation_compatible() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");
        let result = reg
            .negotiate_version(&name, SchemaVersion::new(1, 2, 0))
            .expect("serde deserialization should succeed");
        assert!(result.compatible);
        assert_eq!(result.local_version, SchemaVersion::new(1, 0, 0));
        assert_eq!(result.remote_version, SchemaVersion::new(1, 2, 0));
    }

    #[test]
    fn version_negotiation_exact_match() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");
        let result = reg
            .negotiate_version(&name, SchemaVersion::new(1, 0, 0))
            .expect("serde deserialization should succeed");
        assert!(result.compatible);
    }

    #[test]
    fn version_negotiation_incompatible_major() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");
        let result = reg
            .negotiate_version(&name, SchemaVersion::new(2, 0, 0))
            .expect("serde deserialization should succeed");
        assert!(!result.compatible);
    }

    #[test]
    fn version_negotiation_incompatible_lower_minor() {
        let mut reg = RemoteComputationRegistry::new();
        let mut comp = test_registration("test_comp");
        comp.version = SchemaVersion::new(1, 3, 0);
        reg.register(comp)
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");
        let result = reg
            .negotiate_version(&name, SchemaVersion::new(1, 1, 0))
            .expect("serde deserialization should succeed");
        assert!(!result.compatible);
    }

    #[test]
    fn version_negotiation_computation_not_found() {
        let reg = RemoteComputationRegistry::new();
        let name = ComputationName::new("missing").expect("serde deserialization should succeed");
        assert!(matches!(
            reg.negotiate_version(&name, SchemaVersion::new(1, 0, 0)),
            Err(RegistryError::ComputationNotFound { .. })
        ));
    }

    // -- Closure rejection --

    #[test]
    fn closure_rejection() {
        let err = RemoteComputationRegistry::reject_closure(
            "attempted to register opaque function pointer",
        );
        assert!(matches!(err, RegistryError::ClosureRejected { .. }));
        assert!(err.to_string().contains("opaque function pointer"));
    }

    // -- Audit events --

    #[test]
    fn validation_emits_event() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");
        reg.validate_input(&name, &valid_input(), "trace-ev")
            .expect("serde deserialization should succeed");

        let events = reg.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "schema_validation");
        assert_eq!(events[0].outcome, "success");
        assert_eq!(events[0].computation_name, "test_comp");
        assert_eq!(events[0].trace_id, "trace-ev");
        assert!(!events[0].input_hash.is_empty());
    }

    #[test]
    fn validation_failure_emits_event() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");
        let _ = reg.validate_input(
            &name,
            &CanonicalValue::String("bad".to_string()),
            "trace-fail",
        );

        let events = reg.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "validation_failed");
    }

    #[test]
    fn drain_events_clears() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");
        reg.validate_input(&name, &valid_input(), "t")
            .expect("serde deserialization should succeed");

        let e1 = reg.drain_events();
        assert_eq!(e1.len(), 1);
        let e2 = reg.drain_events();
        assert!(e2.is_empty());
    }

    #[test]
    fn event_counts_track_outcomes() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("test_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("test_comp").expect("serde deserialization should succeed");

        reg.validate_input(&name, &valid_input(), "t1")
            .expect("serde deserialization should succeed");
        reg.validate_input(&name, &valid_input(), "t2")
            .expect("serde deserialization should succeed");
        let _ = reg.validate_input(&name, &CanonicalValue::String("bad".to_string()), "t3");

        assert_eq!(reg.event_counts().get("validation_success"), Some(&2));
        assert_eq!(reg.event_counts().get("validation_failed"), Some(&1));
    }

    // -- Serialization round-trips --

    #[test]
    fn computation_name_serialization_round_trip() {
        let name =
            ComputationName::new("evidence_sync").expect("serde deserialization should succeed");
        let json = serde_json::to_string(&name).expect("serde deserialization should succeed");
        let restored: ComputationName =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(name, restored);
    }

    #[test]
    fn schema_version_serialization_round_trip() {
        let v = SchemaVersion::new(2, 5, 0);
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let restored: SchemaVersion =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(v, restored);
    }

    #[test]
    fn idempotency_class_serialization_round_trip() {
        for class in [
            IdempotencyClass::NaturallyIdempotent,
            IdempotencyClass::RequiresKey,
        ] {
            let json = serde_json::to_string(&class).expect("serde deserialization should succeed");
            let restored: IdempotencyClass =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(class, restored);
        }
    }

    #[test]
    fn registration_serialization_round_trip() {
        let reg = test_registration("evidence_sync");
        let json = serde_json::to_string(&reg).expect("serde deserialization should succeed");
        let restored: ComputationRegistration =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(reg, restored);
    }

    #[test]
    fn registry_event_serialization_round_trip() {
        let event = RegistryEvent {
            trace_id: "trace-1".to_string(),
            component: "registry".to_string(),
            computation_name: "test_comp".to_string(),
            version: "1.0".to_string(),
            input_hash: "abcdef".to_string(),
            event: "schema_validation".to_string(),
            outcome: "success".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let restored: RegistryEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, restored);
    }

    #[test]
    fn registry_error_serialization_round_trip() {
        let errors = vec![
            RegistryError::InvalidComputationName {
                name: "bad".to_string(),
                reason: "empty".to_string(),
            },
            RegistryError::DuplicateRegistration {
                name: "dup".to_string(),
            },
            RegistryError::ComputationNotFound {
                name: "missing".to_string(),
            },
            RegistryError::ClosureRejected {
                reason: "no closures".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let restored: RegistryError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn version_negotiation_result_serialization_round_trip() {
        let result = VersionNegotiationResult {
            computation_name: ComputationName::new("test_comp")
                .expect("serde deserialization should succeed"),
            compatible: true,
            local_version: SchemaVersion::new(1, 0, 0),
            remote_version: SchemaVersion::new(1, 2, 0),
        };
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let restored: VersionNegotiationResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, restored);
    }

    // -- Display --

    #[test]
    fn error_display_messages() {
        assert!(
            RegistryError::DuplicateRegistration {
                name: "x".to_string()
            }
            .to_string()
            .contains("already registered")
        );
        assert!(
            RegistryError::ComputationNotFound {
                name: "y".to_string()
            }
            .to_string()
            .contains("not found")
        );
        assert!(
            RegistryError::ClosureRejected {
                reason: "no closures".to_string()
            }
            .to_string()
            .contains("no closures")
        );
    }

    // -- Default --

    #[test]
    fn registry_default_is_empty() {
        let reg = RemoteComputationRegistry::default();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    // -- Full lifecycle --

    #[test]
    fn full_lifecycle_register_validate_check_negotiate() {
        let mut reg = RemoteComputationRegistry::new();

        // 1. Register
        reg.register(test_registration("revocation_propagate"))
            .expect("serde deserialization should succeed");

        let name = ComputationName::new("revocation_propagate")
            .expect("serde deserialization should succeed");

        // 2. Check capability
        reg.check_capability(&name, &remote_profile(), "trace-1")
            .expect("serde deserialization should succeed");

        // 3. Validate input
        let input_hash = reg
            .validate_input(&name, &valid_input(), "trace-2")
            .expect("serde deserialization should succeed");
        assert_eq!(input_hash.as_bytes().len(), 32);

        // 4. Negotiate version
        let negotiation = reg
            .negotiate_version(&name, SchemaVersion::new(1, 1, 0))
            .expect("serde deserialization should succeed");
        assert!(negotiation.compatible);

        // 5. Compute idempotency hash
        let idem_hash = RemoteComputationRegistry::compute_input_hash(&name, &valid_input());
        assert_eq!(idem_hash.as_bytes().len(), 32);

        // 6. Verify events
        let events = reg.drain_events();
        assert!(!events.is_empty());
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn idempotency_class_serde_all_variants() {
        let variants = [
            IdempotencyClass::NaturallyIdempotent,
            IdempotencyClass::RequiresKey,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let back: IdempotencyClass =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn idempotency_class_display_distinct() {
        let all = [
            IdempotencyClass::NaturallyIdempotent,
            IdempotencyClass::RequiresKey,
        ];
        let set: std::collections::BTreeSet<String> = all.iter().map(|c| format!("{c}")).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn idempotency_class_ordering() {
        assert!(IdempotencyClass::NaturallyIdempotent < IdempotencyClass::RequiresKey);
    }

    #[test]
    fn registry_error_display_distinct() {
        use crate::capability::ProfileKind;
        let variants: Vec<RegistryError> = vec![
            RegistryError::InvalidComputationName {
                name: "x".into(),
                reason: "bad".into(),
            },
            RegistryError::DuplicateRegistration { name: "x".into() },
            RegistryError::ComputationNotFound { name: "x".into() },
            RegistryError::SchemaValidationFailed {
                computation_name: "x".into(),
                reason: "bad".into(),
            },
            RegistryError::CapabilityDenied {
                computation_name: "x".into(),
                required: ProfileKind::Full,
                held: ProfileKind::ComputeOnly,
            },
            RegistryError::VersionIncompatible {
                computation_name: "x".into(),
                registered: SchemaVersion::new(1, 0, 0),
                requested: SchemaVersion::new(2, 0, 0),
            },
            RegistryError::ClosureRejected {
                reason: "no".into(),
            },
            RegistryError::HotRegistrationDenied {
                reason: "no".into(),
            },
        ];
        let set: std::collections::BTreeSet<String> =
            variants.iter().map(|e| format!("{e}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    // -----------------------------------------------------------------------
    // 1. Copy semantics
    // -----------------------------------------------------------------------

    #[test]
    fn idempotency_class_copy_semantics() {
        let a = IdempotencyClass::NaturallyIdempotent;
        let b = a; // copy
        assert_eq!(a, b);
        let c = IdempotencyClass::RequiresKey;
        let d = c; // copy
        assert_eq!(c, d);
    }

    // -----------------------------------------------------------------------
    // 2. Debug distinctness
    // -----------------------------------------------------------------------

    #[test]
    fn idempotency_class_debug_distinct() {
        let a = format!("{:?}", IdempotencyClass::NaturallyIdempotent);
        let b = format!("{:?}", IdempotencyClass::RequiresKey);
        assert_ne!(a, b);
        assert!(a.contains("NaturallyIdempotent"));
        assert!(b.contains("RequiresKey"));
    }

    #[test]
    fn registry_error_debug_nonempty() {
        let e = RegistryError::InvalidComputationName {
            name: "bad".into(),
            reason: "empty".into(),
        };
        let d = format!("{e:?}");
        assert!(!d.is_empty());
        assert!(d.contains("InvalidComputationName"));
    }

    #[test]
    fn registry_event_debug_nonempty() {
        let ev = RegistryEvent {
            trace_id: "t1".into(),
            component: "registry".into(),
            computation_name: "c".into(),
            version: "1.0.0".into(),
            input_hash: "abc".into(),
            event: "test".into(),
            outcome: "ok".into(),
        };
        let d = format!("{ev:?}");
        assert!(!d.is_empty());
        assert!(d.contains("RegistryEvent"));
    }

    #[test]
    fn computation_name_debug_nonempty() {
        let n = ComputationName::new("debug_test").expect("serde deserialization should succeed");
        let d = format!("{n:?}");
        assert!(!d.is_empty());
        assert!(d.contains("ComputationName"));
    }

    #[test]
    fn computation_schema_debug_nonempty() {
        let s = test_input_schema();
        let d = format!("{s:?}");
        assert!(!d.is_empty());
        assert!(d.contains("ComputationSchema"));
    }

    #[test]
    fn computation_registration_debug_nonempty() {
        let r = test_registration("debug_reg");
        let d = format!("{r:?}");
        assert!(!d.is_empty());
        assert!(d.contains("ComputationRegistration"));
    }

    #[test]
    fn version_negotiation_result_debug_nonempty() {
        let result = VersionNegotiationResult {
            computation_name: ComputationName::new("x")
                .expect("serde deserialization should succeed"),
            compatible: true,
            local_version: SchemaVersion::new(1, 0, 0),
            remote_version: SchemaVersion::new(1, 0, 0),
        };
        let d = format!("{result:?}");
        assert!(!d.is_empty());
        assert!(d.contains("VersionNegotiationResult"));
    }

    // -----------------------------------------------------------------------
    // 3. Serde variant distinctness
    // -----------------------------------------------------------------------

    #[test]
    fn registry_error_serde_variants_distinct() {
        let variants: Vec<RegistryError> = vec![
            RegistryError::InvalidComputationName {
                name: "n".into(),
                reason: "r".into(),
            },
            RegistryError::DuplicateRegistration { name: "n".into() },
            RegistryError::ComputationNotFound { name: "n".into() },
            RegistryError::SchemaValidationFailed {
                computation_name: "n".into(),
                reason: "r".into(),
            },
            RegistryError::CapabilityDenied {
                computation_name: "n".into(),
                required: ProfileKind::Full,
                held: ProfileKind::ComputeOnly,
            },
            RegistryError::VersionIncompatible {
                computation_name: "n".into(),
                registered: SchemaVersion::new(1, 0, 0),
                requested: SchemaVersion::new(2, 0, 0),
            },
            RegistryError::ClosureRejected { reason: "r".into() },
            RegistryError::HotRegistrationDenied { reason: "r".into() },
        ];
        let jsons: std::collections::BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).expect("serde deserialization should succeed"))
            .collect();
        // Each variant serialises to a distinct JSON string.
        assert_eq!(jsons.len(), variants.len());
    }

    #[test]
    fn idempotency_class_serde_variants_distinct() {
        let a = serde_json::to_string(&IdempotencyClass::NaturallyIdempotent)
            .expect("serde deserialization should succeed");
        let b = serde_json::to_string(&IdempotencyClass::RequiresKey)
            .expect("serde deserialization should succeed");
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // 4. Clone independence
    // -----------------------------------------------------------------------

    #[test]
    fn computation_name_clone_independence() {
        let orig = ComputationName::new("clone_me").expect("serde deserialization should succeed");
        let mut cloned = orig.clone();
        // Inner string is a clone; modifying cloned does not affect original.
        // We can only verify equality then check they're independent via serde.
        assert_eq!(orig, cloned);
        let serialised =
            serde_json::to_string(&cloned).expect("serde deserialization should succeed");
        cloned = serde_json::from_str(&serialised).expect("serde deserialization should succeed");
        assert_eq!(orig, cloned);
    }

    #[test]
    fn registry_error_clone_independence() {
        let orig = RegistryError::DuplicateRegistration {
            name: "dup".to_string(),
        };
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
    }

    #[test]
    fn registry_event_clone_independence() {
        let ev = RegistryEvent {
            trace_id: "t".into(),
            component: "c".into(),
            computation_name: "n".into(),
            version: "1.0.0".into(),
            input_hash: "h".into(),
            event: "e".into(),
            outcome: "o".into(),
        };
        let cloned = ev.clone();
        assert_eq!(ev, cloned);
    }

    #[test]
    fn computation_registration_clone_independence() {
        let orig = test_registration("clone_reg");
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
    }

    #[test]
    fn computation_schema_clone_independence() {
        let orig = test_input_schema();
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
    }

    // -----------------------------------------------------------------------
    // 5. JSON field-name stability
    // -----------------------------------------------------------------------

    #[test]
    fn registry_event_json_field_names() {
        let ev = RegistryEvent {
            trace_id: "t1".into(),
            component: "reg".into(),
            computation_name: "comp".into(),
            version: "1.0.0".into(),
            input_hash: "abc123".into(),
            event: "schema_validation".into(),
            outcome: "success".into(),
        };
        let json = serde_json::to_string(&ev).expect("serde deserialization should succeed");
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"computation_name\""));
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"input_hash\""));
        assert!(json.contains("\"event\""));
        assert!(json.contains("\"outcome\""));
    }

    #[test]
    fn computation_registration_json_field_names() {
        let reg = test_registration("field_test");
        let json = serde_json::to_string(&reg).expect("serde deserialization should succeed");
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"input_schema\""));
        assert!(json.contains("\"output_schema\""));
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"capability_required\""));
        assert!(json.contains("\"idempotency_class\""));
    }

    #[test]
    fn computation_schema_json_field_names() {
        let schema = test_input_schema();
        let json = serde_json::to_string(&schema).expect("serde deserialization should succeed");
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"schema_hash\""));
        assert!(json.contains("\"expected_fields\""));
    }

    #[test]
    fn version_negotiation_result_json_field_names() {
        let result = VersionNegotiationResult {
            computation_name: ComputationName::new("field_check")
                .expect("serde deserialization should succeed"),
            compatible: false,
            local_version: SchemaVersion::new(1, 0, 0),
            remote_version: SchemaVersion::new(2, 0, 0),
        };
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        assert!(json.contains("\"computation_name\""));
        assert!(json.contains("\"compatible\""));
        assert!(json.contains("\"local_version\""));
        assert!(json.contains("\"remote_version\""));
    }

    // -----------------------------------------------------------------------
    // 6. Display format checks
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_invalid_computation_name() {
        let e = RegistryError::InvalidComputationName {
            name: "BAD".into(),
            reason: "uppercase not allowed".into(),
        };
        let s = e.to_string();
        assert!(s.contains("BAD"));
        assert!(s.contains("uppercase not allowed"));
    }

    #[test]
    fn error_display_schema_validation_failed() {
        let e = RegistryError::SchemaValidationFailed {
            computation_name: "my_comp".into(),
            reason: "missing field".into(),
        };
        let s = e.to_string();
        assert!(s.contains("my_comp"));
        assert!(s.contains("missing field"));
    }

    #[test]
    fn error_display_capability_denied() {
        let e = RegistryError::CapabilityDenied {
            computation_name: "x".into(),
            required: ProfileKind::Full,
            held: ProfileKind::ComputeOnly,
        };
        let s = e.to_string();
        assert!(s.contains("x"));
        assert!(s.contains("requires"));
        assert!(s.contains("held"));
    }

    #[test]
    fn error_display_version_incompatible() {
        let e = RegistryError::VersionIncompatible {
            computation_name: "v_comp".into(),
            registered: SchemaVersion::new(1, 0, 0),
            requested: SchemaVersion::new(2, 0, 0),
        };
        let s = e.to_string();
        assert!(s.contains("v_comp"));
        assert!(s.contains("1.0.0"));
        assert!(s.contains("2.0.0"));
    }

    #[test]
    fn error_display_hot_registration_denied() {
        let e = RegistryError::HotRegistrationDenied {
            reason: "insufficient caps".into(),
        };
        let s = e.to_string();
        assert!(s.contains("hot-registration denied"));
        assert!(s.contains("insufficient caps"));
    }

    #[test]
    fn computation_name_display_matches_as_str() {
        let n =
            ComputationName::new("display_check").expect("serde deserialization should succeed");
        assert_eq!(n.to_string(), n.as_str());
    }

    // -----------------------------------------------------------------------
    // 7. Hash consistency
    // -----------------------------------------------------------------------

    #[test]
    fn computation_name_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let n = ComputationName::new("hash_me").expect("serde deserialization should succeed");
        let mut h1 = DefaultHasher::new();
        n.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        n.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn computation_name_hash_distinct_for_different_names() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let n1 = ComputationName::new("alpha").expect("serde deserialization should succeed");
        let n2 = ComputationName::new("beta").expect("serde deserialization should succeed");
        let mut h1 = DefaultHasher::new();
        n1.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        n2.hash(&mut h2);
        assert_ne!(h1.finish(), h2.finish());
    }

    #[test]
    fn input_hash_32_bytes() {
        let name =
            ComputationName::new("hash_len_check").expect("serde deserialization should succeed");
        let input = valid_input();
        let h = RemoteComputationRegistry::compute_input_hash(&name, &input);
        assert_eq!(h.as_bytes().len(), 32);
    }

    #[test]
    fn input_hash_scalar_differs_from_map() {
        let name =
            ComputationName::new("scalar_vs_map").expect("serde deserialization should succeed");
        let map_input = valid_input();
        let scalar_input = CanonicalValue::U64(42);
        let h1 = RemoteComputationRegistry::compute_input_hash(&name, &map_input);
        let h2 = RemoteComputationRegistry::compute_input_hash(&name, &scalar_input);
        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // 8. Boundary / edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn computation_name_single_char_valid() {
        let n = ComputationName::new("a").expect("serde deserialization should succeed");
        assert_eq!(n.as_str(), "a");
    }

    #[test]
    fn computation_name_leading_digit_valid() {
        // digits are allowed; a name can start with a digit
        assert!(ComputationName::new("1abc").is_ok());
    }

    #[test]
    fn computation_name_only_dots_valid() {
        // dots are allowed; "..." is technically valid per the rule
        assert!(ComputationName::new("...").is_ok());
    }

    #[test]
    fn computation_name_slash_rejected() {
        assert!(matches!(
            ComputationName::new("my/comp"),
            Err(RegistryError::InvalidComputationName { .. })
        ));
    }

    #[test]
    fn computation_name_at_sign_rejected() {
        assert!(matches!(
            ComputationName::new("my@comp"),
            Err(RegistryError::InvalidComputationName { .. })
        ));
    }

    #[test]
    fn validate_input_empty_map_missing_all_fields() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("empty_map_comp"))
            .expect("serde deserialization should succeed");
        let name =
            ComputationName::new("empty_map_comp").expect("serde deserialization should succeed");
        let empty = CanonicalValue::Map(BTreeMap::new());
        let err = reg.validate_input(&name, &empty, "t").unwrap_err();
        assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
    }

    #[test]
    fn validate_input_array_rejected_as_non_map() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("arr_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("arr_comp").expect("serde deserialization should succeed");
        let arr = CanonicalValue::Array(vec![CanonicalValue::U64(1)]);
        let err = reg.validate_input(&name, &arr, "t").unwrap_err();
        assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
    }

    #[test]
    fn validate_input_null_rejected_as_non_map() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("null_comp"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("null_comp").expect("serde deserialization should succeed");
        let err = reg
            .validate_input(&name, &CanonicalValue::Null, "t")
            .unwrap_err();
        assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
    }

    #[test]
    fn registry_starts_empty_no_events() {
        let mut reg = RemoteComputationRegistry::new();
        assert_eq!(reg.drain_events().len(), 0);
        assert!(reg.event_counts().is_empty());
    }

    #[test]
    fn schema_version_major_zero_compatible_with_itself() {
        let v = SchemaVersion::new(0, 0, 0);
        assert!(v.is_compatible_with(&SchemaVersion::new(0, 0, 0)));
    }

    #[test]
    fn schema_version_major_zero_incompatible_higher_major() {
        let v = SchemaVersion::new(0, 0, 0);
        assert!(!v.is_compatible_with(&SchemaVersion::new(1, 0, 0)));
    }

    #[test]
    fn registration_count_increments_correctly() {
        let mut reg = RemoteComputationRegistry::new();
        for i in 0..5u32 {
            let name = format!("comp_{i}");
            reg.register(test_registration(&name))
                .expect("serde deserialization should succeed");
            assert_eq!(reg.len(), (i + 1) as usize);
        }
    }

    // -----------------------------------------------------------------------
    // 9. Serde round-trips (additional variants)
    // -----------------------------------------------------------------------

    #[test]
    fn registry_error_all_variants_serde_roundtrip() {
        let variants: Vec<RegistryError> = vec![
            RegistryError::InvalidComputationName {
                name: "nn".into(),
                reason: "rr".into(),
            },
            RegistryError::DuplicateRegistration { name: "nn".into() },
            RegistryError::ComputationNotFound { name: "nn".into() },
            RegistryError::SchemaValidationFailed {
                computation_name: "nn".into(),
                reason: "rr".into(),
            },
            RegistryError::CapabilityDenied {
                computation_name: "nn".into(),
                required: ProfileKind::EngineCore,
                held: ProfileKind::ComputeOnly,
            },
            RegistryError::VersionIncompatible {
                computation_name: "nn".into(),
                registered: SchemaVersion::new(3, 1, 0),
                requested: SchemaVersion::new(3, 0, 0),
            },
            RegistryError::ClosureRejected {
                reason: "rr".into(),
            },
            RegistryError::HotRegistrationDenied {
                reason: "rr".into(),
            },
        ];
        for err in &variants {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let back: RegistryError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, back);
        }
    }

    #[test]
    fn computation_schema_serde_roundtrip() {
        let schema = ComputationSchema::new(
            "round trip schema",
            b"schema-definition-bytes",
            vec!["field_a".into(), "field_b".into(), "field_c".into()],
        );
        let json = serde_json::to_string(&schema).expect("serde deserialization should succeed");
        let back: ComputationSchema =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(schema, back);
    }

    #[test]
    fn version_negotiation_result_serde_incompatible_roundtrip() {
        let result = VersionNegotiationResult {
            computation_name: ComputationName::new("incompat_rt")
                .expect("serde deserialization should succeed"),
            compatible: false,
            local_version: SchemaVersion::new(2, 0, 0),
            remote_version: SchemaVersion::new(1, 0, 0),
        };
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let back: VersionNegotiationResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, back);
    }

    #[test]
    fn computation_registration_all_profile_kinds_roundtrip() {
        for kind in [
            ProfileKind::Full,
            ProfileKind::EngineCore,
            ProfileKind::Policy,
            ProfileKind::Remote,
            ProfileKind::ComputeOnly,
        ] {
            let reg = ComputationRegistration {
                name: ComputationName::new("rt_comp")
                    .expect("serde deserialization should succeed"),
                input_schema: test_input_schema(),
                output_schema: test_output_schema(),
                version: SchemaVersion::new(1, 0, 0),
                capability_required: kind,
                idempotency_class: IdempotencyClass::NaturallyIdempotent,
            };
            let json = serde_json::to_string(&reg).expect("serde deserialization should succeed");
            let back: ComputationRegistration =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(reg, back);
        }
    }

    // -----------------------------------------------------------------------
    // 10. Additional event / counter coverage
    // -----------------------------------------------------------------------

    #[test]
    fn event_count_registration_key_present() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("cnt_comp"))
            .expect("serde deserialization should succeed");
        assert_eq!(reg.event_counts().get("registration"), Some(&1));
    }

    #[test]
    fn event_count_capability_denied_increments() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("cap_cnt"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("cap_cnt").expect("serde deserialization should succeed");
        let _ = reg.check_capability(&name, &compute_only_profile(), "t");
        assert_eq!(reg.event_counts().get("capability_denied"), Some(&1));
    }

    #[test]
    fn event_count_capability_granted_increments() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("cap_grant"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("cap_grant").expect("serde deserialization should succeed");
        reg.check_capability(&name, &remote_profile(), "t")
            .expect("serde deserialization should succeed");
        assert_eq!(reg.event_counts().get("capability_granted"), Some(&1));
    }

    #[test]
    fn hot_register_event_count_increments() {
        let mut reg = RemoteComputationRegistry::new();
        let profile = CapabilityProfile::policy();
        reg.hot_register(test_registration("hot_cnt"), &profile, "t")
            .expect("serde deserialization should succeed");
        assert_eq!(reg.event_counts().get("hot_registration"), Some(&1));
    }

    #[test]
    fn hot_register_denied_emits_event_with_denied_outcome() {
        let mut reg = RemoteComputationRegistry::new();
        let _ = reg.hot_register(
            test_registration("no_hot"),
            &compute_only_profile(),
            "trace-hot-denied",
        );
        let events = reg.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "hot_registration_denied");
        assert_eq!(events[0].outcome, "denied");
        assert_eq!(events[0].trace_id, "trace-hot-denied");
    }

    #[test]
    fn capability_denied_emits_event() {
        let mut reg = RemoteComputationRegistry::new();
        reg.register(test_registration("cap_ev"))
            .expect("serde deserialization should succeed");
        let name = ComputationName::new("cap_ev").expect("serde deserialization should succeed");
        let _ = reg.check_capability(&name, &compute_only_profile(), "trace-cap-ev");
        let events = reg.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "capability_check");
        assert_eq!(events[0].outcome, "denied");
        assert_eq!(events[0].trace_id, "trace-cap-ev");
    }

    #[test]
    fn computation_names_deterministic_order_many() {
        let mut reg = RemoteComputationRegistry::new();
        let names = ["zeta", "alpha", "mu", "delta", "beta"];
        for n in &names {
            reg.register(test_registration(n))
                .expect("serde deserialization should succeed");
        }
        let mut expected = names.to_vec();
        expected.sort_unstable();
        assert_eq!(reg.computation_names(), expected);
    }

    #[test]
    fn empty_registry_is_empty_and_len_zero() {
        let reg = RemoteComputationRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn reject_closure_message_propagates() {
        let reason = "closure with captures not allowed";
        let err = RemoteComputationRegistry::reject_closure(reason);
        if let RegistryError::ClosureRejected { reason: r } = &err {
            assert_eq!(r, reason);
        } else {
            // SAFETY: Test-only panic to validate closure rejection error handling
            // expects specific ComputationError::ClosureRejected from test scenario
            panic!("expected ClosureRejected");
        }
    }
}
