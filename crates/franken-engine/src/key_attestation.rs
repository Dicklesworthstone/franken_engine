//! Key-attestation compatibility with hardened persistence boundaries.
//!
//! Historical attestation objects and wire formats remain available from
//! `compat`. The exported store/nonce registry are hardened replacements that
//! preserve the public API while validating content-derived IDs, owner/principal
//! binding, nonce monotonicity, and persisted index consistency.

mod compat;
mod strict_store;

pub use compat::{
    attestation_schema, attestation_schema_id, AttestationError, AttestationEvent,
    AttestationEventType, AttestationNonce, CreateAttestationInput, DevicePosture,
    DevicePostureVerifier, KeyAttestation,
};
pub use strict_store::{AttestationStore, NonceRegistry};
