#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const RESPONSE_SCHEMA: &str = "franken-engine.engine-object-id-migration-response.v1";
const LEGACY_VERSION: &str = "legacy_v1";
const V2_VERSION: &str = "sha256_v2";
const SCHEMA_V2_DOMAIN: &[u8] = b"FrankenEngine.SchemaId.sha256.v2";
const OBJECT_V2_DOMAIN: &[u8] = b"FrankenEngine.EngineObjectId.sha256.v2";
const ID_LEN: usize = 32;
const USAGE: &str =
    "usage: franken_engine_object_id_migration --input PATH|- [--output PATH]";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DerivationVersion {
    LegacyV1,
    Sha256V2,
}

impl DerivationVersion {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LegacyV1 => LEGACY_VERSION,
            Self::Sha256V2 => V2_VERSION,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DomainName {
    PolicyObject,
    EvidenceRecord,
    Revocation,
    SignedManifest,
    Attestation,
    CapabilityToken,
    CheckpointArtifact,
    RecoveryArtifact,
    KeyBundle,
}

impl DomainName {
    const ALL: [Self; 9] = [
        Self::PolicyObject,
        Self::EvidenceRecord,
        Self::Revocation,
        Self::SignedManifest,
        Self::Attestation,
        Self::CapabilityToken,
        Self::CheckpointArtifact,
        Self::RecoveryArtifact,
        Self::KeyBundle,
    ];

    const fn tag(self) -> &'static [u8] {
        match self {
            Self::PolicyObject => b"FrankenEngine.PolicyObject.v1",
            Self::EvidenceRecord => b"FrankenEngine.EvidenceRecord.v1",
            Self::Revocation => b"FrankenEngine.Revocation.v1",
            Self::SignedManifest => b"FrankenEngine.SignedManifest.v1",
            Self::Attestation => b"FrankenEngine.Attestation.v1",
            Self::CapabilityToken => b"FrankenEngine.CapabilityToken.v1",
            Self::CheckpointArtifact => b"FrankenEngine.CheckpointArtifact.v1",
            Self::RecoveryArtifact => b"FrankenEngine.RecoveryArtifact.v1",
            Self::KeyBundle => b"FrankenEngine.KeyBundle.v1",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Request {
    Derive {
        domain: DomainName,
        zone: String,
        schema_definition_hex: String,
        canonical_bytes_hex: String,
    },
    Verify {
        version: DerivationVersion,
        domain: DomainName,
        zone: String,
        schema_definition_hex: String,
        canonical_bytes_hex: String,
        expected_object_id_hex: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DerivationRecord {
    version: &'static str,
    algorithm: &'static str,
    preimage_contract: &'static str,
    schema_id_hex: String,
    object_id_hex: String,
}

#[derive(Debug, Serialize)]
struct DeriveResponse {
    schema_version: &'static str,
    status: &'static str,
    operation: &'static str,
    legacy_v1: DerivationRecord,
    sha256_v2: DerivationRecord,
    ids_differ: bool,
    migration_rule: &'static str,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    schema_version: &'static str,
    status: &'static str,
    operation: &'static str,
    version: &'static str,
    expected_object_id_hex: String,
    computed: DerivationRecord,
    verified: bool,
    migration_rule: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    schema_version: &'static str,
    status: &'static str,
    error_code: &'static str,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MigrationError {
    InvalidArguments(String),
    InvalidJson(String),
    InvalidHex { field: &'static str, detail: String },
    EmptyCanonicalBytes,
    LengthOverflow { field: &'static str, length: usize },
    Io(String),
}

impl MigrationError {
    const fn code(&self) -> &'static str {
        match self {
            Self::InvalidArguments(_) => "invalid_arguments",
            Self::InvalidJson(_) => "invalid_json",
            Self::InvalidHex { .. } => "invalid_hex",
            Self::EmptyCanonicalBytes => "empty_canonical_bytes",
            Self::LengthOverflow { .. } => "length_overflow",
            Self::Io(_) => "io_error",
        }
    }
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArguments(detail) | Self::InvalidJson(detail) | Self::Io(detail) => {
                formatter.write_str(detail)
            }
            Self::InvalidHex { field, detail } => {
                write!(formatter, "invalid {field}: {detail}")
            }
            Self::EmptyCanonicalBytes => formatter.write_str("canonical bytes must not be empty"),
            Self::LengthOverflow { field, length } => {
                write!(formatter, "{field} length {length} exceeds u32 preimage encoding")
            }
        }
    }
}

fn parse_args() -> Result<(String, Option<PathBuf>), MigrationError> {
    let mut input = None;
    let mut output = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--input" => {
                input = Some(arguments.next().ok_or_else(|| {
                    MigrationError::InvalidArguments("--input requires a value".to_string())
                })?);
            }
            "--output" => {
                output = Some(PathBuf::from(arguments.next().ok_or_else(|| {
                    MigrationError::InvalidArguments("--output requires a value".to_string())
                })?));
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Err(MigrationError::InvalidArguments("help_requested".to_string()));
            }
            _ => {
                return Err(MigrationError::InvalidArguments(format!(
                    "unknown argument: {argument}"
                )));
            }
        }
    }
    Ok((
        input.ok_or_else(|| {
            MigrationError::InvalidArguments("--input is required".to_string())
        })?,
        output,
    ))
}

fn read_input(input: &str) -> Result<Vec<u8>, MigrationError> {
    if input == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| MigrationError::Io(format!("failed to read stdin: {error}")))?;
        Ok(bytes)
    } else {
        fs::read(input)
            .map_err(|error| MigrationError::Io(format!("failed to read {input}: {error}")))
    }
}

fn write_output(output: Option<&Path>, bytes: &[u8]) -> Result<(), MigrationError> {
    if let Some(path) = output {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| {
            MigrationError::Io(format!(
                "failed to create output directory {}: {error}",
                parent.display()
            ))
        })?;
        let temporary = parent.join(format!(
            ".{}.tmp-{}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("object-id-migration"),
            std::process::id()
        ));
        fs::write(&temporary, bytes).map_err(|error| {
            MigrationError::Io(format!("failed to write {}: {error}", temporary.display()))
        })?;
        if path.exists() {
            fs::remove_file(path).map_err(|error| {
                MigrationError::Io(format!("failed to replace {}: {error}", path.display()))
            })?;
        }
        fs::rename(&temporary, path).map_err(|error| {
            let _ = fs::remove_file(&temporary);
            MigrationError::Io(format!(
                "failed to publish {} as {}: {error}",
                temporary.display(),
                path.display()
            ))
        })?;
    } else {
        print!("{}", String::from_utf8_lossy(bytes));
    }
    Ok(())
}

fn decode_hex(field: &'static str, value: &str) -> Result<Vec<u8>, MigrationError> {
    hex::decode(value).map_err(|error| MigrationError::InvalidHex {
        field,
        detail: error.to_string(),
    })
}

fn decode_id_hex(field: &'static str, value: &str) -> Result<[u8; ID_LEN], MigrationError> {
    let bytes = decode_hex(field, value)?;
    let length = bytes.len();
    bytes.try_into().map_err(|_| MigrationError::InvalidHex {
        field,
        detail: format!("expected {ID_LEN} bytes, got {length}"),
    })
}

fn append_length_prefixed(
    output: &mut Vec<u8>,
    field: &'static str,
    bytes: &[u8],
) -> Result<(), MigrationError> {
    let length = u32::try_from(bytes.len()).map_err(|_| MigrationError::LengthOverflow {
        field,
        length: bytes.len(),
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; ID_LEN] {
    Sha256::digest(bytes).into()
}

fn schema_id_v2(definition: &[u8]) -> Result<[u8; ID_LEN], MigrationError> {
    let mut preimage = Vec::with_capacity(8 + SCHEMA_V2_DOMAIN.len() + definition.len());
    append_length_prefixed(&mut preimage, "schema_v2_domain", SCHEMA_V2_DOMAIN)?;
    append_length_prefixed(&mut preimage, "schema_definition", definition)?;
    Ok(sha256(&preimage))
}

fn object_id_v2(
    domain: DomainName,
    zone: &str,
    schema_id: &[u8; ID_LEN],
    canonical_bytes: &[u8],
) -> Result<[u8; ID_LEN], MigrationError> {
    if canonical_bytes.is_empty() {
        return Err(MigrationError::EmptyCanonicalBytes);
    }
    let mut preimage = Vec::with_capacity(
        16 + OBJECT_V2_DOMAIN.len() + domain.tag().len() + zone.len() + ID_LEN + canonical_bytes.len(),
    );
    append_length_prefixed(&mut preimage, "object_v2_domain", OBJECT_V2_DOMAIN)?;
    append_length_prefixed(&mut preimage, "object_domain", domain.tag())?;
    append_length_prefixed(&mut preimage, "zone", zone.as_bytes())?;
    preimage.extend_from_slice(schema_id);
    append_length_prefixed(&mut preimage, "canonical_bytes", canonical_bytes)?;
    Ok(sha256(&preimage))
}

fn legacy_schema_id(definition: &[u8]) -> [u8; ID_LEN] {
    legacy_deterministic_hash(definition)
}

fn legacy_object_id(
    domain: DomainName,
    zone: &str,
    schema_id: &[u8; ID_LEN],
    canonical_bytes: &[u8],
) -> Result<[u8; ID_LEN], MigrationError> {
    if canonical_bytes.is_empty() {
        return Err(MigrationError::EmptyCanonicalBytes);
    }
    let mut preimage = Vec::with_capacity(8 + domain.tag().len() + zone.len() + ID_LEN + canonical_bytes.len());
    append_length_prefixed(&mut preimage, "object_domain", domain.tag())?;
    append_length_prefixed(&mut preimage, "zone", zone.as_bytes())?;
    preimage.extend_from_slice(schema_id);
    preimage.extend_from_slice(canonical_bytes);
    Ok(legacy_deterministic_hash(&preimage))
}

fn legacy_deterministic_hash(input: &[u8]) -> [u8; ID_LEN] {
    let mut state = [
        0x736f_6d65_7073_6575_u64,
        0x646f_7261_6e64_6f6d_u64,
        0x6c79_6765_6e65_7261_u64,
        0x7465_6462_7974_6573_u64,
    ];
    state[0] ^= input.len() as u64;
    for chunk in input.chunks(8) {
        let mut block = [0_u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        let word = u64::from_le_bytes(block);
        state[3] ^= word;
        sip_round(&mut state);
        sip_round(&mut state);
        state[0] ^= word;
    }
    state[2] ^= 0xff;
    for _ in 0..4 {
        sip_round(&mut state);
    }
    let hash1 = state[0] ^ state[1] ^ state[2] ^ state[3];
    state[1] ^= 0xee;
    for _ in 0..4 {
        sip_round(&mut state);
    }
    let hash2 = state[0] ^ state[1] ^ state[2] ^ state[3];
    state[0] ^= 0xdd;
    for _ in 0..4 {
        sip_round(&mut state);
    }
    let hash3 = state[0] ^ state[1] ^ state[2] ^ state[3];
    state[3] ^= 0xcc;
    for _ in 0..4 {
        sip_round(&mut state);
    }
    let hash4 = state[0] ^ state[1] ^ state[2] ^ state[3];
    let mut output = [0_u8; ID_LEN];
    output[0..8].copy_from_slice(&hash1.to_le_bytes());
    output[8..16].copy_from_slice(&hash2.to_le_bytes());
    output[16..24].copy_from_slice(&hash3.to_le_bytes());
    output[24..32].copy_from_slice(&hash4.to_le_bytes());
    output
}

fn sip_round(state: &mut [u64; 4]) {
    state[0] = state[0].wrapping_add(state[1]);
    state[1] = state[1].rotate_left(13);
    state[1] ^= state[0];
    state[0] = state[0].rotate_left(32);
    state[2] = state[2].wrapping_add(state[3]);
    state[3] = state[3].rotate_left(16);
    state[3] ^= state[2];
    state[0] = state[0].wrapping_add(state[3]);
    state[3] = state[3].rotate_left(21);
    state[3] ^= state[0];
    state[2] = state[2].wrapping_add(state[1]);
    state[1] = state[1].rotate_left(17);
    state[1] ^= state[2];
    state[2] = state[2].rotate_left(32);
}

fn derive_record(
    version: DerivationVersion,
    domain: DomainName,
    zone: &str,
    schema_definition: &[u8],
    canonical_bytes: &[u8],
) -> Result<DerivationRecord, MigrationError> {
    let (schema_id, object_id, algorithm, preimage_contract) = match version {
        DerivationVersion::LegacyV1 => {
            let schema_id = legacy_schema_id(schema_definition);
            let object_id = legacy_object_id(domain, zone, &schema_id, canonical_bytes)?;
            (
                schema_id,
                object_id,
                "de_novo_siphash_like_non_cryptographic",
                "legacy: len(domain_tag)||domain_tag||len(zone)||zone||schema_id||canonical_bytes",
            )
        }
        DerivationVersion::Sha256V2 => {
            let schema_id = schema_id_v2(schema_definition)?;
            let object_id = object_id_v2(domain, zone, &schema_id, canonical_bytes)?;
            (
                schema_id,
                object_id,
                "sha256",
                "v2: len(version_domain)||version_domain||len(domain_tag)||domain_tag||len(zone)||zone||schema_id||len(canonical_bytes)||canonical_bytes",
            )
        }
    };
    Ok(DerivationRecord {
        version: version.as_str(),
        algorithm,
        preimage_contract,
        schema_id_hex: hex::encode(schema_id),
        object_id_hex: hex::encode(object_id),
    })
}

fn process(request: Request) -> Result<(Vec<u8>, bool), MigrationError> {
    match request {
        Request::Derive {
            domain,
            zone,
            schema_definition_hex,
            canonical_bytes_hex,
        } => {
            let schema_definition = decode_hex("schema_definition_hex", &schema_definition_hex)?;
            let canonical_bytes = decode_hex("canonical_bytes_hex", &canonical_bytes_hex)?;
            let legacy = derive_record(
                DerivationVersion::LegacyV1,
                domain,
                &zone,
                &schema_definition,
                &canonical_bytes,
            )?;
            let v2 = derive_record(
                DerivationVersion::Sha256V2,
                domain,
                &zone,
                &schema_definition,
                &canonical_bytes,
            )?;
            let response = DeriveResponse {
                schema_version: RESPONSE_SCHEMA,
                status: "ok",
                operation: "derive",
                ids_differ: legacy.object_id_hex != v2.object_id_hex,
                legacy_v1: legacy,
                sha256_v2: v2,
                migration_rule: "new artifacts use sha256_v2; legacy_v1 verification must be selected explicitly from an artifact's persisted derivation version",
            };
            let mut bytes = serde_json::to_vec_pretty(&response)
                .map_err(|error| MigrationError::InvalidJson(error.to_string()))?;
            bytes.push(b'\n');
            Ok((bytes, true))
        }
        Request::Verify {
            version,
            domain,
            zone,
            schema_definition_hex,
            canonical_bytes_hex,
            expected_object_id_hex,
        } => {
            let schema_definition = decode_hex("schema_definition_hex", &schema_definition_hex)?;
            let canonical_bytes = decode_hex("canonical_bytes_hex", &canonical_bytes_hex)?;
            let expected = decode_id_hex("expected_object_id_hex", &expected_object_id_hex)?;
            let computed = derive_record(version, domain, &zone, &schema_definition, &canonical_bytes)?;
            let computed_bytes = decode_id_hex("computed_object_id_hex", &computed.object_id_hex)?;
            let verified: bool = expected.ct_eq(&computed_bytes).into();
            let response = VerifyResponse {
                schema_version: RESPONSE_SCHEMA,
                status: if verified { "verified" } else { "mismatch" },
                operation: "verify",
                version: version.as_str(),
                expected_object_id_hex: hex::encode(expected),
                computed,
                verified,
                migration_rule: "verification never falls back to another derivation version",
            };
            let mut bytes = serde_json::to_vec_pretty(&response)
                .map_err(|error| MigrationError::InvalidJson(error.to_string()))?;
            bytes.push(b'\n');
            Ok((bytes, verified))
        }
    }
}

fn run() -> Result<ExitCode, MigrationError> {
    let (input, output) = parse_args()?;
    if input == "help_requested" {
        return Ok(ExitCode::SUCCESS);
    }
    let bytes = read_input(&input)?;
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|error| MigrationError::InvalidJson(error.to_string()))?;
    let (response, success) = process(request)?;
    write_output(output.as_deref(), &response)?;
    Ok(if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(MigrationError::InvalidArguments(detail)) if detail == "help_requested" => {
            ExitCode::SUCCESS
        }
        Err(error) => {
            let response = ErrorResponse {
                schema_version: RESPONSE_SCHEMA,
                status: "error",
                error_code: error.code(),
                detail: error.to_string(),
            };
            let mut bytes = serde_json::to_vec_pretty(&response).unwrap_or_else(|_| {
                b"{\"schema_version\":\"franken-engine.engine-object-id-migration-response.v1\",\"status\":\"error\",\"error_code\":\"serialization_failure\",\"detail\":\"failed to serialize error\"}".to_vec()
            });
            bytes.push(b'\n');
            eprint!("{}", String::from_utf8_lossy(&bytes));
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFINITION: &[u8] = br#"{"type":"Policy"}"#;
    const CANONICAL: &[u8] = br#"{"allow":true}"#;

    #[test]
    fn cross_language_vectors_are_stable() {
        let legacy = derive_record(
            DerivationVersion::LegacyV1,
            DomainName::PolicyObject,
            "zone-a",
            DEFINITION,
            CANONICAL,
        )
        .expect("legacy vector");
        assert_eq!(
            legacy.schema_id_hex,
            "9704c8101b9f138f0d7ec78989eb1e1e0760f0756aeade43dee3975b8e73cce5"
        );
        assert_eq!(
            legacy.object_id_hex,
            "242c2cd17a8607149ec8dc88944aeb507a042208a522d21a9b58c112729e1ecd"
        );

        let v2 = derive_record(
            DerivationVersion::Sha256V2,
            DomainName::PolicyObject,
            "zone-a",
            DEFINITION,
            CANONICAL,
        )
        .expect("v2 vector");
        assert_eq!(
            v2.schema_id_hex,
            "95dd1a7336da89398ea01216baed44a5170dd518af89379402227a3b12d1922a"
        );
        assert_eq!(
            v2.object_id_hex,
            "cdc31ac7ad5b4d68d7cbdae29179b3230608bd13afdfc641f2e1a4273913b545"
        );
    }

    #[test]
    fn verification_never_falls_back_between_versions() {
        let v2 = derive_record(
            DerivationVersion::Sha256V2,
            DomainName::PolicyObject,
            "zone-a",
            DEFINITION,
            CANONICAL,
        )
        .expect("v2 vector");
        let request = Request::Verify {
            version: DerivationVersion::LegacyV1,
            domain: DomainName::PolicyObject,
            zone: "zone-a".to_string(),
            schema_definition_hex: hex::encode(DEFINITION),
            canonical_bytes_hex: hex::encode(CANONICAL),
            expected_object_id_hex: v2.object_id_hex,
        };
        let (response, verified) = process(request).expect("verification response");
        assert!(!verified);
        let value: serde_json::Value = serde_json::from_slice(&response).expect("JSON response");
        assert_eq!(value["status"], "mismatch");
        assert_eq!(value["version"], LEGACY_VERSION);
    }

    #[test]
    fn v2_length_prefixes_canonical_bytes() {
        let left_schema = schema_id_v2(b"schema").expect("left schema");
        let right_schema = schema_id_v2(b"schema").expect("right schema");
        let left = object_id_v2(DomainName::PolicyObject, "ab", &left_schema, b"c")
            .expect("left id");
        let right = object_id_v2(DomainName::PolicyObject, "a", &right_schema, b"bc")
            .expect("right id");
        assert_ne!(left, right);
    }

    #[test]
    fn all_domains_have_unique_tags() {
        let tags = DomainName::ALL
            .into_iter()
            .map(|domain| domain.tag())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(tags.len(), DomainName::ALL.len());
    }

    #[test]
    fn empty_canonical_bytes_fail_closed_for_both_versions() {
        for version in [DerivationVersion::LegacyV1, DerivationVersion::Sha256V2] {
            assert_eq!(
                derive_record(version, DomainName::EvidenceRecord, "zone", b"schema", b""),
                Err(MigrationError::EmptyCanonicalBytes)
            );
        }
    }

    #[test]
    fn derivation_output_includes_both_explicit_versions() {
        let request = Request::Derive {
            domain: DomainName::PolicyObject,
            zone: "zone-a".to_string(),
            schema_definition_hex: hex::encode(DEFINITION),
            canonical_bytes_hex: hex::encode(CANONICAL),
        };
        let (response, success) = process(request).expect("derive response");
        assert!(success);
        let value: serde_json::Value = serde_json::from_slice(&response).expect("JSON response");
        assert_eq!(value["status"], "ok");
        assert_eq!(value["legacy_v1"]["version"], LEGACY_VERSION);
        assert_eq!(value["sha256_v2"]["version"], V2_VERSION);
        assert_eq!(value["ids_differ"], true);
    }
}
