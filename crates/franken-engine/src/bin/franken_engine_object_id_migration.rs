#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use frankenengine_engine::engine_object_id::{
    derive_versioned_id, derive_versioned_schema_id, verify_versioned_id, EngineObjectId,
    ObjectDomain, ObjectIdDerivationVersion, VersionedEngineObjectId, VersionedIdError,
    VersionedSchemaId, OBJECT_ID_LEN,
};
use serde::{Deserialize, Serialize};

const RESPONSE_SCHEMA: &str = "franken-engine.engine-object-id-migration-response.v1";
const LEGACY_VERSION: &str = "legacy_v1";
const V2_VERSION: &str = "sha256_v2";
const USAGE: &str =
    "usage: franken_engine_object_id_migration --input PATH|- [--output PATH]";

type DerivationVersion = ObjectIdDerivationVersion;

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
    #[cfg(test)]
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
}

impl From<DomainName> for ObjectDomain {
    fn from(domain: DomainName) -> Self {
        match domain {
            DomainName::PolicyObject => Self::PolicyObject,
            DomainName::EvidenceRecord => Self::EvidenceRecord,
            DomainName::Revocation => Self::Revocation,
            DomainName::SignedManifest => Self::SignedManifest,
            DomainName::Attestation => Self::Attestation,
            DomainName::CapabilityToken => Self::CapabilityToken,
            DomainName::CheckpointArtifact => Self::CheckpointArtifact,
            DomainName::RecoveryArtifact => Self::RecoveryArtifact,
            DomainName::KeyBundle => Self::KeyBundle,
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
    LengthOverflow { field: String, length: usize },
    Derivation(String),
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
            Self::Derivation(_) => "derivation_error",
            Self::Io(_) => "io_error",
        }
    }
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArguments(detail)
            | Self::InvalidJson(detail)
            | Self::Derivation(detail)
            | Self::Io(detail) => formatter.write_str(detail),
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedArgs {
    Run {
        input: String,
        output: Option<PathBuf>,
    },
    Help,
}

fn parse_args(arguments: impl IntoIterator<Item = String>) -> Result<ParsedArgs, MigrationError> {
    let mut input = None;
    let mut output = None;
    let mut arguments = arguments.into_iter();
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
            "-h" | "--help" => return Ok(ParsedArgs::Help),
            _ => {
                return Err(MigrationError::InvalidArguments(format!(
                    "unknown argument: {argument}"
                )));
            }
        }
    }
    Ok(ParsedArgs::Run {
        input: input.ok_or_else(|| {
            MigrationError::InvalidArguments("--input is required".to_string())
        })?,
        output,
    })
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

fn decode_id_hex(field: &'static str, value: &str) -> Result<[u8; OBJECT_ID_LEN], MigrationError> {
    let bytes = decode_hex(field, value)?;
    let length = bytes.len();
    bytes.try_into().map_err(|_| MigrationError::InvalidHex {
        field,
        detail: format!("expected {OBJECT_ID_LEN} bytes, got {length}"),
    })
}

fn map_versioned_error(error: VersionedIdError) -> MigrationError {
    match error {
        VersionedIdError::EmptyCanonicalBytes => MigrationError::EmptyCanonicalBytes,
        VersionedIdError::LengthOverflow { field, length } => {
            MigrationError::LengthOverflow { field, length }
        }
        other => MigrationError::Derivation(other.to_string()),
    }
}

const fn version_name(version: DerivationVersion) -> &'static str {
    match version {
        DerivationVersion::LegacyV1 => LEGACY_VERSION,
        DerivationVersion::Sha256V2 => V2_VERSION,
    }
}

fn derive_parts(
    version: DerivationVersion,
    domain: DomainName,
    zone: &str,
    schema_definition: &[u8],
    canonical_bytes: &[u8],
) -> Result<(VersionedSchemaId, VersionedEngineObjectId), MigrationError> {
    let schema = derive_versioned_schema_id(version, schema_definition)
        .map_err(map_versioned_error)?;
    let object = derive_versioned_id(domain.into(), zone, &schema, canonical_bytes)
        .map_err(map_versioned_error)?;
    Ok((schema, object))
}

fn record_from_parts(
    version: DerivationVersion,
    schema: &VersionedSchemaId,
    object: &VersionedEngineObjectId,
) -> DerivationRecord {
    let (algorithm, preimage_contract) = match version {
        DerivationVersion::LegacyV1 => (
            "de_novo_siphash_like_non_cryptographic",
            "legacy: len(domain_tag)||domain_tag||len(zone)||zone||schema_id||canonical_bytes",
        ),
        DerivationVersion::Sha256V2 => (
            "sha256",
            "v2: len(version_domain)||version_domain||len(domain_tag)||domain_tag||len(zone)||zone||schema_id||len(canonical_bytes)||canonical_bytes",
        ),
    };
    DerivationRecord {
        version: version_name(version),
        algorithm,
        preimage_contract,
        schema_id_hex: schema.schema_id.to_string(),
        object_id_hex: object.to_hex(),
    }
}

fn derive_record(
    version: DerivationVersion,
    domain: DomainName,
    zone: &str,
    schema_definition: &[u8],
    canonical_bytes: &[u8],
) -> Result<DerivationRecord, MigrationError> {
    let (schema, object) = derive_parts(
        version,
        domain,
        zone,
        schema_definition,
        canonical_bytes,
    )?;
    Ok(record_from_parts(version, &schema, &object))
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
            let expected_bytes =
                decode_id_hex("expected_object_id_hex", &expected_object_id_hex)?;
            let (schema, computed_object) = derive_parts(
                version,
                domain,
                &zone,
                &schema_definition,
                &canonical_bytes,
            )?;
            let expected = VersionedEngineObjectId::new(version, EngineObjectId(expected_bytes));
            let verified = match verify_versioned_id(
                &expected,
                domain.into(),
                &zone,
                &schema,
                &canonical_bytes,
            ) {
                Ok(()) => true,
                Err(VersionedIdError::IdMismatch { .. }) => false,
                Err(error) => return Err(map_versioned_error(error)),
            };
            let computed = record_from_parts(version, &schema, &computed_object);
            let response = VerifyResponse {
                schema_version: RESPONSE_SCHEMA,
                status: if verified { "verified" } else { "mismatch" },
                operation: "verify",
                version: version_name(version),
                expected_object_id_hex: hex::encode(expected_bytes),
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
    let ParsedArgs::Run { input, output } = parse_args(env::args().skip(1))? else {
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    };
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
    fn cross_crate_vectors_are_stable() {
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
        let value: serde_json::Value =
            serde_json::from_slice(&response).expect("JSON response");
        assert_eq!(value["status"], "mismatch");
        assert_eq!(value["version"], LEGACY_VERSION);
    }

    #[test]
    fn v2_length_prefixes_canonical_bytes() {
        let schema = derive_versioned_schema_id(DerivationVersion::Sha256V2, b"schema")
            .expect("schema");
        let left = derive_versioned_id(ObjectDomain::PolicyObject, "ab", &schema, b"c")
            .expect("left id");
        let right = derive_versioned_id(ObjectDomain::PolicyObject, "a", &schema, b"bc")
            .expect("right id");
        assert_ne!(left, right);
    }

    #[test]
    fn all_domains_map_to_unique_tags() {
        let tags = DomainName::ALL
            .into_iter()
            .map(ObjectDomain::from)
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
        let value: serde_json::Value =
            serde_json::from_slice(&response).expect("JSON response");
        assert_eq!(value["status"], "ok");
        assert_eq!(value["legacy_v1"]["version"], LEGACY_VERSION);
        assert_eq!(value["sha256_v2"]["version"], V2_VERSION);
        assert_eq!(value["ids_differ"], true);
    }

    #[test]
    fn parser_help_is_a_distinct_success_path() {
        assert_eq!(
            parse_args(["--help".to_string()]).expect("help parse"),
            ParsedArgs::Help
        );
    }
}
