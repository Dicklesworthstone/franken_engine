//! Atomic storage for a node's authenticated fleet checkpoint recovery state.
//!
//! Records are untrusted persistence DTOs. The recovery controller validates
//! their semantic state and an independently provisioned monotonic anchor
//! before using them. A hash stored beside a snapshot is not rollback protection.
//! The concrete backend delegates file admission and commit durability to the
//! approved SQLModel FrankenSQLite control-plane profile.

use serde::{Deserialize, Serialize};

use crate::fleet_immune_protocol::{FLEET_V2_MAX_IDENTIFIER_BYTES, FleetAuthorityId, NodeId};
use crate::hash_tiers::ContentHash;

pub const FLEET_CHECKPOINT_DATABASE_FILENAME: &str = "fleet_checkpoint_state.db";
pub const FLEET_CHECKPOINT_MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
pub const FLEET_CHECKPOINT_MAX_ANCHOR_PERMIT_BYTES: usize = 64 * 1024;

/// An untrusted expected head, including its provisioned storage namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetCheckpointStoreHead {
    pub fleet_authority_id: FleetAuthorityId,
    pub node_id: NodeId,
    pub revision: u64,
    pub state_hash: ContentHash,
}

/// One complete snapshot and the recoverable external-anchor advance permit.
///
/// Public fields let separately implemented storage adapters read and return
/// records. Constructing or deserializing this DTO never confers authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetCheckpointStoreRecord {
    pub fleet_authority_id: FleetAuthorityId,
    pub node_id: NodeId,
    pub revision: u64,
    pub prior_state_hash: ContentHash,
    pub state_hash: ContentHash,
    pub snapshot_json: String,
    pub anchor_permit: Vec<u8>,
}

impl FleetCheckpointStoreRecord {
    pub fn head(&self) -> FleetCheckpointStoreHead {
        FleetCheckpointStoreHead {
            fleet_authority_id: self.fleet_authority_id,
            node_id: self.node_id.clone(),
            revision: self.revision,
            state_hash: self.state_hash,
        }
    }

    /// Validate the storage envelope, not the snapshot's authority or semantics.
    pub fn validate(&self) -> Result<(), FleetCheckpointStoreError> {
        validate_namespace(self.fleet_authority_id, &self.node_id)?;
        if self.revision == 0 {
            return Err(invalid("checkpoint storage revision zero is forbidden"));
        }
        if self.snapshot_json.is_empty()
            || self.snapshot_json.len() > FLEET_CHECKPOINT_MAX_SNAPSHOT_BYTES
        {
            return Err(invalid(format!(
                "checkpoint snapshot must contain 1..={FLEET_CHECKPOINT_MAX_SNAPSHOT_BYTES} bytes"
            )));
        }
        if self.anchor_permit.is_empty()
            || self.anchor_permit.len() > FLEET_CHECKPOINT_MAX_ANCHOR_PERMIT_BYTES
        {
            return Err(invalid(format!(
                "checkpoint anchor permit must contain 1..={FLEET_CHECKPOINT_MAX_ANCHOR_PERMIT_BYTES} bytes"
            )));
        }
        if ContentHash::compute(self.snapshot_json.as_bytes()) != self.state_hash {
            return Err(invalid("checkpoint snapshot hash does not match its bytes"));
        }
        let snapshot: serde_json::Value = serde_json::from_str(&self.snapshot_json)
            .map_err(|error| invalid(format!("checkpoint snapshot is not valid JSON: {error}")))?;
        if !snapshot.is_object() {
            return Err(invalid("checkpoint snapshot must be a JSON object"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetCheckpointStoreCasOutcome {
    Applied(FleetCheckpointStoreRecord),
    Conflict {
        current: Option<FleetCheckpointStoreRecord>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FleetCheckpointStoreError {
    #[error("invalid fleet checkpoint storage record: {detail}")]
    InvalidRecord { detail: String },
    #[error("fleet checkpoint storage namespace mismatch: {detail}")]
    NamespaceMismatch { detail: String },
    #[error("fleet checkpoint storage revision space is exhausted")]
    RevisionExhausted,
    #[error("fleet checkpoint database operation failed: {detail}")]
    Backend { detail: String },
}

/// Required atomic storage contract for checkpoint recovery.
///
/// Successful CAS must mean the exact candidate committed under the backend's
/// durable profile. Both the prior revision and hash must match in one
/// transaction; read-then-write emulation is forbidden. An error does not prove
/// that a commit failed: the recovery controller must reconcile an uncertain
/// outcome before releasing a vote or publishing any state.
pub trait FleetCheckpointStore {
    fn load(&mut self) -> Result<Option<FleetCheckpointStoreRecord>, FleetCheckpointStoreError>;

    fn compare_and_swap(
        &mut self,
        expected: Option<&FleetCheckpointStoreHead>,
        candidate: &FleetCheckpointStoreRecord,
    ) -> Result<FleetCheckpointStoreCasOutcome, FleetCheckpointStoreError>;

    /// Establish that these exact already-readable bytes have completed a
    /// durable commit. An ordinary read after an uncertain CAS is insufficient:
    /// a failed synchronization may leave the new row visible in memory.
    /// Implementations must force a durable write or use an equivalent
    /// backend-owned durability barrier, and reject a different current record.
    fn confirm_durable(
        &mut self,
        expected: &FleetCheckpointStoreRecord,
    ) -> Result<(), FleetCheckpointStoreError>;
}

fn invalid(detail: impl Into<String>) -> FleetCheckpointStoreError {
    FleetCheckpointStoreError::InvalidRecord {
        detail: detail.into(),
    }
}

fn validate_namespace(
    fleet_authority_id: FleetAuthorityId,
    node_id: &NodeId,
) -> Result<(), FleetCheckpointStoreError> {
    FleetAuthorityId::from_provisioned_bytes(*fleet_authority_id.as_bytes())
        .map_err(|error| invalid(error.to_string()))?;
    let node = node_id.as_str();
    if node.is_empty()
        || node.len() > FLEET_V2_MAX_IDENTIFIER_BYTES
        || node.trim() != node
        || node == "__checkpoint__"
    {
        return Err(invalid("checkpoint node identity is invalid"));
    }
    Ok(())
}

#[cfg(feature = "sibling-persistence")]
pub use backend::FrankensqliteFleetCheckpointStore;

#[cfg(feature = "sibling-persistence")]
mod backend {
    use std::fmt;
    use std::path::Path;

    use sqlmodel::{Model, Value, create_table};
    use sqlmodel_frankensqlite::{
        FrankenConnection, FrankenExclusiveTransaction, FrankenExclusiveTransactionError,
    };

    use super::*;

    const STATE_ID: i64 = 1;
    const SCHEMA_VERSION: &str = "fleet_checkpoint_state_v1";

    #[derive(Debug, Clone, Model)]
    #[sqlmodel(table = "fleet_checkpoint_state")]
    struct CheckpointRow {
        #[sqlmodel(primary_key)]
        state_id: i64,
        schema_version: String,
        fleet_authority_id: String,
        node_id: String,
        revision_decimal: String,
        prior_state_hash: String,
        state_hash: String,
        anchor_permit_hex: String,
        snapshot_json: String,
        confirmation_counter: i64,
    }

    impl CheckpointRow {
        fn from_record(record: &FleetCheckpointStoreRecord) -> Self {
            Self {
                state_id: STATE_ID,
                schema_version: SCHEMA_VERSION.to_string(),
                fleet_authority_id: hex::encode(record.fleet_authority_id.as_bytes()),
                node_id: record.node_id.as_str().to_string(),
                revision_decimal: format!("{:020}", record.revision),
                prior_state_hash: record.prior_state_hash.to_hex(),
                state_hash: record.state_hash.to_hex(),
                anchor_permit_hex: hex::encode(&record.anchor_permit),
                snapshot_json: record.snapshot_json.clone(),
                confirmation_counter: 1,
            }
        }

        fn into_record(self) -> Result<FleetCheckpointStoreRecord, FleetCheckpointStoreError> {
            if self.state_id != STATE_ID || self.schema_version != SCHEMA_VERSION {
                return Err(invalid(
                    "checkpoint singleton ID or schema version is invalid",
                ));
            }
            if self.confirmation_counter < 1 {
                return Err(invalid("checkpoint confirmation counter must be positive"));
            }
            if self.revision_decimal.len() != 20
                || !self
                    .revision_decimal
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
            {
                return Err(invalid(
                    "checkpoint revision must be a 20-digit unsigned decimal",
                ));
            }
            let revision = self
                .revision_decimal
                .parse::<u64>()
                .map_err(|_| invalid("checkpoint revision is outside u64"))?;
            let fleet_hash = parse_hash(&self.fleet_authority_id)?;
            let fleet_authority_id =
                FleetAuthorityId::from_provisioned_bytes(*fleet_hash.as_bytes())
                    .map_err(|error| invalid(error.to_string()))?;
            if self.anchor_permit_hex.is_empty()
                || self.anchor_permit_hex.len() > FLEET_CHECKPOINT_MAX_ANCHOR_PERMIT_BYTES * 2
                || !self.anchor_permit_hex.len().is_multiple_of(2)
                || !is_canonical_hex(&self.anchor_permit_hex)
            {
                return Err(invalid(
                    "checkpoint anchor permit is not bounded canonical hex",
                ));
            }
            let record = FleetCheckpointStoreRecord {
                fleet_authority_id,
                node_id: NodeId::new(self.node_id),
                revision,
                prior_state_hash: parse_hash(&self.prior_state_hash)?,
                state_hash: parse_hash(&self.state_hash)?,
                snapshot_json: self.snapshot_json,
                anchor_permit: hex::decode(&self.anchor_permit_hex)
                    .map_err(|error| invalid(format!("invalid checkpoint permit: {error}")))?,
            };
            record.validate()?;
            Ok(record)
        }

        fn values(&self) -> Vec<Value> {
            vec![
                Value::BigInt(self.state_id),
                Value::Text(self.schema_version.clone()),
                Value::Text(self.fleet_authority_id.clone()),
                Value::Text(self.node_id.clone()),
                Value::Text(self.revision_decimal.clone()),
                Value::Text(self.prior_state_hash.clone()),
                Value::Text(self.state_hash.clone()),
                Value::Text(self.anchor_permit_hex.clone()),
                Value::Text(self.snapshot_json.clone()),
                Value::BigInt(self.confirmation_counter),
            ]
        }
    }

    fn is_canonical_hex(value: &str) -> bool {
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn parse_hash(value: &str) -> Result<ContentHash, FleetCheckpointStoreError> {
        if value.len() != 64 || !is_canonical_hex(value) {
            return Err(invalid(
                "checkpoint hash must be 64 lowercase hexadecimal digits",
            ));
        }
        let bytes = hex::decode(value)
            .map_err(|error| invalid(format!("invalid checkpoint hash: {error}")))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| invalid("checkpoint hash must contain 32 bytes"))?;
        Ok(ContentHash::from_bytes(bytes))
    }

    fn database_error(error: impl fmt::Display) -> FleetCheckpointStoreError {
        FleetCheckpointStoreError::Backend {
            detail: error.to_string(),
        }
    }

    fn transaction_error(
        error: FrankenExclusiveTransactionError<FleetCheckpointStoreError>,
    ) -> FleetCheckpointStoreError {
        match error {
            FrankenExclusiveTransactionError::Operation(operation) => operation,
            error => database_error(error),
        }
    }

    // SQLModel quotes the fixed table and column names. FrankenSQLite may omit
    // IF NOT EXISTS when recording the creator's DDL. Normalize only those
    // equivalent spellings. Quoted type and constraint words must stay quoted:
    // they are not interchangeable with SQL keywords.
    fn table_tokens(statement: &str) -> String {
        let mut spaced = String::with_capacity(statement.len() + 32);
        for ch in statement.trim().trim_end_matches(';').chars() {
            if matches!(ch, '(' | ')' | ',') {
                spaced.push(' ');
                spaced.push(ch);
                spaced.push(' ');
            } else {
                spaced.push(ch);
            }
        }
        let mut tokens = spaced
            .split_whitespace()
            .map(|token| {
                let unquoted = token
                    .strip_prefix('"')
                    .and_then(|inner| inner.strip_suffix('"'));
                match unquoted {
                    Some(name)
                        if matches!(
                            name,
                            "fleet_checkpoint_state"
                                | "state_id"
                                | "schema_version"
                                | "fleet_authority_id"
                                | "node_id"
                                | "revision_decimal"
                                | "prior_state_hash"
                                | "state_hash"
                                | "anchor_permit_hex"
                                | "snapshot_json"
                                | "confirmation_counter"
                        ) =>
                    {
                        name
                    }
                    _ => token,
                }
            })
            .collect::<Vec<_>>();
        if tokens.len() > 5
            && tokens
                .iter()
                .zip(["CREATE", "TABLE", "IF", "NOT", "EXISTS"])
                .all(|(token, keyword)| token.eq_ignore_ascii_case(keyword))
        {
            tokens.drain(2..5);
        }
        tokens.join(" ")
    }

    /// Isolated, namespace-bound store with no raw connection accessor.
    pub struct FrankensqliteFleetCheckpointStore {
        connection: FrankenConnection,
        fleet_authority_id: FleetAuthorityId,
        node_id: NodeId,
    }

    impl fmt::Debug for FrankensqliteFleetCheckpointStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("FrankensqliteFleetCheckpointStore")
                .field("path", &self.connection.path())
                .field("fleet_authority_id", &self.fleet_authority_id)
                .field("node_id", &self.node_id)
                .finish_non_exhaustive()
        }
    }

    impl FrankensqliteFleetCheckpointStore {
        pub fn open_file(
            path: impl AsRef<Path>,
            fleet_authority_id: FleetAuthorityId,
            node_id: NodeId,
        ) -> Result<Self, FleetCheckpointStoreError> {
            validate_namespace(fleet_authority_id, &node_id)?;
            let path = path.as_ref();
            if path.file_name().and_then(|name| name.to_str())
                != Some(FLEET_CHECKPOINT_DATABASE_FILENAME)
            {
                return Err(invalid(format!(
                    "checkpoint database must be named {FLEET_CHECKPOINT_DATABASE_FILENAME}"
                )));
            }
            let path = path
                .to_str()
                .ok_or_else(|| invalid("checkpoint database path must be valid UTF-8"))?;
            let connection = FrankenConnection::open_strict_durable_control_plane_file(path)
                .map_err(database_error)?;
            Self::initialize(connection, fleet_authority_id, node_id)
        }

        #[cfg(test)]
        pub(crate) fn open_memory(
            fleet_authority_id: FleetAuthorityId,
            node_id: NodeId,
        ) -> Result<Self, FleetCheckpointStoreError> {
            validate_namespace(fleet_authority_id, &node_id)?;
            let connection = FrankenConnection::open_memory().map_err(database_error)?;
            Self::initialize(connection, fleet_authority_id, node_id)
        }

        fn initialize(
            connection: FrankenConnection,
            fleet_authority_id: FleetAuthorityId,
            node_id: NodeId,
        ) -> Result<Self, FleetCheckpointStoreError> {
            let store = Self {
                connection,
                fleet_authority_id,
                node_id,
            };
            store
                .connection
                .with_exclusive_transaction_result(|transaction| {
                    Self::validate_schema(transaction, true)?;
                    store.load_using(transaction).map(|_| ())
                })
                .map_err(transaction_error)?;
            Ok(store)
        }

        fn check_namespace(
            &self,
            fleet_authority_id: FleetAuthorityId,
            node_id: &NodeId,
        ) -> Result<(), FleetCheckpointStoreError> {
            if fleet_authority_id != self.fleet_authority_id || node_id != &self.node_id {
                return Err(FleetCheckpointStoreError::NamespaceMismatch {
                    detail: "record does not match the independently provisioned fleet and node"
                        .to_string(),
                });
            }
            Ok(())
        }

        fn validate_schema(
            transaction: &mut FrankenExclusiveTransaction<'_>,
            initialize: bool,
        ) -> Result<(), FleetCheckpointStoreError> {
            let counts = transaction
                .query_sync(
                    "SELECT count(*) AS object_count FROM sqlite_schema \
                     WHERE substr(name, 1, 7) <> 'sqlite_';",
                    &[],
                )
                .map_err(database_error)?;
            let count = counts
                .first()
                .ok_or_else(|| invalid("checkpoint schema inventory returned no count"))?
                .get_named::<i64>("object_count")
                .map_err(database_error)?;
            if count == 0 && initialize {
                transaction
                    .execute_raw(&create_table::<CheckpointRow>())
                    .map_err(database_error)?;
            } else if count != 1 {
                return Err(invalid(format!(
                    "isolated checkpoint database must contain exactly one user table, got {count} objects"
                )));
            }

            let probes = transaction
                .query_sync(
                    "SELECT octet_length(type) AS type_bytes, \
                            octet_length(name) AS name_bytes, \
                            octet_length(tbl_name) AS table_bytes, \
                            octet_length(sql) AS sql_bytes \
                     FROM sqlite_schema WHERE substr(name, 1, 7) <> 'sqlite_' LIMIT 2;",
                    &[],
                )
                .map_err(database_error)?;
            if probes.len() != 1 {
                return Err(invalid("checkpoint schema is not a single canonical table"));
            }
            let probe = &probes[0];
            for (field, maximum) in [
                ("type_bytes", 16_i64),
                ("name_bytes", 64),
                ("table_bytes", 64),
                ("sql_bytes", 16_384),
            ] {
                let length = probe.get_named::<i64>(field).map_err(database_error)?;
                if length <= 0 || length > maximum {
                    return Err(invalid(format!(
                        "checkpoint schema {field} is out of bounds"
                    )));
                }
            }
            let schemas = transaction
                .query_sync(
                    "SELECT type, name, tbl_name, sql AS create_sql \
                     FROM sqlite_schema WHERE substr(name, 1, 7) <> 'sqlite_' LIMIT 2;",
                    &[],
                )
                .map_err(database_error)?;
            if schemas.len() != 1 {
                return Err(invalid("checkpoint schema changed during validation"));
            }
            let schema = &schemas[0];
            if schema.get_named::<String>("type").map_err(database_error)? != "table"
                || schema.get_named::<String>("name").map_err(database_error)?
                    != "fleet_checkpoint_state"
                || schema
                    .get_named::<String>("tbl_name")
                    .map_err(database_error)?
                    != "fleet_checkpoint_state"
                || table_tokens(
                    &schema
                        .get_named::<String>("create_sql")
                        .map_err(database_error)?,
                ) != table_tokens(&create_table::<CheckpointRow>())
            {
                return Err(invalid(
                    "checkpoint database has a noncanonical table definition",
                ));
            }
            Ok(())
        }

        fn load_using(
            &self,
            transaction: &mut FrankenExclusiveTransaction<'_>,
        ) -> Result<Option<FleetCheckpointStoreRecord>, FleetCheckpointStoreError> {
            // Probe scalar lengths before materializing any untrusted snapshot
            // or permit. Both queries run inside the same exclusive transaction.
            let probes = transaction
                .query_sync(
                    "SELECT octet_length(state_id) AS id_bytes, \
                            octet_length(schema_version) AS schema_bytes, \
                            octet_length(fleet_authority_id) AS fleet_bytes, \
                            octet_length(node_id) AS node_bytes, \
                            octet_length(revision_decimal) AS revision_bytes, \
                            octet_length(prior_state_hash) AS prior_bytes, \
                            octet_length(state_hash) AS hash_bytes, \
                            octet_length(anchor_permit_hex) AS permit_bytes, \
                            octet_length(snapshot_json) AS snapshot_bytes, \
                            octet_length(confirmation_counter) AS confirmation_bytes \
                     FROM fleet_checkpoint_state LIMIT 2;",
                    &[],
                )
                .map_err(database_error)?;
            if probes.len() > 1 {
                return Err(invalid(
                    "checkpoint database contains multiple singleton rows",
                ));
            }
            let Some(probe) = probes.first() else {
                return Ok(None);
            };
            for (field, expected) in [
                ("id_bytes", 1_usize),
                ("schema_bytes", SCHEMA_VERSION.len()),
                ("fleet_bytes", 64),
                ("revision_bytes", 20),
                ("prior_bytes", 64),
                ("hash_bytes", 64),
            ] {
                let actual = probe.get_named::<i64>(field).map_err(database_error)?;
                if actual != i64::try_from(expected).expect("fixed field size fits i64") {
                    return Err(invalid(format!(
                        "checkpoint {field} has invalid fixed width"
                    )));
                }
            }
            for (field, maximum) in [
                ("node_bytes", FLEET_V2_MAX_IDENTIFIER_BYTES),
                ("permit_bytes", FLEET_CHECKPOINT_MAX_ANCHOR_PERMIT_BYTES * 2),
                ("snapshot_bytes", FLEET_CHECKPOINT_MAX_SNAPSHOT_BYTES),
                ("confirmation_bytes", 19),
            ] {
                let actual = probe.get_named::<i64>(field).map_err(database_error)?;
                if actual <= 0
                    || actual > i64::try_from(maximum).expect("bounded field size fits i64")
                {
                    return Err(invalid(format!(
                        "checkpoint {field} is outside its byte limit"
                    )));
                }
            }
            let rows = transaction
                .query_sync(
                    "SELECT state_id, schema_version, fleet_authority_id, node_id, \
                            revision_decimal, prior_state_hash, state_hash, \
                            anchor_permit_hex, snapshot_json, confirmation_counter \
                     FROM fleet_checkpoint_state LIMIT 2;",
                    &[],
                )
                .map_err(database_error)?;
            if rows.len() != 1 {
                return Err(invalid("checkpoint singleton changed during bounded read"));
            }
            let record = CheckpointRow::from_row(&rows[0])
                .map_err(database_error)?
                .into_record()?;
            self.check_namespace(record.fleet_authority_id, &record.node_id)?;
            Ok(Some(record))
        }

        fn validate_candidate(
            &self,
            expected: Option<&FleetCheckpointStoreHead>,
            candidate: &FleetCheckpointStoreRecord,
        ) -> Result<(), FleetCheckpointStoreError> {
            candidate.validate()?;
            self.check_namespace(candidate.fleet_authority_id, &candidate.node_id)?;
            if let Some(head) = expected {
                validate_namespace(head.fleet_authority_id, &head.node_id)?;
                self.check_namespace(head.fleet_authority_id, &head.node_id)?;
                if head.revision == 0 {
                    return Err(invalid("expected checkpoint revision zero is forbidden"));
                }
            }
            let next_revision = expected
                .map_or(0, |head| head.revision)
                .checked_add(1)
                .ok_or(FleetCheckpointStoreError::RevisionExhausted)?;
            if candidate.revision != next_revision
                || candidate.prior_state_hash
                    != expected.map_or_else(ContentHash::default, |head| head.state_hash)
            {
                return Err(invalid(
                    "checkpoint candidate does not extend the expected head",
                ));
            }
            Ok(())
        }

        fn apply_using(
            transaction: &mut FrankenExclusiveTransaction<'_>,
            expected: Option<&FleetCheckpointStoreHead>,
            candidate: &FleetCheckpointStoreRecord,
        ) -> Result<u64, FleetCheckpointStoreError> {
            let row = CheckpointRow::from_record(candidate);
            let mut values = row.values();
            let statement = if let Some(head) = expected {
                values.extend([
                    Value::Text(format!("{:020}", head.revision)),
                    Value::Text(head.state_hash.to_hex()),
                ]);
                "UPDATE fleet_checkpoint_state \
                 SET schema_version = ?2, fleet_authority_id = ?3, node_id = ?4, \
                     revision_decimal = ?5, prior_state_hash = ?6, state_hash = ?7, \
                     anchor_permit_hex = ?8, snapshot_json = ?9, confirmation_counter = ?10 \
                 WHERE state_id = ?1 \
                   AND fleet_authority_id COLLATE BINARY = ?3 COLLATE BINARY \
                   AND node_id COLLATE BINARY = ?4 COLLATE BINARY \
                   AND revision_decimal COLLATE BINARY = ?11 COLLATE BINARY \
                   AND state_hash COLLATE BINARY = ?12 COLLATE BINARY;"
            } else {
                "INSERT INTO fleet_checkpoint_state \
                 (state_id, schema_version, fleet_authority_id, node_id, \
                  revision_decimal, prior_state_hash, state_hash, anchor_permit_hex, snapshot_json, confirmation_counter) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
                 ON CONFLICT(state_id) DO NOTHING;"
            };
            transaction
                .execute_sync(statement, &values)
                .map_err(database_error)
        }
    }

    impl FleetCheckpointStore for FrankensqliteFleetCheckpointStore {
        fn load(
            &mut self,
        ) -> Result<Option<FleetCheckpointStoreRecord>, FleetCheckpointStoreError> {
            self.connection
                .with_exclusive_transaction_result(|transaction| {
                    Self::validate_schema(transaction, false)?;
                    self.load_using(transaction)
                })
                .map_err(transaction_error)
        }

        fn compare_and_swap(
            &mut self,
            expected: Option<&FleetCheckpointStoreHead>,
            candidate: &FleetCheckpointStoreRecord,
        ) -> Result<FleetCheckpointStoreCasOutcome, FleetCheckpointStoreError> {
            self.validate_candidate(expected, candidate)?;
            self.connection
                .with_exclusive_transaction_result(|transaction| {
                    Self::validate_schema(transaction, false)?;
                    // Reject corrupt or foreign rows before issuing any write.
                    self.load_using(transaction)?;
                    let affected = Self::apply_using(transaction, expected, candidate)?;
                    if affected > 1 {
                        return Err(invalid("checkpoint singleton CAS affected multiple rows"));
                    }
                    let current = self.load_using(transaction)?;
                    if affected == 0 {
                        return Ok(FleetCheckpointStoreCasOutcome::Conflict { current });
                    }
                    if current.as_ref() != Some(candidate) {
                        return Err(invalid("checkpoint CAS readback differed before commit"));
                    }
                    Ok(FleetCheckpointStoreCasOutcome::Applied(
                        current.expect("exact readback was checked as present"),
                    ))
                })
                .map_err(transaction_error)
        }

        fn confirm_durable(
            &mut self,
            expected: &FleetCheckpointStoreRecord,
        ) -> Result<(), FleetCheckpointStoreError> {
            expected.validate()?;
            self.check_namespace(expected.fleet_authority_id, &expected.node_id)?;
            self.connection
                .with_exclusive_transaction_result(|transaction| {
                    Self::validate_schema(transaction, false)?;
                    if self.load_using(transaction)?.as_ref() != Some(expected) {
                        return Err(invalid("checkpoint durability confirmation found a different current record"));
                    }
                    let counters = transaction.query_sync(
                        "SELECT confirmation_counter FROM fleet_checkpoint_state WHERE state_id = ?1;",
                        &[Value::BigInt(STATE_ID)],
                    ).map_err(database_error)?;
                    let counter = counters.first()
                        .ok_or_else(|| invalid("checkpoint confirmation counter disappeared"))?
                        .get_named::<i64>("confirmation_counter")
                        .map_err(database_error)?;
                    let next = counter.checked_add(1)
                        .ok_or_else(|| invalid("checkpoint durability confirmation counter is exhausted"))?;
                    // A changed, independent housekeeping column forces a
                    // write even when the logical recovery snapshot is equal.
                    // The sibling's strict commit must synchronize this write
                    // before the controller can advance its external anchor.
                    let affected = transaction.execute_sync(
                        "UPDATE fleet_checkpoint_state SET confirmation_counter = ?1 \
                         WHERE state_id = ?2 AND confirmation_counter = ?3 \
                           AND revision_decimal COLLATE BINARY = ?4 COLLATE BINARY \
                           AND state_hash COLLATE BINARY = ?5 COLLATE BINARY;",
                        &[
                            Value::BigInt(next),
                            Value::BigInt(STATE_ID),
                            Value::BigInt(counter),
                            Value::Text(format!("{:020}", expected.revision)),
                            Value::Text(expected.state_hash.to_hex()),
                        ],
                    ).map_err(database_error)?;
                    if affected != 1 || self.load_using(transaction)?.as_ref() != Some(expected) {
                        return Err(invalid("checkpoint durability confirmation did not preserve the exact current record"));
                    }
                    let counters = transaction.query_sync(
                        "SELECT confirmation_counter FROM fleet_checkpoint_state WHERE state_id = ?1;",
                        &[Value::BigInt(STATE_ID)],
                    ).map_err(database_error)?;
                    if counters.len() != 1
                        || counters[0].get_named::<i64>("confirmation_counter").map_err(database_error)? != next
                    {
                        return Err(invalid("checkpoint durability confirmation did not perform its required write"));
                    }
                    Ok(())
                })
                .map_err(transaction_error)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        use super::*;

        fn fleet() -> FleetAuthorityId {
            FleetAuthorityId::from_provisioned_bytes([0x71; 32]).unwrap()
        }

        fn node() -> NodeId {
            NodeId::new("checkpoint-store-node")
        }

        fn record(
            revision: u64,
            prior_state_hash: ContentHash,
            label: &str,
        ) -> FleetCheckpointStoreRecord {
            let snapshot_json = serde_json::json!({ "label": label }).to_string();
            FleetCheckpointStoreRecord {
                fleet_authority_id: fleet(),
                node_id: node(),
                revision,
                prior_state_hash,
                state_hash: ContentHash::compute(snapshot_json.as_bytes()),
                snapshot_json,
                anchor_permit: vec![revision as u8, 0x72],
            }
        }

        fn memory() -> FrankensqliteFleetCheckpointStore {
            FrankensqliteFleetCheckpointStore::open_memory(fleet(), node()).unwrap()
        }

        fn retained_path(label: &str) -> PathBuf {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "franken-fleet-checkpoint-{label}-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir_all(&root).unwrap();
            root.join(FLEET_CHECKPOINT_DATABASE_FILENAME)
        }

        #[test]
        fn actual_database_cas_requires_revision_and_hash_and_preserves_conflicts() {
            let mut store = memory();
            assert_eq!(store.load().unwrap(), None);
            let first = record(1, ContentHash::default(), "vote");
            assert_eq!(
                store.compare_and_swap(None, &first).unwrap(),
                FleetCheckpointStoreCasOutcome::Applied(first.clone())
            );
            let alternate = record(1, ContentHash::default(), "different bootstrap");
            assert_eq!(
                store.compare_and_swap(None, &alternate).unwrap(),
                FleetCheckpointStoreCasOutcome::Conflict {
                    current: Some(first.clone())
                }
            );

            let mut wrong_hash = first.head();
            wrong_hash.state_hash = ContentHash::compute(b"not the stored state");
            let fork = record(2, wrong_hash.state_hash, "fork");
            assert!(matches!(
                store.compare_and_swap(Some(&wrong_hash), &fork).unwrap(),
                FleetCheckpointStoreCasOutcome::Conflict { current: Some(current) }
                    if current == first
            ));
            let next = record(2, first.state_hash, "finalized");
            assert_eq!(
                store.compare_and_swap(Some(&first.head()), &next).unwrap(),
                FleetCheckpointStoreCasOutcome::Applied(next.clone())
            );
            assert!(matches!(
                store.compare_and_swap(Some(&first.head()), &fork),
                Err(FleetCheckpointStoreError::InvalidRecord { .. })
            ));
            let stale = record(2, first.state_hash, "stale writer");
            assert_eq!(
                store.compare_and_swap(Some(&first.head()), &stale).unwrap(),
                FleetCheckpointStoreCasOutcome::Conflict {
                    current: Some(next.clone())
                }
            );
            assert_eq!(store.load().unwrap(), Some(next));
        }

        #[test]
        fn actual_database_reopens_exact_committed_state_and_rejects_foreign_namespace() {
            let path = retained_path("reopen");
            let first = record(1, ContentHash::default(), "persist before vote release");
            {
                let mut store =
                    FrankensqliteFleetCheckpointStore::open_file(&path, fleet(), node()).unwrap();
                store.compare_and_swap(None, &first).unwrap();
            }
            let mut reopened =
                FrankensqliteFleetCheckpointStore::open_file(&path, fleet(), node()).unwrap();
            assert_eq!(reopened.load().unwrap(), Some(first.clone()));
            let next = record(2, first.state_hash, "finalized after restart");
            reopened
                .compare_and_swap(Some(&first.head()), &next)
                .unwrap();
            drop(reopened);
            assert!(
                FrankensqliteFleetCheckpointStore::open_file(
                    &path,
                    fleet(),
                    NodeId::new("another-node"),
                )
                .is_err()
            );
            let mut valid =
                FrankensqliteFleetCheckpointStore::open_file(&path, fleet(), node()).unwrap();
            assert_eq!(valid.load().unwrap(), Some(next));
        }

        #[test]
        fn invalid_candidates_fail_before_mutating_the_actual_database() {
            let mut store = memory();
            let first = record(1, ContentHash::default(), "prior");
            store.compare_and_swap(None, &first).unwrap();
            let valid = record(2, first.state_hash, "next");
            let mut candidates = Vec::new();
            let mut candidate = valid.clone();
            candidate.snapshot_json.push(' ');
            candidates.push(candidate);
            let mut candidate = valid.clone();
            candidate.revision = 3;
            candidates.push(candidate);
            let mut candidate = valid.clone();
            candidate.prior_state_hash = ContentHash::default();
            candidates.push(candidate);
            let mut candidate = valid.clone();
            candidate.node_id = NodeId::new("other-node");
            candidates.push(candidate);
            let mut candidate = valid;
            candidate.fleet_authority_id =
                FleetAuthorityId::from_provisioned_bytes([0x73; 32]).unwrap();
            candidates.push(candidate);
            for candidate in candidates {
                assert!(
                    store
                        .compare_and_swap(Some(&first.head()), &candidate)
                        .is_err()
                );
                assert_eq!(store.load().unwrap(), Some(first.clone()));
            }
            let exhausted = FleetCheckpointStoreHead {
                revision: u64::MAX,
                ..first.head()
            };
            assert_eq!(
                store.compare_and_swap(
                    Some(&exhausted),
                    &record(u64::MAX, first.state_hash, "no wrap")
                ),
                Err(FleetCheckpointStoreError::RevisionExhausted)
            );
        }

        #[test]
        fn operation_failure_rolls_back_actual_transaction() {
            let mut store = memory();
            let first = record(1, ContentHash::default(), "prior");
            store.compare_and_swap(None, &first).unwrap();
            let next = record(2, first.state_hash, "uncommitted");
            let result = store.connection.with_exclusive_transaction_result(
                |transaction| -> Result<(), FleetCheckpointStoreError> {
                    assert_eq!(
                        FrankensqliteFleetCheckpointStore::apply_using(
                            transaction,
                            Some(&first.head()),
                            &next
                        )?,
                        1
                    );
                    Err(invalid("injected rejection after SQL write before commit"))
                },
            );
            assert!(result.is_err());
            assert_eq!(store.load().unwrap(), Some(first));
        }

        #[test]
        fn lost_commit_response_requires_a_fresh_durability_confirmation() {
            struct LoseResponse {
                inner: FrankensqliteFleetCheckpointStore,
            }
            impl FleetCheckpointStore for LoseResponse {
                fn load(
                    &mut self,
                ) -> Result<Option<FleetCheckpointStoreRecord>, FleetCheckpointStoreError>
                {
                    self.inner.load()
                }
                fn compare_and_swap(
                    &mut self,
                    expected: Option<&FleetCheckpointStoreHead>,
                    candidate: &FleetCheckpointStoreRecord,
                ) -> Result<FleetCheckpointStoreCasOutcome, FleetCheckpointStoreError>
                {
                    self.inner.compare_and_swap(expected, candidate)?;
                    Err(database_error(
                        "injected response loss after actual database commit",
                    ))
                }
                fn confirm_durable(
                    &mut self,
                    expected: &FleetCheckpointStoreRecord,
                ) -> Result<(), FleetCheckpointStoreError> {
                    self.inner.confirm_durable(expected)
                }
            }
            let mut store = LoseResponse { inner: memory() };
            let first = record(1, ContentHash::default(), "committed response lost");
            assert!(store.compare_and_swap(None, &first).is_err());
            assert_eq!(store.load().unwrap(), Some(first.clone()));
            store.confirm_durable(&first).unwrap();
            let counters = store
                .inner
                .connection
                .query_sync(
                    "SELECT confirmation_counter FROM fleet_checkpoint_state;",
                    &[],
                )
                .unwrap();
            assert_eq!(
                counters[0]
                    .get_named::<i64>("confirmation_counter")
                    .unwrap(),
                2
            );
            assert_eq!(
                store.inner.compare_and_swap(None, &first).unwrap(),
                FleetCheckpointStoreCasOutcome::Conflict {
                    current: Some(first)
                }
            );
        }

        #[test]
        fn durability_confirmation_requires_exact_record_and_checked_counter() {
            let mut store = memory();
            let first = record(1, ContentHash::default(), "stored");
            store.compare_and_swap(None, &first).unwrap();
            let other = record(1, ContentHash::default(), "not the stored candidate");
            assert!(store.confirm_durable(&other).is_err());
            assert_eq!(store.load().unwrap(), Some(first.clone()));
            store.confirm_durable(&first).unwrap();
            store.confirm_durable(&first).unwrap();
            let counters = store
                .connection
                .query_sync(
                    "SELECT confirmation_counter FROM fleet_checkpoint_state;",
                    &[],
                )
                .unwrap();
            assert_eq!(
                counters[0]
                    .get_named::<i64>("confirmation_counter")
                    .unwrap(),
                3
            );
            store
                .connection
                .execute_raw(
                    "UPDATE fleet_checkpoint_state SET confirmation_counter = 9223372036854775807;",
                )
                .unwrap();
            assert!(store.confirm_durable(&first).is_err());
            assert_eq!(store.load().unwrap(), Some(first));
        }

        #[test]
        fn schema_and_bounded_reads_reject_untrusted_database_changes() {
            let mut store = memory();
            let first = record(1, ContentHash::default(), "original");
            store.compare_and_swap(None, &first).unwrap();
            store
                .connection
                .execute_raw(
                    "CREATE TRIGGER unexpected_checkpoint_trigger \
                     AFTER UPDATE ON fleet_checkpoint_state BEGIN SELECT 1; END;",
                )
                .unwrap();
            let next = record(2, first.state_hash, "must not trigger");
            assert!(store.compare_and_swap(Some(&first.head()), &next).is_err());
            assert!(store.load().is_err());

            let mut malformed = memory();
            malformed.compare_and_swap(None, &first).unwrap();
            malformed
                .connection
                .execute_raw("UPDATE fleet_checkpoint_state SET revision_decimal = '1';")
                .unwrap();
            assert!(malformed.load().is_err());

            let mut duplicate = memory();
            duplicate.compare_and_swap(None, &first).unwrap();
            let mut row = CheckpointRow::from_record(&first);
            row.state_id = 2;
            duplicate
                .connection
                .execute_sync(
                    "INSERT INTO fleet_checkpoint_state \
                     (state_id, schema_version, fleet_authority_id, node_id, \
                      revision_decimal, prior_state_hash, state_hash, anchor_permit_hex, snapshot_json, confirmation_counter) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);",
                    &row.values(),
                )
                .unwrap();
            assert!(duplicate.load().is_err());
        }

        #[test]
        fn noncanonical_schema_and_wrong_basename_are_rejected() {
            let connection = FrankenConnection::open_memory().unwrap();
            let malformed = create_table::<CheckpointRow>().replace(
                "\"revision_decimal\" TEXT",
                "\"revision_decimal\" TEXT COLLATE NOCASE",
            );
            assert!(malformed.contains("COLLATE NOCASE"));
            connection.execute_raw(&malformed).unwrap();
            assert!(
                FrankensqliteFleetCheckpointStore::initialize(connection, fleet(), node()).is_err()
            );
            assert!(matches!(
                FrankensqliteFleetCheckpointStore::open_file(
                    "/tmp/not-a-checkpoint-store.db",
                    fleet(),
                    node(),
                ),
                Err(FleetCheckpointStoreError::InvalidRecord { .. })
            ));
        }

        #[test]
        fn schema_normalization_preserves_quoted_types_and_constraints() {
            let generated = create_table::<CheckpointRow>();
            let canonical = table_tokens(&generated);
            assert_eq!(
                canonical,
                table_tokens(&generated.replace('"', "")),
                "known table and column identifier quotes remain equivalent",
            );
            for keyword in ["BIGINT", "TEXT", "PRIMARY", "KEY", "NOT", "NULL"] {
                assert!(generated.contains(keyword));
                let quoted = generated.replace(keyword, &format!("\"{keyword}\""));
                assert_ne!(
                    table_tokens(&quoted),
                    canonical,
                    "quoted SQL keyword {keyword} must not normalize into a keyword",
                );
            }
            let connection = FrankenConnection::open_memory().unwrap();
            // A parser may reject quoted type names itself. If it accepts
            // them, our strict schema validator must still refuse this table.
            let quoted_type = generated.replace(" TEXT", " \"TEXT\"");
            let rejected = match connection.execute_raw(&quoted_type) {
                Ok(()) => {
                    FrankensqliteFleetCheckpointStore::initialize(connection, fleet(), node())
                        .is_err()
                }
                Err(_) => true,
            };
            assert!(
                rejected,
                "quoted type words must never pass schema admission"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_record(snapshot_json: String) -> FleetCheckpointStoreRecord {
        FleetCheckpointStoreRecord {
            fleet_authority_id: FleetAuthorityId::from_provisioned_bytes([0x71; 32]).unwrap(),
            node_id: NodeId::new("checkpoint-node"),
            revision: 1,
            prior_state_hash: ContentHash::default(),
            state_hash: ContentHash::compute(snapshot_json.as_bytes()),
            snapshot_json,
            anchor_permit: vec![1],
        }
    }

    #[test]
    fn envelope_checks_payload_hash_shape_and_exact_byte_limits() {
        let mut record = valid_record(r#"{"state":"accepted"}"#.to_string());
        record.validate().unwrap();
        assert_eq!(record.head().revision, 1);
        record.snapshot_json.push(' ');
        assert!(record.validate().is_err());
        for json in ["null", "[]", "1", "{", "\"text\""] {
            assert!(valid_record(json.to_string()).validate().is_err());
        }
        let mut record = valid_record("{}".to_string());
        record.anchor_permit = vec![0x41; FLEET_CHECKPOINT_MAX_ANCHOR_PERMIT_BYTES];
        record.validate().unwrap();
        record.anchor_permit.push(0x41);
        assert!(record.validate().is_err());

        let exact = format!(
            "{{\"padding\":\"{}\"}}",
            "x".repeat(FLEET_CHECKPOINT_MAX_SNAPSHOT_BYTES - 14)
        );
        assert_eq!(exact.len(), FLEET_CHECKPOINT_MAX_SNAPSHOT_BYTES);
        let mut record = valid_record(exact);
        record.validate().unwrap();
        record.snapshot_json.push(' ');
        record.state_hash = ContentHash::compute(record.snapshot_json.as_bytes());
        assert!(record.validate().is_err());
    }

    #[test]
    fn malformed_identity_revision_and_unknown_envelope_fields_are_rejected() {
        let record = valid_record("{}".to_string());
        for id in ["", " ", " node", "node ", "__checkpoint__"] {
            let mut candidate = record.clone();
            candidate.node_id = NodeId::new(id);
            assert!(candidate.validate().is_err());
        }
        let mut zero_revision = record.clone();
        zero_revision.revision = 0;
        assert!(zero_revision.validate().is_err());
        let mut missing_permit = record.clone();
        missing_permit.anchor_permit.clear();
        assert!(missing_permit.validate().is_err());
        let mut json = serde_json::to_value(&record).unwrap();
        json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<FleetCheckpointStoreRecord>(json).is_err());
    }
}
