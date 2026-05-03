#![forbid(unsafe_code)]

use frankenengine_engine::lease_tracker::{LeaseStore, LeaseType};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::typed_persistence_models::open_typed_frankensqlite_session;
use sqlmodel::prelude::Value;

fn text(value: &str) -> Value {
    Value::Text(value.to_string())
}

#[test]
fn file_backed_frankensqlite_persists_typed_storage_tables_across_reopen() {
    let tmp = tempfile::tempdir().expect("temp db dir");
    let db_path = tmp.path().join("typed-storage.db");

    {
        let session =
            open_typed_frankensqlite_session(&db_path).expect("open file-backed typed database");
        let conn = session.connection();

        conn.execute_raw(
            r#"INSERT INTO replacement_lineage
               ("sequence_id", "slot_id", "operation_type", "source_state", "target_state",
                "receipt_artifact_id", "receipt_signature", "timestamp_ms", "metadata_json")
               VALUES (1, 'slot-real-db', 'delegate_to_native', 'delegate-v1', 'native-v1',
                       'receipt-real-db-1', 'sig-real-db-1', 1700000000001, '{"path":"file"}')"#,
        )
        .expect("insert replacement lineage row");

        conn.execute_raw(
            r#"INSERT INTO ifc_provenance
               ("provenance_id", "source_label", "target_label", "edge_type", "flow_operation",
                "security_level", "declassification_ref", "timestamp_ms", "trace_id", "metadata_json")
               VALUES (7, 'confidential', 'public', 'declassification', 'emit_flow',
                       'high', 'receipt-real-db-1', 1700000000002, 'trace-real-db', '{"path":"file"}')"#,
        )
        .expect("insert ifc provenance row");

        conn.execute_raw(
            r#"INSERT INTO specialization_index
               ("specialization_id", "proof_artifact_id", "specialization_type", "specialized_version",
                "status", "invalidation_timestamp_ms", "invalidation_reason", "security_epoch",
                "created_timestamp_ms", "specialized_content_hash", "metadata_json")
               VALUES (11, 'proof-real-db-1', 'optimization', 'native-v1-fast',
                       'active', NULL, NULL, 9, 1700000000003, 'sha256:realdb', '{"path":"file"}')"#,
        )
        .expect("insert specialization row");
    }

    let reopened =
        open_typed_frankensqlite_session(&db_path).expect("reopen file-backed typed database");
    assert_eq!(reopened.connection().path(), db_path.to_string_lossy());

    let lineage_rows = reopened
        .connection()
        .query_sync(
            r#"SELECT "sequence_id", "operation_type", "target_state"
               FROM replacement_lineage
               WHERE "slot_id" = ?1
               ORDER BY "sequence_id""#,
            &[text("slot-real-db")],
        )
        .expect("query replacement lineage rows");
    assert_eq!(lineage_rows.len(), 1);
    assert_eq!(
        lineage_rows[0]
            .get_named::<i64>("sequence_id")
            .expect("sequence_id"),
        1
    );
    assert_eq!(
        lineage_rows[0]
            .get_named::<String>("operation_type")
            .expect("operation_type"),
        "delegate_to_native"
    );
    assert_eq!(
        lineage_rows[0]
            .get_named::<String>("target_state")
            .expect("target_state"),
        "native-v1"
    );

    let ifc_rows = reopened
        .connection()
        .query_sync(
            r#"SELECT "provenance_id", "declassification_ref"
               FROM ifc_provenance
               WHERE "trace_id" = ?1
               ORDER BY "provenance_id""#,
            &[text("trace-real-db")],
        )
        .expect("query ifc provenance rows");
    assert_eq!(ifc_rows.len(), 1);
    assert_eq!(
        ifc_rows[0]
            .get_named::<i64>("provenance_id")
            .expect("provenance_id"),
        7
    );
    assert_eq!(
        ifc_rows[0]
            .get_named::<String>("declassification_ref")
            .expect("declassification_ref"),
        "receipt-real-db-1"
    );

    let specialization_rows = reopened
        .connection()
        .query_sync(
            r#"SELECT "specialization_id", "status", "invalidation_reason"
               FROM specialization_index
               WHERE "proof_artifact_id" = ?1"#,
            &[text("proof-real-db-1")],
        )
        .expect("query specialization rows");
    assert_eq!(specialization_rows.len(), 1);
    assert_eq!(
        specialization_rows[0]
            .get_named::<i64>("specialization_id")
            .expect("specialization_id"),
        11
    );
    assert_eq!(
        specialization_rows[0]
            .get_named::<String>("status")
            .expect("status"),
        "active"
    );
}

#[test]
fn lease_tracker_events_round_trip_through_file_backed_frankensqlite() {
    let tmp = tempfile::tempdir().expect("temp db dir");
    let db_path = tmp.path().join("lease-events.db");
    let session =
        open_typed_frankensqlite_session(&db_path).expect("open file-backed typed database");
    let conn = session.connection();
    conn.execute_raw(
        r#"CREATE TABLE IF NOT EXISTS lease_tracker_events (
               event_index BIGINT NOT NULL PRIMARY KEY,
               lease_id BIGINT NOT NULL,
               holder TEXT NOT NULL,
               epoch_id BIGINT NOT NULL,
               ttl BIGINT NOT NULL,
               status TEXT NOT NULL,
               escalation_action TEXT NOT NULL,
               trace_id TEXT NOT NULL,
               event TEXT NOT NULL,
               renewal_count BIGINT NOT NULL
           )"#,
    )
    .expect("create lease event table");

    let mut store = LeaseStore::new(SecurityEpoch::from_raw(5));
    let endpoint = store
        .grant(
            "endpoint-real-db",
            LeaseType::RemoteEndpoint,
            10,
            0,
            "trace-lease-grant",
        )
        .expect("grant endpoint lease");
    store
        .renew(&endpoint, 4, "trace-lease-renew")
        .expect("renew endpoint lease");
    let actions = store.scan_expired(15, "trace-lease-expire");
    assert_eq!(actions.len(), 1);

    for (idx, event) in store.drain_events().into_iter().enumerate() {
        let sql = format!(
            r#"INSERT INTO lease_tracker_events
               (event_index, lease_id, holder, epoch_id, ttl, status, escalation_action,
                trace_id, event, renewal_count)
               VALUES ({idx}, {}, '{}', {}, {}, '{}', '{}', '{}', '{}', {})"#,
            event.lease_id,
            event.holder,
            event.epoch_id,
            event.ttl,
            event.status,
            event.escalation_action,
            event.trace_id,
            event.event,
            event.renewal_count
        );
        conn.execute_raw(&sql).expect("persist lease tracker event");
    }

    drop(session);
    let reopened =
        open_typed_frankensqlite_session(&db_path).expect("reopen file-backed typed database");
    let rows = reopened
        .connection()
        .query_sync(
            r#"SELECT event, status, escalation_action, trace_id, renewal_count
               FROM lease_tracker_events
               ORDER BY event_index"#,
            &[],
        )
        .expect("query lease tracker events");
    let events = rows
        .iter()
        .map(|row| row.get_named::<String>("event").expect("event"))
        .collect::<Vec<_>>();
    assert_eq!(events, vec!["grant", "renew", "expiration"]);
    assert_eq!(
        rows[2]
            .get_named::<String>("status")
            .expect("expired status"),
        "expired"
    );
    assert_eq!(
        rows[2]
            .get_named::<String>("escalation_action")
            .expect("escalation action"),
        "mark_endpoint_unreachable(endpoint-real-db)"
    );
    assert_eq!(
        rows[1]
            .get_named::<i64>("renewal_count")
            .expect("renewal count"),
        1
    );
}
