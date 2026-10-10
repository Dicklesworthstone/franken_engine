//! Bounded environment snapshots are explicit host authority; these tests never
//! consult or modify the test process environment.

#![forbid(unsafe_code)]

use std::sync::Arc;

use frankenengine_extension_host::host_io::{
    DenyAllHostIo, ENVIRONMENT_NAME_MAX_BYTES, ENVIRONMENT_SNAPSHOT_MAX_BYTES,
    ENVIRONMENT_SNAPSHOT_MAX_ENTRIES, ENVIRONMENT_VALUE_MAX_BYTES, EnvironmentSnapshotHostIo,
    HostIoCapability, HostIoControl, HostIoError, HostIoProvider, HostIoRequest, HostIoResponse,
    UnrestrictedHostIoControl,
};

#[test]
fn environment_snapshot_is_explicit_capability_checked_and_redacted_bd_omckp() {
    let provider = EnvironmentSnapshotHostIo::new(
        [
            ("NODE_ENV".to_string(), "production".to_string()),
            ("EMPTY".to_string(), String::new()),
            (
                "PRIVATE_KEY".to_string(),
                "private-value-never-in-debug".to_string(),
            ),
        ]
        .into_iter()
        .collect(),
    )
    .expect("bounded snapshot");
    let request = HostIoRequest::EnvRead {
        name: "NODE_ENV".to_string(),
    };
    assert_eq!(
        provider.perform(&request, &[]),
        Err(HostIoError::CapabilityMissing {
            capability: HostIoCapability::EnvRead,
        })
    );
    for (name, expected) in [
        ("NODE_ENV", Some("production")),
        ("EMPTY", Some("")),
        ("NOT_IN_SNAPSHOT", None),
    ] {
        assert_eq!(
            provider.perform(
                &HostIoRequest::EnvRead {
                    name: name.to_string()
                },
                &[HostIoCapability::EnvRead],
            ),
            Ok(HostIoResponse::EnvRead {
                value: expected.map(str::to_string),
            })
        );
    }
    let debug = format!("{provider:?}");
    assert!(!debug.contains("PRIVATE_KEY"));
    assert!(!debug.contains("private-value-never-in-debug"));
    assert!(matches!(
        provider.perform(
            &HostIoRequest::FsRead {
                path: "outside.txt".to_string()
            },
            &[HostIoCapability::EnvRead, HostIoCapability::FsRead],
        ),
        Err(HostIoError::Denied { .. })
    ));
}

#[test]
fn environment_snapshot_bounds_names_values_and_aggregate_bd_omckp() {
    for (name, value) in [
        ("BAD=NAME".to_string(), "x".to_string()),
        ("BAD\0NAME".to_string(), "x".to_string()),
        ("x".repeat(ENVIRONMENT_NAME_MAX_BYTES + 1), "x".to_string()),
        (
            "NAME".to_string(),
            "x".repeat(ENVIRONMENT_VALUE_MAX_BYTES + 1),
        ),
        ("NAME".to_string(), "bad\0value".to_string()),
    ] {
        assert!(matches!(
            EnvironmentSnapshotHostIo::new([(name, value)].into_iter().collect()),
            Err(HostIoError::SandboxViolation { .. })
        ));
    }
    let too_many = (0..=ENVIRONMENT_SNAPSHOT_MAX_ENTRIES)
        .map(|index| (format!("NAME_{index}"), String::new()))
        .collect();
    assert!(EnvironmentSnapshotHostIo::new(too_many).is_err());
    let too_large = (0..=ENVIRONMENT_SNAPSHOT_MAX_BYTES / ENVIRONMENT_VALUE_MAX_BYTES)
        .map(|index| {
            (
                format!("NAME_{index}"),
                "x".repeat(ENVIRONMENT_VALUE_MAX_BYTES),
            )
        })
        .collect();
    assert!(EnvironmentSnapshotHostIo::new(too_large).is_err());

    let provider = EnvironmentSnapshotHostIo::new(Default::default()).unwrap();
    assert!(matches!(
        provider.perform(
            &HostIoRequest::EnvRead {
                name: "x".repeat(ENVIRONMENT_NAME_MAX_BYTES + 1),
            },
            &[HostIoCapability::EnvRead],
        ),
        Err(HostIoError::SandboxViolation { .. })
    ));
}

#[test]
fn environment_snapshot_keeps_each_operations_supervisor_control_bd_omckp() {
    #[derive(Debug)]
    struct Cancelled;

    impl HostIoControl for Cancelled {
        fn checkpoint(&self) -> Result<(), HostIoError> {
            Err(HostIoError::Denied {
                reason: "private-supervisor-diagnostic".to_string(),
            })
        }
    }

    let provider = EnvironmentSnapshotHostIo::with_provider(
        [("NODE_ENV".to_string(), "production".to_string())]
            .into_iter()
            .collect(),
        Arc::new(DenyAllHostIo),
    )
    .unwrap();
    for request in [
        HostIoRequest::EnvRead {
            name: "NODE_ENV".to_string(),
        },
        HostIoRequest::FsRead {
            path: "outside.txt".to_string(),
        },
    ] {
        assert_eq!(
            provider.perform_controlled(
                &request,
                &[HostIoCapability::EnvRead, HostIoCapability::FsRead],
                Arc::new(Cancelled),
            ),
            Err(HostIoError::Denied {
                reason: "HOST_IO_EXECUTION_CANCELLED".to_string(),
            }),
        );
    }

    // One operation's cancellation cannot revoke another caller's snapshot.
    assert_eq!(
        provider.perform_controlled(
            &HostIoRequest::EnvRead {
                name: "NODE_ENV".to_string(),
            },
            &[HostIoCapability::EnvRead],
            Arc::new(UnrestrictedHostIoControl),
        ),
        Ok(HostIoResponse::EnvRead {
            value: Some("production".to_string()),
        }),
    );
}
