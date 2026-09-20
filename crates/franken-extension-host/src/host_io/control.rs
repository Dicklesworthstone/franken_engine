//! Live supervisor control belongs to one host operation, not the provider.
//!
//! No watcher threads, mutable global binding, serialized authority, or new
//! ambient capability is introduced. Concurrent tenants may share a provider
//! without one tenant's cancellation revoking its siblings' network scope.

use super::network_deadline::NetworkDeadline;
use super::{HostIoError, HostIoOutcome, SandboxedHostIo};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const CANCELLED: &str = "HOST_IO_EXECUTION_CANCELLED";

/// Read-only live authority supplied by an embedding supervisor.
///
/// A checkpoint must be bounded, nonblocking and free of guest callbacks. It
/// grants no capability. The native network provider polls it beneath TLS and
/// during DNS/connect waits. Any refusal is a non-catchable host denial, never
/// a guest filesystem error; custom diagnostic text is not exposed on the wire.
pub trait HostIoControl: std::fmt::Debug + Send + Sync {
    fn checkpoint(&self) -> Result<(), HostIoError>;
}

/// Direct host callers with no enclosing execution still retain the provider's
/// independent kill switch, resource bounds, capability checks and deadline.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnrestrictedHostIoControl;

impl HostIoControl for UnrestrictedHostIoControl {
    fn checkpoint(&self) -> Result<(), HostIoError> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(super) struct OperationControl(Arc<OperationControlState>);

#[derive(Debug)]
struct OperationControlState {
    source: Arc<dyn HostIoControl>,
    refused: AtomicBool,
}

impl OperationControl {
    pub(super) fn new(source: Arc<dyn HostIoControl>) -> Self {
        Self(Arc::new(OperationControlState {
            source,
            refused: AtomicBool::new(false),
        }))
    }

    pub(super) fn check_host(&self) -> Result<(), HostIoError> {
        if !self.0.refused.load(Ordering::Acquire) && self.0.source.checkpoint().is_err() {
            self.0.refused.store(true, Ordering::Release);
        }
        if self.0.refused.load(Ordering::Acquire) {
            Err(HostIoError::Denied {
                reason: CANCELLED.to_string(),
            })
        } else {
            Ok(())
        }
    }

    pub(super) fn check_io(&self) -> io::Result<()> {
        self.check_host()
            .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, CANCELLED))
    }
}

impl SandboxedHostIo {
    /// Run exactly one network effect under both independent authority sources.
    /// The local latch prevents a resettable caller signal from converting an
    /// already observed denial into success. It is never stored on the provider.
    pub(super) fn run_controlled_network(
        &self,
        control: Arc<dyn HostIoControl>,
        effect: impl FnOnce(NetworkDeadline) -> HostIoOutcome,
    ) -> HostIoOutcome {
        self.network_revocation.check_host()?;
        let control = OperationControl::new(control);
        control.check_host()?;
        let outcome = self
            .network_deadline()
            .map_err(|error| HostIoError::Io {
                detail: format!("network deadline: {error}"),
            })
            .and_then(|deadline| effect(deadline.with_control(control.clone())));
        // Check every outcome, including TLS-buffered success and native faults.
        // This does not undo effects or hide Read/Write's partial-progress count.
        self.network_revocation.check_host()?;
        control.check_host()?;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::super::{HostIoCapability, HostIoProvider, HostIoRequest};
    use super::*;

    #[derive(Debug, Default)]
    struct Signal(AtomicBool);
    impl HostIoControl for Signal {
        fn checkpoint(&self) -> Result<(), HostIoError> {
            if self.0.load(Ordering::Acquire) {
                // Even a misclassified custom-control error cannot become a
                // catchable guest exception or disclose its private diagnostic.
                Err(HostIoError::Fs {
                    code: "EIO".into(),
                    detail: "private".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn observed_refusal_is_sticky_only_within_the_current_operation() {
        let signal = Arc::new(Signal::default());
        let current = OperationControl::new(signal.clone());
        let clone = current.clone();
        signal.0.store(true, Ordering::Release);
        assert!(
            matches!(current.check_host(), Err(HostIoError::Denied { reason }) if reason == CANCELLED)
        );
        signal.0.store(false, Ordering::Release);
        assert_eq!(
            clone.check_io().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(OperationControl::new(signal).check_host().is_ok());
    }

    #[derive(Debug)]
    struct Legacy;
    impl HostIoProvider for Legacy {
        fn name(&self) -> &str {
            "legacy"
        }
        fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
            panic!("controlled networking cannot fall back to an uninterruptible provider")
        }
    }

    #[test]
    fn uncontrolled_custom_network_provider_is_refused_before_dispatch() {
        let request = HostIoRequest::NetworkRecv {
            endpoint: "127.0.0.1:80".into(),
            max_len: 1,
        };
        assert!(matches!(
            Legacy.perform_controlled(
                &request,
                &[HostIoCapability::NetworkRecv],
                Arc::new(UnrestrictedHostIoControl)
            ),
            Err(HostIoError::NotImplemented { .. })
        ));
    }
}
