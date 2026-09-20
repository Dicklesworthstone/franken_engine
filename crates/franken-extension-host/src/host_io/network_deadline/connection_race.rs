//! Staggered dual-stack connection establishment with owned sockets.
//!
//! This is the connection-racing part of Happy Eyeballs, not a second resolver
//! or an egress policy. Only the supplied addresses can be tried. At most two
//! sockets are pending; expiration, failure and selecting a winner drop the
//! losing sockets synchronously. No worker, TLS handshake or guest payload can
//! outlive this race. DNS and the eventual request retain the original deadline.

use super::{NetworkDeadline, NetworkRevocation, REVOCATION_POLL_INTERVAL};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::{AddressFamily, SocketFlags, SocketType, connect, socket_with};
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
const FAILURE_DELAY: Duration = Duration::from_millis(10);
const MAX_PENDING: usize = 2;
const MAX_ADDRESSES: usize = 64;

pub(super) fn connect_addresses(
    addresses: &[SocketAddr],
    deadline: NetworkDeadline,
) -> io::Result<TcpStream> {
    deadline.remaining()?;
    let mut connector = SocketConnector {
        revocation: deadline.revocation.clone(),
    };
    let stream = race(addresses, deadline.end, &mut connector)?;
    // The surrounding DeadlineTcpStream applies read/write timeouts. Do not
    // return a nonblocking socket to rustls or to its synchronous I/O callers.
    stream.set_nonblocking(false)?;
    deadline.remaining()?;
    Ok(stream)
}

fn expired() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "network effect deadline exceeded")
}

fn remaining(end: Instant, now: Instant) -> io::Result<Duration> {
    end.checked_duration_since(now)
        .filter(|duration| !duration.is_zero())
        .ok_or_else(expired)
}

/// Retain the resolver's first-family preference and relative order within
/// each family, but do not put every IPv6 address ahead of every IPv4 address.
fn interleaved(addresses: &[SocketAddr]) -> io::Result<Vec<SocketAddr>> {
    if addresses.len() > MAX_ADDRESSES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many connection addresses",
        ));
    }
    let Some(first) = addresses.first() else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no connection addresses",
        ));
    };
    let first_v6 = first.is_ipv6();
    let mut unique = Vec::with_capacity(addresses.len());
    for address in addresses {
        if !unique.contains(address) {
            unique.push(*address);
        }
    }
    let mut preferred = unique
        .iter()
        .filter(|address| address.is_ipv6() == first_v6);
    let mut alternate = unique
        .iter()
        .filter(|address| address.is_ipv6() != first_v6);
    let mut result = Vec::with_capacity(unique.len());
    loop {
        let a = preferred.next();
        let b = alternate.next();
        if a.is_none() && b.is_none() {
            return Ok(result);
        }
        result.extend(a.into_iter().chain(b).copied());
    }
}

struct Pending<S> {
    stream: S,
    end: Instant,
}

// The production driver owns real nonblocking sockets. The same scheduling
// loop can be tested with a virtual clock without timing-sensitive blackholes.
trait Connector {
    type Stream;

    fn check_active(&self) -> io::Result<()>;
    fn now(&self) -> Instant;
    fn start(&mut self, address: SocketAddr) -> io::Result<Self::Stream>;
    fn wait(
        &mut self,
        pending: &mut Vec<Pending<Self::Stream>>,
        timeout: Duration,
        last_error: &mut io::Error,
    ) -> io::Result<Option<Self::Stream>>;
}

fn race<C: Connector>(
    addresses: &[SocketAddr],
    end: Instant,
    connector: &mut C,
) -> io::Result<C::Stream> {
    connector.check_active()?;
    remaining(end, connector.now())?;
    let addresses = interleaved(addresses)?;
    let mut pending = Vec::<Pending<C::Stream>>::with_capacity(MAX_PENDING);
    let mut next = 0;
    let mut last_start = connector.now();
    let mut next_start = last_start;
    let mut last_error = io::Error::new(io::ErrorKind::NotFound, "no connection addresses");
    loop {
        connector.check_active()?;
        let now = connector.now();
        remaining(end, now)?;
        let before = pending.len();
        pending.retain(|attempt| attempt.end > now);
        if pending.len() < before {
            last_error = expired();
            next_start = next_start.min(last_start.checked_add(FAILURE_DELAY).unwrap_or(end));
        }
        if next < addresses.len() && pending.len() < MAX_PENDING && now >= next_start {
            // The caller may have been descheduled since the preceding poll.
            // Prefer an already-ready winner before opening another socket.
            if !pending.is_empty() {
                let winner = match connector.wait(&mut pending, Duration::ZERO, &mut last_error) {
                    Ok(winner) => winner,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                };
                connector.check_active()?;
                remaining(end, connector.now())?;
                if let Some(stream) = winner {
                    return Ok(stream);
                }
            }
            let now = connector.now();
            connector.check_active()?;
            let budget = remaining(end, now)?;
            // Reserve a share for every address still unattempted. Two stalled
            // sockets cannot monopolize all the time needed by later addresses.
            let allowance = budget / (addresses.len() - next) as u32;
            if allowance.is_zero() {
                return Err(expired());
            }
            last_start = now;
            next_start = now + ATTEMPT_DELAY.min(budget);
            match connector.start(addresses[next]) {
                Ok(stream) => pending.push(Pending {
                    stream,
                    end: now + allowance,
                }),
                Err(error) => {
                    last_error = error;
                    next_start = now + FAILURE_DELAY.min(budget);
                }
            }
            next += 1;
            continue;
        }
        if pending.is_empty() && next == addresses.len() {
            return Err(last_error);
        }
        let mut wake = pending
            .iter()
            .fold(end, |wake, attempt| wake.min(attempt.end));
        if next < addresses.len() && pending.len() < MAX_PENDING {
            wake = wake.min(next_start);
        }
        let timeout = wake.saturating_duration_since(now);
        let before = pending.len();
        let winner = match connector.wait(&mut pending, timeout, &mut last_error) {
            Ok(winner) => winner,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        // A ready socket observed after the common deadline is not a success.
        // Both that socket and all pending losers drop before returning error.
        connector.check_active()?;
        remaining(end, connector.now())?;
        if let Some(stream) = winner {
            return Ok(stream);
        }
        if pending.len() < before {
            next_start = next_start.min(last_start.checked_add(FAILURE_DELAY).unwrap_or(end));
        }
    }
}

struct SocketConnector {
    revocation: Option<NetworkRevocation>,
}

impl Connector for SocketConnector {
    type Stream = TcpStream;

    fn check_active(&self) -> io::Result<()> {
        self.revocation
            .as_ref()
            .map_or(Ok(()), NetworkRevocation::check)
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn start(&mut self, address: SocketAddr) -> io::Result<TcpStream> {
        self.check_active()?;
        let family = if address.is_ipv6() {
            AddressFamily::INET6
        } else {
            AddressFamily::INET
        };
        let socket = socket_with(
            family,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        match connect(&socket, &address) {
            Ok(()) => {}
            Err(rustix::io::Errno::INPROGRESS | rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(TcpStream::from(socket))
    }

    fn wait(
        &mut self,
        pending: &mut Vec<Pending<TcpStream>>,
        timeout: Duration,
        last_error: &mut io::Error,
    ) -> io::Result<Option<TcpStream>> {
        // One second is representable by poll on every supported Unix target.
        // Waking early never extends either the attempt or operation deadline.
        self.check_active()?;
        let limit = if self.revocation.is_some() {
            REVOCATION_POLL_INTERVAL
        } else {
            Duration::from_secs(1)
        };
        let timeout = timeout.min(limit);
        let timeout = Timespec {
            tv_sec: timeout.as_secs() as _,
            tv_nsec: timeout.subsec_nanos() as _,
        };
        let mut descriptors: Vec<_> = pending
            .iter()
            .map(|attempt| PollFd::new(&attempt.stream, PollFlags::OUT))
            .collect();
        poll(&mut descriptors, Some(&timeout))?;
        self.check_active()?;
        let ready: Vec<_> = descriptors
            .iter()
            .map(|descriptor| !descriptor.revents().is_empty())
            .collect();
        drop(descriptors);
        let mut removed = 0;
        for (original, ready) in ready.into_iter().enumerate() {
            if !ready {
                continue;
            }
            let index = original - removed;
            let result = pending[index].stream.take_error().and_then(|error| {
                if let Some(error) = error {
                    Err(error)
                } else {
                    // Writability can also signal a failed connect. Verify the
                    // actual peer after SO_ERROR, without reading guest bytes.
                    pending[index].stream.peer_addr().map(|_| ())
                }
            });
            match result {
                Ok(()) => return Ok(Some(pending.remove(index).stream)),
                Err(error) => {
                    *last_error = error;
                    pending.remove(index);
                    removed += 1;
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::rc::Rc;

    #[derive(Clone, Copy)]
    enum Behavior {
        Stall,
        Ready(Duration),
        Refuse,
        FailAfter(Duration),
    }

    #[derive(Debug)]
    struct ModelStream {
        address: SocketAddr,
        ready: Option<Instant>,
        failed: bool,
        dropped: Rc<RefCell<Vec<SocketAddr>>>,
    }

    impl Drop for ModelStream {
        fn drop(&mut self) {
            self.dropped.borrow_mut().push(self.address);
        }
    }

    struct Model {
        now: Instant,
        behavior: BTreeMap<SocketAddr, Behavior>,
        starts: Vec<(SocketAddr, Instant)>,
        dropped: Rc<RefCell<Vec<SocketAddr>>>,
        peak: usize,
        interrupts: usize,
        late_success: Duration,
        revoke_at: Option<Instant>,
    }

    impl Model {
        fn new(behavior: &[(SocketAddr, Behavior)]) -> Self {
            Self {
                now: Instant::now(),
                behavior: behavior.iter().copied().collect(),
                starts: Vec::new(),
                dropped: Rc::default(),
                peak: 0,
                interrupts: 0,
                late_success: Duration::ZERO,
                revoke_at: None,
            }
        }
    }

    impl Connector for Model {
        type Stream = ModelStream;

        fn check_active(&self) -> io::Result<()> {
            if self.revoke_at.is_some_and(|at| self.now >= at) {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                Ok(())
            }
        }

        fn now(&self) -> Instant {
            self.now
        }

        fn start(&mut self, address: SocketAddr) -> io::Result<ModelStream> {
            self.starts.push((address, self.now));
            let (ready, failed) = match self.behavior[&address] {
                Behavior::Stall => (None, false),
                Behavior::Ready(delay) => (Some(self.now + delay), false),
                Behavior::FailAfter(delay) => (Some(self.now + delay), true),
                Behavior::Refuse => return Err(io::ErrorKind::ConnectionRefused.into()),
            };
            Ok(ModelStream {
                address,
                ready,
                failed,
                dropped: Rc::clone(&self.dropped),
            })
        }

        fn wait(
            &mut self,
            pending: &mut Vec<Pending<ModelStream>>,
            timeout: Duration,
            last_error: &mut io::Error,
        ) -> io::Result<Option<ModelStream>> {
            self.peak = self.peak.max(pending.len());
            if self.interrupts > 0 {
                self.interrupts -= 1;
                self.now += Duration::from_millis(1);
                return Err(io::ErrorKind::Interrupted.into());
            }
            let wake = pending
                .iter()
                .filter_map(|attempt| attempt.stream.ready)
                .fold(self.now + timeout, Instant::min);
            self.now = self.now.max(wake);
            let ready = pending
                .iter()
                .position(|attempt| attempt.stream.ready.is_some_and(|ready| ready <= self.now));
            if let Some(index) = ready {
                if pending[index].stream.failed {
                    pending.remove(index);
                    *last_error = io::ErrorKind::ConnectionRefused.into();
                    return Ok(None);
                }
                self.now += self.late_success;
                return Ok(Some(pending.remove(index).stream));
            }
            Ok(None)
        }
    }

    fn v4(id: u16) -> SocketAddr {
        format!("127.0.0.1:{}", 8000 + id).parse().unwrap()
    }

    fn v6(id: u16) -> SocketAddr {
        format!("[::1]:{}", 8000 + id).parse().unwrap()
    }

    #[test]
    fn family_order_preserves_preferences_without_duplicate_attempts() {
        assert_eq!(
            interleaved(&[v6(1), v6(1), v6(2), v4(3), v4(4), v6(1)]).unwrap(),
            vec![v6(1), v4(3), v6(2), v4(4)]
        );
        assert_eq!(
            interleaved(&[v4(1), v4(2), v6(3)]).unwrap(),
            vec![v4(1), v6(3), v4(2)]
        );
    }

    #[test]
    fn revocation_before_race_opens_no_socket() {
        let mut model = Model::new(&[(v4(1), Behavior::Stall)]);
        model.revoke_at = Some(model.now);
        let end = model.now + Duration::from_secs(10);
        assert_eq!(
            race(&[v4(1)], end, &mut model).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(model.starts.is_empty());
    }

    #[test]
    fn revocation_drops_all_pending_sockets_before_any_later_candidate() {
        let mut model = Model::new(&[
            (v6(1), Behavior::Stall),
            (v4(2), Behavior::Stall),
            (v6(3), Behavior::Ready(Duration::ZERO)),
        ]);
        model.revoke_at = Some(model.now + ATTEMPT_DELAY + Duration::from_millis(1));
        let end = model.now + Duration::from_secs(10);
        assert_eq!(
            race(&[v6(1), v4(2), v6(3)], end, &mut model)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(model.starts.len(), 2);
        let dropped = model.dropped.borrow();
        assert_eq!(dropped.len(), 2);
        assert!(dropped.contains(&v6(1)) && dropped.contains(&v4(2)));
    }

    #[test]
    fn revocation_observed_with_a_winner_drops_that_winner_too() {
        let mut model = Model::new(&[(v4(1), Behavior::Ready(Duration::from_millis(100)))]);
        model.revoke_at = Some(model.now + Duration::from_millis(50));
        let end = model.now + Duration::from_secs(10);
        assert_eq!(
            race(&[v4(1)], end, &mut model).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(*model.dropped.borrow(), vec![v4(1)]);
    }

    #[test]
    fn stalled_first_family_does_not_block_a_ready_alternate() {
        let mut model = Model::new(&[
            (v6(1), Behavior::Stall),
            (v4(2), Behavior::Ready(Duration::ZERO)),
        ]);
        let start = model.now;
        let stream = race(&[v6(1), v4(2)], start + Duration::from_secs(10), &mut model).unwrap();
        assert_eq!(stream.address, v4(2));
        assert_eq!(
            model.starts,
            vec![(v6(1), start), (v4(2), start + ATTEMPT_DELAY)]
        );
        assert_eq!(&*model.dropped.borrow(), &[v6(1)]);
        assert_eq!(model.peak, 2);
        drop(stream);
        assert_eq!(model.dropped.borrow().len(), 2);
    }

    #[test]
    fn early_success_does_not_open_an_unused_address() {
        let mut model = Model::new(&[(v6(1), Behavior::Ready(Duration::from_millis(2)))]);
        let end = model.now + Duration::from_secs(10);
        let stream = race(&[v6(1), v4(2)], end, &mut model).unwrap();
        assert_eq!(stream.address, v6(1));
        assert_eq!(model.starts.len(), 1);
    }

    #[test]
    fn immediate_failure_advances_after_the_minimum_launch_spacing() {
        let mut model = Model::new(&[
            (v6(1), Behavior::Refuse),
            (v4(2), Behavior::Ready(Duration::ZERO)),
        ]);
        let start = model.now;
        let stream = race(&[v6(1), v4(2)], start + Duration::from_secs(10), &mut model).unwrap();
        assert_eq!(stream.address, v4(2));
        assert_eq!(model.starts[1].1 - start, FAILURE_DELAY);
    }

    #[test]
    fn asynchronous_connection_failure_shortens_the_stagger_without_bursting() {
        let mut model = Model::new(&[
            (v6(1), Behavior::FailAfter(Duration::from_millis(3))),
            (v4(2), Behavior::Ready(Duration::ZERO)),
        ]);
        let start = model.now;
        let stream = race(&[v6(1), v4(2)], start + Duration::from_secs(10), &mut model).unwrap();
        assert_eq!(stream.address, v4(2));
        assert_eq!(model.starts[1].1 - start, FAILURE_DELAY);
        assert_eq!(&*model.dropped.borrow(), &[v6(1)]);
    }

    #[test]
    fn a_short_budget_cannot_bypass_the_minimum_launch_spacing() {
        let mut model = Model::new(&[(v6(1), Behavior::Stall)]);
        let end = model.now + Duration::from_millis(5);
        assert_eq!(
            race(&[v6(1), v4(2)], end, &mut model).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(model.starts.len(), 1);
        assert_eq!(&*model.dropped.borrow(), &[v6(1)]);
    }

    #[test]
    fn two_stalled_sockets_expire_so_later_addresses_are_attempted() {
        let addresses = [v6(1), v4(2), v6(3), v4(4)];
        let behavior = addresses.map(|address| (address, Behavior::Stall));
        let mut model = Model::new(&behavior);
        let end = model.now + Duration::from_secs(8);
        let error = race(&addresses, end, &mut model).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(model.starts.len(), addresses.len());
        assert!(model.starts.iter().all(|(_, started)| *started < end));
        assert_eq!(model.peak, MAX_PENDING);
        assert_eq!(model.dropped.borrow().len(), addresses.len());
    }

    #[test]
    fn interrupted_polls_and_late_success_do_not_renew_the_deadline() {
        let mut model = Model::new(&[(v4(1), Behavior::Ready(Duration::ZERO))]);
        model.interrupts = 3;
        model.late_success = Duration::from_secs(2);
        let end = model.now + Duration::from_secs(1);
        assert_eq!(
            race(&[v4(1)], end, &mut model).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(model.starts.len(), 1);
        assert_eq!(model.dropped.borrow().len(), 1);
    }

    #[test]
    fn invalid_or_expired_admission_cannot_open_a_socket() {
        for addresses in [vec![], vec![v4(1); MAX_ADDRESSES + 1]] {
            let mut model = Model::new(&[]);
            let end = model.now + Duration::from_secs(1);
            assert!(race(&addresses, end, &mut model).is_err());
            assert!(model.starts.is_empty());
        }
        let mut model = Model::new(&[]);
        let end = model.now;
        assert_eq!(
            race(&[v4(1)], end, &mut model).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(model.starts.is_empty());
    }

    #[test]
    fn real_refused_address_falls_back_and_only_the_winner_sends_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let unused = TcpListener::bind("127.0.0.1:0").unwrap();
        let live = listener.local_addr().unwrap();
        let mut stream = connect_addresses(
            &[
                "127.0.0.1:0".parse().unwrap(),
                live,
                unused.local_addr().unwrap(),
            ],
            NetworkDeadline::new(Duration::from_secs(5)).unwrap(),
        )
        .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        stream.write_all(b"exactly once").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"exactly once");
        unused.set_nonblocking(true).unwrap();
        assert_eq!(
            unused.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
