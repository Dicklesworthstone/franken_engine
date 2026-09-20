//! Bounded OS name resolution for one host effect, not an egress policy.
//!
//! `ToSocketAddrs` can block indefinitely inside the OS. Callers wait only for
//! their remaining effect budget. A timed-out OS lookup retains its admission
//! permit until it actually exits: repeated timeouts cannot create an unbounded
//! population of detached threads. There is no queue, cache, or detached socket
//! connection, and all provider instances share the same process-wide limit.

use super::NetworkDeadline;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, mpsc};

const MAX_IN_FLIGHT: usize = 8;
const MAX_ADDRESSES: usize = 64;
const MAX_ENDPOINT_BYTES: usize = 1024;
static RESOLVER_BUDGET: OnceLock<Arc<ResolverBudget>> = OnceLock::new();

#[derive(Debug)]
struct ResolverBudget {
    active: AtomicUsize,
    limit: usize,
}

impl ResolverBudget {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicUsize::new(0),
            limit,
        })
    }

    fn acquire(self: &Arc<Self>) -> io::Result<ResolverPermit> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.limit {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "host DNS lookup capacity exhausted",
                ));
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => active = observed,
            }
        }
        Ok(ResolverPermit(Arc::clone(self)))
    }
}

struct ResolverPermit(Arc<ResolverBudget>);

impl Drop for ResolverPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Validate before copying a hostname or starting a worker. Numeric endpoints
/// never invoke DNS, including bracketed IPv6 with a numeric scope identifier.
fn literal_or_hostname(endpoint: &str) -> io::Result<Option<SocketAddr>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid host:port endpoint");
    if endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(invalid());
    }
    if let Ok(address) = endpoint.parse::<SocketAddr>() {
        return Ok(Some(address));
    }
    let (host, port) = endpoint.rsplit_once(':').ok_or_else(invalid)?;
    if host.is_empty()
        || host.len() > 254
        || !host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
        || port.is_empty()
        || !port.bytes().all(|c| c.is_ascii_digit())
        || port.parse::<u16>().is_err()
    {
        return Err(invalid());
    }
    Ok(None)
}

pub(super) fn resolve_endpoint(
    endpoint: &str,
    deadline: NetworkDeadline,
) -> io::Result<Vec<SocketAddr>> {
    let budget = RESOLVER_BUDGET.get_or_init(|| ResolverBudget::new(MAX_IN_FLIGHT));
    resolve_with(endpoint, deadline, budget, |name| {
        // The OS may allocate internally. This bounds the result retained by
        // the runtime, not libc/NSS memory or CPU while resolution is running.
        let addresses = name.to_socket_addrs()?.take(MAX_ADDRESSES + 1).collect();
        checked_addresses(addresses)
    })
}

fn checked_addresses(addresses: Vec<SocketAddr>) -> io::Result<Vec<SocketAddr>> {
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DNS lookup returned no addresses",
        ));
    }
    if addresses.len() > MAX_ADDRESSES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS lookup returned too many addresses",
        ));
    }
    // Deduplicate before interleaving: duplicate answers must not consume an
    // attempt slot or delay the other family. Keep each family's OS ordering.
    let mut unique = Vec::with_capacity(addresses.len());
    for address in addresses {
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    // RFC 8305 section 4: retain the first-family preference, then alternate
    // families while both are available. A long run of unreachable IPv6 (or
    // IPv4) addresses must not spend every dial opportunity before the other
    // family is tried. This neither resolves again nor invents a destination.
    let first_v6 = unique[0].is_ipv6();
    let mut preferred = unique
        .iter()
        .filter(|address| address.is_ipv6() == first_v6);
    let mut alternate = unique
        .iter()
        .filter(|address| address.is_ipv6() != first_v6);
    let mut ordered = Vec::with_capacity(unique.len());
    loop {
        let first = preferred.next();
        let second = alternate.next();
        if first.is_none() && second.is_none() {
            break;
        }
        ordered.extend(first.into_iter().chain(second).copied());
    }
    Ok(ordered)
}

fn resolve_with<F>(
    endpoint: &str,
    deadline: NetworkDeadline,
    budget: &Arc<ResolverBudget>,
    lookup: F,
) -> io::Result<Vec<SocketAddr>>
where
    F: FnOnce(&str) -> io::Result<Vec<SocketAddr>> + Send + 'static,
{
    deadline.remaining()?;
    if let Some(address) = literal_or_hostname(endpoint)? {
        return Ok(vec![address]);
    }
    let permit = budget.acquire()?;
    deadline.remaining()?;
    let owned_endpoint = endpoint.to_string();
    let (send, receive) = mpsc::sync_channel(1);
    let worker_deadline = deadline.clone();
    std::thread::Builder::new()
        .name("franken-dns".to_string())
        .spawn(move || {
            // A delayed worker must not begin an already-expired lookup.
            let result = worker_deadline
                .remaining()
                .and_then(|_| lookup(&owned_endpoint));
            drop(permit);
            // Sending into the single result slot never waits for the caller.
            // Late results are dropped; no worker is allowed to connect.
            let _ = send.send(result);
        })?;
    let result = loop {
        match receive.recv_timeout(deadline.wait_slice()?) {
            Ok(result) => break result,
            // A short wait is only a revocation checkpoint, never a renewed
            // effect deadline. Returning here leaves the worker's permit held.
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                deadline.remaining()?;
                return Err(io::Error::other("DNS lookup worker terminated"));
            }
        }
    };
    // Even a result made ready just after the deadline cannot authorize I/O.
    deadline.remaining()?;
    result.and_then(checked_addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::time::{Duration, Instant};

    fn deadline() -> NetworkDeadline {
        NetworkDeadline::new(Duration::from_secs(5)).unwrap()
    }

    fn address() -> SocketAddr {
        "127.0.0.1:80".parse().unwrap()
    }

    #[test]
    fn numeric_endpoints_do_not_need_a_resolver_slot_or_worker() {
        for endpoint in ["127.0.0.1:80", "[::1]:443", "[fe80::1%3]:443"] {
            let resolved = resolve_with(endpoint, deadline(), &ResolverBudget::new(0), |_| {
                panic!("numeric address must not reach the OS resolver")
            })
            .unwrap();
            assert_eq!(resolved, vec![endpoint.parse::<SocketAddr>().unwrap()]);
        }
    }

    #[test]
    fn invalid_endpoints_fail_before_resolver_admission() {
        for endpoint in [
            "",
            "localhost",
            ":80",
            "localhost:",
            "localhost:+80",
            "localhost:65536",
            "http://localhost:80",
            "user@localhost:80",
            "[::1:80",
            "::1:80",
            "a\0b:80",
            "a\nb:80",
        ] {
            let result = resolve_with(endpoint, deadline(), &ResolverBudget::new(0), |_| {
                panic!("invalid endpoint must not reach the OS resolver")
            });
            assert_eq!(
                result.unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{endpoint:?}"
            );
        }
        assert_eq!(
            literal_or_hostname(&format!("{}:80", "a".repeat(1024)))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn expired_deadline_rejects_even_a_numeric_endpoint() {
        let result = resolve_with(
            "127.0.0.1:80",
            NetworkDeadline::at(Instant::now()),
            &ResolverBudget::new(1),
            |_| panic!("expired lookup must not run"),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn result_order_and_unique_addresses_are_preserved() {
        let a = address();
        let b = "[::1]:80".parse().unwrap();
        assert_eq!(
            resolve_with(
                "localhost:80",
                deadline(),
                &ResolverBudget::new(1),
                move |name| {
                    assert_eq!(name, "localhost:80");
                    Ok(vec![b, a, b, a])
                }
            )
            .unwrap(),
            vec![b, a]
        );
    }

    #[test]
    fn alternate_family_precedes_the_preferred_familys_remaining_addresses() {
        let v6a: SocketAddr = "[::1]:80".parse().unwrap();
        let v6b: SocketAddr = "[::2]:80".parse().unwrap();
        let v6c: SocketAddr = "[::3]:80".parse().unwrap();
        let v4a: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let v4b: SocketAddr = "127.0.0.2:80".parse().unwrap();
        assert_eq!(
            checked_addresses(vec![v6a, v6b, v6c, v4a, v4b]).unwrap(),
            vec![v6a, v4a, v6b, v4b, v6c]
        );
        assert_eq!(
            checked_addresses(vec![v4a, v4b, v6a, v6b, v6c]).unwrap(),
            vec![v4a, v6a, v4b, v6b, v6c]
        );
    }

    #[test]
    fn duplicate_answers_do_not_delay_the_other_family_or_reorder_unique_peers() {
        let a: SocketAddr = "[::1]:80".parse().unwrap();
        let b: SocketAddr = "[::2]:80".parse().unwrap();
        let c: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let d: SocketAddr = "127.0.0.2:80".parse().unwrap();
        let ordered = checked_addresses(vec![a, a, b, c, c, d, b]).unwrap();
        assert_eq!(ordered, vec![a, c, b, d]);
        // Both the worker and the caller validate the real resolver's result.
        assert_eq!(checked_addresses(ordered.clone()).unwrap(), ordered);
    }

    #[test]
    fn one_family_keeps_its_original_unique_order_and_ports() {
        for inputs in [
            ["127.0.0.2:443", "127.0.0.1:80", "127.0.0.2:443"],
            ["[::2]:443", "[::1]:80", "[::2]:443"],
        ] {
            let addresses: Vec<SocketAddr> =
                inputs.iter().map(|input| input.parse().unwrap()).collect();
            let expected = vec![addresses[0], addresses[1]];
            assert_eq!(checked_addresses(addresses).unwrap(), expected);
        }
    }

    #[test]
    fn empty_oversized_and_failed_results_are_not_success() {
        let budget = ResolverBudget::new(1);
        assert_eq!(
            resolve_with("localhost:80", deadline(), &budget, |_| Ok(Vec::new()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            resolve_with("localhost:80", deadline(), &budget, |_| Ok(vec![
                address();
                MAX_ADDRESSES
                    + 1
            ]))
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            resolve_with("localhost:80", deadline(), &budget, |_| Err(
                io::Error::new(io::ErrorKind::PermissionDenied, "resolver failed")
            ))
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(budget.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn a_timed_out_lookup_keeps_its_slot_until_the_os_call_returns() {
        let budget = ResolverBudget::new(1);
        let worker_budget = Arc::clone(&budget);
        let (entered, wait_entered) = mpsc::sync_channel(1);
        let (release, wait_release) = mpsc::sync_channel(1);
        let caller = std::thread::spawn(move || {
            resolve_with(
                "localhost:80",
                NetworkDeadline::new(Duration::from_millis(250)).unwrap(),
                &worker_budget,
                move |_| {
                    entered.send(()).unwrap();
                    wait_release.recv_timeout(Duration::from_secs(5)).unwrap();
                    Ok(vec![address()])
                },
            )
        });
        wait_entered.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            caller.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            budget.active.load(Ordering::Acquire),
            1,
            "timeout must not admit another blocking worker"
        );
        assert_eq!(
            resolve_with("localhost:80", deadline(), &budget, |_| panic!(
                "overload must not execute"
            ))
            .unwrap_err()
            .kind(),
            io::ErrorKind::WouldBlock
        );
        release.send(()).unwrap();
        let guard = Instant::now() + Duration::from_secs(5);
        while budget.active.load(Ordering::Acquire) != 0 {
            assert!(
                Instant::now() < guard,
                "finished worker must release its slot"
            );
            std::thread::yield_now();
        }
        assert_eq!(
            resolve_with("localhost:80", deadline(), &budget, |_| Ok(vec![address()])).unwrap(),
            vec![address()]
        );
    }

    #[test]
    fn concurrent_admission_never_exceeds_the_shared_limit() {
        let budget = ResolverBudget::new(3);
        let barrier = Arc::new(Barrier::new(17));
        let (results, receive) = mpsc::channel();
        let released = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let mut threads = Vec::new();
        for _ in 0..16 {
            let budget = Arc::clone(&budget);
            let barrier = Arc::clone(&barrier);
            let results = results.clone();
            let released = Arc::clone(&released);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                let permit = budget.acquire();
                results.send(permit.is_ok()).unwrap();
                let (lock, wake) = &*released;
                let mut ready = lock.lock().unwrap();
                while !*ready {
                    ready = wake.wait(ready).unwrap();
                }
                drop(permit);
            }));
        }
        barrier.wait();
        let admitted = (0..16)
            .filter(|_| receive.recv_timeout(Duration::from_secs(5)).unwrap())
            .count();
        let (lock, wake) = &*released;
        *lock.lock().unwrap() = true;
        wake.notify_all();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(admitted, 3);
        assert_eq!(budget.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn worker_panic_releases_capacity_and_is_a_resolution_error() {
        let budget = ResolverBudget::new(1);
        let result = resolve_with("localhost:80", deadline(), &budget, |_| {
            panic!("resolver panic injection")
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
        let guard = Instant::now() + Duration::from_secs(5);
        while budget.active.load(Ordering::Acquire) != 0 {
            assert!(
                Instant::now() < guard,
                "panicked worker must release its slot"
            );
            std::thread::yield_now();
        }
    }

    #[test]
    fn real_localhost_resolution_has_a_bounded_nonempty_result() {
        let addresses = resolve_endpoint("localhost:43210", deadline()).unwrap();
        assert!(!addresses.is_empty());
        assert!(addresses.len() <= MAX_ADDRESSES);
        assert!(addresses.iter().all(|address| address.port() == 43210));
    }

    #[test]
    fn revoking_a_dns_wait_retains_the_worker_permit_until_lookup_exits() {
        let signal = super::super::NetworkRevocation::default();
        let mut deadline = NetworkDeadline::new(Duration::from_secs(10)).unwrap();
        deadline.revocation = Some(signal.clone());
        let budget = ResolverBudget::new(1);
        let worker_budget = Arc::clone(&budget);
        let (entered, wait_entered) = mpsc::sync_channel(1);
        let (release, wait_release) = mpsc::sync_channel(1);
        let (done, wait_done) = mpsc::sync_channel(1);
        let caller = std::thread::spawn(move || {
            let result = resolve_with("host.invalid:80", deadline, &worker_budget, move |_| {
                entered.send(()).unwrap();
                wait_release.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(vec![address()])
            });
            done.send(result).unwrap();
        });
        wait_entered.recv_timeout(Duration::from_secs(2)).unwrap();
        signal.revoke();
        let result = wait_done.recv_timeout(Duration::from_secs(2));
        let active = budget.active.load(Ordering::Acquire);
        // Release the injected OS lookup even if an assertion below fails.
        release.send(()).unwrap();
        caller.join().unwrap();
        assert_eq!(
            result.unwrap().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            active, 1,
            "revocation must not free an occupied OS-worker slot"
        );
        let end = Instant::now() + Duration::from_secs(5);
        while budget.active.load(Ordering::Acquire) != 0 {
            assert!(Instant::now() < end);
            std::thread::yield_now();
        }
    }
}
