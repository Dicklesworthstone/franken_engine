//! One absolute budget for DNS and the socket portion of a host network effect.
//!
//! A per-read timeout alone lets a slow peer retain the interpreter forever by
//! delivering occasional bytes. Keeping the deadline underneath rustls also
//! bounds handshake loops and TLS records that produce no application bytes.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

mod resolver;

#[derive(Debug, Clone, Copy)]
pub(super) struct NetworkDeadline {
    end: Instant,
}

impl NetworkDeadline {
    pub(super) fn new(timeout: Duration) -> io::Result<Self> {
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "network timeout must be positive",
            ));
        }
        Instant::now()
            .checked_add(timeout)
            .map(|end| Self { end })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "network timeout overflow"))
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.end
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "network effect deadline exceeded")
            })
    }
}

/// Owns the stream and its deadline; rustls cannot bypass the shared budget by
/// retrying a read/write internally. The timeout never restarts on progress.
#[derive(Debug)]
pub(super) struct DeadlineTcpStream {
    stream: TcpStream,
    deadline: NetworkDeadline,
}

impl DeadlineTcpStream {
    /// Resolve once, then try the bounded address list in resolver order. Each
    /// remaining address gets a share of the remaining connection budget, so a
    /// blackholed first address cannot consume every later address's chance.
    pub(super) fn connect_endpoint(endpoint: &str, deadline: NetworkDeadline) -> io::Result<Self> {
        let addresses = resolver::resolve_endpoint(endpoint, deadline)?;
        if addresses.len() == 1 {
            return Self::connect(&addresses[0], deadline);
        }
        Self::connect_addresses(&addresses, deadline, TcpStream::connect_timeout)
    }

    fn connect_addresses<F>(
        addresses: &[SocketAddr],
        deadline: NetworkDeadline,
        mut dial: F,
    ) -> io::Result<Self>
    where
        F: FnMut(&SocketAddr, Duration) -> io::Result<TcpStream>,
    {
        let mut last_error = io::Error::new(io::ErrorKind::NotFound, "no connection addresses");
        for (index, address) in addresses.iter().enumerate() {
            let attempts_left = u32::try_from(addresses.len() - index).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "too many connection addresses")
            })?;
            let timeout = deadline.remaining()? / attempts_left;
            if timeout.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "network effect deadline exceeded",
                ));
            }
            let result = dial(address, timeout);
            // A late connect, successful or not, cannot restart the operation's
            // clock. Failover occurs only here, before any guest request bytes.
            deadline.remaining()?;
            match result {
                Ok(stream) => return Ok(Self { stream, deadline }),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    pub(super) fn connect(address: &SocketAddr, deadline: NetworkDeadline) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(address, deadline.remaining()?)?;
        // A late success must not start a fresh budget for the request body.
        deadline.remaining()?;
        Ok(Self { stream, deadline })
    }

    pub(super) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.stream.shutdown(how)
    }
}

impl Read for DeadlineTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.stream
            .set_read_timeout(Some(self.deadline.remaining()?))?;
        let count = self.stream.read(buffer)?;
        self.deadline.remaining()?;
        Ok(count)
    }
}

impl Write for DeadlineTcpStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.stream
            .set_write_timeout(Some(self.deadline.remaining()?))?;
        let count = self.stream.write(bytes)?;
        self.deadline.remaining()?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.deadline.remaining()?;
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn zero_and_unrepresentable_timeouts_are_errors_not_panics() {
        for timeout in [Duration::ZERO, Duration::MAX] {
            assert_eq!(
                NetworkDeadline::new(timeout).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn expired_deadline_cannot_be_renewed_by_another_operation() {
        let deadline = NetworkDeadline {
            end: Instant::now(),
        };
        for _ in 0..10 {
            assert_eq!(
                deadline.remaining().unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
    }

    #[test]
    fn expired_socket_does_not_read_ready_bytes_or_send_new_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        sender.write_all(b"already buffered").unwrap();
        let mut bounded = DeadlineTcpStream {
            stream,
            deadline: NetworkDeadline {
                end: Instant::now(),
            },
        };
        let mut buffer = [0_u8; 32];
        assert_eq!(
            bounded.read(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            bounded.write(b"must not be sent").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(bounded.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(buffer, [0; 32]);
        sender
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        bounded.shutdown(Shutdown::Write).unwrap();
        assert_eq!(sender.read(&mut buffer).unwrap(), 0);
    }

    #[test]
    fn expired_deadline_rejects_connect_before_the_socket_is_opened() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let error = DeadlineTcpStream::connect(
            &listener.local_addr().unwrap(),
            NetworkDeadline {
                end: Instant::now(),
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn refused_first_address_falls_back_without_repeating_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let live = listener.local_addr().unwrap();
        let refused = "127.0.0.1:0".parse().unwrap();
        let deadline = NetworkDeadline::new(Duration::from_secs(5)).unwrap();
        let mut connected = DeadlineTcpStream::connect_addresses(
            &[refused, live],
            deadline,
            TcpStream::connect_timeout,
        )
        .unwrap();
        assert_eq!(connected.deadline.end, deadline.end);
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        connected.write_all(b"exactly once").unwrap();
        connected.shutdown(Shutdown::Write).unwrap();
        let mut observed = Vec::new();
        peer.read_to_end(&mut observed).unwrap();
        assert_eq!(observed, b"exactly once");
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn connection_attempts_share_the_remaining_budget_and_stop_at_success() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let live = listener.local_addr().unwrap();
        let first = "127.0.0.1:0".parse().unwrap();
        let deadline = NetworkDeadline::new(Duration::from_secs(6)).unwrap();
        let mut calls = Vec::new();
        let mut timeouts = Vec::new();
        let stream = DeadlineTcpStream::connect_addresses(
            &[first, live, first],
            deadline,
            |address, timeout| {
                calls.push(*address);
                timeouts.push(timeout);
                if *address == first {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "injected first dial refusal",
                    ))
                } else {
                    TcpStream::connect_timeout(address, timeout)
                }
            },
        )
        .unwrap();
        assert_eq!(calls, vec![first, live]);
        assert!(timeouts[0] <= Duration::from_secs(2));
        assert!(timeouts[1] <= Duration::from_secs(3));
        assert_eq!(
            stream.deadline.end, deadline.end,
            "DNS/dial budget is not renewed for I/O"
        );
    }

    #[test]
    fn exhausted_deadline_stops_before_trying_any_destination() {
        let address = "127.0.0.1:80".parse().unwrap();
        let error = DeadlineTcpStream::connect_addresses(
            &[address, address],
            NetworkDeadline {
                end: Instant::now(),
            },
            |_, _| panic!("deadline exhaustion must precede the first socket"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn empty_and_failed_address_lists_return_errors_without_a_stream() {
        let deadline = NetworkDeadline::new(Duration::from_secs(5)).unwrap();
        let error = DeadlineTcpStream::connect_addresses(&[], deadline, |_, _| {
            panic!("empty list must not dial")
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let address = "127.0.0.1:0".parse().unwrap();
        let mut attempts = 0;
        let error = DeadlineTcpStream::connect_addresses(&[address, address], deadline, |_, _| {
            attempts += 1;
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "injected refusal",
            ))
        })
        .unwrap_err();
        assert_eq!(attempts, 2);
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    }
}
