//! One absolute budget for the socket portion of a host network effect.
//!
//! A per-read timeout alone lets a slow peer retain the interpreter forever by
//! delivering occasional bytes. Keeping the deadline underneath rustls also
//! bounds handshake loops and TLS records that produce no application bytes.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

#[derive(Debug)]
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
}
