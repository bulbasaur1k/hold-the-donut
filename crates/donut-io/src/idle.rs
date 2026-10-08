//! Idle-timeout wrapper for a relayed stream.
//!
//! A spliced relay is just [`tokio::io::copy_bidirectional`] between the
//! tunnel and the upstream socket. That future only resolves when one of
//! the two sides reports EOF or an error — so when a peer *vanishes*
//! without a FIN (its NAT mapping was evicted, the Wi-Fi client slept, the
//! path broke mid-session) the copy parks forever and the two sockets are
//! held for the lifetime of the process.
//!
//! On a home cascade that is not merely an FD leak. Each held socket also
//! burns one NAT slot on the upstream router, whose translation table is
//! only a few thousand entries wide; once it fills, *every* device behind
//! it stops being able to open new connections. Observed 2026-08-02: 2045
//! sockets held on the client against 62 live ones on the server, and the
//! whole household lost the ability to establish TCP until the client was
//! restarted.
//!
//! Xray bounds the same failure with `connIdle` (default 300 s). This is
//! our equivalent: wrap each half of the relay so that a stretch of total
//! silence — no byte read, no byte written, in either direction — fails
//! the copy with [`io::ErrorKind::TimedOut`]. The caller then shuts both
//! sockets down, which sends the FIN the dead peer never got, and the
//! NAT slot is released.
//!
//! Note this bounds *silence*, not connection lifetime: a busy download
//! that runs for hours keeps resetting the deadline and is never cut.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// Wraps a duplex stream and fails it once no I/O has happened for
/// `idle`. Reads and writes share one deadline, so activity in either
/// direction keeps the relay alive.
///
/// The timer is boxed so the wrapper stays `Unpin` for any `Unpin` stream
/// — relays are `TcpStream`-shaped, and keeping `Unpin` lets them go on
/// using `AsyncReadExt` / `copy_bidirectional` unchanged.
#[derive(Debug)]
pub struct IdleTimeout<S> {
    inner: S,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
}

impl<S> IdleTimeout<S> {
    /// Wrap `inner`, failing it after `idle` of complete silence.
    /// [`Duration::ZERO`] disables the reaping — the wrapper then just
    /// forwards, which keeps the type the same on both sides of the
    /// `tcp_idle = 0` config switch.
    pub fn new(inner: S, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
        }
    }

    /// Unwrap, discarding the timer.
    pub fn into_inner(self) -> S {
        self.inner
    }

    fn enabled(&self) -> bool {
        !self.idle.is_zero()
    }

    fn touch(&mut self) {
        if self.enabled() {
            let next = Instant::now() + self.idle;
            self.deadline.as_mut().reset(next);
        }
    }

    /// `Pending` from the inner stream: the relay is only dead if the
    /// deadline has also elapsed.
    fn poll_idle<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        if !self.enabled() {
            return Poll::Pending;
        }
        match self.deadline.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(timed_out())),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "relay idle timeout")
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTimeout<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(res) => {
                // Only real bytes count. A `Ready(Ok)` that filled nothing
                // is EOF, which ends the copy on its own.
                if res.is_ok() && buf.filled().len() > before {
                    this.touch();
                }
                Poll::Ready(res)
            }
            Poll::Pending => this.poll_idle(cx),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTimeout<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.touch();
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.poll_idle(cx),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.touch();
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.poll_idle(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const IDLE: Duration = Duration::from_millis(50);

    /// A peer that vanished without a FIN: the socket stays open, nothing
    /// ever arrives. Un-wrapped this read would park forever.
    #[tokio::test(start_paused = true)]
    async fn silence_fails_the_stream() {
        let (a, _b) = tokio::io::duplex(64);
        let mut a = IdleTimeout::new(a, IDLE);

        let err = a.read(&mut [0u8; 16]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// Traffic that keeps arriving — each gap shorter than the idle window
    /// — must never be cut, even though the total run far exceeds it.
    #[tokio::test(start_paused = true)]
    async fn activity_keeps_resetting_the_deadline() {
        let (a, mut b) = tokio::io::duplex(64);
        let mut a = IdleTimeout::new(a, IDLE);

        let writer = tokio::spawn(async move {
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                b.write_all(b"x").await.unwrap();
            }
        });

        // 10 reads across ~200 ms of wall time with a 50 ms idle budget.
        let mut buf = [0u8; 1];
        for _ in 0..10 {
            a.read_exact(&mut buf).await.expect("must not time out");
        }
        writer.await.unwrap();
    }

    /// The deadline is shared, so a write-only direction also counts as
    /// activity and keeps the read side from firing.
    #[tokio::test(start_paused = true)]
    async fn writes_count_as_activity() {
        let (a, mut b) = tokio::io::duplex(1024);
        let mut a = IdleTimeout::new(a, IDLE);

        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            a.write_all(b"x").await.expect("must not time out");
        }

        let mut buf = vec![0u8; 10];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"xxxxxxxxxx");
    }

    /// `Duration::ZERO` is the documented "disabled" switch: the wrapper
    /// must then behave like the bare stream and never fire.
    #[tokio::test(start_paused = true)]
    async fn zero_disables_the_reaping() {
        let (a, mut b) = tokio::io::duplex(64);
        let mut a = IdleTimeout::new(a, Duration::ZERO);

        let writer = tokio::spawn(async move {
            // Far longer than any sane idle budget.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            b.write_all(b"x").await.unwrap();
        });

        let mut buf = [0u8; 1];
        a.read_exact(&mut buf).await.expect("must never time out");
        assert_eq!(&buf, b"x");
        writer.await.unwrap();
    }

    /// EOF is not activity: a half-closed peer must still be reaped.
    #[tokio::test(start_paused = true)]
    async fn eof_is_reported_not_reset() {
        let (a, b) = tokio::io::duplex(64);
        drop(b);
        let mut a = IdleTimeout::new(a, IDLE);

        let n = a.read(&mut [0u8; 16]).await.unwrap();
        assert_eq!(n, 0, "dropped peer reads as EOF, not as a timeout");
    }
}
