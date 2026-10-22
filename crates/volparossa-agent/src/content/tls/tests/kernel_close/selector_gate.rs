//! Test-only forward-read gate. No buffering or fabricated write/flush readiness.

use super::*;
use std::{sync::PoisonError, task::Waker};

struct State {
    held: bool,
    pending: Option<Waker>,
    blocked: Option<oneshot::Sender<()>>,
}

pub(super) struct Gate(Arc<Mutex<State>>);

impl Gate {
    pub(super) fn new() -> (Arc<Self>, oneshot::Receiver<()>) {
        let (blocked, receiver) = oneshot::channel();
        let gate = Arc::new(Self(Arc::new(Mutex::new(State {
            held: false,
            pending: None,
            blocked: Some(blocked),
        }))));
        (gate, receiver)
    }

    pub(super) fn hold(&self) {
        self.0.lock().unwrap().held = true;
    }

    pub(super) fn is_held(&self) -> bool {
        self.0.lock().unwrap().held
    }

    pub(super) fn release(&self) {
        let pending = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            state.held = false;
            state.pending.take()
        };
        if let Some(waker) = pending {
            waker.wake();
        }
    }

    pub(super) fn wrap<S>(&self, inner: S) -> ForwardGate<S> {
        ForwardGate {
            inner,
            gate: Arc::clone(&self.0),
        }
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.release();
    }
}

pub(super) struct ForwardGate<S> {
    inner: S,
    gate: Arc<Mutex<State>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for ForwardGate<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Pin::new(&mut this.inner).poll_read(cx, output);
        }
        let mut state = this.gate.lock().unwrap();
        if state.held {
            state.pending = Some(cx.waker().clone());
            if let Some(blocked) = state.blocked.take() {
                let _ = blocked.send(());
            }
            return Poll::Pending;
        }
        // Hold only across the original synchronous poll, never across await.
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ForwardGate<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
