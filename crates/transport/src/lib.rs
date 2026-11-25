//! AgentNet transport seam.
//!
//! A [`Transport`] moves opaque, already-encrypted frames between agents by
//! content topic. It knows nothing about identities, envelopes or policy.
//! Implementations: the deterministic `MockTransport` (tests) and the
//! `LogosRestTransport` adapter (feature `logos-rest`) that talks to a
//! separately running Logos Delivery node.
//!
//! Contract every implementation must honour:
//! * `publish` returning `Ok` means the *local node accepted* the frame. It is
//!   never evidence that any recipient received it.
//! * Delivery is at-least-once and unordered. `poll` and `history` may both
//!   return the same frame; callers dedupe on [`InboundFrame::transport_id`]
//!   and again at the application layer.
//! * No method may block indefinitely; every network call has a timeout.
//! * Nothing here panics on malformed remote data.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A validated Waku content topic: `/<application>/<version>/<name>/<encoding>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentTopic(String);

impl ContentTopic {
    /// Validates the four-segment form accepted by Logos Delivery autosharding.
    pub fn new(s: impl Into<String>) -> Result<Self, TransportError> {
        let s = s.into();
        let parts: Vec<&str> = s.split('/').collect();
        let ok = parts.len() == 5
            && parts[0].is_empty()
            && parts[1..].iter().all(|p| {
                !p.is_empty()
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            });
        if ok {
            Ok(Self(s))
        } else {
            Err(TransportError::Protocol(format!(
                "invalid content topic: {s:?}"
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where an inbound frame came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameSource {
    /// Received while subscribed.
    Live,
    /// Recovered from a store/history service.
    History,
}

/// One frame received from the network. `payload` is untrusted bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundFrame {
    pub topic: ContentTopic,
    pub payload: Vec<u8>,
    /// Sender-supplied transport timestamp (nanoseconds); untrusted.
    pub timestamp_ns: i64,
    /// Stable transport-level identifier of this frame (for Logos Delivery: the
    /// Waku message hash). Equal for the same frame seen live and in history.
    pub transport_id: [u8; 32],
    pub source: FrameSource,
}

/// Result of a publish the local node accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishReceipt {
    pub transport_id: [u8; 32],
    pub timestamp_ns: i64,
}

/// A bounded history query. `end_ns - start_ns` must not exceed
/// [`Transport::max_history_window_ns`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryQuery {
    pub topic: ContentTopic,
    pub start_ns: i64,
    pub end_ns: i64,
    /// Opaque cursor from a previous [`HistoryPage::next_cursor`].
    pub cursor: Option<String>,
    pub limit: u32,
}

/// One page of history in ascending time order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryPage {
    pub frames: Vec<InboundFrame>,
    pub next_cursor: Option<String>,
}

/// A peer of the local node, as far as the transport can tell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub connected: bool,
    /// Whether this peer is in the configured allowlist (always true when no
    /// allowlist is configured).
    pub allowed: bool,
}

/// Snapshot of transport health. Must not contain secrets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportStatus {
    /// The local node is reachable and has at least one connected peer.
    pub ready: bool,
    pub peers: Vec<PeerInfo>,
    /// `Some(reason)` when private-mode isolation checks fail. While set,
    /// `publish`, `poll` and `history` must return [`TransportError::Isolation`].
    pub isolation_violation: Option<String>,
    /// Sanitized human-readable detail (no addresses of third parties, no keys).
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// Node unreachable, no peers, timeout. Retry later.
    #[error("transport unavailable: {0}")]
    Unavailable(String),
    /// The frame can never be accepted (retrying is pointless).
    #[error("frame too large: {size} bytes exceeds maximum {max}")]
    TooLarge { size: usize, max: usize },
    /// Private-mode isolation check failed; fail closed.
    #[error("isolation violation: {0}")]
    Isolation(String),
    /// History service not reachable or not configured.
    #[error("history unavailable: {0}")]
    HistoryUnavailable(String),
    /// Malformed request or response.
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl TransportError {
    /// Whether retrying the same operation later can succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Unavailable(_) | Self::HistoryUnavailable(_) | Self::Isolation(_)
        )
    }
}

#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Start receiving frames for `topic`. Idempotent; implementations must
    /// transparently re-establish subscriptions lost by a node restart.
    async fn subscribe(&self, topic: &ContentTopic) -> Result<(), TransportError>;

    /// Hand one frame to the local node.
    async fn publish(
        &self,
        topic: &ContentTopic,
        payload: &[u8],
    ) -> Result<PublishReceipt, TransportError>;

    /// Drain frames received live for `topic` since the previous call. Returns
    /// an empty vector when there is nothing new.
    async fn poll(&self, topic: &ContentTopic) -> Result<Vec<InboundFrame>, TransportError>;

    /// Query retained history. Absence of a frame is not proof it never
    /// existed: retention may have expired or the service missed it.
    async fn history(&self, query: &HistoryQuery) -> Result<HistoryPage, TransportError>;

    /// Health and isolation snapshot.
    async fn status(&self) -> TransportStatus;

    /// Largest `payload` accepted by `publish` for this topic.
    fn max_payload_len(&self, topic: &ContentTopic) -> usize;

    /// Largest time span a single history query may cover.
    fn max_history_window_ns(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_topic_validation() {
        assert!(ContentTopic::new("/agentnet/1/inbox-0a/proto").is_ok());
        for bad in [
            "",
            "agentnet/1/x/proto",
            "/a/1/b",
            "/a/1/b/c/d",
            "/a//b/c",
            "/a/1/b c/proto",
        ] {
            assert!(
                ContentTopic::new(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }
}
