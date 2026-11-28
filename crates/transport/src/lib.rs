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

#![warn(missing_docs)]

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod mock;

#[cfg(any(feature = "logos-rest", feature = "waku-native"))]
pub mod waku_common;

#[cfg(feature = "logos-rest")]
pub mod logos_rest;

#[cfg(feature = "waku-native")]
pub mod waku_native;

/// Maximum accepted length of a content topic string (bytes).
pub const MAX_CONTENT_TOPIC_LEN: usize = 256;

/// A validated Waku content topic: `/<application>/<version>/<name>/<encoding>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct ContentTopic(String);

impl TryFrom<String> for ContentTopic {
    type Error = TransportError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl ContentTopic {
    /// Validates the four-segment form accepted by Logos Delivery autosharding.
    pub fn new(s: impl Into<String>) -> Result<Self, TransportError> {
        let s = s.into();
        if s.len() > MAX_CONTENT_TOPIC_LEN {
            return Err(TransportError::Protocol(format!(
                "content topic exceeds {MAX_CONTENT_TOPIC_LEN} bytes"
            )));
        }
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

    /// The topic as a string slice.
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
    /// Content topic the frame was received on.
    pub topic: ContentTopic,
    /// Opaque (already encrypted) payload bytes.
    pub payload: Vec<u8>,
    /// Sender-supplied transport timestamp (nanoseconds); untrusted.
    pub timestamp_ns: i64,
    /// Stable transport-level identifier of this frame (for Logos Delivery: the
    /// Waku message hash). Equal for the same frame seen live and in history.
    pub transport_id: [u8; 32],
    /// Whether the frame arrived live or from history.
    pub source: FrameSource,
}

/// Result of a publish the local node accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishReceipt {
    /// Transport id the frame will carry on receipt and in history.
    pub transport_id: [u8; 32],
    /// Timestamp (nanoseconds) the frame was published with.
    pub timestamp_ns: i64,
}

/// A bounded history query. `end_ns - start_ns` must not exceed
/// [`Transport::max_history_window_ns`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryQuery {
    /// Content topic to query.
    pub topic: ContentTopic,
    /// Window start (nanoseconds, inclusive).
    pub start_ns: i64,
    /// Window end (nanoseconds).
    pub end_ns: i64,
    /// Opaque cursor from a previous [`HistoryPage::next_cursor`].
    pub cursor: Option<String>,
    /// Maximum frames per page (implementations may return fewer).
    pub limit: u32,
}

/// One page of history in ascending time order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryPage {
    /// Frames of this page, ascending by time.
    pub frames: Vec<InboundFrame>,
    /// Cursor for the next page; `None` on the last page.
    pub next_cursor: Option<String>,
}

/// A peer of the local node, as far as the transport can tell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    /// libp2p peer id.
    pub peer_id: String,
    /// Whether the node currently holds a live connection to the peer.
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
    /// Known peers of the local node.
    pub peers: Vec<PeerInfo>,
    /// `Some(reason)` when private-mode isolation checks fail. While set,
    /// `publish`, `poll` and `history` must return [`TransportError::Isolation`].
    pub isolation_violation: Option<String>,
    /// Sanitized human-readable detail (no addresses of third parties, no keys).
    pub detail: String,
}

/// Errors returned by every [`Transport`] operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// Node unreachable, no peers, timeout. Retry later.
    #[error("transport unavailable: {0}")]
    Unavailable(String),
    /// The frame can never be accepted (retrying is pointless).
    #[error("frame too large: {size} bytes exceeds maximum {max}")]
    TooLarge {
        /// Payload size that was offered.
        size: usize,
        /// Largest accepted payload size.
        max: usize,
    },
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

/// The transport seam; see the module docs for the contract.
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
