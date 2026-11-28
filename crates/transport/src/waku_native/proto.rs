//! Waku v2 protobuf wire definitions and length-prefixed request-response codecs.
//!
//! Field tags and types match `upstream/logos-delivery-v0.39.2`:
//! - `WakuMessage`: `14/WAKU2-MESSAGE` (`waku_core/message/codec.nim`)
//! - `WakuMetadataMessage`: `/vac/waku/metadata/1.0.0` (`waku_metadata/rpc.nim`)
//! - `StoreQueryRequest` / `StoreQueryResponse`: `/vac/waku/store-query/3.0.0` (`waku_store/rpc_codec.nim`)

use std::io;
use std::marker::PhantomData;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::gossipsub;
use libp2p::request_response;
use libp2p::StreamProtocol;
use prost::Message;
use sha2::{Digest, Sha256};

/// Waku Relay GossipSub protocol ID (11/WAKU2-RELAY).
pub const RELAY_PROTOCOL: &str = "/vac/waku/relay/2.0.0";
/// Waku Metadata protocol ID (66/WAKU2-METADATA).
pub const METADATA_PROTOCOL: &str = "/vac/waku/metadata/1.0.0";
/// Waku Store v3 protocol ID (13/WAKU2-STORE v3).
pub const STORE_PROTOCOL: &str = "/vac/waku/store-query/3.0.0";

/// Maximum encoded size for a `/vac/waku/metadata/1.0.0` message (64 KiB).
pub const MAX_METADATA_BYTES: usize = 64 * 1024;
/// Maximum encoded size for a `/vac/waku/store-query/3.0.0` request (1 MiB).
pub const MAX_STORE_REQUEST_BYTES: usize = 1024 * 1024;
/// Maximum encoded size for a `/vac/waku/store-query/3.0.0` response (16 MiB).
pub const MAX_STORE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// 14/WAKU2-MESSAGE protobuf wire structure.
#[derive(Clone, PartialEq, Message)]
pub struct WakuMessage {
    /// Opaque payload bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub payload: Vec<u8>,
    /// Content topic (`/<app>/<ver>/<name>/<enc>`).
    #[prost(string, tag = "2")]
    pub content_topic: String,
    /// Protocol version (always 0 in Waku v2).
    #[prost(uint32, optional, tag = "3")]
    pub version: Option<u32>,
    /// Publisher timestamp in Unix nanoseconds (zigzag `sint64`).
    #[prost(sint64, optional, tag = "10")]
    pub timestamp: Option<i64>,
    /// Optional metadata bytes.
    #[prost(bytes = "vec", optional, tag = "11")]
    pub meta: Option<Vec<u8>>,
    /// Optional RLN rate-limit proof (unused in private clusters).
    #[prost(bytes = "vec", optional, tag = "21")]
    pub proof: Option<Vec<u8>>,
    /// When true, Store nodes must not persist this message.
    #[prost(bool, optional, tag = "31")]
    pub ephemeral: Option<bool>,
}

/// 66/WAKU2-METADATA request and response message.
///
/// `nwaku` encodes `shards` as unpacked repeated `uint32` on tag 2, and also
/// accepts packed repeated `uint32` on tag 3. We emit tag 2 (unpacked) and
/// accept both tags when decoding.
#[derive(Clone, PartialEq, Message)]
pub struct WakuMetadataMessage {
    /// Cluster ID.
    #[prost(uint32, optional, tag = "1")]
    pub cluster_id: Option<u32>,
    /// Shard indices (unpacked repeated uint32, tag 2).
    #[prost(uint32, repeated, packed = "false", tag = "2")]
    pub shards: Vec<u32>,
    /// Alternate packed shard indices (tag 3), accepted on decode for interop.
    #[prost(uint32, repeated, tag = "3")]
    pub shards_packed: Vec<u32>,
}

impl WakuMetadataMessage {
    /// Builds a metadata message for a single cluster and shard.
    pub fn single(cluster_id: u16, shard: u16) -> Self {
        Self {
            cluster_id: Some(u32::from(cluster_id)),
            shards: vec![u32::from(shard)],
            shards_packed: Vec::new(),
        }
    }

    /// Returns whether this peer's metadata includes `(cluster_id, shard)`.
    pub fn supports(&self, cluster_id: u16, shard: u16) -> bool {
        let cid_ok = self.cluster_id == Some(u32::from(cluster_id));
        let target = u32::from(shard);
        let shard_ok = self.shards.contains(&target) || self.shards_packed.contains(&target);
        cid_ok && shard_ok
    }
}

/// 13/WAKU2-STORE v3 query request.
#[derive(Clone, PartialEq, Message)]
pub struct StoreQueryRequest {
    /// Caller-chosen request ID echoed in the response.
    #[prost(string, tag = "1")]
    pub request_id: String,
    /// When true, return full `WakuMessage` payloads; otherwise hashes only.
    #[prost(bool, tag = "2")]
    pub include_data: bool,
    /// Optional pubsub topic filter.
    #[prost(string, optional, tag = "10")]
    pub pubsub_topic: Option<String>,
    /// Optional content topic filter list.
    #[prost(string, repeated, tag = "11")]
    pub content_topics: Vec<String>,
    /// Optional inclusive start timestamp (Unix nanoseconds, `sint64`).
    #[prost(sint64, optional, tag = "12")]
    pub time_start: Option<i64>,
    /// Optional inclusive end timestamp (Unix nanoseconds, `sint64`).
    #[prost(sint64, optional, tag = "13")]
    pub time_end: Option<i64>,
    /// Optional explicit message hash lookup list.
    #[prost(bytes = "vec", repeated, tag = "20")]
    pub message_hashes: Vec<Vec<u8>>,
    /// Optional pagination cursor (32-byte Waku message hash).
    #[prost(bytes = "vec", optional, tag = "51")]
    pub pagination_cursor: Option<Vec<u8>>,
    /// `true` = forward (ascending), `false` = backward (descending).
    #[prost(bool, tag = "52")]
    pub pagination_forward: bool,
    /// Optional maximum records per page.
    #[prost(uint64, optional, tag = "53")]
    pub pagination_limit: Option<u64>,
}

/// One stored message entry returned in [`StoreQueryResponse`].
#[derive(Clone, PartialEq, Message)]
pub struct WakuMessageKeyValue {
    /// 32-byte deterministic Waku message hash.
    #[prost(bytes = "vec", tag = "1")]
    pub message_hash: Vec<u8>,
    /// Present when `include_data = true`.
    #[prost(message, optional, tag = "2")]
    pub message: Option<WakuMessage>,
    /// Pubsub topic the message was archived under.
    #[prost(string, optional, tag = "3")]
    pub pubsub_topic: Option<String>,
}

/// 13/WAKU2-STORE v3 query response.
#[derive(Clone, PartialEq, Message)]
pub struct StoreQueryResponse {
    /// Echoed request ID.
    #[prost(string, tag = "1")]
    pub request_id: String,
    /// HTTP-style status code (200 = OK, 400 = bad request, 500 = server error).
    #[prost(uint32, optional, tag = "10")]
    pub status_code: Option<u32>,
    /// Human-readable status description.
    #[prost(string, optional, tag = "11")]
    pub status_desc: Option<String>,
    /// Matching stored messages in requested pagination order.
    #[prost(message, repeated, tag = "20")]
    pub messages: Vec<WakuMessageKeyValue>,
    /// Cursor for fetching the next page, if more entries remain.
    #[prost(bytes = "vec", optional, tag = "51")]
    pub pagination_cursor: Option<Vec<u8>>,
}

/// GossipSub deduplication ID function matching `nwaku`'s
/// `waku_relay/message_id.nim`: `SHA-256(message.data)`.
pub fn gossipsub_message_id(msg: &gossipsub::Message) -> gossipsub::MessageId {
    let digest = Sha256::digest(&msg.data);
    gossipsub::MessageId::from(digest.to_vec())
}

/// Reads an unsigned LEB128 varint (up to 64 bits, 10 bytes max).
async fn read_varint<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<u64> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut byte = [0u8; 1];
    for _ in 0..10 {
        io.read_exact(&mut byte).await?;
        let b = byte[0];
        let low = u64::from(b & 0x7f);
        if shift == 63 && low > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "varint overflow",
            ));
        }
        value |= low << shift;
        if (b & 0x80) == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "varint exceeded 10 bytes",
    ))
}

/// Encodes `v` as an unsigned LEB128 varint into `buf`.
fn encode_varint(mut v: u64, buf: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        buf.push(b);
        if v == 0 {
            break;
        }
    }
}

async fn read_lp_proto<T, M>(io: &mut T, max_len: usize) -> io::Result<M>
where
    T: AsyncRead + Unpin,
    M: Message + Default,
{
    let len_u64 = read_varint(io).await?;
    let len = usize::try_from(len_u64)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length overflow"))?;
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame length {len} exceeds maximum {max_len}"),
        ));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    M::decode(buf.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

async fn write_lp_proto<T, M>(io: &mut T, msg: &M, max_len: usize) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
    M: Message,
{
    let body = msg.encode_to_vec();
    if body.len() > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame length {} exceeds maximum {max_len}", body.len()),
        ));
    }
    let mut header = Vec::with_capacity(10);
    encode_varint(body.len() as u64, &mut header);
    io.write_all(&header).await?;
    io.write_all(&body).await?;
    io.flush().await
}

/// Generic varint length-prefixed protobuf codec for `libp2p-request-response`.
#[derive(Debug)]
pub struct VarintProtoCodec<Req, Resp, const MAX_REQ: usize, const MAX_RESP: usize> {
    _marker: PhantomData<fn(Req) -> Resp>,
}

impl<Req, Resp, const MAX_REQ: usize, const MAX_RESP: usize> Default
    for VarintProtoCodec<Req, Resp, MAX_REQ, MAX_RESP>
{
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<Req, Resp, const MAX_REQ: usize, const MAX_RESP: usize> Clone
    for VarintProtoCodec<Req, Resp, MAX_REQ, MAX_RESP>
{
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<Req, Resp, const MAX_REQ: usize, const MAX_RESP: usize> request_response::Codec
    for VarintProtoCodec<Req, Resp, MAX_REQ, MAX_RESP>
where
    Req: Message + Default + Send + 'static,
    Resp: Message + Default + Send + 'static,
{
    type Protocol = StreamProtocol;
    type Request = Req;
    type Response = Resp;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_lp_proto(io, MAX_REQ).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_lp_proto(io, MAX_RESP).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_lp_proto(io, &req, MAX_REQ).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_lp_proto(io, &res, MAX_RESP).await
    }
}

/// Codec for `/vac/waku/metadata/1.0.0`.
pub type MetadataCodec = VarintProtoCodec<
    WakuMetadataMessage,
    WakuMetadataMessage,
    MAX_METADATA_BYTES,
    MAX_METADATA_BYTES,
>;

/// Codec for `/vac/waku/store-query/3.0.0`.
pub type StoreCodec = VarintProtoCodec<
    StoreQueryRequest,
    StoreQueryResponse,
    MAX_STORE_REQUEST_BYTES,
    MAX_STORE_RESPONSE_BYTES,
>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waku_common::waku_message_hash;

    #[test]
    fn waku_message_roundtrip_and_sint64_timestamp() {
        let msg = WakuMessage {
            payload: b"hello waku".to_vec(),
            content_topic: "/agentnet/1/inbox-01/proto".into(),
            version: Some(0),
            timestamp: Some(1_795_706_642_062_000_000),
            meta: Some(vec![]),
            proof: None,
            ephemeral: Some(false),
        };
        let bytes = msg.encode_to_vec();
        let decoded = WakuMessage::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, msg);
        // Tag 10 wire type 0 (varint) => (10 << 3) | 0 = 0x50; zigzag encoding of positive n is 2*n.
        assert!(bytes.contains(&0x50));
        let h = waku_message_hash(
            "/waku/2/rs/66/0",
            &decoded.payload,
            &decoded.content_topic,
            decoded.meta.as_deref().unwrap_or(&[]),
            decoded.timestamp.unwrap(),
        );
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn metadata_supports_unpacked_and_packed_shards() {
        let unpacked = WakuMetadataMessage::single(66, 0);
        assert!(unpacked.supports(66, 0));
        assert!(!unpacked.supports(66, 1));
        assert!(!unpacked.supports(1, 0));
        let packed = WakuMetadataMessage {
            cluster_id: Some(66),
            shards: vec![],
            shards_packed: vec![0, 2],
        };
        assert!(packed.supports(66, 0));
        assert!(packed.supports(66, 2));
        assert!(!packed.supports(66, 1));
    }

    #[tokio::test]
    async fn varint_lp_codec_roundtrip_and_size_cap() {
        let mut codec = MetadataCodec::default();
        let proto = StreamProtocol::new(METADATA_PROTOCOL);
        let req = WakuMetadataMessage::single(66, 0);
        let mut wire = Vec::new();
        request_response::Codec::write_request(&mut codec, &proto, &mut wire, req.clone())
            .await
            .unwrap();
        let mut cursor = futures::io::Cursor::new(wire);
        let back = request_response::Codec::read_request(&mut codec, &proto, &mut cursor)
            .await
            .unwrap();
        assert_eq!(back, req);

        // Oversize length prefix is rejected without allocating huge buffers.
        let mut huge = Vec::new();
        encode_varint((MAX_METADATA_BYTES as u64) + 1, &mut huge);
        let mut cursor = futures::io::Cursor::new(huge);
        assert!(
            request_response::Codec::read_request(&mut codec, &proto, &mut cursor)
                .await
                .is_err()
        );
    }
}
