//! Shared, library-independent glue: the AgentNet-like payload and a tiny argument parser.
//! Nothing here is cryptographic.
#![allow(dead_code)]

use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An AgentNet-like application payload. In the OpenPGP design this JSON is the *body* of the
/// literal data packet; the sender and recipient fields are application-level claims that the
/// receiver must check against the cryptographically verified signer / own certificate.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub v: u32,
    pub message_id: String,
    /// Lowercase hex v6 fingerprint of the sender's primary key (32 bytes = 64 hex chars).
    pub sender: String,
    /// Lowercase hex v6 fingerprint of the recipient's primary key.
    pub recipient: String,
    pub created_at: i64,
    pub ttl_s: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub body: String,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

pub fn random_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Deterministic printable body of exactly `len` bytes (ASCII, so JSON adds no escapes).
pub fn body_of_len(len: usize) -> String {
    (0..len).map(|i| (b'a' + (i % 26) as u8) as char).collect()
}

pub fn make_payload(sender: &str, recipient: &str, body_len: usize) -> Vec<u8> {
    let p = Payload {
        v: 1,
        message_id: random_id(),
        sender: sender.into(),
        recipient: recipient.into(),
        created_at: now_ms(),
        ttl_s: 3600,
        kind: "message".into(),
        body: body_of_len(body_len),
    };
    serde_json::to_vec(&p).unwrap()
}

/// Application-level checks that stay with AgentNet whatever the crypto layer is.
pub fn check_payload(bytes: &[u8], signer: &str, me: &str, now: i64) -> Result<Payload> {
    let p: Payload =
        serde_json::from_slice(bytes).map_err(|e| anyhow!("payload not valid: {e}"))?;
    if p.v != 1 {
        bail!("unknown payload version {}", p.v);
    }
    if p.sender != signer {
        bail!("payload.sender {} != verified signer {}", p.sender, signer);
    }
    if p.recipient != me {
        bail!("payload.recipient {} != my fingerprint {}", p.recipient, me);
    }
    if p.created_at > now + 120_000 {
        bail!("created in the future");
    }
    if p.created_at + (p.ttl_s as i64) * 1000 <= now {
        bail!("expired");
    }
    Ok(p)
}

/// Target total size (bytes of the inner packet sequence, padding packet header included) for
/// a given unpadded size `n`. `none` => n; `pow2` => smallest power of two >= max(512, n + 2).
pub fn padded_total(n: u64, mode: &str) -> u64 {
    match mode {
        "pow2" => {
            let mut t = 512u64;
            while t < n + 2 {
                t *= 2;
            }
            t
        }
        _ => n,
    }
}

/// Body length of a padding packet so that header + body == `want` bytes (new-format header).
pub fn padding_body_for_total(want: u64) -> u64 {
    // new-format length encoding: 1 tag byte + 1 (<192), 2 (<8384) or 5 length bytes
    for h in [2u64, 3, 6] {
        if want < h {
            continue;
        }
        let body = want - h;
        let ok = match h {
            2 => body < 192,
            3 => (192..8384).contains(&body),
            _ => body >= 8384,
        };
        if ok {
            return body;
        }
    }
    0
}

pub struct Args(pub HashMap<String, String>, pub Vec<String>);

impl Args {
    pub fn parse(argv: &[String]) -> Args {
        let mut m = HashMap::new();
        let mut pos = vec![];
        let mut i = 0;
        while i < argv.len() {
            if let Some(k) = argv[i].strip_prefix("--") {
                if i + 1 < argv.len() && !argv[i + 1].starts_with("--") {
                    m.insert(k.to_string(), argv[i + 1].clone());
                    i += 2;
                } else {
                    m.insert(k.to_string(), "true".into());
                    i += 1;
                }
            } else {
                pos.push(argv[i].clone());
                i += 1;
            }
        }
        Args(m, pos)
    }
    pub fn get(&self, k: &str) -> Result<&str> {
        self.0
            .get(k)
            .map(|s| s.as_str())
            .ok_or_else(|| anyhow!("missing --{k}"))
    }
    pub fn opt(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(|s| s.as_str())
    }
    pub fn flag(&self, k: &str) -> bool {
        self.0.get(k).map(|v| v == "true").unwrap_or(false)
    }
    pub fn num(&self, k: &str, d: u64) -> u64 {
        self.0.get(k).and_then(|v| v.parse().ok()).unwrap_or(d)
    }
}
