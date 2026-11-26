//! Agent addresses: `an1` + base32(pk || checksum).
//!
//! An address *is* the agent's Ed25519 signing public key, plus a 4-byte typo
//! checksum. The checksum is not a security mechanism. See `docs/protocol.md`.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use agentnet_transport::ContentTopic;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::AddressError;

/// Domain separation for the address checksum.
pub const ADDRESS_CHECKSUM_DOMAIN: &[u8] = b"agentnet/v1/address-checksum";
/// Domain separation for inbox topic derivation.
pub const INBOX_TOPIC_DOMAIN: &[u8] = b"agentnet/v1/inbox-topic";
/// Human-readable prefix of every v1 address.
pub const ADDRESS_PREFIX: &str = "an1";
/// Length of the checksum in bytes.
pub const CHECKSUM_LEN: usize = 4;
/// Length of the base32 part (36 bytes -> 58 characters).
const BASE32_LEN: usize = 58;
/// Total length of the string form.
pub const ADDRESS_STR_LEN: usize = 3 + BASE32_LEN;

/// Smallest and largest valid number of inbox buckets.
pub const MIN_INBOX_BUCKETS: u16 = 1;
pub const MAX_INBOX_BUCKETS: u16 = 256;
/// Default number of inbox buckets.
pub const DEFAULT_INBOX_BUCKETS: u16 = 16;

/// An agent address: a validated Ed25519 public key.
#[derive(Clone, Copy)]
pub struct Address {
    bytes: [u8; 32],
    key: VerifyingKey,
}

fn checksum(pk: &[u8; 32]) -> [u8; CHECKSUM_LEN] {
    let mut h = Sha256::new();
    h.update(ADDRESS_CHECKSUM_DOMAIN);
    h.update(pk);
    let d = h.finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&d[..CHECKSUM_LEN]);
    out
}

impl Address {
    /// Build an address from raw public key bytes.
    ///
    /// The key must decode to a point on the curve in canonical encoding and
    /// must not be a weak (small-order) key, i.e. it must be acceptable to
    /// `verify_strict`.
    pub fn from_public_key(pk: &[u8; 32]) -> Result<Self, AddressError> {
        let key = VerifyingKey::from_bytes(pk).map_err(|_| AddressError::InvalidKey)?;
        if key.is_weak() {
            return Err(AddressError::InvalidKey);
        }
        // Reject non-canonical encodings (y >= p): re-compress and compare.
        if key.to_edwards().compress().to_bytes() != *pk {
            return Err(AddressError::InvalidKey);
        }
        Ok(Self { bytes: *pk, key })
    }

    /// Build an address from a verifying key (checked like [`Self::from_public_key`]).
    pub fn from_verifying_key(key: &VerifyingKey) -> Result<Self, AddressError> {
        Self::from_public_key(key.as_bytes())
    }

    /// The raw 32-byte Ed25519 public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// The Ed25519 verifying key (already validated).
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }

    /// Inbox bucket index for `inbox_buckets` buckets (`1..=256`; 0 is treated as 1).
    pub fn inbox_bucket(&self, inbox_buckets: u16) -> u16 {
        let mut h = Sha256::new();
        h.update(INBOX_TOPIC_DOMAIN);
        h.update(self.bytes);
        let d = h.finalize();
        u16::from_be_bytes([d[0], d[1]]) % inbox_buckets.max(1)
    }

    /// Content topic of this address's inbox: `/agentnet/1/inbox-<hh>/proto`.
    ///
    /// `inbox_buckets` must be in `1..=256` (enforced everywhere it is parsed);
    /// larger values would produce a 3-digit bucket, which is still a valid
    /// content topic but is not part of the protocol.
    pub fn inbox_topic(&self, inbox_buckets: u16) -> ContentTopic {
        let b = self.inbox_bucket(inbox_buckets);
        // The format is statically valid for every bucket value, so this
        // cannot fail (covered by a test over all buckets).
        ContentTopic::new(format!("/agentnet/1/inbox-{b:02x}/proto"))
            .expect("inbox topic format is statically valid")
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl Eq for Address {}
impl Hash for Address {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}
impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Address {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut raw = [0u8; 36];
        raw[..32].copy_from_slice(&self.bytes);
        raw[32..].copy_from_slice(&checksum(&self.bytes));
        write!(
            f,
            "{ADDRESS_PREFIX}{}",
            BASE32_NOPAD.encode(&raw).to_ascii_lowercase()
        )
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix(ADDRESS_PREFIX)
            .ok_or(AddressError::BadPrefix)?;
        if rest.len() != BASE32_LEN {
            return Err(AddressError::BadLength);
        }
        if !rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        {
            return Err(AddressError::BadEncoding);
        }
        // data-encoding rejects non-zero trailing bits by default.
        let raw = BASE32_NOPAD
            .decode(rest.to_ascii_uppercase().as_bytes())
            .map_err(|_| AddressError::BadEncoding)?;
        let (pk_b, ck_b) = raw.split_at_checked(32).ok_or(AddressError::BadEncoding)?;
        let pk: [u8; 32] = pk_b.try_into().map_err(|_| AddressError::BadEncoding)?;
        if ck_b != checksum(&pk) {
            return Err(AddressError::BadChecksum);
        }
        Self::from_public_key(&pk)
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    #[test]
    fn known_vector() {
        // Generated once (seed [7; 32]) and cross-checked with an independent
        // Python implementation; detects accidental format changes.
        let pk = key(7);
        let a = Address::from_public_key(&pk).unwrap();
        let s = a.to_string();
        assert_eq!(s.len(), ADDRESS_STR_LEN);
        assert_eq!(s, KNOWN_ADDRESS, "address wire format changed");
        assert_eq!(s.parse::<Address>().unwrap(), a);
    }
    const KNOWN_ADDRESS: &str = "an15jfgyy7ctrjavpxvkb5rglwf7gkuo5vox27hxescd3vgsfcg2iwicroqze";

    #[test]
    fn roundtrip_and_serde() {
        for seed in 0..20u8 {
            let a = Address::from_public_key(&key(seed)).unwrap();
            let s = a.to_string();
            assert_eq!(s.parse::<Address>().unwrap(), a);
            let j = serde_json::to_string(&a).unwrap();
            assert_eq!(j, format!("\"{s}\""));
            assert_eq!(serde_json::from_str::<Address>(&j).unwrap(), a);
        }
    }

    #[test]
    fn strictness() {
        let a = Address::from_public_key(&key(1)).unwrap().to_string();
        assert_eq!(
            a.to_ascii_uppercase().parse::<Address>(),
            Err(AddressError::BadPrefix)
        );
        let up = format!("an1{}", a[3..].to_ascii_uppercase());
        assert_eq!(up.parse::<Address>(), Err(AddressError::BadEncoding));
        assert_eq!(
            a[..a.len() - 1].parse::<Address>(),
            Err(AddressError::BadLength)
        );
        assert_eq!(
            format!("{a}a").parse::<Address>(),
            Err(AddressError::BadLength)
        );
        assert_eq!("".parse::<Address>(), Err(AddressError::BadPrefix));
        assert_eq!(
            format!("an1{}", "1".repeat(58)).parse::<Address>(),
            Err(AddressError::BadEncoding)
        );
        // flip one character -> checksum (or encoding) failure
        let mut b = a.clone().into_bytes();
        b[10] = if b[10] == b'a' { b'b' } else { b'a' };
        assert!(String::from_utf8(b).unwrap().parse::<Address>().is_err());
        // non-ASCII input must not panic
        assert!("an1\u{e9}\u{e9}".parse::<Address>().is_err());
        assert!(format!("an1{}", "\u{e9}".repeat(29))
            .parse::<Address>()
            .is_err());
    }

    #[test]
    fn trailing_bits_must_be_zero() {
        // 58 chars carry 290 bits for 288 data bits: the low 2 bits of the last char are padding.
        let a = Address::from_public_key(&key(3)).unwrap().to_string();
        let last = a.as_bytes()[a.len() - 1];
        let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
        let idx = alphabet.iter().position(|c| *c == last).unwrap();
        assert_eq!(idx & 0b11, 0, "canonical encoding has zero trailing bits");
        let mut b = a.into_bytes();
        let n = b.len();
        b[n - 1] = alphabet[idx | 2];
        assert!(String::from_utf8(b).unwrap().parse::<Address>().is_err());
    }

    fn address_str_for(pk: &[u8; 32]) -> String {
        let mut raw = [0u8; 36];
        raw[..32].copy_from_slice(pk);
        raw[32..].copy_from_slice(&checksum(pk));
        format!("an1{}", BASE32_NOPAD.encode(&raw).to_ascii_lowercase())
    }

    #[test]
    fn rejects_weak_keys() {
        // identity point (y = 1) and order-2 point (y = -1)
        let mut ident = [0u8; 32];
        ident[0] = 1;
        assert_eq!(
            Address::from_public_key(&ident),
            Err(AddressError::InvalidKey)
        );
        assert_eq!(
            address_str_for(&ident).parse::<Address>(),
            Err(AddressError::InvalidKey)
        );
        let mut m1 = [0xffu8; 32];
        m1[0] = 0xec;
        m1[31] = 0x7f;
        assert_eq!(Address::from_public_key(&m1), Err(AddressError::InvalidKey));
        // y = 0 is an order-4 point
        assert_eq!(
            Address::from_public_key(&[0u8; 32]),
            Err(AddressError::InvalidKey)
        );
    }

    #[test]
    fn rejects_non_canonical_point_encoding() {
        // y' = y + p for small y has the same field element as y.
        let mut found = 0;
        for y in 2u8..19 {
            let mut canon = [0u8; 32];
            canon[0] = y;
            let Ok(vk) = VerifyingKey::from_bytes(&canon) else {
                continue;
            };
            if vk.is_weak() {
                continue;
            }
            // p = 2^255 - 19 -> p + y = 0x7fff..ff(ed + y)
            let mut nc = [0xffu8; 32];
            nc[0] = 0xed + y;
            nc[31] = 0x7f;
            assert!(Address::from_public_key(&canon).is_ok());
            assert_eq!(Address::from_public_key(&nc), Err(AddressError::InvalidKey));
            found += 1;
        }
        assert!(found > 0, "no test point found");
    }

    #[test]
    fn topic_vector_and_all_buckets_valid() {
        let a = Address::from_public_key(&key(7)).unwrap();
        assert_eq!(a.inbox_topic(16).as_str(), KNOWN_TOPIC16);
        assert_eq!(a.inbox_topic(256).as_str(), KNOWN_TOPIC256);
        assert_eq!(a.inbox_topic(1).as_str(), "/agentnet/1/inbox-00/proto");
        for n in 1..=256u16 {
            let b = a.inbox_bucket(n);
            assert!(b < n);
            let t = a.inbox_topic(n);
            assert_eq!(t.as_str().len(), "/agentnet/1/inbox-00/proto".len());
        }
    }
    const KNOWN_TOPIC16: &str = "/agentnet/1/inbox-06/proto";
    const KNOWN_TOPIC256: &str = "/agentnet/1/inbox-c6/proto";

    #[test]
    fn ordering_and_hash() {
        use std::collections::HashSet;
        let a = Address::from_public_key(&key(1)).unwrap();
        let b = Address::from_public_key(&key(2)).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.cmp(&b), a.as_bytes().cmp(b.as_bytes()));
        let set: HashSet<Address> = [a, b, a].into_iter().collect();
        assert_eq!(set.len(), 2);
    }
}
