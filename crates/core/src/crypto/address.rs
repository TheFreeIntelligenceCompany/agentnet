//! Agent addresses: `an2` + base32(fingerprint || checksum).
//!
//! An address *is* the 32-byte RFC 9580 v6 fingerprint of the agent's OpenPGP
//! primary key, plus a 4-byte typo checksum. The checksum is not a security
//! mechanism. A fingerprint pins a certificate (it is a SHA-256 hash over the
//! primary key packet) but cannot verify anything by itself: the certificate
//! is the contact record. See `docs/protocol.md`.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use agentnet_transport::ContentTopic;
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::AddressError;

/// Domain separation for the address checksum (a typo guard, not a security mechanism).
pub const ADDRESS_CHECKSUM_DOMAIN: &[u8] = b"agentnet/v2/address-checksum";
/// Human-readable prefix of every address of this format.
pub const ADDRESS_PREFIX: &str = "an2";
/// Length of the checksum in bytes.
pub const CHECKSUM_LEN: usize = 4;
/// Length of the base32 part (36 bytes -> 58 characters).
const BASE32_LEN: usize = 58;
/// Total length of the string form.
pub const ADDRESS_STR_LEN: usize = 3 + BASE32_LEN;

/// Number of inbox buckets. A protocol constant: the bucket is taken from the
/// leading bytes of the fingerprint (already a SHA-256 output), so no per-agent
/// setting or signed field is needed.
pub const INBOX_BUCKETS: u16 = 16;

/// An agent address: a v6 primary-key fingerprint.
#[derive(Clone, Copy)]
pub struct Address {
    fp: [u8; 32],
}

fn checksum(fp: &[u8; 32]) -> [u8; CHECKSUM_LEN] {
    let mut h = Sha256::new();
    h.update(ADDRESS_CHECKSUM_DOMAIN);
    h.update(fp);
    let d = h.finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&d[..CHECKSUM_LEN]);
    out
}

impl Address {
    /// Build an address from a 32-byte v6 fingerprint.
    pub fn from_fingerprint(fp: &[u8; 32]) -> Self {
        Self { fp: *fp }
    }

    /// The raw 32-byte fingerprint.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.fp
    }

    /// Inbox bucket index: `u16_be(fingerprint[0..2]) % INBOX_BUCKETS`.
    pub fn inbox_bucket(&self) -> u16 {
        u16::from_be_bytes([self.fp[0], self.fp[1]]) % INBOX_BUCKETS
    }

    /// Content topic of this address's inbox: `/agentnet/1/inbox-<hh>/proto`.
    pub fn inbox_topic(&self) -> ContentTopic {
        let b = self.inbox_bucket();
        // The format is statically valid for every bucket value.
        ContentTopic::new(format!("/agentnet/1/inbox-{b:02x}/proto"))
            .expect("inbox topic format is statically valid")
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.fp == other.fp
    }
}
impl Eq for Address {}
impl Hash for Address {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fp.hash(state);
    }
}
impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Address {
    fn cmp(&self, other: &Self) -> Ordering {
        self.fp.cmp(&other.fp)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut raw = [0u8; 36];
        raw[..32].copy_from_slice(&self.fp);
        raw[32..].copy_from_slice(&checksum(&self.fp));
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
        let (fp_b, ck_b) = raw.split_at_checked(32).ok_or(AddressError::BadEncoding)?;
        let fp: [u8; 32] = fp_b.try_into().map_err(|_| AddressError::BadEncoding)?;
        if ck_b != checksum(&fp) {
            return Err(AddressError::BadChecksum);
        }
        Ok(Self { fp })
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

    fn fp(seed: u8) -> [u8; 32] {
        let mut f = [0u8; 32];
        for (i, b) in f.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8).wrapping_mul(7);
        }
        f
    }

    #[test]
    fn roundtrip_and_serde() {
        for seed in 0..20u8 {
            let a = Address::from_fingerprint(&fp(seed));
            let s = a.to_string();
            assert_eq!(s.len(), ADDRESS_STR_LEN);
            assert!(s.starts_with("an2"));
            let back: Address = s.parse().unwrap();
            assert_eq!(a, back);
            let j = serde_json::to_string(&a).unwrap();
            assert_eq!(j, format!("\"{s}\""));
            assert_eq!(serde_json::from_str::<Address>(&j).unwrap(), a);
        }
    }

    #[test]
    fn strictness() {
        let a = Address::from_fingerprint(&fp(1)).to_string();
        assert_eq!(a.parse::<Address>().map(|_| ()), Ok(()));
        assert_eq!(
            a.replacen("an2", "an1", 1).parse::<Address>(),
            Err(AddressError::BadPrefix)
        );
        assert_eq!(
            "".parse::<Address>().unwrap_err(),
            AddressError::BadPrefix
        );
        assert_eq!(
            format!("{a}a").parse::<Address>(),
            Err(AddressError::BadLength)
        );
        assert_eq!(
            a[..a.len() - 1].parse::<Address>(),
            Err(AddressError::BadLength)
        );
        assert_eq!(
            a.to_uppercase().parse::<Address>(),
            Err(AddressError::BadPrefix)
        );
        let mut bad = a.clone().into_bytes();
        bad[10] = b'1';
        assert_eq!(
            String::from_utf8(bad).unwrap().parse::<Address>(),
            Err(AddressError::BadEncoding)
        );
        // flip one character of the body: either checksum or encoding error
        let mut flipped = a.clone().into_bytes();
        flipped[20] = if flipped[20] == b'a' { b'b' } else { b'a' };
        assert!(String::from_utf8(flipped).unwrap().parse::<Address>().is_err());
    }

    #[test]
    fn trailing_bits_must_be_zero() {
        // 36 bytes = 288 bits = 57.6 base32 characters: the last character carries
        // 3 unused bits that must be zero.
        let a = Address::from_fingerprint(&fp(3)).to_string();
        let last = a.chars().last().unwrap();
        let alt = if last == 'a' { 'b' } else { 'a' };
        let mut s = a;
        s.pop();
        s.push(alt);
        assert!(s.parse::<Address>().is_err());
    }

    #[test]
    fn topic_and_all_buckets_valid() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..=255u8 {
            let mut f = fp(0);
            f[1] = i;
            let t = Address::from_fingerprint(&f).inbox_topic();
            assert_eq!(t.as_str().len(), "/agentnet/1/inbox-00/proto".len());
            seen.insert(t.to_string());
        }
        assert_eq!(seen.len(), INBOX_BUCKETS as usize);
        let mut f = [0u8; 32];
        f[1] = 0x35;
        assert_eq!(
            Address::from_fingerprint(&f).inbox_topic().as_str(),
            "/agentnet/1/inbox-05/proto"
        );
    }

    #[test]
    fn ordering_and_hash() {
        let a = Address::from_fingerprint(&fp(1));
        let b = Address::from_fingerprint(&fp(2));
        assert_ne!(a, b);
        assert_eq!(a.cmp(&b), a.as_bytes().cmp(b.as_bytes()));
        let mut set = std::collections::HashSet::new();
        set.insert(a);
        assert!(set.contains(&a) && !set.contains(&b));
    }
}
