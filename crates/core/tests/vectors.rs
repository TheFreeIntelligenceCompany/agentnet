//! Published test vectors (owner condition 8, restated for ADR 0004).
//!
//! * `tests/data/a3.pub.asc`, `a4.sec.asc`, `a7.msg.asc`, `a85.msg.asc` are the
//!   armored blocks of RFC 9580 (https://www.rfc-editor.org/rfc/rfc9580.txt)
//!   Appendix A.3 (v6 transferable public key), A.4 (v6 secret key),
//!   A.7 (inline-signed message) and A.8.5 (SEIPD v2 / AES-128-OCB message with a
//!   trailing Padding packet, to the A.4 key). They were extracted by script
//!   from the RFC text by the spike (`results/a2-openpgp/rfc9580-vectors/SOURCE.txt`
//!   lists the line ranges); none was typed from memory. They are run through
//!   the same library (Sequoia, OpenSSL 3 backend) and the same policy objects
//!   the implementation uses, and through AgentNet's own parser for contacts.
//! * `tests/data/rfc6234_sha256.json` and `rfc4648_base32.json` (SHA-256 and
//!   base32, used only for the address checksum and text form) are as before.
//!
//! The RFC 9180 (HPKE) and RFC 8032 (Ed25519) vector tests were removed with the
//! code they tested; Ed25519 and X25519 now come from the OpenSSL backend of the
//! OpenPGP library and are covered by the RFC 9580 vectors below.

use sequoia_openpgp as openpgp;

use openpgp::crypto::SessionKey;
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::SymmetricAlgorithm;
use openpgp::Cert;

use agentnet_core::crypto::{Address, VerifiedContact};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn data(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap()
}

fn raw(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    std::fs::read(&p).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

// ---------------------------------------------------------------- RFC 6234

#[test]
fn rfc6234_sha256_vectors() {
    let f = data("rfc6234_sha256.json");
    for v in f["vectors"].as_array().unwrap() {
        let d = Sha256::digest(s(v, "message").as_bytes());
        assert_eq!(hex(&d), s(v, "digest"));
    }
}

// ---------------------------------------------------------------- RFC 4648

#[test]
fn rfc4648_base32_vectors_and_the_address_alphabet() {
    let f = data("rfc4648_base32.json");
    for v in f["vectors"].as_array().unwrap() {
        let plain = s(v, "plain").as_bytes();
        let padded = s(v, "base32");
        assert_eq!(data_encoding::BASE32.encode(plain), padded);
        assert_eq!(
            data_encoding::BASE32_NOPAD.encode(plain),
            padded.trim_end_matches('=')
        );
        assert_eq!(
            data_encoding::BASE32.decode(padded.as_bytes()).unwrap(),
            plain
        );
    }
    // an address is "an2" + lowercase RFC 4648 base32 (no padding) of fingerprint || checksum
    let fp = [7u8; 32];
    let text = Address::from_fingerprint(&fp).to_string();
    let body = text.strip_prefix("an2").unwrap();
    assert_eq!(body.len(), 58);
    let raw = data_encoding::BASE32_NOPAD
        .decode(body.to_ascii_uppercase().as_bytes())
        .unwrap();
    assert_eq!(&raw[..32], &fp);
    assert_eq!(raw.len(), 36);
}

// ---------------------------------------------------------------- RFC 9580

const A3_FINGERPRINT: &str = "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9";

/// Appendix A.3: the v6 public key. Its fingerprint (RFC 9580 section 5.5.4.3,
/// SHA2-256 over the primary key packet) is the published one, and it is the
/// same key as the A.4 secret key.
#[test]
fn rfc9580_a3_and_a4_fingerprint_and_policy() {
    let p = StandardPolicy::new();
    let public = Cert::from_bytes(&raw("a3.pub.asc")).unwrap();
    let secret = Cert::from_bytes(&raw("a4.sec.asc")).unwrap();
    assert_eq!(public.fingerprint().to_hex().to_lowercase(), A3_FINGERPRINT);
    assert_eq!(secret.fingerprint(), public.fingerprint());
    assert!(secret.is_tsk() && !public.is_tsk());
    assert!(public.with_policy(&p, None).is_ok());
    assert_eq!(public.primary_key().key().version(), 6);
}

/// The RFC's own certificate parses through AgentNet's contact parser, and its
/// address is its fingerprint.
#[test]
fn rfc9580_a3_is_accepted_as_a_contact_and_names_the_published_fingerprint() {
    // RFC 9580 Appendix A.3 key: created 2022-11-30; evaluate in 2023.
    let now = 1_700_000_000_000;
    let doc = String::from_utf8(raw("a3.pub.asc")).unwrap();
    let c = VerifiedContact::parse_and_verify_allow_expired(&doc, now).unwrap();
    assert_eq!(c.address.as_bytes().to_vec(), unhex(A3_FINGERPRINT));
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

struct Dec<'a> {
    sec: &'a Cert,
    certs: Vec<Cert>,
    good: usize,
}

impl VerificationHelper for Dec<'_> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.certs.clone())
    }
    fn check(&mut self, s: MessageStructure) -> openpgp::Result<()> {
        for layer in s.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for r in results {
                    r.map_err(|e| openpgp::anyhow::anyhow!("bad signature: {e}"))?;
                    self.good += 1;
                }
            }
        }
        Ok(())
    }
}

impl DecryptionHelper for Dec<'_> {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _s: &[SKESK],
        sym: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        for pkesk in pkesks {
            for ka in self.sec.keys().subkeys().unencrypted_secret() {
                let mut pair = ka.key().clone().into_keypair()?;
                if let Some((algo, sk)) = pkesk.decrypt(&mut pair, sym) {
                    if decrypt(algo, &sk) {
                        return Ok(None);
                    }
                }
            }
        }
        Err(openpgp::anyhow::anyhow!("cannot decrypt"))
    }
}

use openpgp::packet::{PKESK, SKESK};

/// Appendix A.8.5: a v6 PKESK + SEIPD v2 (AES-128 OCB) message with a trailing
/// Padding packet, produced by the RFC authors (a third-party padded message),
/// decrypts to "Hello, world!" with the A.4 key.
#[test]
fn rfc9580_a85_seipd2_ocb_with_padding_packet_decrypts() {
    let p = StandardPolicy::new();
    let sec = Cert::from_bytes(&raw("a4.sec.asc")).unwrap();
    let h = Dec {
        sec: &sec,
        certs: vec![],
        good: 0,
    };
    let msg = raw("a85.msg.asc");
    let mut d = DecryptorBuilder::from_bytes(&msg)
        .unwrap()
        .with_policy(&p, None, h)
        .unwrap();
    let mut out = Vec::new();
    std::io::copy(&mut d, &mut out).unwrap();
    assert_eq!(out, b"Hello, world!");
}

/// Appendix A.7: an inline-signed message verifies against the A.3 certificate
/// with exactly one good signature.
#[test]
fn rfc9580_a7_inline_signature_verifies() {
    let p = StandardPolicy::new();
    let cert = Cert::from_bytes(&raw("a3.pub.asc")).unwrap();
    let sec = Cert::from_bytes(&raw("a4.sec.asc")).unwrap();
    let h = Dec {
        sec: &sec,
        certs: vec![cert],
        good: 0,
    };
    let msg = raw("a7.msg.asc");
    let mut v = VerifierBuilder::from_bytes(&msg)
        .unwrap()
        .with_policy(&p, None, h)
        .unwrap();
    let mut out = Vec::new();
    std::io::copy(&mut v, &mut out).unwrap();
    assert!(String::from_utf8_lossy(&out).starts_with("What we need from the grocery store:"));
    assert_eq!(v.helper_ref().good, 1);
}

/// A tampered copy of the A.7 message does not verify (negative control for the above).
#[test]
fn rfc9580_a7_tampered_message_does_not_verify() {
    let p = StandardPolicy::new();
    let cert = Cert::from_bytes(&raw("a3.pub.asc")).unwrap();
    let sec = Cert::from_bytes(&raw("a4.sec.asc")).unwrap();
    let text = String::from_utf8(raw("a7.msg.asc")).unwrap();
    // flip one character inside the armored body (a base64 data line)
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let i = lines
        .iter()
        .position(|l| l.len() > 30 && !l.starts_with("-----"))
        .unwrap();
    let mut b = lines[i].clone().into_bytes();
    b[10] = if b[10] == b'A' { b'B' } else { b'A' };
    lines[i] = String::from_utf8(b).unwrap();
    let tampered = lines.join("\n");
    let h = Dec {
        sec: &sec,
        certs: vec![cert],
        good: 0,
    };
    let r = VerifierBuilder::from_bytes(tampered.as_bytes())
        .and_then(|b| b.with_policy(&p, None, h))
        .and_then(|mut v| {
            let mut out = Vec::new();
            std::io::copy(&mut v, &mut out)?;
            Ok(v.helper_ref().good)
        });
    assert!(!matches!(r, Ok(1)), "a tampered A.7 message must not verify");
}
