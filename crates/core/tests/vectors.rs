//! Published test vectors and frozen known-answer tests (owner condition 8).
//!
//! The vectors in `tests/data/rfc*.json` were extracted by a script from the
//! RFC texts downloaded from rfc-editor.org (source URL, section and retrieval
//! date are recorded in each file); none was typed from memory. They are run
//! through the same library APIs the implementation uses.
//!
//! `tests/data/kat_v1.json` is different: it was generated once by this
//! implementation from fixed seeds and frozen. It protects against accidental
//! format changes (address, inbox topic, contact-record and envelope signature
//! inputs, a sealed frame); it is NOT independent evidence of correctness.
//! Regenerate deliberately with `AGENTNET_REGEN_KAT=1 cargo test --test vectors`.

use std::convert::Infallible;

use agentnet_core::crypto::envelope::testing::{seal_presigned, sign_envelope_bytes};
use agentnet_core::crypto::envelope::{
    open, seal, Envelope, OpenLimits, CIPHERTEXT_OFFSET, ENC_OFFSET, ENVELOPE_DOMAIN,
    HPKE_INFO_DOMAIN,
};
use agentnet_core::crypto::{Address, Identity, VerifiedContact};
use agentnet_core::contact::CONTACT_RECORD_DOMAIN;
use ed25519_dalek::{Signature, Signer, SigningKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use serde_json::Value;
use sha2::{Digest, Sha256};

type Kem = X25519HkdfSha256;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn data(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

// ----------------------------------------------------------------- RFC 9180

/// A "random" source that returns fixed bytes, so that the HPKE ephemeral key
/// of RFC 9180 Appendix A.2.1 (derived from `ikmE`) can be reproduced.
struct FixedRng(Vec<u8>);

impl hpke::rand_core::TryRng for FixedRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        assert!(self.0.len() >= dst.len(), "test RNG exhausted");
        let rest = self.0.split_off(dst.len());
        dst.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}
impl hpke::rand_core::TryCryptoRng for FixedRng {}

#[test]
fn rfc9180_a2_base_decapsulates_and_decrypts_sequence_0() {
    let f = data("rfc9180_a2_base.json");
    let v = &f["vector"];
    assert_eq!(s(&f, "retrieved").len(), 10);
    assert!(s(&f, "source").starts_with("https://www.rfc-editor.org/rfc/rfc9180"));
    let (info, aad, pt, ct) = (
        unhex(s(v, "info")),
        unhex(s(v, "aad")),
        unhex(s(v, "pt")),
        unhex(s(v, "ct")),
    );
    let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(&unhex(s(v, "skRm"))).unwrap();
    // the published key pair is what the library derives from ikmR / skRm
    let (dsk, dpk) = Kem::derive_keypair(&unhex(s(v, "ikmR")));
    // RFC 9180 prints the raw 32-byte secret; the library stores it clamped
    // (RFC 7748), which differs only in the cleared/set bits below.
    let mut clamped = unhex(s(v, "skRm"));
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    assert_eq!(dsk.to_bytes().to_vec(), clamped);
    assert_eq!(hex(&dpk.to_bytes()), s(v, "pkRm"));
    assert_eq!(hex(&Kem::sk_to_pk(&sk).to_bytes()), s(v, "pkRm"));
    // decapsulation + decryption of the sequence-0 ciphertext
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&unhex(s(v, "enc"))).unwrap();
    let out = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &sk,
        &enc,
        &info,
        &ct,
        &aad,
    )
    .unwrap();
    assert_eq!(out, pt);
    // wrong aad / info / ciphertext bit flip must fail
    assert!(hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base, &sk, &enc, &info, &ct, b"Count-1"
    )
    .is_err());
    assert!(hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base, &sk, &enc, b"other info", &ct, &aad
    )
    .is_err());
    let mut bad = ct.clone();
    bad[0] ^= 1;
    assert!(hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base, &sk, &enc, &info, &bad, &aad
    )
    .is_err());
}

/// The `hpke` crate exposes `single_shot_seal_with_rng`, so encapsulation can be
/// made deterministic: feeding the RFC's `ikmE` must reproduce the published
/// `enc` and the sequence-0 ciphertext exactly.
#[test]
fn rfc9180_a2_base_encapsulation_with_published_ephemeral_ikm_reproduces_enc_and_ct() {
    let v = &data("rfc9180_a2_base.json")["vector"];
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&unhex(s(v, "pkRm"))).unwrap();
    let mut rng = FixedRng(unhex(s(v, "ikmE")));
    let (enc, ct) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &pk,
        &unhex(s(v, "info")),
        &unhex(s(v, "pt")),
        &unhex(s(v, "aad")),
        &mut rng,
    )
    .unwrap();
    assert!(rng.0.is_empty(), "exactly ikmE was consumed");
    assert_eq!(hex(&enc.to_bytes()), s(v, "enc"));
    assert_eq!(hex(&ct), s(v, "ct"));
}

// ----------------------------------------------------------------- RFC 8032

#[test]
fn rfc8032_section_7_1_ed25519_sign_and_verify_strict() {
    let f = data("rfc8032_ed25519.json");
    let vs = f["vectors"].as_array().unwrap();
    assert_eq!(vs.len(), 5);
    for v in vs {
        let name = s(v, "name");
        let sk = SigningKey::from_bytes(&unhex(s(v, "secret_key")).try_into().unwrap());
        let msg = unhex(s(v, "message"));
        let want_sig = unhex(s(v, "signature"));
        assert_eq!(
            hex(sk.verifying_key().as_bytes()),
            s(v, "public_key"),
            "public key, test {name}"
        );
        // Ed25519 is deterministic: signing reproduces the published signature
        assert_eq!(sk.sign(&msg).to_bytes().to_vec(), want_sig, "sign, test {name}");
        // verify_strict (the call the implementation uses) accepts it ...
        let sig = Signature::from_bytes(&want_sig.clone().try_into().unwrap());
        sk.verifying_key().verify_strict(&msg, &sig).unwrap();
        // ... and rejects a changed message or signature
        let mut m2 = msg.clone();
        m2.push(0);
        assert!(sk.verifying_key().verify_strict(&m2, &sig).is_err());
        let mut s2 = want_sig.clone();
        s2[10] ^= 1;
        let sig2 = Signature::from_bytes(&s2.try_into().unwrap());
        assert!(sk.verifying_key().verify_strict(&msg, &sig2).is_err());
        // the public key is a valid AgentNet address key
        let pk: [u8; 32] = unhex(s(v, "public_key")).try_into().unwrap();
        assert!(Address::from_public_key(&pk).is_ok(), "test {name}");
    }
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
        assert_eq!(data_encoding::BASE32.decode(padded.as_bytes()).unwrap(), plain);
    }
    // an address is "an1" + lowercase RFC 4648 base32 (no padding) of pk || checksum
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let a = Address::from_verifying_key(&sk.verifying_key()).unwrap();
    let text = a.to_string();
    let body = text.strip_prefix("an1").unwrap();
    assert_eq!(body.len(), 58);
    let raw = data_encoding::BASE32_NOPAD
        .decode(body.to_ascii_uppercase().as_bytes())
        .unwrap();
    assert_eq!(&raw[..32], sk.verifying_key().as_bytes());
    assert_eq!(raw.len(), 36);
}

// ------------------------------------------------- frozen known-answer tests

const NOW: i64 = 1_700_000_000_000;

fn seeded(tag: u8) -> Identity {
    let mut signing = [0u8; 32];
    let mut kem = [0u8; 32];
    for i in 0..32 {
        signing[i] = tag.wrapping_add(i as u8);
        kem[i] = tag.wrapping_mul(3).wrapping_add(0x80).wrapping_add(i as u8);
    }
    Identity::from_seeds_for_tests(signing, kem, 16, NOW).unwrap()
}

fn fixed_envelope(a: &Identity, b: &Identity) -> Envelope {
    Envelope {
        v: 1,
        message_id: "11111111-1111-4111-8111-111111111111".into(),
        sender: a.address(),
        recipient: b.address(),
        suite: 1,
        recipient_key_epoch: 1,
        message_type: "message".into(),
        conversation_id: Some("conv-1".into()),
        correlation_id: None,
        created_at: NOW,
        expires_at: NOW + 3_600_000,
        body: "frozen known answer".into(),
    }
}

/// Everything that is deterministic given the seeds.
fn compute() -> Value {
    let (a, b) = (seeded(1), seeded(2));
    let rec = b.contact_record();
    let mut contact_input = CONTACT_RECORD_DOMAIN.to_vec();
    contact_input.extend_from_slice(rec.record_bytes());
    let env = fixed_envelope(&a, &b);
    let env_bytes = serde_json::to_vec(&env).unwrap();
    let mut env_input = ENVELOPE_DOMAIN.to_vec();
    env_input.extend_from_slice(&env_bytes);
    let mut info = HPKE_INFO_DOMAIN.to_vec();
    info.extend_from_slice(&b.kem_public_key());
    serde_json::json!({
        "address_a": a.address().to_string(),
        "address_b": b.address().to_string(),
        "inbox_topic_b_16_buckets": b.inbox_topic().to_string(),
        "inbox_topic_a_1_bucket": a.address().inbox_topic(1).to_string(),
        "kem_public_key_b": hex(&b.kem_public_key()),
        "contact_record_b": String::from_utf8(rec.record_bytes().to_vec()).unwrap(),
        "contact_signature_input_b": hex(&contact_input),
        "contact_signature_b": hex(rec.signature()),
        "envelope_json": String::from_utf8(env_bytes.clone()).unwrap(),
        "envelope_signature_input": hex(&env_input),
        "envelope_signature": hex(&sign_envelope_bytes(&a, &env_bytes)),
        "hpke_info_b": hex(&info),
        "frame_header": "414e0101",
    })
}

fn kat_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/kat_v1.json")
}

#[test]
fn frozen_known_answers_do_not_change() {
    let now = compute();
    if std::env::var_os("AGENTNET_REGEN_KAT").is_some() {
        let (a, b) = (seeded(1), seeded(2));
        let vc = VerifiedContact::parse_and_verify(&b.contact_record().to_document(), NOW).unwrap();
        let frame = seal(&a, &vc, &fixed_envelope(&a, &b), NOW, 150 * 1024).unwrap();
        let out = serde_json::json!({
            "note": "Frozen by this implementation from fixed seeds (signing seed i = tag+i, kem seed i = 3*tag+0x80+i, tags 1 and 2). Protects against accidental format changes; not independent evidence.",
            "known_answers": now,
            "frame_hex": hex(&frame),
        });
        std::fs::write(kat_path(), serde_json::to_string_pretty(&out).unwrap()).unwrap();
        return;
    }
    let frozen: Value = serde_json::from_slice(&std::fs::read(kat_path()).unwrap()).unwrap();
    assert_eq!(
        frozen["known_answers"], now,
        "a frozen known answer changed: this is a wire/format change"
    );
}

#[test]
fn the_frozen_frame_still_opens_to_the_frozen_envelope() {
    let frozen: Value = serde_json::from_slice(&std::fs::read(kat_path()).unwrap()).unwrap();
    let (a, b) = (seeded(1), seeded(2));
    let frame = unhex(s(&frozen, "frame_hex"));
    assert_eq!(&frame[..4], &[b'A', b'N', 1, 1]);
    let opened = open(&b, &frame, NOW, &OpenLimits::default()).unwrap();
    assert_eq!(opened.sender, a.address());
    assert_eq!(opened.envelope, fixed_envelope(&a, &b));
    // layout constants
    assert_eq!(ENC_OFFSET, 4);
    assert_eq!(CIPHERTEXT_OFFSET, 36);
    // a frame re-created from the frozen signed bytes also opens (framing is stable)
    let env_bytes = serde_json::to_vec(&fixed_envelope(&a, &b)).unwrap();
    let sig = sign_envelope_bytes(&a, &env_bytes);
    let re = seal_presigned(&b.kem_public_key(), &sig, &env_bytes, 150 * 1024).unwrap();
    assert_eq!(re.len(), frame.len());
    assert!(open(&b, &re, NOW, &OpenLimits::default()).is_ok());
}
