//! Black-box tests of the identity / contact / envelope cryptography.

use agentnet_core::address::Address;
use agentnet_core::contact::VerifiedContact;
use agentnet_core::envelope::testing::{seal_presigned, seal_raw_plaintext, sign_envelope_bytes};
use agentnet_core::envelope::{
    self, max_body_len, open, seal, Envelope, OpenLimits, OpenedEnvelope, CIPHERTEXT_OFFSET,
    DEFAULT_MAX_FRAME_LEN, ENC_LEN, ENC_OFFSET, FRAME_OVERHEAD, MESSAGE_TYPE_ACK_RECEIVED,
    MESSAGE_TYPE_MESSAGE, MESSAGE_TYPE_TASK_REQUEST, MESSAGE_TYPE_TASK_RESULT, MIN_BUCKET,
    PLAINTEXT_OVERHEAD,
};
use agentnet_core::error::{ContactError, IdentityError, OpenError, SealError};
use agentnet_core::identity::Identity;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use proptest::prelude::*;

const NOW: i64 = 1_700_000_000_000;
const MAX: usize = DEFAULT_MAX_FRAME_LEN;
const TTL: i64 = 3_600_000;

fn lim() -> OpenLimits {
    OpenLimits::default()
}

fn ident() -> Identity {
    Identity::generate_default(NOW).unwrap()
}

fn contact_of(id: &Identity) -> VerifiedContact {
    VerifiedContact::parse_and_verify(&id.contact_record().to_document(), NOW).unwrap()
}

/// An envelope as `seal` will produce it for a recipient on key epoch 1
/// (the signed `suite` and `recipient_key_epoch` are filled in by `seal`).
fn env(from: &Identity, to: &Identity, body: &str) -> Envelope {
    let mut e = Envelope::new(
        from.address(),
        to.address(),
        MESSAGE_TYPE_MESSAGE,
        body.to_owned(),
        NOW,
        TTL,
    )
    .unwrap();
    e.recipient_key_epoch = to.key_epoch();
    e
}

fn seal_to(from: &Identity, to: &Identity, body: &str) -> Vec<u8> {
    seal(from, &contact_of(to), &env(from, to, body), NOW, MAX).unwrap()
}

/// Serialize + sign + frame without any of `seal`'s checks.
fn raw_frame(signer: &Identity, kem_pk: &[u8; 32], e: &Envelope) -> Vec<u8> {
    raw_frame_bytes(signer, kem_pk, &serde_json::to_vec(e).unwrap())
}

fn raw_frame_bytes(signer: &Identity, kem_pk: &[u8; 32], bytes: &[u8]) -> Vec<u8> {
    let sig = sign_envelope_bytes(signer, bytes);
    seal_presigned(kem_pk, &sig, bytes, MAX).unwrap()
}

/// Deterministic xorshift64* for reproducible "random" inputs.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn fill(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
}

// ------------------------------------------------------------------ layout

#[test]
fn frame_layout_offsets() {
    let (a, b) = (ident(), ident());
    let frame = seal_to(&a, &b, "hi");
    assert_eq!(&frame[0..2], b"AN");
    assert_eq!(frame[2], 0x01, "frame version");
    assert_eq!(frame[3], 0x01, "suite id");
    assert_eq!(ENC_OFFSET, 4);
    assert_eq!(CIPHERTEXT_OFFSET, 36);
    assert_eq!(ENC_LEN, 32);
    assert_eq!(FRAME_OVERHEAD, 52);
    // header(4) + enc(32) + ciphertext(plaintext 512 + tag 16)
    assert_eq!(frame.len(), 4 + 32 + MIN_BUCKET + 16);
    assert_eq!(frame.len() - CIPHERTEXT_OFFSET, MIN_BUCKET + 16);
    // fresh ephemeral key each time
    let frame2 = seal_to(&a, &b, "hi");
    assert_ne!(frame[4..36], frame2[4..36]);
}

#[test]
fn round_trip_all_message_types() {
    let (a, b) = (ident(), ident());
    for t in [
        MESSAGE_TYPE_MESSAGE,
        MESSAGE_TYPE_ACK_RECEIVED,
        MESSAGE_TYPE_TASK_REQUEST,
        MESSAGE_TYPE_TASK_RESULT,
        "x-custom.type_1",
    ] {
        let mut e = env(&a, &b, "payload");
        e.message_type = t.into();
        e.conversation_id = Some("conv-1".into());
        e.correlation_id = Some("corr~2".into());
        let frame = seal(&a, &contact_of(&b), &e, NOW, MAX).unwrap();
        let o: OpenedEnvelope = open(&b, &frame, NOW, &lim()).unwrap();
        assert_eq!(o.envelope, e);
        assert_eq!(o.sender, a.address());
    }
}

#[test]
fn unicode_bodies_are_byte_exact() {
    let (a, b) = (ident(), ident());
    for body in [
        "emoji \u{1F600}\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} and flags \u{1F1E6}\u{1F1F9}",
        "RTL \u{202E}evil\u{202C} \u{05E9}\u{05DC}\u{05D5}\u{05DD} \u{0645}\u{0631}\u{062D}\u{0628}\u{0627}",
        "embedded NUL \u{0} between \u{0}\u{0}",
        "quotes \" \\ / \n\r\t \u{7f} \u{1}",
        "",
        "combining e\u{301} vs \u{e9}",
        "\u{feff}BOM and \u{2028}\u{2029}",
    ] {
        let frame = seal_to(&a, &b, body);
        let o = open(&b, &frame, NOW, &lim()).unwrap();
        assert_eq!(o.envelope.body.as_bytes(), body.as_bytes(), "{body:?}");
    }
}

// ------------------------------------------------------------------ auth

#[test]
fn wrong_recipient_is_not_for_us() {
    let (a, b, c) = (ident(), ident(), ident());
    let frame = seal_to(&a, &b, "for b");
    assert_eq!(open(&c, &frame, NOW, &lim()), Err(OpenError::NotForUs));
    assert!(open(&b, &frame, NOW, &lim()).is_ok());
}

#[test]
fn forged_sender_is_bad_signature() {
    let (a, m, b) = (ident(), ident(), ident());
    let mut e = env(&a, &b, "send money");
    e.sender = a.address(); // claims to be A ...
    let frame = raw_frame(&m, &b.kem_public_key(), &e); // ... but signed by M
    assert_eq!(open(&b, &frame, NOW, &lim()), Err(OpenError::BadSignature));
    // control: signed by A is accepted
    let frame = raw_frame(&a, &b.kem_public_key(), &e);
    assert!(open(&b, &frame, NOW, &lim()).is_ok());
}

#[test]
fn surreptitious_forwarding_is_wrong_recipient() {
    let (a, b, c) = (ident(), ident(), ident());
    // A sends to B; B holds A's valid signature and exact envelope bytes.
    let e = env(&a, &b, "secret for b only");
    let bytes = serde_json::to_vec(&e).unwrap();
    let sig = sign_envelope_bytes(&a, &bytes);
    // B re-seals them to C: signature verifies, recipient does not match.
    let forwarded = seal_presigned(&c.kem_public_key(), &sig, &bytes, MAX).unwrap();
    assert_eq!(
        open(&c, &forwarded, NOW, &lim()),
        Err(OpenError::WrongRecipient)
    );
    // and to B itself it is fine
    let direct = seal_presigned(&b.kem_public_key(), &sig, &bytes, MAX).unwrap();
    assert!(open(&b, &direct, NOW, &lim()).is_ok());
}

#[test]
fn signature_over_other_domain_is_rejected() {
    use agentnet_core::contact::CONTACT_RECORD_DOMAIN;
    // A signature with the contact-record domain over the envelope bytes must not verify.
    let (a, b) = (ident(), ident());
    let bytes = serde_json::to_vec(&env(&a, &b, "x")).unwrap();
    let good = sign_envelope_bytes(&a, &bytes);
    let mut other = Vec::new();
    other.extend_from_slice(CONTACT_RECORD_DOMAIN);
    other.extend_from_slice(&bytes);
    assert_ne!(good, sign_envelope_bytes(&a, &other));
    // tamper: signature of different bytes
    let mut bytes2 = bytes.clone();
    let n = bytes2.len();
    bytes2[n - 3] ^= 0x01; // inside body / closing
    let frame = seal_presigned(&b.kem_public_key(), &good, &bytes2, MAX).unwrap();
    assert!(open(&b, &frame, NOW, &lim()).is_err());
}

#[test]
fn seal_rejects_mismatches() {
    let (a, b, c) = (ident(), ident(), ident());
    let cb = contact_of(&b);
    let e = env(&a, &b, "x");
    assert_eq!(seal(&c, &cb, &e, NOW, MAX), Err(SealError::SenderMismatch));
    assert_eq!(
        seal(&a, &contact_of(&c), &e, NOW, MAX),
        Err(SealError::RecipientMismatch)
    );
    let mut bad = e.clone();
    bad.message_id = "not-a-uuid".into();
    assert_eq!(
        seal(&a, &cb, &bad, NOW, MAX),
        Err(SealError::InvalidField("message_id"))
    );
    let mut bad = e.clone();
    bad.expires_at = bad.created_at;
    assert_eq!(
        seal(&a, &cb, &bad, NOW, MAX),
        Err(SealError::InvalidField("expires_at"))
    );
    let mut bad = e.clone();
    bad.v = 2;
    assert_eq!(
        seal(&a, &cb, &bad, NOW, MAX),
        Err(SealError::InvalidField("v"))
    );
}

#[test]
fn seal_refuses_expired_recipient_key() {
    let a = ident();
    let mut b = ident();
    b.rotate_kem(NOW, NOW, Some(NOW + 1000)).unwrap();
    let doc = b.contact_record().to_document();
    let c = VerifiedContact::parse_and_verify_allow_expired(&doc, NOW + 5000).unwrap();
    let e = env(&a, &b, "x");
    assert_eq!(
        seal(&a, &c, &e, NOW + 5000, MAX),
        Err(SealError::RecipientKemExpired)
    );
    assert!(seal(&a, &c, &e, NOW + 999, MAX).is_ok());
}

// ------------------------------------------------------------------ robustness

#[test]
fn every_single_bit_flip_is_rejected() {
    let (a, b) = (ident(), ident());
    let frame = seal_to(&a, &b, "bit flip target");
    assert_eq!(frame.len(), FRAME_OVERHEAD + MIN_BUCKET);
    assert!(open(&b, &frame, NOW, &lim()).is_ok());
    let mut f = frame.clone();
    let mut kinds = std::collections::HashSet::new();
    for byte in 0..frame.len() {
        for bit in 0..8 {
            f[byte] ^= 1 << bit;
            let r = open(&b, &f, NOW, &lim());
            f[byte] ^= 1 << bit;
            match r {
                Ok(_) => panic!("bit flip at byte {byte} bit {bit} was accepted"),
                Err(e) => {
                    kinds.insert(std::mem::discriminant(&e));
                }
            }
        }
    }
    assert!(kinds.len() >= 3, "header flips should give distinct errors");
}

#[test]
fn header_errors_are_distinct() {
    let (a, b) = (ident(), ident());
    let frame = seal_to(&a, &b, "x");
    let mut f = frame.clone();
    f[0] = b'X';
    assert_eq!(open(&b, &f, NOW, &lim()), Err(OpenError::BadMagic));
    let mut f = frame.clone();
    f[2] = 9;
    assert_eq!(
        open(&b, &f, NOW, &lim()),
        Err(OpenError::UnknownFrameVersion(9))
    );
    let mut f = frame.clone();
    f[3] = 7;
    assert_eq!(open(&b, &f, NOW, &lim()), Err(OpenError::UnknownSuite(7)));
    assert_eq!(
        open(&b, &frame[..3], NOW, &lim()),
        Err(OpenError::Truncated)
    );
    assert_eq!(open(&b, &[], NOW, &lim()), Err(OpenError::Truncated));
    // low-order / all-zero encapsulated keys make HPKE's DH check fail: clean NotForUs
    for enc in [[0u8; 32], {
        let mut x = [0u8; 32];
        x[0] = 1;
        x
    }] {
        let mut f = frame.clone();
        f[ENC_OFFSET..ENC_OFFSET + ENC_LEN].copy_from_slice(&enc);
        assert_eq!(open(&b, &f, NOW, &lim()), Err(OpenError::NotForUs));
    }
    let small = OpenLimits {
        max_frame_len: frame.len() - 1,
        ..lim()
    };
    assert_eq!(open(&b, &frame, NOW, &small), Err(OpenError::FrameTooLarge));
    let exact = OpenLimits {
        max_frame_len: frame.len(),
        ..lim()
    };
    assert!(open(&b, &frame, NOW, &exact).is_ok());
}

#[test]
fn truncation_at_every_length_is_rejected() {
    let (a, b) = (ident(), ident());
    let frame = seal_to(&a, &b, "truncate me");
    for n in 0..frame.len() {
        assert!(open(&b, &frame[..n], NOW, &lim()).is_err(), "len {n}");
    }
    // extension is also rejected (AEAD covers the whole ciphertext)
    let mut longer = frame.clone();
    longer.push(0);
    assert!(open(&b, &longer, NOW, &lim()).is_err());
}

#[test]
fn ten_thousand_random_frames_never_panic() {
    let b = ident();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut ok = 0;
    for i in 0..10_000 {
        let n = (rng.next() % 800) as usize;
        let mut f = rng.fill(n);
        // half of them start with a valid header so that deeper code paths run
        if i % 2 == 0 && f.len() >= 4 {
            f[..4].copy_from_slice(b"AN\x01\x01");
        }
        if open(&b, &f, NOW, &lim()).is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 0);
}

// ------------------------------------------------------------------ padding

fn env_len(a: &Identity, b: &Identity, body_len: usize) -> usize {
    serde_json::to_vec(&env(a, b, &"x".repeat(body_len)))
        .unwrap()
        .len()
}

#[test]
fn equal_frame_length_within_a_bucket() {
    let (a, b) = (ident(), ident());
    let room = MIN_BUCKET - PLAINTEXT_OVERHEAD - env_len(&a, &b, 0);
    let lens: std::collections::BTreeSet<usize> = [0usize, 1, 10, 50, room / 2, room]
        .iter()
        .map(|n| seal_to(&a, &b, &"y".repeat(*n)).len())
        .collect();
    assert_eq!(lens.len(), 1, "{lens:?}");
    assert_eq!(*lens.iter().next().unwrap(), FRAME_OVERHEAD + 512);
}

#[test]
fn bucket_boundaries_are_exact() {
    let (a, b) = (ident(), ident());
    let base = env_len(&a, &b, 0);
    // body_len such that 4 + 64 + env_len == bucket
    for (bucket, next) in [
        (512usize, 1024usize),
        (1024, 2048),
        (2048, 4096),
        (65536, 131072),
    ] {
        let body = bucket - PLAINTEXT_OVERHEAD - base;
        let exact = seal_to(&a, &b, &"z".repeat(body));
        assert_eq!(exact.len(), FRAME_OVERHEAD + bucket, "bucket {bucket}");
        let over = seal_to(&a, &b, &"z".repeat(body + 1));
        assert_eq!(over.len(), FRAME_OVERHEAD + next, "bucket {bucket}+1");
        let under = seal_to(&a, &b, &"z".repeat(body - 1));
        assert_eq!(under.len(), FRAME_OVERHEAD + bucket);
        assert!(open(&b, &exact, NOW, &lim()).is_ok());
        assert!(open(&b, &over, NOW, &lim()).is_ok());
    }
}

#[test]
fn nonzero_padding_is_rejected() {
    let (a, b) = (ident(), ident());
    let e = env(&a, &b, "pad");
    let bytes = serde_json::to_vec(&e).unwrap();
    let sig = sign_envelope_bytes(&a, &bytes);
    let build = |tweak: &dyn Fn(&mut Vec<u8>)| {
        let mut pt = Vec::new();
        pt.extend_from_slice(&((64 + bytes.len()) as u32).to_be_bytes());
        pt.extend_from_slice(&sig);
        pt.extend_from_slice(&bytes);
        pt.resize(512, 0);
        tweak(&mut pt);
        seal_raw_plaintext(&b.kem_public_key(), &pt).unwrap()
    };
    // control
    assert!(open(&b, &build(&|_| {}), NOW, &lim()).is_ok());
    // last padding byte non-zero
    assert_eq!(
        open(&b, &build(&|pt| *pt.last_mut().unwrap() = 1), NOW, &lim()),
        Err(OpenError::NonZeroPadding)
    );
    // first padding byte non-zero
    let first_pad = 4 + 64 + bytes.len();
    assert_eq!(
        open(&b, &build(&|pt| pt[first_pad] = 0x80), NOW, &lim()),
        Err(OpenError::NonZeroPadding)
    );
    // length prefix too long / too short / zero / huge
    for bad in [513u32 - 4 + 1, 64, 0, 3, u32::MAX] {
        let f = build(&|pt| pt[..4].copy_from_slice(&bad.to_be_bytes()));
        assert_eq!(
            open(&b, &f, NOW, &lim()),
            Err(OpenError::BadLengthPrefix),
            "len {bad}"
        );
    }
    // length prefix shorter than the real inner => truncated JSON and non-zero "padding"
    let f = build(&|pt| {
        let n = (64 + bytes.len() - 5) as u32;
        pt[..4].copy_from_slice(&n.to_be_bytes());
    });
    assert!(open(&b, &f, NOW, &lim()).is_err());
    // plaintext shorter than the length prefix itself
    let f = seal_raw_plaintext(&b.kem_public_key(), &[0, 0]).unwrap();
    assert!(open(&b, &f, NOW, &lim()).is_err());
}

#[test]
fn max_frame_len_cap_and_too_large() {
    let (a, b) = (ident(), ident());
    let cb = contact_of(&b);
    let base = env_len(&a, &b, 0);
    let cap = 1000usize; // max frame length: plaintext cap = 948
    let max_pt = cap - FRAME_OVERHEAD;
    let seal_cap = |n: usize| seal(&a, &cb, &env(&a, &b, &"q".repeat(n)), NOW, cap);

    // fits the 512 bucket
    assert_eq!(seal_cap(10).unwrap().len(), FRAME_OVERHEAD + 512);
    // needs bucket 1024 which would exceed the cap: padded to the cap exactly
    let n_first_over_512 = 512 - PLAINTEXT_OVERHEAD - base + 1;
    let f = seal_cap(n_first_over_512).unwrap();
    assert_eq!(f.len(), cap);
    assert!(open(
        &b,
        &f,
        NOW,
        &OpenLimits {
            max_frame_len: cap,
            ..lim()
        }
    )
    .is_ok());
    // exactly full
    let n_full = max_pt - PLAINTEXT_OVERHEAD - base;
    let f = seal_cap(n_full).unwrap();
    assert_eq!(f.len(), cap);
    // one more byte: too large, and the hint is exact for plain ASCII bodies
    match seal_cap(n_full + 1) {
        Err(SealError::TooLarge {
            body_len,
            max_body_len_hint,
        }) => {
            assert_eq!(body_len, n_full + 1);
            assert_eq!(max_body_len_hint, n_full);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
    assert_eq!(max_body_len(cap, &env(&a, &b, "ignored body")), n_full);
    // a cap smaller than any frame
    assert!(matches!(
        seal(&a, &cb, &env(&a, &b, ""), NOW, 10),
        Err(SealError::TooLarge { .. })
    ));
    assert!(matches!(
        seal(&a, &cb, &env(&a, &b, ""), NOW, 0),
        Err(SealError::TooLarge { .. })
    ));
    // the default cap holds a large body
    let big = "b".repeat(100_000);
    let f = seal(&a, &cb, &env(&a, &b, &big), NOW, MAX).unwrap();
    assert!(f.len() <= MAX);
    assert_eq!(
        open(&b, &f, NOW, &lim()).unwrap().envelope.body.len(),
        100_000
    );
}

// ------------------------------------------------------------------ time

fn time_env(a: &Identity, b: &Identity, created: i64, expires: i64) -> Envelope {
    let mut e = env(a, b, "t");
    e.created_at = created;
    e.expires_at = expires;
    e
}

fn open_time(created: i64, expires: i64, limits: &OpenLimits) -> Result<OpenedEnvelope, OpenError> {
    let (a, b) = (ident(), ident());
    let f = raw_frame(&a, &b.kem_public_key(), &time_env(&a, &b, created, expires));
    open(&b, &f, NOW, limits)
}

#[test]
fn time_checks_and_exact_boundaries() {
    let l = lim();
    let skew = l.clock_skew_ms;
    let ttl = l.max_ttl_ms;
    // fine
    assert!(open_time(NOW, NOW + 1000, &l).is_ok());
    // created_at at exactly now + skew accepted; one more rejected
    assert!(open_time(NOW + skew, NOW + skew + 1000, &l).is_ok());
    assert_eq!(
        open_time(NOW + skew + 1, NOW + skew + 1000, &l).unwrap_err(),
        OpenError::FromFuture
    );
    // expires_at == now is expired, now + 1 is not
    assert_eq!(
        open_time(NOW - 1000, NOW, &l).unwrap_err(),
        OpenError::Expired
    );
    assert_eq!(
        open_time(NOW - 1000, NOW - 1, &l).unwrap_err(),
        OpenError::Expired
    );
    assert!(open_time(NOW - 1000, NOW + 1, &l).is_ok());
    // expires <= created (while created within skew, expires in future)
    assert_eq!(
        open_time(NOW + 10, NOW + 10, &l).unwrap_err(),
        OpenError::ExpiresBeforeCreated
    );
    assert_eq!(
        open_time(NOW + 10, NOW + 5, &l).unwrap_err(),
        OpenError::ExpiresBeforeCreated
    );
    // TTL exactly max accepted, +1 rejected
    assert!(open_time(NOW, NOW + ttl, &l).is_ok());
    assert_eq!(
        open_time(NOW, NOW + ttl + 1, &l).unwrap_err(),
        OpenError::TtlTooLong
    );
    // extreme values do not overflow
    assert_eq!(
        open_time(i64::MIN, i64::MAX, &l).unwrap_err(),
        OpenError::TtlTooLong
    );
    assert_eq!(
        open_time(i64::MAX, i64::MAX, &l).unwrap_err(),
        OpenError::FromFuture
    );
    // custom limits
    let tight = OpenLimits {
        clock_skew_ms: 0,
        max_ttl_ms: 10,
        ..l
    };
    assert!(open_time(NOW, NOW + 10, &tight).is_ok());
    assert_eq!(
        open_time(NOW + 1, NOW + 5, &tight).unwrap_err(),
        OpenError::FromFuture
    );
    assert_eq!(
        open_time(NOW, NOW + 11, &tight).unwrap_err(),
        OpenError::TtlTooLong
    );
    // `open` itself takes `now`: the same frame expires as time passes
    let (a, b) = (ident(), ident());
    let f = seal_to(&a, &b, "x");
    assert!(open(&b, &f, NOW + TTL - 1, &l).is_ok());
    assert_eq!(open(&b, &f, NOW + TTL, &l), Err(OpenError::Expired));
    // replay is not detected here: the same frame opens twice
    assert!(open(&b, &f, NOW, &l).is_ok());
    assert!(open(&b, &f, NOW, &l).is_ok());
}

// ------------------------------------------------------------------ parsing

#[test]
fn envelope_parsing_is_strict() {
    let (a, b) = (ident(), ident());
    let pk = b.kem_public_key();
    let good = serde_json::to_string(&env(&a, &b, "body")).unwrap();
    assert!(open(&b, &raw_frame_bytes(&a, &pk, good.as_bytes()), NOW, &lim()).is_ok());

    // unknown envelope version: reported as such even if other fields are different
    let v2 = good.replacen("\"v\":1", "\"v\":2", 1);
    assert_eq!(
        open(&b, &raw_frame_bytes(&a, &pk, v2.as_bytes()), NOW, &lim()),
        Err(OpenError::UnknownEnvelopeVersion(2))
    );
    let v2b = r#"{"v":99,"totally":"different","shape":[1,2,3]}"#;
    assert_eq!(
        open(&b, &raw_frame_bytes(&a, &pk, v2b.as_bytes()), NOW, &lim()),
        Err(OpenError::UnknownEnvelopeVersion(99))
    );
    let v0 = good.replacen("\"v\":1", "\"v\":0", 1);
    assert_eq!(
        open(&b, &raw_frame_bytes(&a, &pk, v0.as_bytes()), NOW, &lim()),
        Err(OpenError::UnknownEnvelopeVersion(0))
    );
    let vbig = good.replacen("\"v\":1", "\"v\":18446744073709551615", 1);
    assert_eq!(
        open(&b, &raw_frame_bytes(&a, &pk, vbig.as_bytes()), NOW, &lim()),
        Err(OpenError::UnknownEnvelopeVersion(u64::MAX))
    );

    // unknown field in a v1 envelope
    let unk = good.replacen("\"v\":1,", "\"v\":1,\"extra\":\"x\",", 1);
    assert_eq!(
        open(&b, &raw_frame_bytes(&a, &pk, unk.as_bytes()), NOW, &lim()),
        Err(OpenError::MalformedEnvelope("unknown field"))
    );

    // duplicate keys (serde_json's derive-generated visitor rejects them)
    let dup = good.replacen("\"v\":1,", "\"v\":1,\"v\":1,", 1);
    assert_eq!(
        open(&b, &raw_frame_bytes(&a, &pk, dup.as_bytes()), NOW, &lim()),
        Err(OpenError::MalformedEnvelope("duplicate field"))
    );
    let dup_body = good.replacen(
        "\"body\":\"body\"}",
        "\"body\":\"body\",\"body\":\"evil\"}",
        1,
    );
    assert_ne!(dup_body, good);
    assert_eq!(
        open(
            &b,
            &raw_frame_bytes(&a, &pk, dup_body.as_bytes()),
            NOW,
            &lim()
        ),
        Err(OpenError::MalformedEnvelope("duplicate field"))
    );

    // missing field
    let missing = good.replacen("\"body\":\"body\"", "\"x\":0", 1);
    assert!(open(
        &b,
        &raw_frame_bytes(&a, &pk, missing.as_bytes()),
        NOW,
        &lim()
    )
    .is_err());

    // non-UTF-8 bytes inside the body string
    let mut raw = good.clone().into_bytes();
    let at = good.find("body\"}").unwrap();
    raw[at] = 0xff;
    raw[at + 1] = 0xfe;
    assert_eq!(
        open(&b, &raw_frame_bytes(&a, &pk, &raw), NOW, &lim()),
        Err(OpenError::MalformedEnvelope("invalid JSON syntax"))
    );

    // trailing garbage, empty, not JSON, wrong types
    for bad in [
        &b""[..],
        b"null",
        b"[]",
        b"{}",
        b"{\"v\":1}",
        b"not json",
        b"{\"v\":\"1\"}",
        b"{\"v\":1.0}",
    ] {
        assert!(open(&b, &raw_frame_bytes(&a, &pk, bad), NOW, &lim()).is_err());
    }
    let trailing = format!("{good}x");
    assert!(open(
        &b,
        &raw_frame_bytes(&a, &pk, trailing.as_bytes()),
        NOW,
        &lim()
    )
    .is_err());

    // invalid field values inside an authentic v1 envelope
    let mut e = env(&a, &b, "x");
    e.message_id = "123E4567-E89B-42D3-A456-426614174000".into();
    assert_eq!(
        open(&b, &raw_frame(&a, &pk, &e), NOW, &lim()),
        Err(OpenError::InvalidField("message_id"))
    );
    let mut e = env(&a, &b, "x");
    e.message_type = "Bad Type".into();
    assert_eq!(
        open(&b, &raw_frame(&a, &pk, &e), NOW, &lim()),
        Err(OpenError::InvalidField("type"))
    );
    let mut e = env(&a, &b, "x");
    e.conversation_id = Some("has space".into());
    assert_eq!(
        open(&b, &raw_frame(&a, &pk, &e), NOW, &lim()),
        Err(OpenError::InvalidField("conversation_id"))
    );
    // bad sender address string
    let bad_addr = good.replacen(
        &a.address().to_string(),
        &format!("an1{}", "a".repeat(58)),
        1,
    );
    assert!(open(
        &b,
        &raw_frame_bytes(&a, &pk, bad_addr.as_bytes()),
        NOW,
        &lim()
    )
    .is_err());
}

#[test]
fn wrong_recipient_field_after_valid_signature() {
    let (a, b, c) = (ident(), ident(), ident());
    let e = env(&a, &c, "meant for c");
    let f = raw_frame(&a, &b.kem_public_key(), &e);
    assert_eq!(open(&b, &f, NOW, &lim()), Err(OpenError::WrongRecipient));
}

// ------------------------------------------------------------------ contact

#[test]
fn contact_record_round_trip_and_tampering() {
    let (a, b) = (ident(), ident());
    let doc = a.contact_record().to_document();
    let c = VerifiedContact::parse_and_verify(&doc, NOW).unwrap();
    assert_eq!(c.address, a.address());
    assert_eq!(c.document(), doc);
    assert_eq!(c.inbox_topic(), a.inbox_topic());

    // swap in another identity's KEM key while keeping A's signature
    let d: serde_json::Value = serde_json::from_str(&doc).unwrap();
    let rec = B64.decode(d["record"].as_str().unwrap()).unwrap();
    let mut rv: serde_json::Value = serde_json::from_slice(&rec).unwrap();
    rv["kem_pk"] = serde_json::json!(B64.encode(b.kem_public_key()));
    let tampered = serde_json::json!({
        "record": B64.encode(serde_json::to_vec(&rv).unwrap()),
        "sig": d["sig"],
    })
    .to_string();
    assert_eq!(
        VerifiedContact::parse_and_verify(&tampered, NOW),
        Err(ContactError::BadSignature)
    );

    // a different identity's whole document is fine but is a different address
    let other = VerifiedContact::parse_and_verify(&b.contact_record().to_document(), NOW).unwrap();
    assert_ne!(other.address, c.address);
    assert_ne!(other.kem_pk, c.kem_pk);

    // expired KEM key
    let mut e = ident();
    e.rotate_kem(NOW, NOW, Some(NOW + 10)).unwrap();
    let edoc = e.contact_record().to_document();
    assert_eq!(
        VerifiedContact::parse_and_verify(&edoc, NOW + 10),
        Err(ContactError::KemKeyExpired)
    );
    assert!(VerifiedContact::parse_and_verify(&edoc, NOW + 9).is_ok());

    // size cap and garbage
    assert_eq!(
        VerifiedContact::parse_and_verify(&" ".repeat(5000), NOW),
        Err(ContactError::TooLarge)
    );
    let mut rng = Rng(42);
    for _ in 0..2000 {
        let n = (rng.next() % 300) as usize;
        let s: String = rng.fill(n).iter().map(|b| (*b & 0x7f) as char).collect();
        assert!(VerifiedContact::parse_and_verify(&s, NOW).is_err());
    }
}

#[test]
fn inbox_buckets_in_contact_and_topic() {
    for buckets in [1u16, 2, 16, 255, 256] {
        let id = Identity::generate(buckets, NOW).unwrap();
        let c = contact_of(&id);
        assert_eq!(c.inbox_buckets, buckets);
        assert_eq!(c.inbox_topic(), id.inbox_topic());
        assert!(c.inbox_topic().as_str().starts_with("/agentnet/1/inbox-"));
    }
    assert_eq!(
        Identity::generate(1, NOW).unwrap().inbox_topic().as_str(),
        "/agentnet/1/inbox-00/proto"
    );
}

// ------------------------------------------------------------------ rotation

#[test]
fn kem_rotation_keeps_old_key_until_retire_time() {
    let a = ident();
    let mut b = ident();
    let old_contact = contact_of(&b);
    let old_frame = seal(&a, &old_contact, &env(&a, &b, "to old key"), NOW, MAX).unwrap();
    let retire = NOW + 10_000;

    b.rotate_kem(NOW + 1, retire, None).unwrap();
    assert_ne!(contact_of(&b).kem_pk, old_contact.kem_pk);
    assert_eq!(
        contact_of(&b).address,
        old_contact.address,
        "address is stable"
    );
    assert!(contact_of(&b).created_at >= old_contact.created_at);

    // opens until the retire time ...
    assert!(open(&b, &old_frame, NOW + 2, &lim()).is_ok());
    assert!(open(
        &b,
        &old_frame,
        retire - 1,
        &OpenLimits {
            max_ttl_ms: i64::MAX,
            ..lim()
        }
    )
    .is_ok());
    // ... even without pruning, not at/after it
    assert_eq!(
        open(&b, &old_frame, retire, &lim()),
        Err(OpenError::NotForUs)
    );
    // frames to the new key open
    let new_frame = seal_to(&a, &b, "to new key");
    assert!(open(&b, &new_frame, NOW + 2, &lim()).is_ok());
    // pruning removes the old key permanently
    b.prune_retired(retire);
    assert_eq!(b.previous_kem_count(), 0);
    assert_eq!(
        open(&b, &old_frame, NOW + 2, &lim()),
        Err(OpenError::NotForUs)
    );
    assert!(open(&b, &new_frame, NOW + 2, &lim()).is_ok());
}

// ------------------------------------------------------------------ identity files

#[cfg(unix)]
mod files {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &std::path::Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn save_load_permissions_and_atomicity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let mut id = ident();
        id.rotate_kem(NOW, NOW + 5000, Some(NOW + 100_000)).unwrap();
        id.save(&path, false).unwrap();
        assert_eq!(mode(&path), 0o600);
        // only the final file remains (no temp leftovers)
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec!["identity.json".to_string()]);

        let back = Identity::load(&path).unwrap();
        assert_eq!(back.address(), id.address());
        assert_eq!(back.kem_public_key(), id.kem_public_key());
        assert_eq!(back.previous_kem_count(), 1);
        assert_eq!(back.kem_expires_at(), Some(NOW + 100_000));
        assert_eq!(back.inbox_buckets(), 16);

        // refuses to overwrite, leaves the original byte-identical, no temp files
        let before = std::fs::read(&path).unwrap();
        let other = ident();
        assert!(matches!(
            other.save(&path, false),
            Err(IdentityError::AlreadyExists(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        // overwrite=true replaces atomically and keeps 0600
        other.save(&path, true).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(Identity::load(&path).unwrap().address(), other.address());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

        // group/world readable files are refused with a chmod hint
        for m in [0o644, 0o640, 0o604, 0o660, 0o700 | 0o010] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(m)).unwrap();
            match Identity::load(&path) {
                Err(e @ IdentityError::InsecurePermissions { .. }) => {
                    assert!(e.to_string().contains("chmod 600"), "{e}");
                }
                other => panic!("mode {m:o}: expected InsecurePermissions, got {other:?}"),
            }
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(Identity::load(&path).is_ok());
    }

    #[test]
    fn save_into_missing_directory_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope").join("identity.json");
        assert!(matches!(
            ident().save(&path, false),
            Err(IdentityError::Io { .. })
        ));
    }

    #[test]
    fn load_rejects_bad_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let id = ident();
        id.save(&path, false).unwrap();
        let good = std::fs::read_to_string(&path).unwrap();

        let write = |s: &str| {
            std::fs::remove_file(&path).unwrap();
            let f = std::fs::OpenOptions::new();
            let mut f = f;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut fh = f
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            fh.write_all(s.as_bytes()).unwrap();
        };
        // address from a different identity
        let other = ident();
        write(&good.replace(&id.address().to_string(), &other.address().to_string()));
        assert!(matches!(
            Identity::load(&path),
            Err(IdentityError::AddressMismatch)
        ));
        // garbage / empty / oversize
        for s in ["", "{", "null", "{\"v\":7}"] {
            write(s);
            assert!(Identity::load(&path).is_err(), "{s:?}");
        }
        write(&" ".repeat(300 * 1024));
        assert!(matches!(
            Identity::load(&path),
            Err(IdentityError::TooLarge)
        ));
        // missing file, directory
        assert!(matches!(
            Identity::load(&dir.path().join("absent")),
            Err(IdentityError::Io { .. })
        ));
        assert!(Identity::load(dir.path()).is_err());
    }

    #[test]
    fn debug_output_has_no_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let mut id = ident();
        id.rotate_kem(NOW, NOW + 1000, None).unwrap();
        id.save(&path, false).unwrap();
        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let dbg = format!("{id:?}");
        let dbg_alt = format!("{id:#?}");
        let mut secrets = vec![
            j["signing_sk"].as_str().unwrap().to_owned(),
            j["kem_sk"].as_str().unwrap().to_owned(),
            j["previous_kems"][0]["kem_sk"].as_str().unwrap().to_owned(),
        ];
        for s in secrets.clone() {
            let raw = B64.decode(&s).unwrap();
            secrets.push(raw.iter().map(|b| format!("{b:02x}")).collect());
            secrets.push(format!("{raw:?}"));
        }
        for s in &secrets {
            assert!(!dbg.contains(s.as_str()) && !dbg_alt.contains(s.as_str()));
        }
        // nor the public KEM key bytes (not secret, but nothing byte-like should print)
        assert!(dbg.contains(&id.address().to_string()));
    }
}

#[test]
fn encrypted_export_import() {
    let a = ident();
    let mut b = ident();
    let old_frame = seal_to(&a, &b, "before export");
    b.rotate_kem(NOW + 1, NOW + 1_000_000, None).unwrap();
    let exported = b.export_encrypted("correct horse battery staple").unwrap();
    let text = std::str::from_utf8(&exported).unwrap();
    assert!(
        text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
        "{text}"
    );
    // the export does not contain the plaintext address or keys
    assert!(!text.contains(&b.address().to_string()));

    let back = Identity::import_encrypted(&exported, "correct horse battery staple").unwrap();
    assert_eq!(back.address(), b.address());
    assert_eq!(back.kem_public_key(), b.kem_public_key());
    assert_eq!(back.previous_kem_count(), 1);
    // the imported identity opens a frame sealed to the pre-rotation key
    let o = open(&back, &old_frame, NOW + 2, &lim()).unwrap();
    assert_eq!(o.envelope.body, "before export");
    // ... and signs as the same agent
    let to_a = seal(
        &back,
        &contact_of(&a),
        &env(&back, &a, "from imported"),
        NOW,
        MAX,
    )
    .unwrap();
    assert_eq!(open(&a, &to_a, NOW, &lim()).unwrap().sender, b.address());

    // failures are clean errors
    assert!(matches!(
        Identity::import_encrypted(&exported, "wrong passphrase"),
        Err(IdentityError::Decrypt)
    ));
    assert!(matches!(
        Identity::import_encrypted(b"garbage", "x"),
        Err(IdentityError::Decrypt)
    ));
    let mut corrupted = exported.clone();
    let mid = corrupted.len() / 2;
    corrupted[mid] = if corrupted[mid] == b'A' { b'B' } else { b'A' };
    assert!(Identity::import_encrypted(&corrupted, "correct horse battery staple").is_err());
    assert!(matches!(
        Identity::import_encrypted(
            &exported[..exported.len() / 2],
            "correct horse battery staple"
        ),
        Err(IdentityError::Decrypt)
    ));
    assert!(matches!(
        b.export_encrypted(""),
        Err(IdentityError::EmptyPassphrase)
    ));
    assert!(matches!(
        Identity::import_encrypted(&vec![b'a'; 300 * 1024], "x"),
        Err(IdentityError::TooLarge)
    ));
}

// ------------------------------------------------------------------ proptest

fn arb_opt_id() -> impl Strategy<Value = Option<String>> {
    prop::option::of("[!-~]{1,128}")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_round_trip(
        body in ".{0,3000}",
        mtype in "[a-z0-9._-]{1,64}",
        conv in arb_opt_id(),
        corr in arb_opt_id(),
    ) {
        let (a, b) = (ident(), ident());
        let mut e = env(&a, &b, &body);
        e.message_type = mtype;
        e.conversation_id = conv;
        e.correlation_id = corr;
        let frame = seal(&a, &contact_of(&b), &e, NOW, MAX).unwrap();
        prop_assert!(frame.len() <= MAX);
        prop_assert_eq!((frame.len() - FRAME_OVERHEAD).count_ones(), 1,
            "frame is a power-of-two bucket");
        let o = open(&b, &frame, NOW, &lim()).unwrap();
        prop_assert_eq!(o.envelope, e);
        prop_assert_eq!(o.sender, a.address());
    }

    #[test]
    fn prop_open_never_panics_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
        with_header in any::<bool>(),
    ) {
        let b = ident();
        let mut f = bytes;
        if with_header && f.len() >= 4 {
            f[..4].copy_from_slice(b"AN\x01\x01");
        }
        prop_assert!(open(&b, &f, NOW, &lim()).is_err());
    }

    #[test]
    fn prop_authentic_garbage_envelope_never_panics(
        env_bytes in prop::collection::vec(any::<u8>(), 0..600),
        raw_pt in prop::collection::vec(any::<u8>(), 0..700),
    ) {
        let (a, b) = (ident(), ident());
        // authentic signature and AEAD over arbitrary envelope bytes
        let f = raw_frame_bytes(&a, &b.kem_public_key(), &env_bytes);
        prop_assert!(open(&b, &f, NOW, &lim()).is_err());
        // authentic AEAD over an arbitrary plaintext
        let f = seal_raw_plaintext(&b.kem_public_key(), &raw_pt).unwrap();
        prop_assert!(open(&b, &f, NOW, &lim()).is_err());
    }

    #[test]
    fn prop_address_parse_total(s in ".{0,100}") {
        let _ = s.parse::<Address>();
    }

    #[test]
    fn prop_contact_parse_total(s in ".{0,500}") {
        prop_assert!(VerifiedContact::parse_and_verify(&s, NOW).is_err());
    }
}

#[test]
fn constants_match_spec() {
    assert_eq!(envelope::HEADER_LEN, 4);
    assert_eq!(envelope::TAG_LEN, 16);
    assert_eq!(envelope::SIG_LEN, 64);
    assert_eq!(envelope::LEN_PREFIX_LEN, 4);
    assert_eq!(envelope::MIN_BUCKET, 512);
    assert_eq!(envelope::ENVELOPE_DOMAIN, b"agentnet/v1/envelope\0");
    assert_eq!(envelope::HPKE_INFO_DOMAIN, b"agentnet/v1/hpke\0");
    assert_eq!(OpenLimits::default().clock_skew_ms, 120_000);
    assert_eq!(OpenLimits::default().max_ttl_ms, 7 * 24 * 3600 * 1000);
}

// ------------------------------------------------- conditions 1, 6, 7: suites,
// ------------------------------------------------- epochs, headers, fresh contexts

mod hardening {
    use super::*;
    use agentnet_core::crypto::envelope::testing::decrypts_with_aad;
    use agentnet_core::crypto::{
        HpkeBaseEd25519, MessageProtection, SuiteRegistry, SUITE_HPKE_BASE_ED25519,
    };
    use std::sync::Arc;

    fn contact_with_suites(id: &mut Identity, suites: &[u8]) -> VerifiedContact {
        id.set_advertised_suites(suites.to_vec());
        VerifiedContact::parse_and_verify(&id.contact_record().to_document(), NOW).unwrap()
    }

    /// Test-only suite: NOT cryptography, only a frame the registry can route
    /// (`"AN" 1 <id>` header followed by the envelope JSON).
    struct DummySuite(u8);

    impl MessageProtection for DummySuite {
        fn suite_id(&self) -> u8 {
            self.0
        }
        fn supported_suites(&self) -> Vec<u8> {
            vec![self.0]
        }
        fn seal(
            &self,
            _sender: &Identity,
            recipient: &VerifiedContact,
            envelope: &Envelope,
            _now: i64,
            _max: usize,
        ) -> Result<Vec<u8>, SealError> {
            assert!(
                recipient.suites.contains(&self.0),
                "never seal to an unlisted suite"
            );
            let mut f = vec![b'A', b'N', 1, self.0];
            f.extend(serde_json::to_vec(envelope).unwrap());
            Ok(f)
        }
        fn open(
            &self,
            _r: &Identity,
            frame: &[u8],
            _now: i64,
            _l: &OpenLimits,
        ) -> Result<OpenedEnvelope, OpenError> {
            let envelope: Envelope = serde_json::from_slice(&frame[4..]).unwrap();
            Ok(OpenedEnvelope {
                sender: envelope.sender,
                envelope,
            })
        }
        fn max_body_len(&self, _m: usize, _e: &Envelope) -> usize {
            0
        }
    }

    fn registry(ids: &[u8]) -> SuiteRegistry {
        let mut r = SuiteRegistry::new(vec![]);
        for id in ids {
            if *id == SUITE_HPKE_BASE_ED25519 {
                r.register(Arc::new(HpkeBaseEd25519));
            } else {
                r.register(Arc::new(DummySuite(*id)));
            }
        }
        r
    }

    #[test]
    fn two_seals_of_the_same_envelope_use_fresh_hpke_contexts() {
        let (a, b) = (ident(), ident());
        let c = contact_of(&b);
        let e = env(&a, &b, "same envelope");
        let f1 = seal(&a, &c, &e, NOW, MAX).unwrap();
        let f2 = seal(&a, &c, &e, NOW, MAX).unwrap();
        // different ephemeral key (enc) and different ciphertext
        assert_ne!(
            f1[ENC_OFFSET..ENC_OFFSET + ENC_LEN],
            f2[ENC_OFFSET..ENC_OFFSET + ENC_LEN]
        );
        assert_ne!(f1[CIPHERTEXT_OFFSET..], f2[CIPHERTEXT_OFFSET..]);
        assert_eq!(f1.len(), f2.len());
        // both open to the same envelope
        let o1 = open(&b, &f1, NOW, &lim()).unwrap();
        let o2 = open(&b, &f2, NOW, &lim()).unwrap();
        assert_eq!(o1.envelope, o2.envelope);
        // many seals never repeat an enc
        let mut encs = std::collections::HashSet::new();
        for _ in 0..64 {
            let f = seal(&a, &c, &e, NOW, MAX).unwrap();
            assert!(encs.insert(f[ENC_OFFSET..ENC_OFFSET + ENC_LEN].to_vec()));
        }
    }

    #[test]
    fn frame_version_and_suite_bytes_are_authenticated_as_aad() {
        let (a, b) = (ident(), ident());
        let f = seal_to(&a, &b, "x");
        let header: [u8; 4] = f[..4].try_into().unwrap();
        assert!(decrypts_with_aad(&b, &f, &header, NOW));
        for i in 0..4 {
            for flip in [1u8, 0x80, 0xff] {
                let mut bad = header;
                bad[i] ^= flip;
                assert!(
                    !decrypts_with_aad(&b, &f, &bad, NOW),
                    "byte {i} ^ {flip:#x} must fail authentication"
                );
            }
        }
        // and through the real entry point, a changed version/suite never opens
        for (i, want) in [
            (2usize, OpenError::UnknownFrameVersion(2)),
            (3, OpenError::UnknownSuite(2)),
        ] {
            let mut g = f.clone();
            g[i] = 2;
            assert_eq!(open(&b, &g, NOW, &lim()), Err(want));
        }
    }

    #[test]
    fn signed_suite_and_key_epoch_must_match_the_frame_and_the_decrypting_key() {
        let (a, mut b) = (ident(), ident());
        b.rotate_kem(NOW, NOW + 1_000_000, None).unwrap(); // epoch 2, epoch-1 key retained
        let cur = b.kem_public_key();
        let mut e = env(&a, &b, "m");
        e.recipient_key_epoch = 2;
        // control: epoch 2 to the epoch-2 key
        assert!(open(&b, &raw_frame(&a, &cur, &e), NOW, &lim()).is_ok());
        // wrong signed epoch
        for bad in [0u64, 1, 3] {
            let mut x = e.clone();
            x.recipient_key_epoch = bad;
            assert_eq!(
                open(&b, &raw_frame(&a, &cur, &x), NOW, &lim()),
                Err(OpenError::KeyEpochMismatch),
                "epoch {bad}"
            );
        }
        // wrong signed suite
        let mut x = e.clone();
        x.suite = 2;
        assert_eq!(
            open(&b, &raw_frame(&a, &cur, &x), NOW, &lim()),
            Err(OpenError::SuiteMismatch)
        );
    }

    #[test]
    fn an_old_recipient_key_cannot_rewrap_a_message_into_a_newer_epoch() {
        let a = ident();
        let mut b = ident();
        let old_pk = b.kem_public_key();
        b.rotate_kem(NOW, NOW + 1_000_000, None).unwrap();
        // attacker holding the OLD secret key re-wraps A's (validly signed)
        // epoch-1 envelope claiming epoch 2: the signature covers the epoch
        // field, and the epoch that actually decrypts is 1.
        let mut e = env(&a, &b, "m");
        e.recipient_key_epoch = 1;
        assert!(open(&b, &raw_frame(&a, &old_pk, &e), NOW, &lim()).is_ok());
        e.recipient_key_epoch = 2;
        assert_eq!(
            open(&b, &raw_frame(&a, &old_pk, &e), NOW, &lim()),
            Err(OpenError::KeyEpochMismatch)
        );
    }

    #[test]
    fn kem_rotation_with_revoke_destroys_old_keys_and_signs_the_floor() {
        let a = ident();
        let mut b = ident();
        let old = contact_of(&b);
        assert_eq!((old.key_epoch, old.revoked_kem_epochs_below), (1, 1));
        let f_old = seal(&a, &old, &env(&a, &b, "to the old key"), NOW, MAX).unwrap();
        assert!(open(&b, &f_old, NOW, &lim()).is_ok());

        b.rotate_kem_with(NOW, NOW + 1_000_000, None, true).unwrap();
        assert_eq!(b.previous_kem_count(), 0);
        assert_eq!(open(&b, &f_old, NOW, &lim()), Err(OpenError::NotForUs));
        let new = contact_of(&b);
        assert_eq!((new.key_epoch, new.revoked_kem_epochs_below), (2, 2));
        // the floor survives an export/import, and a later plain rotation keeps it
        let mut c = Identity::import_encrypted(&b.export_encrypted("pw").unwrap(), "pw").unwrap();
        assert_eq!((c.key_epoch(), c.min_valid_epoch()), (2, 2));
        c.rotate_kem(NOW, NOW + 1_000, None).unwrap();
        let n3 = contact_of(&c);
        assert_eq!((n3.key_epoch, n3.revoked_kem_epochs_below), (3, 2));
        // overlap rotation (no revoke) keeps the old key openable until the window ends
        let mut d = ident();
        let f = seal_to(&a, &d, "overlap");
        d.rotate_kem(NOW, NOW + 1_000_000, None).unwrap();
        assert!(open(&d, &f, NOW, &lim()).is_ok());
        assert_eq!(
            open(&d, &f, NOW + 1_000_000, &lim()),
            Err(OpenError::NotForUs)
        );
    }

    #[test]
    fn identity_files_without_epochs_load_with_defaults() {
        let mut id = ident();
        id.rotate_kem(NOW, NOW + 1_000_000, None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("id.json");
        id.save(&p, false).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("kem_epoch");
        v.as_object_mut().unwrap().remove("min_valid_epoch");
        for k in v["previous_kems"].as_array_mut().unwrap() {
            k.as_object_mut().unwrap().remove("epoch");
        }
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
        let legacy = Identity::load(&p).unwrap();
        assert_eq!((legacy.key_epoch(), legacy.min_valid_epoch()), (2, 1));
    }

    #[test]
    fn registry_negotiates_the_highest_common_suite_and_never_falls_back_silently() {
        let (a, mut b) = (ident(), ident());
        // recipient lists [1,2]; sender supports [1,2] -> suite 2
        let both = contact_with_suites(&mut b, &[1, 2]);
        let r12 = registry(&[1, 2]);
        let f = r12.seal(&a, &both, &env(&a, &b, "x"), NOW, MAX).unwrap();
        assert_eq!(f[3], 2);
        // recipient lists [1]; sender supports [1,2] -> suite 1
        let one = contact_with_suites(&mut b, &[1]);
        let f = r12.seal(&a, &one, &env(&a, &b, "x"), NOW, MAX).unwrap();
        assert_eq!(f[3], 1);
        // recipient lists only [2]; sender supports only [1] -> error, no downgrade
        let two = contact_with_suites(&mut b, &[2]);
        let r1 = registry(&[1]);
        assert_eq!(
            r1.seal(&a, &two, &env(&a, &b, "x"), NOW, MAX),
            Err(SealError::NoCommonSuite)
        );
        // the single-suite implementation refuses a record that does not list it
        assert_eq!(
            HpkeBaseEd25519.seal(&a, &two, &env(&a, &b, "x"), NOW, MAX),
            Err(SealError::NoCommonSuite)
        );
        assert_eq!(r12.supported_suites(), vec![1, 2]);
        assert_eq!(r12.suite_id(), 2);
    }

    #[test]
    fn receiver_rejects_frames_for_suites_it_does_not_advertise() {
        let (a, mut b) = (ident(), ident());
        let both = contact_with_suites(&mut b, &[1, 2]);
        // an attacker (or stale sender) seals under suite 2 ...
        let f2 = registry(&[1, 2])
            .seal(&a, &both, &env(&a, &b, "x"), NOW, MAX)
            .unwrap();
        assert_eq!(f2[3], 2);
        // ... a receiver that registered suite 2 but advertises only [1] refuses it
        let mut recv = registry(&[1, 2]);
        recv.set_advertised(&[1]);
        assert_eq!(recv.advertised_suites(), vec![1]);
        assert_eq!(
            recv.open(&b, &f2, NOW, &lim()).err(),
            Some(OpenError::SuiteNotAdvertised(2))
        );
        // advertising it makes the same frame routable
        let mut recv = registry(&[1, 2]);
        recv.set_advertised(&[1, 2]);
        assert!(recv.open(&b, &f2, NOW, &lim()).is_ok());
        // a suite nobody registered is a different error
        assert_eq!(
            registry(&[1]).open(&b, &f2, NOW, &lim()).err(),
            Some(OpenError::UnknownSuite(2))
        );
        // suite 1 frames still open on the default registry
        let f1 = seal_to(&a, &b, "x");
        assert!(registry(&[1]).open(&b, &f1, NOW, &lim()).is_ok());
    }
}
