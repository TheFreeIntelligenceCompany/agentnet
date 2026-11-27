//! Tests of `agentnet_core::crypto` (ADR 0004): the OpenPGP profile, the
//! receiver policy with its distinct errors, certificate acceptance and merge
//! rules, rotation, revocation, padding and identity files.
//!
//! The RFC 9580 Appendix A vectors are in `vectors.rs`; the engine-level
//! regression tests (revoked primary, missing Intended Recipient) are in
//! `engine_security.rs`.

use std::time::Duration;

use agentnet_core::crypto::testing::{self as t, BuildOpts};
use agentnet_core::crypto::{
    Address, Envelope, Identity, MessageProtection, NoSenders, OpenLimits, OpenPgpProtection,
    SenderAuth, SenderDirectory, VerifiedContact, VerifiedRevocation,
};
use agentnet_core::envelope::{
    MESSAGE_TYPE_ACK_RECEIVED, MESSAGE_TYPE_CONTACT_UPDATE, MESSAGE_TYPE_IDENTITY_REVOKED,
    MESSAGE_TYPE_MESSAGE, MESSAGE_TYPE_TASK_REQUEST, MESSAGE_TYPE_TASK_RESULT,
};
use agentnet_core::error::{ContactError, OpenError, SealError};
use proptest::prelude::*;

const NOW: i64 = 1_700_000_000_000;
const MAX_FRAME: usize = 153_600;

fn lim() -> OpenLimits {
    OpenLimits {
        clock_skew_ms: 120_000,
        max_ttl_ms: 7 * 24 * 3600 * 1000,
        max_frame_len: MAX_FRAME,
    }
}

fn ident() -> Identity {
    Identity::generate_default(NOW).unwrap()
}

fn contact_of(id: &Identity) -> VerifiedContact {
    VerifiedContact::parse_and_verify(&id.contact_record().to_document(), NOW).unwrap()
}

fn env(from: &Identity, to: &Identity, body: &str) -> Envelope {
    env_at(from, to, body, NOW)
}

fn env_at(from: &Identity, to: &Identity, body: &str, now: i64) -> Envelope {
    Envelope::new(
        from.address(),
        to.address(),
        MESSAGE_TYPE_MESSAGE,
        body.to_owned(),
        now,
        3_600_000,
    )
    .unwrap()
}

fn seal_to(from: &Identity, to: &Identity, body: &str) -> Vec<u8> {
    OpenPgpProtection
        .seal(from, &contact_of(to), &env(from, to, body), NOW, MAX_FRAME)
        .unwrap()
}

struct Pinned(Vec<VerifiedContact>);
impl SenderDirectory for Pinned {
    fn certificate(&self, a: &Address) -> Option<VerifiedContact> {
        self.0.iter().find(|c| c.address == *a).cloned()
    }
}

fn pinned(ids: &[&Identity]) -> Pinned {
    Pinned(ids.iter().map(|i| contact_of(i)).collect())
}

fn open_at(
    to: &Identity,
    frame: &[u8],
    dir: &dyn SenderDirectory,
    now: i64,
) -> Result<agentnet_core::crypto::OpenedEnvelope, OpenError> {
    OpenPgpProtection.open(to, frame, now, &lim(), dir)
}

fn open_pinned(
    to: &Identity,
    frame: &[u8],
    from: &Identity,
) -> Result<agentnet_core::crypto::OpenedEnvelope, OpenError> {
    open_at(to, frame, &pinned(&[from]), NOW)
}

// ------------------------------------------------------------- round trips

#[test]
fn round_trip_all_message_types() {
    let (a, b) = (ident(), ident());
    for ty in [
        MESSAGE_TYPE_MESSAGE,
        MESSAGE_TYPE_ACK_RECEIVED,
        MESSAGE_TYPE_TASK_REQUEST,
        MESSAGE_TYPE_TASK_RESULT,
        MESSAGE_TYPE_CONTACT_UPDATE,
        MESSAGE_TYPE_IDENTITY_REVOKED,
    ] {
        let mut e = env(
            &a,
            &b,
            if ty == MESSAGE_TYPE_ACK_RECEIVED {
                ""
            } else {
                "body"
            },
        );
        e.message_type = ty.to_owned();
        e.conversation_id = Some("conv-1".into());
        e.correlation_id = Some("corr-1".into());
        let frame = OpenPgpProtection
            .seal(&a, &contact_of(&b), &e, NOW, MAX_FRAME)
            .unwrap();
        let o = open_pinned(&b, &frame, &a).unwrap();
        assert_eq!(o.envelope, e, "type {ty}");
        assert_eq!(o.sender, a.address());
        assert_eq!(o.auth, SenderAuth::Pinned);
    }
}

#[test]
fn unicode_bodies_are_byte_exact() {
    let (a, b) = (ident(), ident());
    for body in [
        "héllo wörld",
        "日本語のテキスト",
        "emoji 🦀🔐 and \u{0}nul and \"quotes\" and \\ backslash\n\ttabs",
        "",
    ] {
        let f = seal_to(&a, &b, body);
        assert_eq!(open_pinned(&b, &f, &a).unwrap().envelope.body, body);
    }
}

#[test]
fn the_generated_certificate_has_the_profile_of_adr_0004() {
    let id = ident();
    let doc = id.contact_record().to_document();
    let c = VerifiedContact::parse_and_verify(&doc, NOW).unwrap();
    assert!(
        doc.len() < 700,
        "a fresh certificate is small: {}",
        doc.len()
    );
    assert!(c.address.to_string().starts_with("an2"));
    assert_eq!(c.address, id.address());
    // the encryption subkey has an expiry
    let exp = c.kem_expires_at.expect("encryption subkey must expire");
    assert!(exp > NOW && exp <= NOW + 366 * 86_400_000);
    // fresh keys every time
    assert_ne!(ident().address(), id.address());
    // the inbox topic follows from the fingerprint
    assert_eq!(id.inbox_topic(), id.address().inbox_topic());
}

// ------------------------------------------------- recipient binding, signer

#[test]
fn wrong_recipient_is_not_for_us() {
    let (a, b, c) = (ident(), ident(), ident());
    let f = seal_to(&a, &b, "x");
    assert_eq!(open_pinned(&c, &f, &a).unwrap_err(), OpenError::NotForUs);
}

#[test]
fn a_different_signer_is_unknown_or_a_mismatch() {
    let (alice, bob, mallory) = (ident(), ident(), ident());
    // Mallory signs a payload that claims sender = Alice.
    let mut e = env(&alice, &bob, "forged");
    e.sender = alice.address();
    let payload = t::payload_for(&alice, &e);
    let frame = t::seal_payload(
        &mallory,
        &contact_of(&bob),
        &payload,
        NOW,
        BuildOpts::default(),
    )
    .unwrap();
    // Alice is pinned, Mallory is not: the signer is not who the payload names.
    assert_eq!(
        open_pinned(&bob, &frame, &alice).unwrap_err(),
        OpenError::UnknownSender
    );
    // Both pinned: the signature verifies as Mallory, the payload says Alice.
    assert_eq!(
        open_at(&bob, &frame, &pinned(&[&alice, &mallory]), NOW).unwrap_err(),
        OpenError::SignerMismatch
    );
}

#[test]
fn surreptitious_forwarding_is_rejected_by_the_intended_recipient() {
    let (a, b, c) = (ident(), ident(), ident());
    let f = seal_to(&a, &b, "for bob only");
    assert!(open_pinned(&b, &f, &a).is_ok());
    let forwarded = t::forward(&b, &f, &contact_of(&c), NOW).unwrap();
    assert_eq!(
        open_pinned(&c, &forwarded, &a).unwrap_err(),
        OpenError::WrongIntendedRecipient
    );
}

#[test]
fn a_signature_without_intended_recipient_is_rejected_even_when_forwarded() {
    let (a, b, c) = (ident(), ident(), ident());
    let e = env(&a, &b, "no intended recipient");
    let opts = BuildOpts {
        intended_recipient: false,
        ..BuildOpts::default()
    };
    let f = t::seal_with(&a, &contact_of(&b), &e, NOW, opts).unwrap();
    // Bob cannot accept it either: the subpacket is mandatory.
    assert_eq!(
        open_pinned(&b, &f, &a).unwrap_err(),
        OpenError::MissingIntendedRecipient
    );
    // The control: this is the forwardable message; Carol rejects it as well.
    let forwarded = t::forward(&b, &f, &contact_of(&c), NOW).unwrap();
    assert_eq!(
        open_pinned(&c, &forwarded, &a).unwrap_err(),
        OpenError::MissingIntendedRecipient
    );
}

#[test]
fn an_unsigned_message_is_rejected() {
    let (a, b) = (ident(), ident());
    let e = env(&a, &b, "unsigned");
    let opts = BuildOpts {
        sign: false,
        ..BuildOpts::default()
    };
    let f = t::seal_with(&a, &contact_of(&b), &e, NOW, opts).unwrap();
    assert_eq!(
        open_pinned(&b, &f, &a).unwrap_err(),
        OpenError::BadStructure
    );
}

// --------------------------------------------------------- receiver policy

#[test]
fn policy_violations_have_distinct_errors() {
    let (a, b) = (ident(), ident());
    let e = env(&a, &b, "x");
    let good = seal_to(&a, &b, "x");
    let payload = t::payload_for(&a, &e);

    // PKESK v3 anywhere in the message
    let f = t::prepend_pkesk_v3(&good);
    assert_eq!(open_pinned(&b, &f, &a).unwrap_err(), OpenError::PkeskNotV6);

    // SKESK
    let f = t::prepend_skesk(&good);
    assert_eq!(
        open_pinned(&b, &f, &a).unwrap_err(),
        OpenError::SkeskPresent
    );

    // compression
    let f = t::seal_compressed(&a, &contact_of(&b), &payload, NOW);
    assert_eq!(open_pinned(&b, &f, &a).unwrap_err(), OpenError::Compressed);

    // SEIPD v1 (no AEAD): Sequoia only builds it together with a PKESK v3, which is
    // refused first. (`OpenError::NotAead` for PKESK v6 + SEIPD v1 is defence in depth
    // that cannot be constructed with this library: UNTESTED directly.)
    let f = t::seal_seipd1(&a, &contact_of(&b), &payload, NOW)
        .expect("could not build the SEIPD v1 control message");
    assert!(matches!(
        open_pinned(&b, &f, &a).unwrap_err(),
        OpenError::PkeskNotV6 | OpenError::NotAead
    ));
}

#[test]
fn unknown_sender_is_authenticated_by_the_embedded_certificate() {
    let (a, b) = (ident(), ident());
    let f = seal_to(&a, &b, "hello stranger");
    let o = open_at(&b, &f, &NoSenders, NOW).unwrap();
    assert_eq!(o.sender, a.address());
    assert_eq!(o.auth, SenderAuth::EmbeddedCertificate);
    assert_eq!(o.envelope.body, "hello stranger");
}

#[test]
fn a_receipt_from_an_unknown_sender_cannot_be_authenticated() {
    let (a, b) = (ident(), ident());
    let mut e = env(&a, &b, "");
    e.message_type = MESSAGE_TYPE_ACK_RECEIVED.into();
    let f = OpenPgpProtection
        .seal(&a, &contact_of(&b), &e, NOW, MAX_FRAME)
        .unwrap();
    assert_eq!(
        open_at(&b, &f, &NoSenders, NOW).unwrap_err(),
        OpenError::UnknownSender
    );
    assert!(open_pinned(&b, &f, &a).is_ok());
}

#[test]
fn an_embedded_certificate_of_another_address_is_rejected() {
    let (a, b, m) = (ident(), ident(), ident());
    let e = env(&a, &b, "x");
    let mut v: serde_json::Value = serde_json::from_slice(&t::payload_for(&a, &e)).unwrap();
    v["sender_cert"] = m.contact_record().to_document().into();
    let f = t::seal_payload(
        &a,
        &contact_of(&b),
        &serde_json::to_vec(&v).unwrap(),
        NOW,
        BuildOpts::default(),
    )
    .unwrap();
    assert_eq!(
        open_at(&b, &f, &NoSenders, NOW).unwrap_err(),
        OpenError::UnknownSender
    );
    // a pinned contact's certificate wins over whatever the payload carries
    assert!(open_pinned(&b, &f, &a).is_ok());
}

#[test]
fn a_revoked_or_expired_sender_is_rejected_with_its_own_error() {
    let (a, b) = (ident(), ident());
    let f = seal_to(&a, &b, "x");
    // the receiver learns that Alice's key is revoked (merged certificate)
    let rev = a.create_revocation("compromised", NOW + 1000).unwrap();
    let revoked = contact_of(&a)
        .merge(
            &VerifiedContact::parse_and_verify_allow_expired(&rev.to_document(), NOW + 2000)
                .unwrap(),
            NOW + 2000,
        )
        .unwrap();
    assert!(revoked.revocation(NOW + 2000).is_some());
    assert_eq!(
        open_at(&b, &f, &Pinned(vec![revoked]), NOW + 2000).unwrap_err(),
        OpenError::SenderRevoked
    );
    // an expired sender certificate
    let short =
        Identity::generate_with_primary_expiry_for_tests(NOW, Duration::from_secs(3600)).unwrap();
    let f = seal_to(&short, &b, "x");
    assert!(open_pinned(&b, &f, &short).is_ok());
    let later = NOW + 2 * 3600 * 1000;
    let mut limits = lim();
    limits.max_ttl_ms = 10 * 3600 * 1000;
    let mut e = env(&short, &b, "z");
    e.expires_at = e.created_at + 5 * 3600 * 1000;
    let f3 = OpenPgpProtection
        .seal(&short, &contact_of(&b), &e, NOW, MAX_FRAME)
        .unwrap();
    assert_eq!(
        OpenPgpProtection
            .open(&b, &f3, later, &limits, &pinned(&[&short]))
            .unwrap_err(),
        OpenError::SenderExpired
    );
}

// ------------------------------------------------------- payload strictness

fn frame_with_payload(a: &Identity, b: &Identity, payload: &[u8]) -> Vec<u8> {
    t::seal_payload(a, &contact_of(b), payload, NOW, BuildOpts::default()).unwrap()
}

#[test]
fn the_payload_is_strict_json() {
    let (a, b) = (ident(), ident());
    let good = t::payload_for(&a, &env(&a, &b, "x"));
    let v: serde_json::Value = serde_json::from_slice(&good).unwrap();
    assert!(open_pinned(&b, &frame_with_payload(&a, &b, &good), &a).is_ok());

    let reject = |p: Vec<u8>, want: OpenError| {
        let f = frame_with_payload(&a, &b, &p);
        assert_eq!(open_pinned(&b, &f, &a).unwrap_err(), want);
    };
    // not JSON, wrong shapes
    for g in [
        &b""[..],
        b"null",
        b"[]",
        b"{",
        b"\xff\xfe",
        b"{\"agentnet\":2}",
    ] {
        reject(g.to_vec(), OpenError::MalformedPayload);
    }
    // unknown field
    let mut u = v.clone();
    u["extra"] = 1.into();
    reject(serde_json::to_vec(&u).unwrap(), OpenError::MalformedPayload);
    // duplicate field
    let s = String::from_utf8(good.clone()).unwrap();
    let dup = s.replacen("{", "{\"body\":\"first\",", 1);
    reject(dup.into_bytes(), OpenError::MalformedPayload);
    // wrong field types
    for (k, bad) in [
        ("created_at", serde_json::json!("x")),
        ("expires_at", serde_json::json!(1.5)),
        ("body", serde_json::json!(7)),
        ("sender", serde_json::json!("an2nope")),
        ("sender_cert", serde_json::json!(5)),
    ] {
        let mut u = v.clone();
        u[k] = bad;
        reject(serde_json::to_vec(&u).unwrap(), OpenError::MalformedPayload);
    }
    // missing required field
    let mut u = v.clone();
    u.as_object_mut().unwrap().remove("message_id");
    reject(serde_json::to_vec(&u).unwrap(), OpenError::MalformedPayload);
    // unknown payload version
    let mut u = v.clone();
    u["agentnet"] = 3.into();
    reject(
        serde_json::to_vec(&u).unwrap(),
        OpenError::UnknownEnvelopeVersion(3),
    );
    // invalid field values
    for (k, bad, f) in [
        ("message_id", "not-a-uuid", "message_id"),
        ("type", "UPPER", "type"),
        ("conversation_id", "has space", "conversation_id"),
    ] {
        let mut u = v.clone();
        u[k] = bad.into();
        reject(serde_json::to_vec(&u).unwrap(), OpenError::InvalidField(f));
    }
}

#[test]
fn a_payload_recipient_that_is_not_me_is_rejected_after_a_valid_signature() {
    let (a, b, c) = (ident(), ident(), ident());
    let mut e = env(&a, &b, "x");
    e.recipient = c.address();
    let f = frame_with_payload(&a, &b, &t::payload_for(&a, &e));
    assert_eq!(
        open_pinned(&b, &f, &a).unwrap_err(),
        OpenError::WrongRecipient
    );
}

fn time_env(a: &Identity, b: &Identity, created: i64, expires: i64) -> Envelope {
    let mut e = env(a, b, "t");
    e.created_at = created;
    e.expires_at = expires;
    e
}

fn open_time(
    created: i64,
    expires: i64,
    limits: &OpenLimits,
) -> Result<agentnet_core::crypto::OpenedEnvelope, OpenError> {
    let (a, b) = (ident(), ident());
    let e = time_env(&a, &b, created, expires);
    let f = frame_with_payload(&a, &b, &t::payload_for(&a, &e));
    OpenPgpProtection.open(&b, &f, NOW, limits, &pinned(&[&a]))
}

#[test]
fn time_checks_and_exact_boundaries() {
    let l = lim();
    let h = 3_600_000;
    assert!(open_time(NOW, NOW + h, &l).is_ok());
    // created_at at exactly now + skew is accepted, one ms later is deferred
    assert!(open_time(NOW + l.clock_skew_ms, NOW + h, &l).is_ok());
    assert_eq!(
        open_time(NOW + l.clock_skew_ms + 1, NOW + h, &l).unwrap_err(),
        OpenError::FromFuture
    );
    // expires_at == now is expired, one ms later is fine
    assert_eq!(open_time(NOW - h, NOW, &l).unwrap_err(), OpenError::Expired);
    assert!(open_time(NOW - h, NOW + 1, &l).is_ok());
    assert_eq!(
        open_time(NOW, NOW, &l).unwrap_err(),
        OpenError::ExpiresBeforeCreated
    );
    assert_eq!(
        open_time(NOW, NOW - 1, &l).unwrap_err(),
        OpenError::ExpiresBeforeCreated
    );
    // TTL exactly at the maximum is fine, one ms over is not
    assert!(open_time(NOW, NOW + l.max_ttl_ms, &l).is_ok());
    assert_eq!(
        open_time(NOW, NOW + l.max_ttl_ms + 1, &l).unwrap_err(),
        OpenError::TtlTooLong
    );
}

// ----------------------------------------------------------- tamper and DoS

#[test]
fn every_single_byte_flip_and_truncation_is_rejected_without_panic() {
    let (a, b) = (ident(), ident());
    let frame = seal_to(&a, &b, "tamper me");
    let dir = pinned(&[&a]);
    assert!(open_at(&b, &frame, &dir, NOW).is_ok());
    let mut accepted = vec![];
    for i in 0..frame.len() {
        let mut f = frame.clone();
        f[i] ^= 0x01;
        let r =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open_at(&b, &f, &dir, NOW)));
        match r {
            Ok(Ok(_)) => accepted.push(i),
            Ok(Err(_)) => {}
            Err(_) => panic!("panic on a flip at offset {i}"),
        }
    }
    assert!(accepted.is_empty(), "accepted flips at {accepted:?}");
    for n in 0..frame.len() {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            open_at(&b, &frame[..n], &dir, NOW)
        }));
        assert!(
            matches!(r, Ok(Err(_))),
            "truncation to {n} was not rejected"
        );
    }
    // trailing garbage must not be accepted either
    let mut f = frame.clone();
    f.extend_from_slice(b"junk");
    assert!(open_at(&b, &f, &dir, NOW).is_err());
}

#[test]
fn frame_size_limits_are_enforced_before_any_cryptography() {
    let b = ident();
    assert_eq!(
        open_at(&b, &[], &NoSenders, NOW).unwrap_err(),
        OpenError::Truncated
    );
    let big = vec![0xC1u8; MAX_FRAME + 1];
    assert_eq!(
        open_at(&b, &big, &NoSenders, NOW).unwrap_err(),
        OpenError::FrameTooLarge
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..3000)) {
        let b = ident_cached();
        let _ = open_at(b, &bytes, &NoSenders, NOW);
    }

    #[test]
    fn valid_prefix_then_garbage_never_panics(cut in 0usize..2400, tail in proptest::collection::vec(any::<u8>(), 0..300)) {
        let (a, b) = pair_cached();
        let frame = frame_cached(a, b);
        let mut f = frame[..cut.min(frame.len())].to_vec();
        f.extend_from_slice(&tail);
        let _ = open_at(b, &f, &pinned_one(a), NOW);
    }
}

fn pinned_one(a: &Identity) -> Pinned {
    pinned(&[a])
}

fn ident_cached() -> &'static Identity {
    static ID: std::sync::OnceLock<Identity> = std::sync::OnceLock::new();
    ID.get_or_init(ident)
}

fn pair_cached() -> (&'static Identity, &'static Identity) {
    static P: std::sync::OnceLock<(Identity, Identity)> = std::sync::OnceLock::new();
    let p = P.get_or_init(|| (ident(), ident()));
    (&p.0, &p.1)
}

fn frame_cached(a: &Identity, b: &Identity) -> &'static Vec<u8> {
    static F: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    F.get_or_init(|| seal_to(a, b, "cached frame body"))
}

// ------------------------------------------------------------------ padding

fn frame_len(a: &Identity, b: &Identity, body_len: usize) -> usize {
    seal_to(a, b, &"x".repeat(body_len)).len()
}

#[test]
fn equal_frame_length_within_a_bucket_and_steps_between() {
    let (a, b) = (ident(), ident());
    // the smallest bucket is 1024 bytes of inner packets (about 2.5 KB frame with the embedded certificate)
    let l0 = frame_len(&a, &b, 0);
    for n in [1, 10, 100, 200] {
        assert_eq!(frame_len(&a, &b, n), l0, "body {n}");
    }
    // lengths are non-decreasing and take few distinct values (power-of-two steps)
    let mut seen = std::collections::BTreeSet::new();
    let mut prev = 0;
    for n in (0..20_000).step_by(397) {
        let l = frame_len(&a, &b, n);
        assert!(l >= prev);
        prev = l;
        seen.insert(l);
    }
    assert!(seen.len() <= 6, "too many distinct lengths: {seen:?}");
    // a different recipient / sender at the same body size gives the same length
    let (c, d) = (ident(), ident());
    assert_eq!(frame_len(&c, &d, 100), l0);
}

#[test]
fn a_third_party_padded_message_is_accepted() {
    let (a, b) = (ident(), ident());
    let e = env(&a, &b, "padded by someone else");
    let payload = t::payload_for(&a, &e);
    for pad_to in [0u64, 1500, 4096, 9000] {
        let f = t::seal_third_party_padded(&a, &contact_of(&b), &payload, NOW, pad_to);
        let o = open_pinned(&b, &f, &a).unwrap();
        assert_eq!(o.envelope.body, "padded by someone else", "pad_to {pad_to}");
    }
}

#[test]
fn measured_frame_sizes_for_the_body_limit() {
    let (a, b) = (ident(), ident());
    let mut report = vec![];
    for body in [0usize, 1024, 65_536] {
        let f = seal_to(&a, &b, &"a".repeat(body));
        report.push((body, f.len()));
        assert!(f.len() < MAX_FRAME, "{body}: {} >= {MAX_FRAME}", f.len());
        assert!(open_pinned(&b, &f, &a).is_ok());
    }
    println!("FRAME-SIZES (body, frame) = {report:?}");
    // The worst case for JSON expansion: 64 KiB of quotes become 128 KiB of
    // escapes; the padded size would exceed the limit, so the unpadded frame
    // is used and must still fit.
    let q = "\"".repeat(65_536);
    let r = OpenPgpProtection.seal(&a, &contact_of(&b), &env(&a, &b, &q), NOW, MAX_FRAME);
    let f = r.expect("a 64 KiB body of quotes must fit (unpadded fallback)");
    assert!(f.len() <= MAX_FRAME);
    println!("FRAME-SIZE worst case 64 KiB of quotes: {}", f.len());
    assert_eq!(open_pinned(&b, &f, &a).unwrap().envelope.body, q);
}

#[test]
fn too_large_messages_are_refused_with_a_hint() {
    let (a, b) = (ident(), ident());
    let body = "x".repeat(200_000);
    match OpenPgpProtection.seal(&a, &contact_of(&b), &env(&a, &b, &body), NOW, MAX_FRAME) {
        Err(SealError::TooLarge {
            body_len,
            max_body_len_hint,
        }) => {
            assert_eq!(body_len, 200_000);
            assert!(max_body_len_hint > 100_000 && max_body_len_hint < MAX_FRAME);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

// ------------------------------------------------------ sealing refusals

#[test]
fn seal_rejects_mismatches() {
    let (a, b, c) = (ident(), ident(), ident());
    let p = OpenPgpProtection;
    // sender mismatch
    let e = env(&c, &b, "x");
    assert_eq!(
        p.seal(&a, &contact_of(&b), &e, NOW, MAX_FRAME).unwrap_err(),
        SealError::SenderMismatch
    );
    // recipient mismatch
    let e = env(&a, &c, "x");
    assert_eq!(
        p.seal(&a, &contact_of(&b), &e, NOW, MAX_FRAME).unwrap_err(),
        SealError::RecipientMismatch
    );
    // invalid field
    let mut e = env(&a, &b, "x");
    e.message_id = "nope".into();
    assert_eq!(
        p.seal(&a, &contact_of(&b), &e, NOW, MAX_FRAME).unwrap_err(),
        SealError::InvalidField("message_id")
    );
}

/// The Sequoia foot-gun (spike notes, section 3): key-level filters such as
/// `.revoked(false)` do not see a revoked PRIMARY key, so a certificate whose
/// primary is revoked but whose encryption subkey looks fine would be accepted
/// by a naive sealer. The sealer checks the certificate first.
#[test]
fn sealing_to_a_certificate_with_a_revoked_primary_is_refused() {
    let (a, b) = (ident(), ident());
    let doc = t::public_cert_primary_revoked(&b, NOW + 1000);
    let c = VerifiedContact::parse_and_verify_allow_expired(&doc, NOW + 2000).unwrap();
    assert!(c.revocation(NOW + 2000).is_some());
    let mut e = env(&a, &b, "x");
    e.recipient = c.address;
    // sealed at a time when the revocation is in force
    assert_eq!(
        OpenPgpProtection
            .seal(&a, &c, &e, NOW + 2000, MAX_FRAME)
            .unwrap_err(),
        SealError::RecipientRevoked
    );
    // the encryption subkey itself is untouched: a key-level filter would find it
    assert!(c.kem_expires_at.is_some() || !c.is_kem_expired(NOW + 2000));
}

#[test]
fn sealing_to_an_expired_subkey_is_refused() {
    let a = ident();
    let b = Identity::generate_with(NOW, Some(Duration::from_secs(3600))).unwrap();
    let c = contact_of(&b);
    let e = env(&a, &b, "x");
    assert!(OpenPgpProtection
        .seal(&a, &c, &e, NOW + 1000, MAX_FRAME)
        .is_ok());
    assert_eq!(
        OpenPgpProtection
            .seal(&a, &c, &e, NOW + 2 * 3_600_000, MAX_FRAME)
            .unwrap_err(),
        SealError::RecipientKemExpired
    );
    assert!(c.is_kem_expired(NOW + 2 * 3_600_000));
    // parsing an already-expired contact is refused with a clear error
    assert_eq!(
        VerifiedContact::parse_and_verify(&b.contact_record().to_document(), NOW + 2 * 3_600_000)
            .unwrap_err(),
        ContactError::NoEncryptionKey
    );
}

#[test]
fn sealing_to_an_expired_primary_is_refused() {
    let a = ident();
    let b =
        Identity::generate_with_primary_expiry_for_tests(NOW, Duration::from_secs(3600)).unwrap();
    let c = contact_of(&b);
    let e = env(&a, &b, "x");
    assert!(OpenPgpProtection
        .seal(&a, &c, &e, NOW + 1000, MAX_FRAME)
        .is_ok());
    assert_eq!(
        OpenPgpProtection
            .seal(&a, &c, &e, NOW + 2 * 3_600_000, MAX_FRAME)
            .unwrap_err(),
        SealError::RecipientExpired
    );
    assert_eq!(
        VerifiedContact::parse_and_verify(&b.contact_record().to_document(), NOW + 2 * 3_600_000)
            .unwrap_err(),
        ContactError::Expired
    );
}

#[test]
fn a_revoked_subkey_is_never_encrypted_to() {
    let (a, mut b) = (ident(), ident());
    let old = contact_of(&b);
    // compromise response: new subkey, old one hard-revoked and its secret destroyed
    b.rotate_kem_with(NOW + 10_000, NOW + 10_000, None, true)
        .unwrap();
    let merged = old
        .merge(&contact_of_at(&b, NOW + 20_000), NOW + 20_000)
        .unwrap();
    let e = env(&a, &b, "after compromise");
    let f = OpenPgpProtection
        .seal(&a, &merged, &e, NOW + 20_000, MAX_FRAME)
        .unwrap();
    // only the new subkey was targeted: the message opens with the new key
    let o = OpenPgpProtection
        .open(
            &b,
            &f,
            NOW + 20_000,
            &lim(),
            &pinned_at(&[&a], NOW + 20_000),
        )
        .unwrap();
    assert_eq!(o.envelope.body, "after compromise");
    // a message sealed to the stale certificate (old subkey) can no longer be opened
    let stale = OpenPgpProtection
        .seal(&a, &old, &e, NOW + 5_000, MAX_FRAME)
        .unwrap();
    assert_eq!(
        OpenPgpProtection
            .open(
                &b,
                &stale,
                NOW + 20_000,
                &lim(),
                &pinned_at(&[&a], NOW + 20_000)
            )
            .unwrap_err(),
        OpenError::NotForUs
    );
}

fn contact_of_at(id: &Identity, now: i64) -> VerifiedContact {
    VerifiedContact::parse_and_verify(&id.contact_record().to_document(), now).unwrap()
}

fn pinned_at(ids: &[&Identity], now: i64) -> Pinned {
    Pinned(ids.iter().map(|i| contact_of_at(i, now)).collect())
}

// ------------------------------------------------- certificates: acceptance

#[test]
fn secret_key_material_is_never_accepted_as_a_contact() {
    let id = ident();
    let doc = t::secret_cert_document(&id);
    assert_eq!(
        VerifiedContact::parse_and_verify(&doc, NOW).unwrap_err(),
        ContactError::ContainsSecretKey
    );
}

#[test]
fn contact_documents_are_validated() {
    for bad in ["", "not base64 !!", "AAAA", &"A".repeat(20_000)] {
        assert!(VerifiedContact::parse_and_verify(bad, NOW).is_err());
    }
    assert_eq!(
        VerifiedContact::parse_and_verify(&"A".repeat(20_000), NOW).unwrap_err(),
        ContactError::TooLarge
    );
    // ASCII armor of the Appendix A.3 key is accepted by `parse_and_verify_allow_expired` (vectors.rs)
}

#[test]
fn junk_in_a_certificate_is_dropped_before_anything_is_stored() {
    let (a, mallory) = (ident(), ident());
    let plain = contact_of(&a);
    let doc = t::public_cert_with_junk(&a, &mallory, NOW);
    let junk = VerifiedContact::parse_and_verify(&doc, NOW).unwrap();
    // user IDs, third-party certifications and unknown packets are gone: identical record
    assert!(junk.same_record(&plain));
    assert_eq!(junk.document(), plain.document());
}

#[test]
fn a_stripped_or_forged_subkey_binding_is_refused() {
    let (victim, attacker) = (ident(), ident());
    // no binding at all: no usable subkey
    let stripped = t::public_cert_without_bindings(&victim);
    assert!(VerifiedContact::parse_and_verify(&stripped, NOW).is_err());
    // the attacker's subkey with the attacker's own binding under the victim's primary
    let grafted = t::public_cert_with_grafted_subkey(&victim, &attacker);
    assert!(VerifiedContact::parse_and_verify(&grafted, NOW).is_err());
    // merging either into the genuine contact changes nothing
    let genuine = contact_of(&victim);
    for doc in [&stripped, &grafted] {
        let inc = VerifiedContact::parse_and_verify_allow_expired(doc, NOW);
        if let Ok(inc) = inc {
            let m = genuine.merge(&inc, NOW).unwrap();
            assert!(m.same_record(&genuine), "a bad binding changed the contact");
        }
    }
}

#[test]
fn updates_are_merges_only_and_a_different_primary_is_refused() {
    let (a, b) = (ident(), ident());
    let ca = contact_of(&a);
    assert_eq!(
        ca.merge(&contact_of(&b), NOW).unwrap_err(),
        ContactError::PrimaryMismatch
    );
    // merging the same record is a no-op
    assert!(ca.merge(&ca, NOW).unwrap().same_record(&ca));
}

#[test]
fn revocations_accumulate_and_are_never_dropped() {
    let a = ident();
    let base = contact_of(&a);
    let rev_doc = a
        .create_revocation("test revocation", NOW + 1000)
        .unwrap()
        .to_document();
    let rev = VerifiedRevocation::parse_and_verify(&rev_doc, NOW + 2000).unwrap();
    assert_eq!(rev.address, a.address());
    assert_eq!(rev.reason, "test revocation");
    let revoked_c = VerifiedContact::parse_and_verify_allow_expired(&rev_doc, NOW + 2000).unwrap();
    let merged = base.merge(&revoked_c, NOW + 2000).unwrap();
    assert!(merged.revocation(NOW + 2000).is_some());
    // merging the stale, unrevoked certificate into the merged one keeps the revocation
    let again = merged.merge(&base, NOW + 3000).unwrap();
    assert!(again.revocation(NOW + 3000).is_some());
    // a certificate that is not revoked is not a revocation document
    assert!(VerifiedRevocation::parse_and_verify(&a.contact_record().to_document(), NOW).is_err());
    // bad reasons are refused when creating
    for bad in ["", "tab\there", &"x".repeat(257)] {
        assert!(a.create_revocation(bad, NOW).is_err());
    }
}

#[test]
fn rotation_publishes_a_new_subkey_and_keeps_old_messages_readable_until_retire_time() {
    let (a, mut b) = (ident(), ident());
    let old_cert = contact_of(&b);
    let before = OpenPgpProtection
        .seal(
            &a,
            &old_cert,
            &env(&a, &b, "sealed to the old subkey"),
            NOW + 1000,
            MAX_FRAME,
        )
        .unwrap();
    let retire = NOW + 7 * 86_400_000;
    b.rotate_kem(NOW + 5_000, retire, Some(NOW + 90 * 86_400_000))
        .unwrap();
    assert_eq!(b.previous_kem_count(), 1);
    // the published certificate carries the new subkey; merging it into the stored one works
    let merged = old_cert
        .merge(&contact_of_at(&b, NOW + 6_000), NOW + 6_000)
        .unwrap();
    assert!(!merged.same_record(&old_cert));
    assert_eq!(merged.kem_expires_at, Some(NOW + 90 * 86_400_000));
    // old messages still open until the retire time ...
    let dir = pinned_at(&[&a], NOW + 6_000);
    let l = OpenLimits {
        max_ttl_ms: 30 * 86_400_000,
        ..lim()
    };
    let o = OpenPgpProtection
        .open(&b, &before, NOW + 6_000, &l, &dir)
        .unwrap();
    assert_eq!(o.envelope.body, "sealed to the old subkey");
    // ... a sender who merged the update seals to the new subkey only
    let after = OpenPgpProtection
        .seal(
            &a,
            &merged,
            &env(&a, &b, "sealed to the new subkey"),
            NOW + 6_000,
            MAX_FRAME,
        )
        .unwrap();
    assert!(OpenPgpProtection
        .open(&b, &after, NOW + 6_000, &l, &dir)
        .is_ok());
    // after the retire time and a prune the old subkey's secret is gone
    let late = retire + 1;
    assert_eq!(b.decryption_key_count(late), 1);
    b.prune_retired(late);
    assert_eq!(b.previous_kem_count(), 0);
    let l = OpenLimits {
        max_ttl_ms: 40 * 86_400_000,
        ..lim()
    };
    // (the message from `before` is long expired by TTL, so use a fresh one sealed to the stale cert)
    let stale = OpenPgpProtection
        .seal(
            &a,
            &old_cert,
            &env_at(&a, &b, "stale", late),
            late,
            MAX_FRAME,
        )
        .unwrap();
    assert_eq!(
        OpenPgpProtection
            .open(&b, &stale, late, &l, &pinned_at(&[&a], late))
            .unwrap_err(),
        OpenError::NotForUs
    );
    let fresh = OpenPgpProtection
        .seal(
            &a,
            &merged,
            &env_at(&a, &b, "fresh", late - 1),
            late - 1,
            MAX_FRAME,
        )
        .unwrap();
    assert!(OpenPgpProtection
        .open(&b, &fresh, late, &l, &pinned_at(&[&a], late))
        .is_ok());
}

// ------------------------------------------------------------ identity files

#[test]
fn identity_file_roundtrip_permissions_and_atomic_writes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.json");
    let id = ident();
    id.save(&path, false).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    // never overwrites without `overwrite`
    assert!(matches!(
        id.save(&path, false),
        Err(agentnet_core::error::IdentityError::AlreadyExists(_))
    ));
    // no temp files left behind
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(leftovers, vec!["identity.json".to_string()]);
    let back = Identity::load(&path).unwrap();
    assert_eq!(back.address(), id.address());
    // the loaded identity can open what was sealed to the original
    let a = ident();
    let f = seal_to(&a, &id, "to the file");
    assert!(open_pinned(&back, &f, &a).is_ok());
    // group/other readable files are refused
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Identity::load(&path),
        Err(agentnet_core::error::IdentityError::InsecurePermissions { .. })
    ));
}

#[test]
fn encrypted_export_import() {
    let id = ident();
    let blob = id.export_encrypted("correct horse").unwrap();
    assert!(String::from_utf8_lossy(&blob).contains("BEGIN AGE ENCRYPTED FILE"));
    let back = Identity::import_encrypted(&blob, "correct horse").unwrap();
    assert_eq!(back.address(), id.address());
    assert!(Identity::import_encrypted(&blob, "wrong").is_err());
    assert!(Identity::import_encrypted(&blob, "").is_err());
    assert!(id.export_encrypted("").is_err());
    let mut bad = blob.clone();
    let n = bad.len() / 2;
    bad[n] ^= 1;
    assert!(Identity::import_encrypted(&bad, "correct horse").is_err());
    // the export never contains the address in the clear in a way that reveals key bytes
    let text = String::from_utf8_lossy(&blob);
    assert!(!text.contains(&id.address().to_string()));
}

#[test]
fn debug_output_has_no_secret_material() {
    let id = ident();
    let dbg = format!("{id:?} {:?} {:?}", contact_of(&id), id.address());
    for frag in id.secret_fragments_for_tests() {
        assert!(!dbg.contains(&frag));
    }
}

#[test]
fn constants_match_spec() {
    let id = ident();
    let s = id.address().to_string();
    assert_eq!(s.len(), 61);
    assert!(s.starts_with("an2"));
    assert_eq!(agentnet_core::address::INBOX_BUCKETS, 16);
    assert!(id.inbox_topic().as_str().starts_with("/agentnet/1/inbox-"));
}
