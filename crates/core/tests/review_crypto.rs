//! Tests for the findings of the adversarial review of 2026-11-27
//! (`results/review/fable-crypto-review.md`); each test names its finding.
//! Crypto-level tests; the engine-level ones are in `review_engine.rs`.

use std::time::Duration;

use agentnet_core::crypto::{
    Address, Envelope, Identity, MessageProtection, OpenLimits, OpenPgpProtection, SenderDirectory,
    VerifiedContact,
};
use agentnet_core::envelope::MESSAGE_TYPE_MESSAGE;
use agentnet_core::error::{IdentityError, OpenError};

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

fn contact_at(id: &Identity, now: i64) -> VerifiedContact {
    VerifiedContact::parse_and_verify(&id.contact_record().to_document(), now).unwrap()
}

fn env(from: &Identity, to: &Identity, body: &str, now: i64) -> Envelope {
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

struct Pinned(Vec<VerifiedContact>);
impl SenderDirectory for Pinned {
    fn certificate(&self, a: &Address) -> Option<VerifiedContact> {
        self.0.iter().find(|c| c.address == *a).cloned()
    }
}

/// A copy of `id` as it was now (export and import): holds the secrets of
/// exactly the subkeys it has now.
fn snapshot(id: &Identity) -> Identity {
    let blob = id.export_encrypted("pw").unwrap();
    Identity::import_encrypted(&blob, "pw").unwrap()
}

/// M1, the reviewer's scenario: many rotations with `--revoke-previous`, then
/// the ORIGINAL certificate is merged back at the sender. The message sealed
/// afterwards must not open with the first ("compromised") subkey secret.
#[test]
fn m1_revoked_subkey_stays_revoked_after_many_rotations_and_a_stale_merge() {
    let a = ident();
    let mut b = ident();
    let original = contact_at(&b, NOW);
    let compromised = snapshot(&b); // holds only the first subkey secret
    let mut seen_by_a = original.clone();
    let mut last_ok = NOW;
    let mut refused = false;
    for i in 1..=30i64 {
        let t = NOW + i * 10_000;
        match b.rotate_kem_with(t, t, None, true) {
            Ok(()) => {
                last_ok = t;
                seen_by_a = seen_by_a.merge(&contact_at(&b, t), t).unwrap();
            }
            Err(IdentityError::CertificateTooLarge { .. }) => {
                refused = true;
                assert!(
                    i > 9,
                    "the cap must allow at least 9 rotations (reviewer's case)"
                );
                break;
            }
            Err(e) => panic!("unexpected {e}"),
        }
    }
    // the stale certificate is merged back in
    let t = last_ok + 1_000;
    let merged = seen_by_a.merge(&original, t).unwrap();
    let f = OpenPgpProtection
        .seal(
            &a,
            &merged,
            &env(&a, &b, "after compromise", t),
            t,
            MAX_FRAME,
        )
        .unwrap();
    let dir = Pinned(vec![contact_at(&a, t)]);
    // the holder of only the first subkey secret cannot open it ...
    assert_eq!(
        OpenPgpProtection
            .open(&compromised, &f, t, &lim(), &dir)
            .unwrap_err(),
        OpenError::NotForUs
    );
    // ... the current identity can
    assert_eq!(
        OpenPgpProtection
            .open(&b, &f, t, &lim(), &dir)
            .unwrap()
            .envelope
            .body,
        "after compromise"
    );
    // the publisher's own record was not trimmed either
    assert!(b.contact_record().as_bytes().len() <= agentnet_core::crypto::pgp::MAX_CERT_LEN);
    assert!(
        refused,
        "rotations must eventually fail with a clear error, not trim revocations"
    );
}

/// M1: a failed rotation changes nothing.
#[test]
fn m1_a_refused_rotation_leaves_the_identity_unchanged() {
    let mut b = ident();
    let mut t = NOW;
    let mut refused = false;
    for _ in 0..60 {
        t += 10_000;
        let before = b.contact_record();
        let before_count = b.previous_kem_count();
        match b.rotate_kem_with(t, t, None, true) {
            Ok(()) => assert_ne!(before, b.contact_record()),
            Err(IdentityError::CertificateTooLarge { limit }) => {
                assert_eq!(limit, agentnet_core::crypto::pgp::MAX_CERT_LEN);
                assert_eq!(before, b.contact_record());
                assert_eq!(before_count, b.previous_kem_count());
                refused = true;
                break;
            }
            Err(e) => panic!("unexpected {e}"),
        }
    }
    assert!(refused);
}

/// M1: subkeys whose expiry has passed may be dropped to fit the cap, and a
/// stale certificate that brings them back does not make them usable.
#[test]
fn m1_expired_subkeys_are_trimmed_and_cannot_come_back() {
    let a = ident();
    let mut b = Identity::generate_with(NOW, Some(Duration::from_secs(50))).unwrap();
    let original = contact_at(&b, NOW);
    let compromised = snapshot(&b);
    let mut seen_by_a = original.clone();
    let mut t = NOW;
    for _ in 0..40 {
        t += 100_000;
        // each new subkey lives 50 s: older ones are expired when the next is added
        b.rotate_kem_with(t, t, Some(t + 50_000), true).unwrap();
        seen_by_a = seen_by_a.merge(&contact_at(&b, t), t).unwrap();
        assert!(b.contact_record().as_bytes().len() <= agentnet_core::crypto::pgp::MAX_CERT_LEN);
    }
    let t2 = t + 10_000;
    let merged = seen_by_a.merge(&original, t2).unwrap();
    let f = OpenPgpProtection
        .seal(&a, &merged, &env(&a, &b, "x", t2), t2, MAX_FRAME)
        .unwrap();
    let dir = Pinned(vec![contact_at(&a, t2)]);
    assert_eq!(
        OpenPgpProtection
            .open(&compromised, &f, t2, &lim(), &dir)
            .unwrap_err(),
        OpenError::NotForUs
    );
    assert!(OpenPgpProtection.open(&b, &f, t2, &lim(), &dir).is_ok());
}

/// L7: evicting a retained subkey entry (more than 32) destroys its secret.
#[test]
fn l7_evicting_a_retained_subkey_strips_its_secret() {
    let a = ident();
    let mut b = Identity::generate_with(NOW, Some(Duration::from_secs(30))).unwrap();
    let original = contact_at(&b, NOW);
    let keep_until = NOW + 365 * 86_400_000;
    let mut t = NOW;
    for _ in 0..40 {
        t += 60_000;
        // soft rotation: the previous subkey stays decryptable until `keep_until`
        b.rotate_kem_with(t, keep_until, Some(t + 30_000), false)
            .unwrap();
    }
    assert!(
        b.decryption_key_count(t) <= 33,
        "{} secret subkeys are still held (32 retired plus the current one is the most)",
        b.decryption_key_count(t)
    );
    // a frame sealed to the very first subkey can no longer be opened
    let f = OpenPgpProtection
        .seal(
            &a,
            &original,
            &env(&a, &b, "old", NOW + 1_000),
            NOW + 1_000,
            MAX_FRAME,
        )
        .unwrap();
    let dir = Pinned(vec![contact_at(&a, t)]);
    assert_eq!(
        OpenPgpProtection
            .open(&b, &f, NOW + 2_000, &lim(), &dir)
            .unwrap_err(),
        OpenError::NotForUs
    );
}

// ------------------------------------------------------------------- L2

mod l2 {
    use super::*;
    use agentnet_core::crypto::testing::{self as t, BuildOpts, Inner};
    use agentnet_core::crypto::testing::{Aead as AEADAlgorithm, Cipher as SymmetricAlgorithm};

    fn contact(id: &Identity) -> VerifiedContact {
        contact_at(id, NOW)
    }

    fn open_from(to: &Identity, frame: &[u8], from: &Identity) -> Result<(), OpenError> {
        let dir = Pinned(vec![contact(from)]);
        OpenPgpProtection
            .open(to, frame, NOW, &lim(), &dir)
            .map(|_| ())
    }

    fn setup() -> (Identity, Identity, Vec<u8>) {
        let (a, b) = (ident(), ident());
        let frame = OpenPgpProtection
            .seal(&a, &contact(&b), &env(&a, &b, "hello", NOW), NOW, MAX_FRAME)
            .unwrap();
        (a, b, frame)
    }

    #[test]
    fn the_canonical_frame_opens() {
        let (a, b, frame) = setup();
        open_from(&b, &frame, &a).unwrap();
        // the same signed packets rewrapped unchanged (AES-256/OCB) open too
        let same = t::rewrap(
            &b,
            &frame,
            &contact(&b),
            NOW,
            Inner::Same,
            SymmetricAlgorithm::AES256,
            AEADAlgorithm::OCB,
        );
        open_from(&b, &same, &a).unwrap();
    }

    #[test]
    fn l2_a_prepended_marker_packet_is_rejected() {
        let (a, b, frame) = setup();
        assert_eq!(
            open_from(&b, &t::prepend_marker(&frame), &a).unwrap_err(),
            OpenError::BadStructure
        );
    }

    #[test]
    fn l2_an_appended_outer_padding_packet_is_rejected() {
        let (a, b, frame) = setup();
        assert_eq!(
            open_from(&b, &t::append_outer_padding(&frame, 64), &a).unwrap_err(),
            OpenError::BadStructure
        );
    }

    #[test]
    fn l2_trailing_data_is_rejected() {
        let (a, b, frame) = setup();
        assert!(open_from(&b, &t::append_bytes(&frame, &[0u8; 7]), &a).is_err());
        assert!(open_from(&b, &t::append_bytes(&frame, b"\n"), &a).is_err());
    }

    #[test]
    fn l2_an_ascii_armored_frame_is_rejected() {
        let (a, b, frame) = setup();
        assert!(open_from(&b, &t::armored(&frame), &a).is_err());
    }

    #[test]
    fn l2_extra_foreign_pkesks_are_accepted_up_to_the_maximum_and_refused_beyond() {
        let (a, b, frame) = setup();
        // the real PKESK plus 7 foreign ones is exactly the maximum of 8
        open_from(&b, &t::prepend_foreign_pkesks(&frame, 7), &a).unwrap();
        // 8 foreign ones plus the real one is 9: refused
        assert_eq!(
            open_from(&b, &t::prepend_foreign_pkesks(&frame, 8), &a).unwrap_err(),
            OpenError::Malformed
        );
    }

    #[test]
    fn l2_other_ciphers_and_aead_modes_are_rejected() {
        let (a, b, frame) = setup();
        for (c, m) in [
            (SymmetricAlgorithm::AES128, AEADAlgorithm::OCB),
            (SymmetricAlgorithm::AES192, AEADAlgorithm::OCB),
            // (other AEAD modes cannot be produced: this Sequoia build lacks EAX and GCM)
        ] {
            let f = t::rewrap(&b, &frame, &contact(&b), NOW, Inner::Same, c, m);
            assert_eq!(
                open_from(&b, &f, &a).unwrap_err(),
                OpenError::UnsupportedCipher,
                "{c:?} {m:?}"
            );
        }
    }

    #[test]
    fn l2_inner_markers_extra_padding_and_misplaced_padding_are_rejected() {
        let (a, b, frame) = setup();
        for shape in [
            Inner::MarkerFirst,
            Inner::MarkerLast,
            Inner::TwoPaddings,
            Inner::PaddingBeforeSignature,
        ] {
            let f = t::rewrap(
                &b,
                &frame,
                &contact(&b),
                NOW,
                shape,
                SymmetricAlgorithm::AES256,
                AEADAlgorithm::OCB,
            );
            assert!(open_from(&b, &f, &a).is_err(), "{shape:?}");
        }
    }

    #[test]
    fn l2_two_signatures_are_wrong_signature_count() {
        let (a, b) = (ident(), ident());
        let c = ident();
        let payload = t::payload_for(&a, &env(&a, &b, "x", NOW));
        let f = t::seal_two_signers(&a, &c, &contact(&b), &payload, NOW);
        assert_eq!(
            open_from(&b, &f, &a).unwrap_err(),
            OpenError::WrongSignatureCount
        );
    }

    #[test]
    fn l2_a_signature_made_by_a_signing_subkey_is_not_accepted() {
        let b = ident();
        let x = ident();
        let payload = t::payload_for(&x, &env(&x, &b, "x", NOW));
        let (doc, frame) = t::seal_signed_by_signing_subkey(&contact(&b), &payload, NOW);
        let sub = VerifiedContact::parse_and_verify_allow_expired(&doc, NOW).unwrap();
        let dir = Pinned(vec![sub]);
        assert_eq!(
            OpenPgpProtection
                .open(&b, &frame, NOW, &lim(), &dir)
                .unwrap_err(),
            // the issuer is the subkey, whose fingerprint is not an address in
            // the directory: the signer stays unknown (the directory is keyed by
            // primary fingerprint; there is no separate subkey branch in `check`,
            // see the comment there and tests/interop-rpgp `rejection_subkey_signature`)
            OpenError::UnknownSender
        );
    }

    #[test]
    fn l2_a_message_without_padding_still_opens() {
        let (a, b) = (ident(), ident());
        let f = t::seal_with(
            &a,
            &contact(&b),
            &env(&a, &b, "x", NOW),
            NOW,
            BuildOpts {
                pad: false,
                ..BuildOpts::default()
            },
        )
        .unwrap();
        open_from(&b, &f, &a).unwrap();
    }
}

mod l2_adverts {
    use super::*;
    use agentnet_core::crypto::advert::testing as at;
    use agentnet_core::crypto::testing as t;
    use agentnet_core::crypto::{AdvertContent, AdvertLimits, Capability, VerifiedAdvert};

    const TOPIC: &str = "agentnet-test";
    const ALIMITS: AdvertLimits = AdvertLimits {
        max_ttl_ms: 86_400_000,
        clock_skew_ms: 120_000,
        max_capabilities: 16,
    };

    fn good(id: &Identity) -> String {
        id.create_advert(
            &AdvertContent {
                topic: TOPIC,
                capabilities: &[Capability {
                    name: "echo".into(),
                    description: "d".into(),
                }],
                display_name: None,
                issued_at: NOW,
                expires_at: NOW + 60_000,
                seq: 1,
            },
            &ALIMITS,
        )
        .unwrap()
        .to_document()
    }

    fn parse(doc: &str) -> bool {
        VerifiedAdvert::parse_and_verify(doc, TOPIC, NOW, &ALIMITS).is_ok()
    }

    #[test]
    fn l2_only_the_canonical_binary_advert_is_accepted() {
        let id = ident();
        let doc = good(&id);
        assert!(parse(&doc));
        let msg = at::message_bytes(&doc).unwrap();
        // ASCII armor
        assert!(!parse(&at::document_from_bytes(&t::armored(&msg))));
        // prefix-signature form
        assert!(!parse(&at::document_from_bytes(&t::prefix_signature_form(
            &msg
        ))));
        // cleartext signature framework
        let record = at::content_of(&doc).unwrap();
        assert!(!parse(&at::document_from_bytes(&t::sign_cleartext(
            &id, &record, NOW
        ))));
    }
}

// ---- L4

/// L4: every body length of two whole size classes gives one frame length per
/// class (the reviewer measured 2005 B for body length 712 and 2197 B for all
/// the others).
#[test]
fn l4_one_frame_length_per_class_for_every_body_length() {
    let (a, b) = (ident(), ident());
    let cb = contact_at(&b, NOW);
    let mut lengths = std::collections::BTreeMap::<usize, usize>::new();
    for body_len in 0..=2400usize {
        let body = "x".repeat(body_len);
        let f = OpenPgpProtection
            .seal(&a, &cb, &env(&a, &b, &body, NOW), NOW, MAX_FRAME)
            .unwrap();
        *lengths.entry(f.len()).or_default() += 1;
    }
    // two classes (2 KiB and 4 KiB inner size) and nothing else: exactly two lengths
    assert_eq!(lengths.len(), 2, "frame lengths seen: {lengths:?}");
}

// ------------------------------------------------------------------- L4

/// L4: the padded size is a power of two for EVERY inner length (no gaps).
#[test]
fn l4_every_inner_length_has_an_exactly_encodable_padding_target() {
    use agentnet_core::crypto::pgp::padded_total;
    for n in 0..70_000u64 {
        let t = padded_total(n);
        assert!(
            t.is_power_of_two() && t >= 1024 && t >= n + 2,
            "n={n} t={t}"
        );
        // the padding packet needs a body that makes header + body == t - n
        let want = t - n;
        let body_ok = [(2u64, 0u64..192), (3, 192..8384), (6, 8384..u64::MAX)]
            .iter()
            .any(|(h, r)| want >= *h && r.contains(&(want - h)));
        assert!(body_ok, "n={n}: no padding packet of total size {want}");
    }
}

// ------------------------------------------------------------------- M3

/// M3 (a): an ack is not distinguishable by size from the smallest ordinary
/// message of the same sender, whatever the size of the sender's certificate.
#[test]
fn m3_an_ack_has_the_size_of_the_smallest_ordinary_message() {
    use agentnet_core::envelope::MESSAGE_TYPE_ACK_RECEIVED;
    let a = ident();
    let mut b = ident();
    let mut t = NOW;
    for round in 0..8 {
        if round > 0 {
            t += 10_000;
            b.rotate_kem_with(t, t, None, true).unwrap();
        }
        let cb = contact_at(&b, t);
        let smallest = OpenPgpProtection
            .seal(&b, &contact_at(&a, t), &env(&b, &a, "x", t), t, MAX_FRAME)
            .unwrap();
        let mut ack = env(&b, &a, "", t);
        ack.message_type = MESSAGE_TYPE_ACK_RECEIVED.to_owned();
        ack.correlation_id = Some("9d3c1a52-0f5e-4b7e-8a41-6a0d7a9c2b11".into());
        ack.conversation_id = Some("0c7bb2d4-5d11-4a5f-9b5b-1f0f6d2e3a77".into());
        let ackf = OpenPgpProtection
            .seal(&b, &contact_at(&a, t), &ack, t, MAX_FRAME)
            .unwrap();
        eprintln!(
            "M3 round {round}: sender certificate {} B, smallest message {} B, ack {} B",
            b.contact_record().as_bytes().len(),
            smallest.len(),
            ackf.len()
        );
        assert_eq!(ackf.len(), smallest.len(), "round {round}");
        let _ = cb;
    }
}

// ------------------------------------------------------------------- L1

/// L1: a sender whose clock is ahead has a signature time in the future. Within
/// the permitted skew the frame opens; beyond it the frame is "from the future"
/// (deferred and re-evaluated later), not a bad signature.
#[test]
fn l1_a_signature_time_ahead_of_the_clock_is_from_future_not_bad_signature() {
    let (a, b) = (ident(), ident());
    let dir = Pinned(vec![contact_at(&a, NOW + 600_000)]);
    // the envelope's created_at is honest (NOW); only the signature time is ahead
    for (ahead_ms, expect) in [
        (0, None),
        (60_000, None),
        (119_000, None),
        (121_000, Some(OpenError::FromFuture)),
        (600_000, Some(OpenError::FromFuture)),
    ] {
        let f = OpenPgpProtection
            .seal(
                &a,
                &contact_at(&b, NOW + 600_000),
                &env(&a, &b, "x", NOW),
                NOW + ahead_ms,
                MAX_FRAME,
            )
            .unwrap();
        let r = OpenPgpProtection.open(&b, &f, NOW, &lim(), &dir);
        match expect {
            None => {
                r.unwrap_or_else(|e| panic!("signature {ahead_ms} ms ahead: {e:?}"));
            }
            Some(e) => assert_eq!(r.unwrap_err(), e, "signature {ahead_ms} ms ahead"),
        }
    }
}

// ------------------------------------------------------------------- L3

/// L3: junk in unhashed subpacket areas and corrupted copies of binding
/// signatures that name the primary as issuer are dropped: the stored form of
/// the bloated certificate is byte-identical to the clean one, so a bloated copy
/// cannot use up the size cap.
#[test]
fn l3_unhashed_junk_and_invalid_signatures_do_not_survive_sanitising() {
    use agentnet_core::crypto::testing as t;
    let mut b = ident();
    b.rotate_kem_with(NOW + 10_000, NOW + 10_000, None, true)
        .unwrap();
    let clean = b.contact_record().to_document();
    let bloated = t::public_cert_bloated(&b, 4, 2);
    assert!(
        bloated.len() > 3 * clean.len(),
        "the test input must be much larger ({} vs {})",
        bloated.len(),
        clean.len()
    );
    let t0 = NOW + 20_000;
    let vc_clean = VerifiedContact::parse_and_verify(&clean, t0).unwrap();
    let vc_bloated = VerifiedContact::parse_and_verify(&bloated, t0).unwrap();
    assert!(
        vc_bloated.document() == vc_clean.document(),
        "the stored form of the bloated certificate differs from the clean one"
    );
    // and merging the bloated copy into a stored contact changes nothing
    let merged = vc_clean.merge(&vc_bloated, t0).unwrap();
    assert!(merged.document() == vc_clean.document());
}

// ------------------------------------------------------------- frame sizes

/// Frame sizes (recorded in `docs/protocol.md` s5 and `docs/threat-model.md`)
/// for the sender certificate of a fresh identity and of one at the certificate
/// cap, and the transport limit for the largest body (64 KiB), also in the
/// worst JSON expansion (64 KiB of quotes).
#[test]
fn frame_sizes_with_a_fresh_and_a_maximal_sender_certificate_fit_the_transport_limit() {
    use agentnet_core::envelope::MESSAGE_TYPE_ACK_RECEIVED;
    let a = ident();
    let fresh = ident();
    let mut maximal = ident();
    let mut t = NOW;
    loop {
        t += 10_000;
        if maximal.rotate_kem_with(t, t, None, true).is_err() {
            break;
        }
    }
    for (label, sender) in [("fresh", &fresh), ("maximal", &maximal)] {
        let cert = sender.contact_record().as_bytes().len();
        let recipient = contact_at(&a, t);
        let mut sizes = vec![];
        for body in [0usize, 1024, 65_536] {
            let f = OpenPgpProtection
                .seal(
                    sender,
                    &recipient,
                    &env(sender, &a, &"a".repeat(body), t),
                    t,
                    MAX_FRAME,
                )
                .unwrap();
            assert!(f.len() < MAX_FRAME, "{label} {body}: {}", f.len());
            let dir = Pinned(vec![contact_at(sender, t)]);
            assert_eq!(
                OpenPgpProtection
                    .open(&a, &f, t, &lim(), &dir)
                    .unwrap()
                    .envelope
                    .body
                    .len(),
                body
            );
            sizes.push((body, f.len()));
        }
        let q = "\"".repeat(65_536);
        let worst = OpenPgpProtection
            .seal(sender, &recipient, &env(sender, &a, &q, t), t, MAX_FRAME)
            .unwrap();
        assert!(worst.len() <= MAX_FRAME, "{label} quotes: {}", worst.len());
        let mut ack = env(sender, &a, "", t);
        ack.message_type = MESSAGE_TYPE_ACK_RECEIVED.to_owned();
        ack.correlation_id = Some("9d3c1a52-0f5e-4b7e-8a41-6a0d7a9c2b11".into());
        ack.conversation_id = Some("0c7bb2d4-5d11-4a5f-9b5b-1f0f6d2e3a77".into());
        let ackf = OpenPgpProtection
            .seal(sender, &recipient, &ack, t, MAX_FRAME)
            .unwrap();
        eprintln!(
            "FRAME-SIZES {label}: certificate {cert} B, (body, frame) {sizes:?}, 64 KiB of quotes {} B, ack {} B",
            worst.len(),
            ackf.len()
        );
    }
}

#[test]
fn review_negative_created_at_cannot_overflow_or_bypass_max_ttl() {
    let (a, b) = (ident(), ident());
    let dir = Pinned(vec![contact_at(&a, NOW)]);
    let mut e = env(&a, &b, "overflow", NOW);
    e.created_at = -5_000_000_000_000_000_000;
    e.expires_at = 5_000_000_000_000_000_000;
    let f = OpenPgpProtection
        .seal(&a, &contact_at(&b, NOW), &e, NOW, MAX_FRAME)
        .unwrap();
    let err = OpenPgpProtection
        .open(&b, &f, NOW, &lim(), &dir)
        .unwrap_err();
    assert_eq!(err, OpenError::InvalidField("created_at"));
}

#[test]
fn review_primary_revocation_succeeds_and_merges_at_rotation_cap() {
    use agentnet_core::crypto::VerifiedRevocation;
    let mut id = ident();
    let mut t = NOW;
    loop {
        t += 10_000;
        if id.rotate_kem_with(t, t, None, true).is_err() {
            break;
        }
    }
    let stored = VerifiedContact::parse_and_verify(&id.contact_record().to_document(), t).unwrap();
    let rev = id
        .create_revocation("compromised at cap", t + 1_000)
        .unwrap();
    let vrev = VerifiedRevocation::parse_and_verify(&rev.to_document(), t + 1_000).unwrap();
    assert_eq!(vrev.address, id.address());
    let rev_contact =
        VerifiedContact::parse_and_verify_allow_expired(vrev.document(), t + 1_000).unwrap();
    let merged = stored.merge(&rev_contact, t + 1_000).unwrap();
    assert!(merged.revocation(t + 1_000).is_some());
}

#[test]
fn review_accept_rollback_on_healthy_store_does_not_disarm_future_guard() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("agentnet.db");
    let sp = agentnet_core::guard::sidecar_path(&db);
    let store = agentnet_core::store::Store::open(&db).unwrap();
    store
        .tx(|tx| {
            agentnet_core::store::kv_set(tx, "own_address", "an2test")?;
            agentnet_core::store::kv_set(tx, "store_generation", "5")
        })
        .unwrap();
    store.close();
    agentnet_core::guard::write_sidecar(
        &sp,
        &agentnet_core::guard::Sidecar {
            generation: 5,
            guard: None,
        },
    )
    .unwrap();
    assert!(!agentnet_core::guard::accept_rollback(&db).unwrap());
    let store = agentnet_core::store::Store::open(&db).unwrap();
    let clear = store
        .read(|c| agentnet_core::store::kv_get(c, "replay_guard_clear_request"))
        .unwrap();
    store.close();
    assert!(
        clear.is_none(),
        "accept_rollback on healthy store must not plant replay_guard_clear_request"
    );
}
