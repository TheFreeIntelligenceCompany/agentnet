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
                assert!(i > 9, "the cap must allow at least 9 rotations (reviewer's case)");
                break;
            }
            Err(e) => panic!("unexpected {e}"),
        }
    }
    // the stale certificate is merged back in
    let t = last_ok + 1_000;
    let merged = seen_by_a.merge(&original, t).unwrap();
    let f = OpenPgpProtection
        .seal(&a, &merged, &env(&a, &b, "after compromise", t), t, MAX_FRAME)
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
    assert!(refused, "rotations must eventually fail with a clear error, not trim revocations");
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
