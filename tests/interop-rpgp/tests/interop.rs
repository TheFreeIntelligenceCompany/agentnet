//! Independent interoperability check: rPGP against AgentNet's OpenPGP frames (ADR 0004).
//! Run: `cd tests/interop-rpgp && cargo test --locked -- --nocapture` (needs OpenSSL 3, see docs/licensing.md).

use agentnet_core::crypto::testing as t;
use agentnet_core::crypto::{
    Address, Envelope, Identity, MessageProtection, NoSenders, OpenLimits, OpenPgpProtection,
    SenderAuth, SenderDirectory, VerifiedContact,
};
use agentnet_core::envelope::MESSAGE_TYPE_MESSAGE;
use agentnet_core::error::OpenError;
use agentnet_interop_rpgp as rp;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

const MAX_FRAME: usize = 153_600;

fn lim() -> OpenLimits {
    OpenLimits::default()
}

fn contact_of(id: &Identity) -> VerifiedContact {
    VerifiedContact::parse_and_verify(&id.contact_record().to_document(), now_ms()).unwrap()
}

fn env(from: &Identity, to: &Identity, body: &str) -> Envelope {
    Envelope::new(
        from.address(),
        to.address(),
        MESSAGE_TYPE_MESSAGE,
        body.to_owned(),
        now_ms(),
        3_600_000,
    )
    .unwrap()
}

fn fp_hex(a: &Address) -> String {
    a.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

struct Pinned(Vec<VerifiedContact>);
impl SenderDirectory for Pinned {
    fn certificate(&self, a: &Address) -> Option<VerifiedContact> {
        self.0.iter().find(|c| c.address == *a).cloned()
    }
}

/// rPGP views of an AgentNet identity: its secret key and its public certificate.
fn rp_secret(id: &Identity) -> rpgpie::tsk::Tsk {
    rp::tsk_from_doc(&t::secret_cert_document(id)).expect("rPGP loads the AgentNet secret key")
}
fn rp_public(id: &Identity) -> rpgpie::certificate::Certificate {
    rp::cert_from_doc(&id.contact_record().to_document())
        .expect("rPGP loads the AgentNet certificate")
}

fn pair() -> (Identity, Identity) {
    (
        Identity::generate_default(now_ms()).unwrap(),
        Identity::generate_default(now_ms()).unwrap(),
    )
}

/// (a) A frame sealed by AgentNet is opened by rPGP.
#[test]
fn rpgp_opens_agentnet_frame() {
    let (alice, bob) = pair();
    let e = env(&alice, &bob, "hello from agentnet");
    let frame = OpenPgpProtection
        .seal(&alice, &contact_of(&bob), &e, now_ms(), MAX_FRAME)
        .unwrap();
    println!(
        "agentnet frame: {} bytes\n--- rPGP packet dump ---\n{}",
        frame.len(),
        rp::dump(&frame)
    );

    let o = rp::open(&rp_secret(&bob), &rp_public(&alice), &frame).expect("rPGP opens the frame");
    // signer is the sender's primary key; Intended Recipient Fingerprint names the recipient
    assert_eq!(o.signer, fp_hex(&alice.address()));
    assert_eq!(o.intended, vec![fp_hex(&bob.address())]);
    let j: serde_json::Value = serde_json::from_slice(&o.payload).unwrap();
    assert_eq!(j["body"], "hello from agentnet");
    assert_eq!(j["sender"].as_str().unwrap(), alice.address().to_string());
    assert_eq!(j["recipient"].as_str().unwrap(), bob.address().to_string());
    assert_eq!(j["type"], "message");
    assert_eq!(j["message_id"], e.message_id);
    println!("rPGP opened: signer={} intended={:?}", o.signer, o.intended);
}

/// (a, negative) rPGP rejects the frame under a wrong recipient key, a wrong sender
/// certificate, and every single-bit flip.
#[test]
fn rpgp_rejects_wrong_key_and_tampered_frames() {
    let (alice, bob) = pair();
    let carol = Identity::generate_default(now_ms()).unwrap();
    let frame = OpenPgpProtection
        .seal(
            &alice,
            &contact_of(&bob),
            &env(&alice, &bob, "x"),
            now_ms(),
            MAX_FRAME,
        )
        .unwrap();
    // control
    rp::open(&rp_secret(&bob), &rp_public(&alice), &frame).expect("control");
    // wrong recipient secret key
    let e = rp::open(&rp_secret(&carol), &rp_public(&alice), &frame).unwrap_err();
    println!("wrong recipient key -> {e}");
    // wrong sender certificate (signature must not verify)
    let e = rp::open(&rp_secret(&bob), &rp_public(&carol), &frame).unwrap_err();
    println!("wrong sender certificate -> {e}");

    // every single-bit flip of every byte, and every truncation, must be rejected without panic
    let mut accepted = vec![];
    let mut panics = 0usize;
    for i in 0..frame.len() {
        let mut d = frame.clone();
        d[i] ^= 0x01;
        let bob_sk = rp_secret(&bob);
        let alice_pk = rp_public(&alice);
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rp::open(&bob_sk, &alice_pk, &d)
        })) {
            Ok(Ok(_)) => accepted.push(i),
            Ok(Err(_)) => {}
            Err(_) => panics += 1,
        }
    }
    println!(
        "rPGP bit flips: {} offsets, accepted={:?}, panics={}",
        frame.len(),
        accepted,
        panics
    );
    assert!(accepted.is_empty(), "flips accepted at {accepted:?}");
    assert_eq!(panics, 0);
    let bob_sk = rp_secret(&bob);
    let alice_pk = rp_public(&alice);
    for n in 0..frame.len() {
        assert!(
            rp::open(&bob_sk, &alice_pk, &frame[..n]).is_err(),
            "truncation to {n} accepted"
        );
    }
}

/// (b) A message made by rPGP (anonymous v6 PKESK, SEIPD v2, v6 signature with Intended Recipient
/// Fingerprint, no Padding packet) is opened by AgentNet's normal `open`.
#[test]
fn agentnet_opens_rpgp_message() {
    let (alice, bob) = pair();
    let e = env(&alice, &bob, "hello from rpgp");
    let payload = t::payload_for(&alice, &e);
    let frame = rp::seal(
        &rp_secret(&alice),
        &rp_public(&bob),
        &payload,
        rp::SealOpts::default(),
    )
    .expect("rPGP seals");
    println!(
        "rPGP message: {} bytes\n--- rPGP packet dump ---\n{}",
        frame.len(),
        rp::dump(&frame)
    );

    // sender not a contact: authenticated by the certificate embedded in the payload
    let o = OpenPgpProtection
        .open(&bob, &frame, now_ms(), &lim(), &NoSenders)
        .expect("AgentNet opens the rPGP message (embedded certificate)");
    assert_eq!(o.envelope, e);
    assert_eq!(o.sender, alice.address());
    assert_eq!(o.auth, SenderAuth::EmbeddedCertificate);
    // sender pinned as a contact
    let pinned = Pinned(vec![contact_of(&alice)]);
    let o = OpenPgpProtection
        .open(&bob, &frame, now_ms(), &lim(), &pinned)
        .expect("AgentNet opens the rPGP message (pinned contact)");
    assert_eq!(o.envelope.body, "hello from rpgp");
    assert_eq!(o.auth, SenderAuth::Pinned);
    println!("AgentNet opened the rPGP message (embedded and pinned)");
}

/// (b, negatives) AgentNet rejects rPGP messages that violate the receiver policy. Each case is
/// paired with the accepted control above, so the failure is caused by the one changed property.
#[test]
fn agentnet_rejects_nonconforming_rpgp_messages() {
    let (alice, bob) = pair();
    let carol = Identity::generate_default(now_ms()).unwrap();
    let e = env(&alice, &bob, "negative cases");
    let payload = t::payload_for(&alice, &e);
    let open = |frame: &[u8]| OpenPgpProtection.open(&bob, frame, now_ms(), &lim(), &NoSenders);

    // control
    let ok = rp::seal(
        &rp_secret(&alice),
        &rp_public(&bob),
        &payload,
        rp::SealOpts::default(),
    )
    .unwrap();
    open(&ok).expect("control accepted");

    // 1. no Intended Recipient Fingerprint
    let m = rp::seal(
        &rp_secret(&alice),
        &rp_public(&bob),
        &payload,
        rp::SealOpts {
            intended: false,
            ..Default::default()
        },
    )
    .unwrap();
    let err = open(&m).unwrap_err();
    println!("no Intended Recipient Fingerprint -> {err:?}");
    assert!(
        matches!(err, OpenError::MissingIntendedRecipient),
        "{err:?}"
    );

    // 2. signer is a different v6 key than the sender named in the payload (carol signs, payload says alice)
    let m = rp::seal(
        &rp_secret(&carol),
        &rp_public(&bob),
        &payload,
        rp::SealOpts::default(),
    )
    .unwrap();
    let err = open(&m).unwrap_err();
    println!("wrong signer (v6 key of another identity) -> {err:?}");
    assert!(
        matches!(
            err,
            OpenError::UnknownSender | OpenError::SignerMismatch | OpenError::BadSignature
        ),
        "{err:?}"
    );
    // ... and also when alice is a pinned contact
    let pinned = Pinned(vec![contact_of(&alice)]);
    let err = OpenPgpProtection
        .open(&bob, &m, now_ms(), &lim(), &pinned)
        .unwrap_err();
    println!("wrong signer, sender pinned -> {err:?}");
    assert!(
        matches!(
            err,
            OpenError::UnknownSender | OpenError::SignerMismatch | OpenError::BadSignature
        ),
        "{err:?}"
    );

    // 3. signer is a version 4 key
    let v4 = rp::generate(true).expect("rPGP generates a v4 key");
    let m = rp::seal(&v4, &rp_public(&bob), &payload, rp::SealOpts::default()).unwrap();
    let err = open(&m).unwrap_err();
    println!("v4 signing key -> {err:?}");
    assert!(
        matches!(
            err,
            OpenError::UnknownSender
                | OpenError::SignerMismatch
                | OpenError::UnsupportedSignature
                | OpenError::BadSignature
        ),
        "{err:?}"
    );

    // 4. addressed to someone else (encrypted to carol): not for bob
    let m = rp::seal(
        &rp_secret(&alice),
        &rp_public(&carol),
        &payload,
        rp::SealOpts::default(),
    )
    .unwrap();
    let err = open(&m).unwrap_err();
    println!("encrypted to another identity -> {err:?}");
    assert!(matches!(err, OpenError::NotForUs), "{err:?}");

    // 5. a named (non-anonymous) PKESK v6 is an equally valid message: AgentNet still opens it
    //    (documents that anonymity is a sender-side choice, not a receive requirement)
    let m = rp::seal(
        &rp_secret(&alice),
        &rp_public(&bob),
        &payload,
        rp::SealOpts {
            anonymous: false,
            ..Default::default()
        },
    )
    .unwrap();
    match open(&m) {
        Ok(_) => println!("named-recipient PKESK v6 -> accepted"),
        Err(e) => println!("named-recipient PKESK v6 -> rejected {e:?}"),
    }
}
