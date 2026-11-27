//! Receiver-policy rejection branches that Sequoia's high-level API cannot construct, driven by
//! messages built by rPGP (a second implementation) and fed to AgentNet's normal `open` path.
//! Every negative is paired with a positive control that differs only in the property under test
//! (same sender, recipient, payload and builder code path), so a case cannot pass for the wrong
//! reason. The expected `OpenError` and the `open_error.*` counter the engine would increment
//! (`OpenError::metric_kind`, used by `ingest_frame` for every error except `NotForUs`,
//! `SenderRevoked` and `FromFuture`) are asserted exactly.
//! Run: `cd tests/interop-rpgp && cargo test --locked -- --nocapture rejection`.

use agentnet_core::crypto::testing as t;
use agentnet_core::crypto::{
    Address, Identity, MessageProtection, NoSenders, OpenLimits, OpenPgpProtection, SenderAuth,
    SenderDirectory, VerifiedContact,
};
use agentnet_core::envelope::{Envelope, MESSAGE_TYPE_MESSAGE};
use agentnet_core::error::OpenError;
use agentnet_interop_rpgp as rp;
use pgp::crypto::aead::AeadAlgorithm;

type Opened = Result<(SenderAuth, String), OpenError>;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn contact_of(id: &Identity) -> VerifiedContact {
    VerifiedContact::parse_and_verify(&id.contact_record().to_document(), now_ms()).unwrap()
}

fn env_to(from: Address, to: &Identity, body: &str) -> Envelope {
    Envelope::new(
        from,
        to.address(),
        MESSAGE_TYPE_MESSAGE,
        body.to_owned(),
        now_ms(),
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

fn rp_secret(id: &Identity) -> rpgpie::tsk::Tsk {
    rp::tsk_from_doc(&t::secret_cert_document(id)).expect("rPGP loads the AgentNet secret key")
}
fn rp_public(id: &Identity) -> rpgpie::certificate::Certificate {
    rp::cert_from_doc(&id.contact_record().to_document())
        .expect("rPGP loads the AgentNet certificate")
}

fn ident() -> Identity {
    Identity::generate_default(now_ms()).unwrap()
}

/// Open as `bob` with `dir` as the sender directory.
fn open(bob: &Identity, frame: &[u8], dir: &dyn SenderDirectory) -> Opened {
    OpenPgpProtection
        .open(bob, frame, now_ms(), &OpenLimits::default(), dir)
        .map(|o| (o.auth, o.envelope.body))
}

/// Assert the exact variant and the counter name; print the observation for the evidence log.
fn expect_rejected(what: &str, r: Opened, want: OpenError, counter: &str) {
    let e = r.expect_err(&format!("{what}: must be rejected"));
    println!(
        "REJECTED  {what:<64} -> {e:?} (counter open_error.{})",
        e.metric_kind()
    );
    assert_eq!(e, want, "{what}");
    assert_eq!(format!("open_error.{}", e.metric_kind()), counter, "{what}");
}

fn expect_accepted(what: &str, r: Opened) {
    let (auth, body) = r.unwrap_or_else(|e| panic!("{what}: control rejected: {e:?}"));
    println!("ACCEPTED  {what:<64} -> auth {auth:?}, body {body:?}");
}

struct World {
    alice: Identity,
    bob: Identity,
    payload: Vec<u8>,
    pinned: Pinned,
}

fn world() -> World {
    let (alice, bob) = (ident(), ident());
    let payload = t::payload_for(&alice, &env_to(alice.address(), &bob, "rejection branches"));
    let pinned = Pinned(vec![contact_of(&alice)]);
    World {
        alice,
        bob,
        payload,
        pinned,
    }
}

fn seal(w: &World, o: rp::SealOpts) -> Vec<u8> {
    rp::seal(&rp_secret(&w.alice), &rp_public(&w.bob), &w.payload, o).expect("rPGP seals")
}

/// Packet-level dump of the OUTER packets of a message (the inner ones are encrypted).
fn show(title: &str, m: &[u8]) {
    let d = rp::dump(m);
    // the encrypted data is long; keep the structure and the configuration, cut the ciphertext
    let short: String = d
        .lines()
        .map(|l| match l.find(", data: ") {
            Some(i) => format!("{} ... }})", &l[..i]),
            None => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    println!("--- {title}: outer packets ---\n{short}");
}

/// (c) AEAD modes other than OCB in the SEIPD v2 packet: rejected by the outer packet check,
/// before any decryption (`check_outer`, `UnsupportedCipher`).
#[test]
fn rejection_aead_modes_other_than_ocb() {
    let w = world();
    let control = seal(&w, rp::SealOpts::default());
    show("control, OCB", &control);
    expect_accepted(
        "control: PKESK v6 + SEIPD v2 AES-256 OCB",
        open(&w.bob, &control, &w.pinned),
    );
    for (name, aead) in [("EAX", AeadAlgorithm::Eax), ("GCM", AeadAlgorithm::Gcm)] {
        let m = seal(
            &w,
            rp::SealOpts {
                aead,
                ..Default::default()
            },
        );
        show(name, &m);
        expect_rejected(
            &format!("SEIPD v2 AES-256 {name}, pinned sender"),
            open(&w.bob, &m, &w.pinned),
            OpenError::UnsupportedCipher,
            "open_error.unsupported_cipher",
        );
        expect_rejected(
            &format!("SEIPD v2 AES-256 {name}, unknown sender"),
            open(&w.bob, &m, &NoSenders),
            OpenError::UnsupportedCipher,
            "open_error.unsupported_cipher",
        );
    }
}

/// (c) SEIPD v1 (no AEAD) together with a PKESK v6: rejected by the outer packet check
/// (`Packet::SEIP(_) => NotAead`), after the PKESK v6 passed.
#[test]
fn rejection_seipd_v1_with_pkesk_v6() {
    let w = world();
    let control = seal(&w, rp::SealOpts::default());
    expect_accepted(
        "control: PKESK v6 + SEIPD v2 AES-256 OCB",
        open(&w.bob, &control, &w.pinned),
    );
    let m = rp::seal_seipd1_with_pkesk_v6(
        &rp_secret(&w.alice),
        &rp_public(&w.bob),
        &w.payload,
        rp::SealOpts::default(),
    )
    .expect("rPGP builds SEIPD v1 + PKESK v6");
    show("SEIPD v1 + PKESK v6", &m);
    expect_rejected(
        "PKESK v6 + SEIPD v1, pinned sender",
        open(&w.bob, &m, &w.pinned),
        OpenError::NotAead,
        "open_error.not_aead",
    );
    expect_rejected(
        "PKESK v6 + SEIPD v1, unknown sender",
        open(&w.bob, &m, &NoSenders),
        OpenError::NotAead,
        "open_error.not_aead",
    );
}

/// (b) A TEXT-type (0x01, canonical text) signature instead of a binary (0x00) one. The signature
/// is valid (a bad one would be `BadSignature`); only its type differs from the control.
#[test]
fn rejection_text_type_signature() {
    let w = world();
    let control = seal(&w, rp::SealOpts::default());
    expect_accepted(
        "control: binary (0x00) document signature",
        open(&w.bob, &control, &w.pinned),
    );
    let m = seal(
        &w,
        rp::SealOpts {
            text_signature: true,
            ..Default::default()
        },
    );
    expect_rejected(
        "text (0x01) signature, pinned sender",
        open(&w.bob, &m, &w.pinned),
        OpenError::UnsupportedSignature,
        "open_error.unsupported_signature",
    );
    expect_rejected(
        "text (0x01) signature, unknown sender (embedded certificate)",
        open(&w.bob, &m, &NoSenders),
        OpenError::UnsupportedSignature,
        "open_error.unsupported_signature",
    );
}

/// (a) A version 4 signature made with the sender's version 6 key, and a message signed by a
/// genuine version 4 key.
#[test]
fn rejection_v4_signature_and_v4_key() {
    let w = world();
    let control = seal(&w, rp::SealOpts::default());
    expect_accepted(
        "control: v6 signature by v6 key",
        open(&w.bob, &control, &w.pinned),
    );

    // rPGP refuses a v6 Issuer Fingerprint in the HASHED area of a v4 signature, so for the v4
    // signature the issuer is in the unhashed area, and the Intended Recipient is left out of both
    // messages below (a v4 signature carrying one is not needed to hit the version check). The
    // control for the v4 signature is the same message with a v6 signature and no Intended
    // Recipient: it gets as far as the Intended Recipient check, i.e. past the signature
    // version, type and key-algorithm checks, so only the signature version differs.
    let v6_no_ir = seal(
        &w,
        rp::SealOpts {
            intended: false,
            ..Default::default()
        },
    );
    expect_rejected(
        "control: v6 signature, no Intended Recipient (reaches the IR check)",
        open(&w.bob, &v6_no_ir, &w.pinned),
        OpenError::MissingIntendedRecipient,
        "open_error.missing_intended_recipient",
    );
    let v4_sig = seal(
        &w,
        rp::SealOpts {
            intended: false,
            v4_signature: true,
            ..Default::default()
        },
    );
    // Sequoia's verifier refuses a v4 signature by a v6 key itself ("Signature (v4) and key (v6)
    // version mismatch", sequoia-openpgp 2.5.0 src/packet/signature.rs:2872), so AgentNet sees a
    // failed verification, not a good signature of the wrong version.
    expect_rejected(
        "v4 signature by the pinned v6 key",
        open(&w.bob, &v4_sig, &w.pinned),
        OpenError::BadSignature,
        "open_error.bad_signature",
    );
    expect_rejected(
        "v4 signature by the v6 key, unknown sender (embedded certificate)",
        open(&w.bob, &v4_sig, &NoSenders),
        OpenError::BadSignature,
        "open_error.bad_signature",
    );

    // A genuine v4 key signs a message that names alice as the sender: its 20-byte issuer
    // fingerprint is not an AgentNet address, so the signer stays unknown.
    let v4_key = rp::generate(true).expect("rPGP generates a v4 key");
    let m = rp::seal(
        &v4_key,
        &rp_public(&w.bob),
        &w.payload,
        rp::SealOpts::default(),
    )
    .unwrap();
    expect_rejected(
        "v4 key signs (payload names alice), alice pinned",
        open(&w.bob, &m, &w.pinned),
        OpenError::UnknownSender,
        "open_error.unknown_sender",
    );
    expect_rejected(
        "v4 key signs, unknown sender",
        open(&w.bob, &m, &NoSenders),
        OpenError::UnknownSender,
        "open_error.unknown_sender",
    );
}

/// (d) A signature made by a signing-capable SUBKEY of a certificate the directory DOES know.
/// The control is the same certificate, recipient, payload and builder with the PRIMARY key
/// signing; it passes the whole receiver policy and the signer resolves to the pinned address.
#[test]
fn rejection_subkey_signature() {
    let (secret_doc, public_doc) = t::cert_with_signing_subkey_documents(now_ms());
    let bob = ident();
    let known = VerifiedContact::parse_and_verify(&public_doc, now_ms()).expect("contact");
    // The payload names the certificate's own address as the sender, so the control opens fully.
    // The embedded certificate in the payload is a throwaway identity's (unused: the sender is pinned).
    let x = ident();
    let payload = t::payload_for(&x, &env_to(known.address, &bob, "subkey"));
    let sender = rp::tsk_from_doc(&secret_doc).expect("rPGP loads the secret certificate");
    let dir = Pinned(vec![known]);
    let bob_pub = rp_public(&bob);
    let seal = |o: rp::SealOpts| rp::seal(&sender, &bob_pub, &payload, o).expect("rPGP seals");

    let control = seal(rp::SealOpts::default());
    let r = open(&bob, &control, &dir);
    println!("control (primary signs), pinned -> {r:?}");
    assert!(
        r.is_ok(),
        "control must open completely (signer == payload sender): {r:?}"
    );

    let by_subkey = seal(rp::SealOpts {
        signer_index: 1,
        ..Default::default()
    });
    expect_rejected(
        "signing subkey signs, hashed issuer = the subkey, cert pinned",
        open(&bob, &by_subkey, &dir),
        OpenError::UnknownSender,
        "open_error.unknown_sender",
    );
    expect_rejected(
        "signing subkey signs, hashed issuer = the subkey, unknown sender",
        open(&bob, &by_subkey, &NoSenders),
        OpenError::UnknownSender,
        "open_error.unknown_sender",
    );
    // The subkey signs but claims the primary key as issuer (the only way to make the directory
    // hand over the certificate): the primary key's verification fails.
    let claims_primary = seal(rp::SealOpts {
        signer_index: 1,
        claim_primary_issuer: true,
        ..Default::default()
    });
    expect_rejected(
        "signing subkey signs, hashed issuer claims the primary, cert pinned",
        open(&bob, &claims_primary, &dir),
        OpenError::BadSignature,
        "open_error.bad_signature",
    );
}
