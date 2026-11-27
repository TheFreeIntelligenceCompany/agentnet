//! Builders of deliberately weakened, forged or re-targeted messages and
//! certificates, for tests of the receiver policy and the engine. Built with
//! Sequoia's lower-level API on purpose, independent of the production
//! `seal`. Not part of the supported API (feature `test-support`).

use std::io::Write as _;

use sequoia_openpgp as openpgp;

use openpgp::cert::prelude::*;
use openpgp::crypto::{Password, SessionKey};
use openpgp::packet::prelude::*;
use openpgp::parse::{PacketParser, PacketParserResult, Parse};
use openpgp::serialize::stream::padding::Padder;
use openpgp::serialize::stream::{
    Compressor, Encryptor, LiteralWriter, Message, Recipient, Signer,
};
use openpgp::serialize::{Marshal, MarshalInto};
use openpgp::types::{
    AEADAlgorithm, CompressionAlgorithm, Features, KeyFlags, SignatureType, SymmetricAlgorithm,
};
use openpgp::{Cert, Packet};

use super::contact::VerifiedContact;
use super::envelope::Envelope;
use super::identity::Identity;
use super::pgp::{self};
pub use super::pgp::BuildOpts;
use super::protection::{payload_bytes, OpenPgpProtection};
use crate::error::SealError;


/// The JSON payload the engine would put in the literal data packet.
pub fn payload_for(sender: &Identity, env: &Envelope) -> Vec<u8> {
    payload_bytes(sender, env).unwrap_or_default()
}

/// Seal `env` with explicit options (no Intended Recipient, no padding, unsigned...).
pub fn seal_with(
    sender: &Identity,
    recipient: &VerifiedContact,
    env: &Envelope,
    now_ms: i64,
    opts: BuildOpts,
) -> Result<Vec<u8>, SealError> {
    OpenPgpProtection.seal_with(sender, recipient, env, now_ms, usize::MAX, opts)
}

/// Seal an arbitrary payload (any bytes in the literal data packet).
pub fn seal_payload(
    sender: &Identity,
    recipient: &VerifiedContact,
    payload: &[u8],
    now_ms: i64,
    opts: BuildOpts,
) -> Result<Vec<u8>, SealError> {
    let signer = sender
        .signer()
        .ok_or(SealError::SenderNotUsable("no signing key"))?;
    pgp::seal_message(signer, recipient.cert(), payload, now_ms, &opts)
}

fn recipients_of<'a>(vc: &'a ValidCert<'a>) -> Vec<Recipient<'a>> {
    vc.keys()
        .subkeys()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .map(|ka| Recipient::new(vc.features(), None, ka.key()))
        .collect()
}

/// Re-encrypt the SAME signed inner packets of `frame` (decrypted by `me`) to
/// `to`: what a malicious recipient does in a surreptitious-forwarding attack.
pub fn forward(
    me: &Identity,
    frame: &[u8],
    to: &VerifiedContact,
    now_ms: i64,
) -> Result<Vec<u8>, String> {
    let mut inner: Vec<u8> = Vec::new();
    let mut ppr = PacketParser::from_bytes(frame).map_err(|e| e.to_string())?;
    let mut session: Option<(Option<SymmetricAlgorithm>, SessionKey)> = None;
    let keys = me.decryption_keypairs(now_ms);
    while let PacketParserResult::Some(mut pp) = ppr {
        match &pp.packet {
            Packet::PKESK(k) => {
                for mut pair in keys.iter().map(|k| k.clone()) {
                    if let Some((a, sk)) = k.decrypt(&mut pair, None) {
                        session = Some((a, sk));
                        break;
                    }
                }
            }
            Packet::SEIP(_) => {
                let (a, sk) = session.as_ref().ok_or("cannot decrypt")?;
                pp.decrypt(Some(a.unwrap_or(SymmetricAlgorithm::AES256)), sk)
                    .map_err(|e| e.to_string())?;
            }
            Packet::Padding(_) => {}
            Packet::OnePassSig(_) | Packet::Signature(_) | Packet::Literal(_) => {
                if let Packet::Literal(_) = &pp.packet {
                    pp.buffer_unread_content().map_err(|e| e.to_string())?;
                }
                pp.packet.serialize(&mut inner).map_err(|e| e.to_string())?;
            }
            _ => {}
        }
        ppr = pp.recurse().map_err(|e| e.to_string())?.1;
    }
    if inner.is_empty() {
        return Err("nothing recovered".into());
    }
    let policy = pgp::policy();
    let vc = to
        .cert()
        .with_policy(&policy, pgp::st(now_ms))
        .map_err(|e| e.to_string())?;
    let recips = recipients_of(&vc);
    let mut sink = Vec::new();
    {
        let m = Message::new(&mut sink);
        let mut m = Encryptor::for_recipients(m, recips)
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .aead_algo(AEADAlgorithm::OCB)
            .build()
            .map_err(|e| e.to_string())?;
        m.write_all(&inner).map_err(|e| e.to_string())?;
        m.finalize().map_err(|e| e.to_string())?;
    }
    Ok(sink)
}

/// Prepend a PKESK v3 (to a throwaway v4 key) to `frame`.
pub fn prepend_pkesk_v3(frame: &[u8]) -> Vec<u8> {
    let (cert, _) = CertBuilder::new()
        .add_subkey(KeyFlags::empty().set_transport_encryption(), None, None)
        .generate()
        .expect("v4 cert");
    let p = pgp::policy();
    let vc = cert.with_policy(&p, None).expect("policy");
    let ka = vc
        .keys()
        .subkeys()
        .for_transport_encryption()
        .next()
        .expect("subkey");
    let sk = SessionKey::new(32).expect("session key");
    let pk = PKESK3::for_recipient(SymmetricAlgorithm::AES256, &sk, ka.key()).expect("pkesk3");
    let mut out = Packet::from(pk).to_vec().expect("serialize");
    out.extend_from_slice(frame);
    out
}

/// Prepend an SKESK (password-encrypted session key) to `frame`.
pub fn prepend_skesk(frame: &[u8]) -> Vec<u8> {
    let sk = SessionKey::new(32).expect("session key");
    let skesk = SKESK4::with_password(
        SymmetricAlgorithm::AES256,
        SymmetricAlgorithm::AES256,
        openpgp::crypto::S2K::default(),
        &sk,
        &Password::from("x"),
    )
    .expect("skesk");
    let mut out = Packet::from(SKESK::V4(skesk)).to_vec().expect("serialize");
    out.extend_from_slice(frame);
    out
}

/// A message sealed like the production one but with a Compressed Data packet
/// (algorithm "uncompressed", the only one compiled in) inside the encryption.
pub fn seal_compressed(
    sender: &Identity,
    recipient: &VerifiedContact,
    payload: &[u8],
    now_ms: i64,
) -> Vec<u8> {
    let p = pgp::policy();
    let vc = recipient
        .cert()
        .with_policy(&p, pgp::st(now_ms))
        .expect("policy");
    let mut sink = Vec::new();
    {
        let m = Message::new(&mut sink);
        let m = Encryptor::for_recipients(m, recipients_of(&vc))
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .aead_algo(AEADAlgorithm::OCB)
            .build()
            .expect("enc");
        let m = Compressor::new(m)
            .algo(CompressionAlgorithm::Uncompressed)
            .build()
            .expect("compress");
        let m = Signer::new(m, sender.signer().expect("signer"))
            .expect("signer")
            .creation_time(pgp::st(now_ms))
            .add_intended_recipient(recipient.cert())
            .build()
            .expect("sign");
        let mut m = LiteralWriter::new(m).build().expect("literal");
        m.write_all(payload).expect("write");
        m.finalize().expect("finalize");
    }
    sink
}

/// A message encrypted with SEIPD v1 (no AEAD) to the recipient's v6 subkey.
pub fn seal_seipd1(
    sender: &Identity,
    recipient: &VerifiedContact,
    payload: &[u8],
    now_ms: i64,
) -> Option<Vec<u8>> {
    let p = pgp::policy();
    let vc = recipient.cert().with_policy(&p, pgp::st(now_ms)).ok()?;
    let recips: Vec<Recipient> = vc
        .keys()
        .subkeys()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .map(|ka| Recipient::new(Features::empty(), None, ka.key()))
        .collect();
    let mut sink = Vec::new();
    {
        let m = Message::new(&mut sink);
        let m = Encryptor::for_recipients(m, recips)
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()
            .ok()?;
        let m = Signer::new(m, sender.signer()?)
            .ok()?
            .creation_time(pgp::st(now_ms))
            .add_intended_recipient(recipient.cert())
            .build()
            .ok()?;
        let mut m = LiteralWriter::new(m).build().ok()?;
        m.write_all(payload).ok()?;
        m.finalize().ok()?;
    }
    Some(sink)
}

/// A padded message made by a different code path than production: the
/// Padding packet has a fixed odd size chosen by the caller (`pad_to` total
/// bytes of the inner sequence), as a third-party implementation might do.
pub fn seal_third_party_padded(
    sender: &Identity,
    recipient: &VerifiedContact,
    payload: &[u8],
    now_ms: i64,
    pad_to: u64,
) -> Vec<u8> {
    let p = pgp::policy();
    let vc = recipient
        .cert()
        .with_policy(&p, pgp::st(now_ms))
        .expect("policy");
    let mut sink = Vec::new();
    {
        let m = Message::new(&mut sink);
        let m = Encryptor::for_recipients(m, recipients_of(&vc))
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .aead_algo(AEADAlgorithm::OCB)
            .build()
            .expect("enc");
        // Pad to exactly `pad_to` bytes if that is larger than the content, else a fixed 100.
        let m = Padder::new(m)
            .with_policy(move |n: u64| if n < pad_to { pad_to } else { n + 100 })
            .build()
            .expect("pad");
        let m = Signer::new(m, sender.signer().expect("signer"))
            .expect("signer")
            .creation_time(pgp::st(now_ms))
            .add_intended_recipient(recipient.cert())
            .build()
            .expect("sign");
        let mut m = LiteralWriter::new(m).build().expect("literal");
        m.write_all(payload).expect("write");
        m.finalize().expect("finalize");
    }
    sink
}

/// A document of `id`'s public certificate with junk added: a User ID carrying
/// a third-party certification, and an unknown-tag packet. `sanitize` must drop all of it.
pub fn public_cert_with_junk(id: &Identity, certifier: &Identity, now_ms: i64) -> String {
    let cert = id.public_cert();
    let uid: UserID = "mallory@example.invalid".into();
    let mut kp = pgp::primary_keypair(certifier.cert()).expect("certifier key");
    let cert_sig = uid
        .certify(
            &mut kp,
            &cert,
            SignatureType::PositiveCertification,
            None,
            pgp::st(now_ms),
        )
        .expect("certify");
    let (cert, _) = cert
        .insert_packets(vec![Packet::from(uid), Packet::from(cert_sig)])
        .expect("insert");
    let mut bytes = cert.to_vec().expect("serialize");
    // an unknown packet (tag 60, private) appended
    bytes.extend_from_slice(&[0xC0 | 60, 3, 1, 2, 3]);
    super::protection::b64(&bytes)
}

/// `victim`'s public certificate with every subkey binding signature removed.
pub fn public_cert_without_bindings(victim: &Identity) -> String {
    let c = victim.public_cert();
    let mut out: Vec<Packet> = Vec::new();
    let mut after_subkey = false;
    for pk in c.into_packets() {
        match &pk {
            Packet::PublicSubkey(_) | Packet::SecretSubkey(_) => {
                after_subkey = true;
                out.push(pk);
            }
            Packet::Signature(_) if after_subkey => {}
            _ => {
                if !matches!(pk, Packet::Signature(_)) {
                    after_subkey = false;
                }
                out.push(pk)
            }
        }
    }
    let c = Cert::from_packets(out.into_iter()).expect("cert");
    super::protection::b64(&c.to_vec().expect("serialize"))
}

/// `victim`'s primary key with `attacker`'s subkey and the attacker's own
/// binding signature grafted under it (a forged subkey binding).
pub fn public_cert_with_grafted_subkey(victim: &Identity, attacker: &Identity) -> String {
    let v = victim.public_cert();
    let x = attacker.public_cert();
    let mut out: Vec<Packet> = Vec::new();
    for pk in v.into_packets() {
        if matches!(pk, Packet::PublicSubkey(_) | Packet::SecretSubkey(_)) {
            break;
        }
        out.push(pk);
    }
    let mut take = false;
    for pk in x.into_packets() {
        if matches!(pk, Packet::PublicSubkey(_) | Packet::SecretSubkey(_)) {
            take = true;
        }
        if take {
            out.push(pk);
        }
    }
    let c = Cert::from_packets(out.into_iter()).expect("cert");
    super::protection::b64(&c.to_vec().expect("serialize"))
}

/// The identity's SECRET certificate (transferable secret key) as a contact
/// document: AgentNet must refuse it.
pub fn secret_cert_document(id: &Identity) -> String {
    super::protection::b64(&id.cert().as_tsk().to_vec().expect("serialize"))
}

/// The public certificate of `id` with the PRIMARY key revoked and the
/// encryption subkey untouched (so a key-level filter would still find a
/// usable encryption subkey: the Sequoia foot-gun). Document form.
pub fn public_cert_primary_revoked(id: &Identity, now_ms: i64) -> String {
    let rev = pgp::revoke_primary(id.cert(), now_ms, "test").expect("revoke");
    super::protection::b64(&rev.to_vec().expect("serialize"))
}
