//! rPGP side of the interoperability check (ADR 0004). Test-only helper code.
//!
//! This crate deliberately uses NO Sequoia API: everything OpenPGP here is rPGP (`pgp` 0.21.1)
//! plus the `rpgpie` semantics layer. AgentNet is reached only through `agentnet_core`'s public
//! crypto interface (and its `test-support` module for exporting a disposable test key).
//!
//! rPGP/rpgpie do not evaluate the Intended Recipient Fingerprint subpacket on receipt, so
//! [`open`] does that in a few lines of non-cryptographic glue (as spike/openpgp-eval did).
//! rPGP 0.21.1's `MessageBuilder` cannot emit a Padding packet, so messages built here are unpadded.

use std::io::Cursor;

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use pgp::composed::{Message, MessageBuilder, SubpacketConfig};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Subpacket, SubpacketData};
use pgp::types::{Fingerprint, KeyDetails, KeyVersion, Password, SigningKey, Timestamp};
use rand::thread_rng;
use rpgpie::certificate::{Certificate, Checked};
use rpgpie::message::unpack;
use rpgpie::tsk::Tsk;

pub fn hexfp(fp: &Fingerprint) -> String {
    hex::encode(fp.as_bytes())
}

/// Load a transferable secret key from an AgentNet document (base64url of the binary key).
pub fn tsk_from_doc(doc: &str) -> Result<Tsk> {
    let bytes = B64.decode(doc.trim())?;
    let mut v = Tsk::load(&mut Cursor::new(bytes)).map_err(|e| anyhow!("load tsk: {e:?}"))?;
    if v.len() != 1 {
        bail!("expected exactly one key");
    }
    Ok(v.remove(0))
}

/// Load a public certificate from an AgentNet contact document (base64url of the binary cert).
pub fn cert_from_doc(doc: &str) -> Result<Certificate> {
    let bytes = B64.decode(doc.trim())?;
    let mut v =
        Certificate::load(&mut Cursor::new(bytes)).map_err(|e| anyhow!("load cert: {e:?}"))?;
    if v.len() != 1 {
        bail!("expected exactly one certificate");
    }
    Ok(v.remove(0))
}

pub fn tsk_fp(t: &Tsk) -> String {
    hexfp(&Certificate::from(t.clone()).fingerprint())
}

/// A fresh rPGP key (disposable). `v4` selects a version 4 key, which AgentNet must refuse.
pub fn generate(v4: bool) -> Result<Tsk> {
    let (ver, kt, enc) = if v4 {
        (
            KeyVersion::V4,
            pgp::composed::KeyType::Ed25519Legacy,
            pgp::composed::KeyType::ECDH(pgp::crypto::ecc_curve::ECCCurve::Curve25519Legacy),
        )
    } else {
        (
            KeyVersion::V6,
            pgp::composed::KeyType::Ed25519,
            pgp::composed::KeyType::X25519,
        )
    };
    Tsk::generate(
        ver,
        kt,
        Some(enc),
        v4.then(|| "v4-test@example.invalid".to_string()),
        vec![],
        None,
    )
    .map_err(|e| anyhow!("{e:?}"))
}

#[derive(Clone, Copy)]
pub struct SealOpts {
    /// Add the Intended Recipient Fingerprint subpacket (the recipient's primary key).
    pub intended: bool,
    /// Anonymous (wildcard key id/fingerprint) PKESK v6.
    pub anonymous: bool,
}

impl Default for SealOpts {
    fn default() -> Self {
        Self {
            intended: true,
            anonymous: true,
        }
    }
}

/// Encrypt (PKESK v6 + SEIPD v2, AES-256/OCB) and sign `payload` with rPGP.
pub fn seal(from: &Tsk, to: &Certificate, payload: &[u8], o: SealOpts) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let checked: Checked = to.clone().into();
    let keys = checked.valid_encryption_capable_component_keys();
    if keys.is_empty() {
        bail!("recipient has no valid encryption subkey");
    }
    let signer = from
        .signing_capable_component_keys()
        .next()
        .ok_or_else(|| anyhow!("sender has no valid signing key"))?;
    let mut b = MessageBuilder::from_bytes("", payload.to_vec()).seipd_v2(
        &mut rng,
        SymmetricKeyAlgorithm::AES256,
        AeadAlgorithm::Ocb,
        ChunkSize::default(),
    );
    for k in &keys {
        if o.anonymous {
            b.encrypt_to_key_anonymous(&mut rng, k)?;
        } else {
            b.encrypt_to_key(&mut rng, k)?;
        }
    }
    let mut hashed = vec![
        Subpacket::critical(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
    ];
    if o.intended {
        hashed.push(Subpacket::critical(
            SubpacketData::IntendedRecipientFingerprint(to.fingerprint()),
        )?);
    }
    b.sign_with_subpackets(
        &signer,
        Password::empty(),
        signer.hash_alg(),
        SubpacketConfig::UserDefined {
            hashed,
            unhashed: vec![],
        },
    );
    Ok(b.to_vec(&mut rng)?)
}

#[derive(Debug)]
pub struct Opened {
    pub payload: Vec<u8>,
    /// Lowercase hex fingerprint of the verified signer certificate.
    pub signer: String,
    /// Fingerprints named by Intended Recipient Fingerprint subpackets.
    pub intended: Vec<String>,
}

/// Decrypt with `me`, verify the signature against `sender`, require exactly one valid
/// signature from `sender`, SEIPD v2, and an Intended Recipient Fingerprint naming `me`.
pub fn open(me: &Tsk, sender: &Certificate, data: &[u8]) -> Result<Opened> {
    let msg =
        Message::from_bytes(Cursor::new(data.to_vec())).map_err(|e| anyhow!("parse: {e:?}"))?;
    let certs = vec![sender.clone()];
    let r = unpack(
        msg,
        vec![me.as_signed_secret_key()],
        vec![],
        vec![],
        &[],
        &certs,
    )
    .map_err(|e| anyhow!("unpack: {e:?}"))?;
    if !matches!(r.encryption_mode, rpgpie::message::EncryptionMode::Seipdv2) {
        bail!("not SEIPD v2");
    }
    if r.validated.len() != 1 {
        bail!(
            "expected exactly one valid signature from the claimed sender, got {}",
            r.validated.len()
        );
    }
    let v = &r.validated[0];
    let signer_cert = v.certs.first().ok_or_else(|| anyhow!("no signer cert"))?;
    if signer_cert.fingerprint() != sender.fingerprint() {
        bail!("signer is not the claimed sender");
    }
    let mut ir = vec![];
    if let Some(cfg) = v.sig.config() {
        for sp in &cfg.hashed_subpackets {
            if let SubpacketData::IntendedRecipientFingerprint(fp) = &sp.data {
                ir.push(hexfp(fp));
            }
        }
    }
    let my_fp = hexfp(&me.as_signed_secret_key().primary_key.fingerprint());
    if !ir.contains(&my_fp) {
        bail!("signature has no Intended Recipient Fingerprint naming me");
    }
    Ok(Opened {
        payload: r.cleartext.to_vec(),
        signer: hexfp(&signer_cert.fingerprint()),
        intended: ir,
    })
}

/// Packet-level dump (Debug of each parsed packet) of a binary OpenPGP message, for the evidence log.
pub fn dump(data: &[u8]) -> String {
    let mut s = String::new();
    for p in pgp::packet::PacketParser::new(Cursor::new(data.to_vec())) {
        match p {
            Ok(p) => s += &format!("{p:?}\n"),
            Err(e) => s += &format!("<parse error: {e:?}>\n"),
        }
    }
    s
}
