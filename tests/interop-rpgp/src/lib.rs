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
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{PacketTrait, PublicKeyEncryptedSessionKey, Subpacket, SubpacketData};
use pgp::types::{
    Fingerprint, KeyDetails, KeyId, KeyVersion, Password, PublicParams, SignatureBytes, SigningKey,
    Timestamp,
};
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
    /// AEAD mode of the SEIPD v2 packet (AgentNet accepts only OCB).
    pub aead: AeadAlgorithm,
    /// Sign with `SignatureType::Text` (0x01, canonical text) instead of Binary (0x00).
    pub text_signature: bool,
    /// Produce a version 4 signature with a version 6 key (the signing key is wrapped so that
    /// rPGP's own builder believes it is a v4 key; the signature itself is computed by rPGP).
    pub v4_signature: bool,
    /// Name the PRIMARY key of the signer's certificate in the hashed Issuer Fingerprint
    /// subpacket even when a subkey makes the signature.
    pub claim_primary_issuer: bool,
    /// Which of the sender's signing-capable keys signs: 0 is the first (the primary key), 1 the
    /// next (a signing subkey of a certificate that has one).
    pub signer_index: usize,
}

impl Default for SealOpts {
    fn default() -> Self {
        Self {
            intended: true,
            anonymous: true,
            aead: AeadAlgorithm::Ocb,
            text_signature: false,
            v4_signature: false,
            claim_primary_issuer: false,
            signer_index: 0,
        }
    }
}

/// A signing key that reports itself as a version 4 key while delegating every operation (and the
/// fingerprint, key id and parameters) to the real version 6 key. rPGP's message builder chooses
/// the signature version (and the One-Pass Signature version) from `KeyDetails::version`, so this
/// makes rPGP emit a v4 signature over the same key. No cryptography is done here.
#[derive(Debug)]
struct AsV4<'a, S: SigningKey>(&'a S);

impl<S: SigningKey> KeyDetails for AsV4<'_, S> {
    fn version(&self) -> KeyVersion {
        KeyVersion::V4
    }
    fn legacy_key_id(&self) -> KeyId {
        self.0.legacy_key_id()
    }
    fn fingerprint(&self) -> Fingerprint {
        self.0.fingerprint()
    }
    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.0.algorithm()
    }
    fn created_at(&self) -> Timestamp {
        self.0.created_at()
    }
    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.0.legacy_v3_expiration_days()
    }
    fn public_params(&self) -> &PublicParams {
        self.0.public_params()
    }
}

impl<S: SigningKey> SigningKey for AsV4<'_, S> {
    fn sign(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes> {
        self.0.sign(key_pw, hash, data)
    }
    fn hash_alg(&self) -> HashAlgorithm {
        self.0.hash_alg()
    }
}

/// `(hashed, unhashed)` subpackets. rPGP refuses a v6 Issuer Fingerprint in the hashed area of a
/// v4 signature, so for `v4_signature` the issuer goes in the unhashed area (where a receiver
/// still reads it).
fn subpackets(
    issuer: Fingerprint,
    to: &Certificate,
    o: &SealOpts,
) -> Result<(Vec<Subpacket>, Vec<Subpacket>)> {
    let issuer = Subpacket::regular(SubpacketData::IssuerFingerprint(issuer))?;
    let mut hashed = vec![Subpacket::critical(SubpacketData::SignatureCreationTime(
        Timestamp::now(),
    ))?];
    let mut unhashed = vec![];
    if o.v4_signature {
        unhashed.push(issuer);
    } else {
        hashed.push(issuer);
    }
    if o.intended {
        hashed.push(Subpacket::critical(
            SubpacketData::IntendedRecipientFingerprint(to.fingerprint()),
        )?);
    }
    Ok((hashed, unhashed))
}

/// Add the signature to a builder (a macro because the builder type differs per SEIPD version).
macro_rules! add_signature {
    ($b:expr, $from:expr, $signer:expr, $v4:expr, $to:expr, $o:expr) => {{
        let issuer = if $o.claim_primary_issuer {
            Certificate::from($from.clone()).fingerprint()
        } else {
            $signer.fingerprint()
        };
        let (hashed, unhashed) = subpackets(issuer, $to, &$o)?;
        let cfg = SubpacketConfig::UserDefined { hashed, unhashed };
        if $o.text_signature {
            $b.sign_text();
        }
        if $o.v4_signature {
            $b.sign_with_subpackets(&$v4, Password::empty(), $signer.hash_alg(), cfg);
        } else {
            $b.sign_with_subpackets(&$signer, Password::empty(), $signer.hash_alg(), cfg);
        }
    }};
}

/// Encrypt (PKESK v6 + SEIPD v2, AES-256, OCB unless `o.aead` says otherwise) and sign `payload`
/// with rPGP. The signing key is the first signing-capable key of `from` (a signing subkey when
/// the primary key cannot sign).
pub fn seal(from: &Tsk, to: &Certificate, payload: &[u8], o: SealOpts) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let checked: Checked = to.clone().into();
    let keys = checked.valid_encryption_capable_component_keys();
    if keys.is_empty() {
        bail!("recipient has no valid encryption subkey");
    }
    let signer = from
        .signing_capable_component_keys()
        .nth(o.signer_index)
        .ok_or_else(|| anyhow!("sender has no valid signing key at that index"))?;
    let v4 = AsV4(&signer);
    let mut b = MessageBuilder::from_bytes("", payload.to_vec()).seipd_v2(
        &mut rng,
        SymmetricKeyAlgorithm::AES256,
        o.aead,
        ChunkSize::default(),
    );
    for k in &keys {
        if o.anonymous {
            b.encrypt_to_key_anonymous(&mut rng, k)?;
        } else {
            b.encrypt_to_key(&mut rng, k)?;
        }
    }
    add_signature!(b, from, signer, v4, to, o);
    Ok(b.to_vec(&mut rng)?)
}

/// A signed, NOT encrypted message (one-pass signature, literal data, signature) over `content`,
/// as AgentNet's adverts are. `o.intended` is ignored (no Intended Recipient).
pub fn sign_only(from: &Tsk, content: &[u8], mut o: SealOpts) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    o.intended = false;
    let signer = from
        .signing_capable_component_keys()
        .nth(o.signer_index)
        .ok_or_else(|| anyhow!("sender has no valid signing key at that index"))?;
    let v4 = AsV4(&signer);
    let to = Certificate::from(from.clone());
    let mut b = MessageBuilder::from_bytes("", content.to_vec());
    add_signature!(b, from, signer, v4, &to, o);
    Ok(b.to_vec(&mut rng)?)
}

/// A message with SEIPD version 1 (no AEAD, modification detection code) carrying an anonymous
/// PKESK **version 6**. rPGP's builder pairs SEIPD v1 only with PKESK v3, so the v6 PKESK (made by
/// rPGP from the same session key, `from_session_key_v6`) is written in front of the packet the
/// builder produced. No cryptography is done here: the frame is a genuine v6 PKESK followed by a
/// genuine SEIPD v1 packet under the same session key.
pub fn seal_seipd1_with_pkesk_v6(
    from: &Tsk,
    to: &Certificate,
    payload: &[u8],
    o: SealOpts,
) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let checked: Checked = to.clone().into();
    let keys = checked.valid_encryption_capable_component_keys();
    let key = keys
        .first()
        .ok_or_else(|| anyhow!("recipient has no valid encryption subkey"))?;
    let signer = from
        .signing_capable_component_keys()
        .next()
        .ok_or_else(|| anyhow!("sender has no valid signing key"))?;
    let v4 = AsV4(&signer);
    let mut b = MessageBuilder::from_bytes("", payload.to_vec())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    add_signature!(b, from, signer, v4, to, o);
    let mut pkesk =
        PublicKeyEncryptedSessionKey::from_session_key_v6(&mut rng, b.session_key(), key)?;
    if let PublicKeyEncryptedSessionKey::V6 { fingerprint, .. } = &mut pkesk {
        *fingerprint = None; // anonymous, like the control
    }
    let seipd = b.to_vec(&mut rng)?;
    let mut out = Vec::new();
    pkesk.to_writer_with_header(&mut out)?;
    out.extend_from_slice(&seipd);
    Ok(out)
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
