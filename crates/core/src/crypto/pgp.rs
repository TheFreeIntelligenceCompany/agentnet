//! The only module that talks to `sequoia-openpgp`.
//!
//! AgentNet defines **no cryptographic construction** here: certificates,
//! subkey bindings, expiry, revocation, the anonymous v6 PKESK, SEIPD v2
//! (AES-256/OCB), the v6 data signature with its Intended Recipient
//! Fingerprint and the Padding packet are all RFC 9580 constructions
//! implemented by Sequoia (OpenSSL 3 backend). What lives here is the policy
//! and glue that an independent review must read (`docs/crypto-requirements.md`):
//!
//! * which certificates are accepted and how updates merge (`sanitize`,
//!   `merge`, `normalize`),
//! * which subkeys a sender may encrypt to (certificate-level checks first:
//!   Sequoia's key-level filters do not see a revoked primary key),
//! * the receiver policy of ADR 0004 (`open_message`).

use std::cell::RefCell;
use std::io::{Read, Write};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sequoia_openpgp as openpgp;

use openpgp::anyhow;
use openpgp::cert::prelude::*;
use openpgp::cert::{CertRevocationBuilder, SubkeyRevocationBuilder};
use openpgp::crypto::{KeyPair, SessionKey};
use openpgp::packet::key::{Key6, SecretParts, SubordinateRole};
use openpgp::packet::prelude::*;
use openpgp::packet::key;
use openpgp::packet::Tag;
use openpgp::parse::stream::*;
use openpgp::parse::{Dearmor, PacketParserBuilder, PacketParserResult, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::padding::Padder;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Recipient, Signer};
use openpgp::serialize::MarshalInto;
use openpgp::types::{
    AEADAlgorithm, KeyFlags, PublicKeyAlgorithm, ReasonForRevocation, RevocationStatus,
    SignatureType, SymmetricAlgorithm,
};
use openpgp::{Cert, Fingerprint, KeyHandle, Packet, Profile};

use super::address::Address;
use crate::error::{ContactError, OpenError, SealError};

/// Largest accepted binary certificate (ADR 0004 decision 6, raised from 4096
/// by the review of 2026-11-27, finding M1).
///
/// Arithmetic (measured, `results/review-fixes/`): a fresh certificate is 419
/// bytes; every rotation with `--revoke-previous` adds 369 bytes (new subkey
/// and binding plus the revocation of the old one). Revoked subkeys that have
/// not expired are never dropped, so the cap bounds the number of rotations
/// within one subkey validity period (default 365 days): (8192 - 419) / 369 =
/// 21 rotations, about one every 17 days. Every message embeds the sender
/// certificate (base64url, so up to 10.9 KiB); a maximal certificate plus a
/// 64 KiB body still pads to 128 KiB, below the 150 KiB frame limit.
pub const MAX_CERT_LEN: usize = 8192;
/// Smallest padded size of the inner packet sequence (bytes).
pub const MIN_PAD_BUCKET: u64 = 1024;
/// Most PKESKs a message may carry (bound on trial decryptions per frame).
const MAX_PKESKS: usize = 8;

/// The one policy object (Sequoia's standard policy; the stricter ADR 0004 rules
/// are enforced explicitly in [`open_message`]).
pub(crate) fn policy() -> StandardPolicy<'static> {
    StandardPolicy::new()
}

/// Unix milliseconds to a `SystemTime` (negative values clamp to the epoch).
pub(crate) fn st(ms: i64) -> SystemTime {
    // OpenPGP times are 32-bit seconds (until 2106): clamp instead of overflowing.
    UNIX_EPOCH + Duration::from_millis(u64::try_from(ms.clamp(0, 4_000_000_000_000)).unwrap_or(0))
}

/// `SystemTime` to Unix milliseconds.
pub(crate) fn ms_of(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

pub(crate) fn fp32(fp: &Fingerprint) -> Option<[u8; 32]> {
    match fp {
        Fingerprint::V6(b) => Some(*b),
        _ => None,
    }
}

/// The address (v6 fingerprint) of a certificate, requiring a v6 Ed25519 primary key.
pub(crate) fn cert_address(cert: &Cert) -> Result<Address, ContactError> {
    let k = cert.primary_key().key();
    if k.version() != 6 {
        return Err(ContactError::Unsupported("primary key is not a v6 key"));
    }
    if k.pk_algo() != PublicKeyAlgorithm::Ed25519 {
        return Err(ContactError::Unsupported("primary key is not Ed25519"));
    }
    let fp = fp32(&cert.fingerprint()).ok_or(ContactError::Unsupported(
        "fingerprint is not a v6 fingerprint",
    ))?;
    Ok(Address::from_fingerprint(&fp))
}

// ------------------------------------------------------------------ generation

/// A fresh identity certificate: v6, Ed25519 primary (certify + sign, no
/// expiry), one X25519 encryption subkey with `enc_validity` (None: no expiry).
/// Created at `now_ms` (the engine clock, so mock-clock tests are consistent).
pub(crate) fn generate_cert(
    now_ms: i64,
    enc_validity: Option<Duration>,
    primary_validity: Option<Duration>,
) -> openpgp::Result<Cert> {
    let (cert, _rev) = CertBuilder::new()
        .set_profile(Profile::RFC9580)?
        .set_cipher_suite(CipherSuite::Cv25519)
        .set_creation_time(st(now_ms))
        .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
        .set_validity_period(primary_validity)
        .add_subkey(
            KeyFlags::empty().set_transport_encryption(),
            enc_validity,
            None,
        )
        .generate()?;
    Ok(cert)
}

pub(crate) fn primary_keypair(cert: &Cert) -> Option<KeyPair> {
    cert.primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .ok()?
        .into_keypair()
        .ok()
}

/// Retire every live encryption subkey (a *soft* revocation, "key retired",
/// effective at `now_ms`) and add a new X25519 encryption subkey that expires
/// after `validity`. Returns the new certificate (with secrets) and the
/// fingerprints of the retired subkeys.
pub(crate) fn rotate_cert(
    cert: &Cert,
    now_ms: i64,
    validity: Option<Duration>,
    reason: ReasonForRevocation,
    reason_text: &[u8],
) -> openpgp::Result<(Cert, Vec<Fingerprint>)> {
    let p = policy();
    let mut kp =
        primary_keypair(cert).ok_or_else(|| anyhow::anyhow!("no usable primary secret"))?;
    let mut packets: Vec<Packet> = Vec::new();
    let mut retired = Vec::new();
    let vc = cert.with_policy(&p, st(now_ms))?;
    for ka in vc.keys().subkeys().for_transport_encryption() {
        if matches!(ka.revocation_status(), RevocationStatus::Revoked(_)) {
            continue;
        }
        let sig = SubkeyRevocationBuilder::new()
            .set_reason_for_revocation(reason, reason_text)?
            .set_signature_creation_time(st(now_ms))?
            .build(&mut kp, cert, ka.key(), None)?;
        packets.push(sig.into());
        retired.push(ka.key().fingerprint());
    }
    let mut new: Key<SecretParts, SubordinateRole> = Key6::generate_x25519()?.into();
    new.set_creation_time(st(now_ms))?;
    let mut b = SignatureBuilder::new(SignatureType::SubkeyBinding)
        .set_key_flags(KeyFlags::empty().set_transport_encryption())?
        .set_signature_creation_time(st(now_ms))?;
    if let Some(v) = validity {
        b = b.set_key_validity_period(v)?;
    }
    let bind = new.bind(&mut kp, cert, b)?;
    packets.push(new.into());
    packets.push(bind.into());
    let (c, _) = cert.clone().insert_packets(packets)?;
    Ok((c, retired))
}

/// A hard primary-key revocation of `cert` effective at `now_ms`; returns the
/// public certificate carrying the revocation signature.
pub(crate) fn revoke_primary(cert: &Cert, now_ms: i64, reason: &str) -> openpgp::Result<Cert> {
    let mut kp =
        primary_keypair(cert).ok_or_else(|| anyhow::anyhow!("no usable primary secret"))?;
    let sig = CertRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::Unspecified, reason.as_bytes())?
        .set_signature_creation_time(st(now_ms))?
        .build(&mut kp, cert, None)?;
    let (c, _) = cert
        .clone()
        .strip_secret_key_material()
        .insert_packets(sig)?;
    Ok(c)
}

/// Drop the secret material of the named subkeys (keep the public parts).
pub(crate) fn strip_subkey_secrets(cert: &Cert, fps: &[Fingerprint]) -> openpgp::Result<Cert> {
    // `Cert::into_packets` strips secrets; the TSK form keeps them.
    let packets: Vec<Packet> = cert
        .clone()
        .into_tsk()
        .into_packets()
        .map(|p| match p {
            Packet::SecretSubkey(k) if fps.contains(&k.fingerprint()) => {
                // `parts_into_public` only changes the type: take the secret out
                Packet::PublicSubkey(k.parts_into_public().take_secret().0)
            }
            Packet::PublicSubkey(k) if fps.contains(&k.fingerprint()) => {
                Packet::PublicSubkey(k.take_secret().0)
            }
            other => other,
        })
        .collect();
    Cert::from_packets(packets.into_iter())
}

// ------------------------------------------------------------ public certificates

fn issued_by_primary(s: &Signature, primary: &KeyHandle) -> bool {
    s.get_issuers().iter().any(|h| h.aliases(primary))
}

/// Rebuild a certificate from validated components only (review finding L3):
/// the primary key, the subkeys, and the primary's own direct-key / key-revocation
/// signatures and the subkeys' own binding / revocation signatures, each of which
/// must VERIFY cryptographically against the primary key (an invalid signature that
/// merely claims the primary as issuer is dropped). The unhashed subpacket area of
/// every kept signature is cleared (it is not covered by the signature, so anyone
/// can fill it: bloat or smuggling). User IDs, user attributes, third-party
/// certifications, designated-revoker revocations, unknown packets and markers are
/// dropped (a certificate-flooding and third-party-certification defence;
/// `docs/threat-model.md`). The result is canonical: a clean certificate and the
/// same certificate with junk added sanitize to the same bytes.
pub(crate) fn sanitize(cert: Cert) -> Result<Cert, ContactError> {
    #[derive(PartialEq, Clone, Copy)]
    enum Ctx {
        Primary,
        Sub,
        Skip,
    }
    let primary_fp = cert.fingerprint();
    let primary_handle: KeyHandle = primary_fp.clone().into();
    let primary = cert.primary_key().key().clone();
    let mut sub: Option<Key<key::PublicParts, key::SubordinateRole>> = None;
    let mut ctx = Ctx::Skip;
    let mut out: Vec<Packet> = Vec::new();
    for pkt in cert.into_packets() {
        match pkt {
            Packet::PublicKey(_) => {
                ctx = Ctx::Primary;
                out.push(pkt);
            }
            Packet::PublicSubkey(k) => {
                ctx = Ctx::Sub;
                sub = Some(k.clone());
                out.push(Packet::PublicSubkey(k));
            }
            Packet::Signature(mut s) => {
                if !issued_by_primary(&s, &primary_handle) {
                    continue;
                }
                let ok = match (ctx, s.typ()) {
                    (Ctx::Primary, SignatureType::DirectKey) => {
                        s.verify_direct_key(&primary, &primary).is_ok()
                    }
                    (Ctx::Primary, SignatureType::KeyRevocation) => {
                        s.verify_primary_key_revocation(&primary, &primary).is_ok()
                    }
                    (Ctx::Sub, SignatureType::SubkeyBinding) => sub
                        .as_ref()
                        .is_some_and(|k| s.verify_subkey_binding(&primary, &primary, k).is_ok()),
                    (Ctx::Sub, SignatureType::SubkeyRevocation) => sub
                        .as_ref()
                        .is_some_and(|k| s.verify_subkey_revocation(&primary, &primary, k).is_ok()),
                    _ => false,
                };
                if ok {
                    s.unhashed_area_mut().clear();
                    out.push(Packet::Signature(s));
                }
            }
            // secret keys never get here (refused earlier); everything else is dropped
            _ => ctx = Ctx::Skip,
        }
    }
    Cert::from_packets(out.into_iter())
        .map_err(|_| ContactError::Malformed("not a valid certificate"))
}

/// Parse a public certificate (binary or ASCII armor), refuse secret keys and
/// non-v6/non-Ed25519 primaries, and sanitize it. Does not check validity.
pub(crate) fn parse_public(bytes: &[u8]) -> Result<Cert, ContactError> {
    if bytes.len() > MAX_CERT_LEN * 2 {
        return Err(ContactError::TooLarge);
    }
    let cert = Cert::from_bytes(bytes)
        .map_err(|_| ContactError::Malformed("not an OpenPGP certificate"))?;
    if cert.is_tsk() {
        return Err(ContactError::ContainsSecretKey);
    }
    cert_address(&cert)?;
    sanitize(cert)
}

/// Sanitize, require a valid self-signature at `now_ms`, drop subkeys without
/// a valid binding, and fit the size limit by dropping the oldest subkeys whose
/// authenticated expiry has passed.
///
/// A subkey that is revoked but has not expired is NEVER dropped (review
/// finding M1): dropping it together with its revocation would let a stale copy
/// of the certificate, merged back in, make it usable for sealing again. An
/// expired subkey that comes back through a stale certificate is still expired
/// (its own binding signature carries the expiry and time only moves forward),
/// so dropping it is safe. If the certificate still exceeds
/// [`MAX_CERT_LEN`] the result is [`ContactError::TooLarge`].
pub(crate) fn normalize(cert: Cert, now_ms: i64) -> Result<Cert, ContactError> {
    let p = policy();
    let cert = sanitize(cert)?;
    let t = st(now_ms);
    let valid: Vec<Fingerprint> = {
        let vc = cert
            .with_policy(&p, t)
            .map_err(|_| ContactError::NotValid)?;
        vc.keys()
            .subkeys()
            .map(|ka| ka.key().fingerprint())
            .collect()
    };
    let mut cert = cert.retain_subkeys(|sk| valid.contains(&sk.key().fingerprint()));
    // Fit the size limit.
    loop {
        let len = cert
            .to_vec()
            .map_err(|_| ContactError::Malformed("serialization"))?
            .len();
        if len <= MAX_CERT_LEN {
            return Ok(cert);
        }
        let victim: Option<Fingerprint> = {
            let vc = cert
                .with_policy(&p, t)
                .map_err(|_| ContactError::NotValid)?;
            vc.keys()
                .subkeys()
                .filter(|ka| ka.key_expiration_time().is_some_and(|e| e <= t))
                .min_by_key(|ka| ka.key().creation_time())
                .map(|ka| ka.key().fingerprint())
        };
        match victim {
            Some(v) => cert = cert.retain_subkeys(|sk| sk.key().fingerprint() != v),
            None => return Err(ContactError::TooLarge),
        }
    }
}

/// Merge `incoming` into `existing`: same primary key only; the union of
/// signatures (revocations accumulate and are never dropped); invalid or
/// unbound subkeys do not survive normalization.
pub(crate) fn merge(existing: &Cert, incoming: &Cert, now_ms: i64) -> Result<Cert, ContactError> {
    if existing.fingerprint() != incoming.fingerprint() {
        return Err(ContactError::PrimaryMismatch);
    }
    let merged = existing
        .clone()
        .merge_public(incoming.clone())
        .map_err(|_| ContactError::PrimaryMismatch)?;
    normalize(merged, now_ms)
}

/// Certificate-level status at `now_ms`: `(revoked_at_ms, reason)` when the
/// primary key is revoked.
pub(crate) fn primary_revocation(cert: &Cert, now_ms: i64) -> Option<(i64, String)> {
    let p = policy();
    match cert.revocation_status(&p, st(now_ms)) {
        RevocationStatus::Revoked(sigs) => {
            let sig = sigs.first()?;
            let at = sig.signature_creation_time().map(ms_of).unwrap_or(0);
            let reason = sig
                .reason_for_revocation()
                .map(|(_, r)| String::from_utf8_lossy(r).into_owned())
                .unwrap_or_default();
            Some((at, reason))
        }
        _ => None,
    }
}

/// Certificate-level health at `now_ms` for *signing* (sender side): valid, alive, not revoked.
pub(crate) fn check_primary_usable(cert: &Cert, now_ms: i64) -> Result<(), ContactError> {
    let p = policy();
    let vc = cert
        .with_policy(&p, st(now_ms))
        .map_err(|_| ContactError::NotValid)?;
    if let RevocationStatus::Revoked(_) = vc.revocation_status() {
        return Err(ContactError::Revoked);
    }
    vc.alive().map_err(|_| ContactError::Expired)?;
    Ok(())
}

/// The live encryption subkeys of `cert` at `now_ms`: bound, alive, not revoked,
/// v6 X25519. Checks the CERTIFICATE first (a revoked or expired primary refuses
/// even if a subkey looks usable; Sequoia's key-level filters do not see a
/// revoked primary key).
fn live_encryption_subkeys(cert: &Cert, now_ms: i64) -> Result<Vec<Fingerprint>, SealError> {
    let p = policy();
    let t = st(now_ms);
    let vc = cert
        .with_policy(&p, t)
        .map_err(|_| SealError::Crypto("recipient certificate is not valid"))?;
    if let RevocationStatus::Revoked(_) = vc.revocation_status() {
        return Err(SealError::RecipientRevoked);
    }
    if vc.alive().is_err() {
        return Err(SealError::RecipientExpired);
    }
    let v: Vec<Fingerprint> = vc
        .keys()
        .subkeys()
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .filter(|ka| ka.key().pk_algo() == PublicKeyAlgorithm::X25519 && ka.key().version() == 6)
        .map(|ka| ka.key().fingerprint())
        .collect();
    if v.is_empty() {
        return Err(SealError::RecipientKemExpired);
    }
    Ok(v)
}

/// Expiry (ms) of the live encryption subkey with the latest expiry, or None
/// when it never expires or there is none.
pub(crate) fn kem_expiry_ms(cert: &Cert, now_ms: i64) -> Option<i64> {
    let p = policy();
    let vc = cert.with_policy(&p, st(now_ms)).ok()?;
    let mut best: Option<Option<i64>> = None;
    for ka in vc
        .keys()
        .subkeys()
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
    {
        let e = ka.key_expiration_time().map(ms_of);
        best = Some(match (best, e) {
            (None, e) => e,
            (Some(None), _) | (_, None) => None,
            (Some(Some(a)), Some(b)) => Some(a.max(b)),
        });
    }
    best.flatten()
}

/// True when at least one encryption subkey is live at `now_ms`.
pub(crate) fn has_live_kem(cert: &Cert, now_ms: i64) -> bool {
    live_encryption_subkeys(cert, now_ms).is_ok()
}

// ----------------------------------------------------------------------- sealing

/// How to build a message. Production use: `BuildOpts::default()`.
#[derive(Clone, Copy, Debug)]
pub struct BuildOpts {
    /// Pad the inner packet sequence to a power of two with a Padding packet.
    pub pad: bool,
    /// Put the recipient's primary fingerprint in the signature.
    pub intended_recipient: bool,
    /// Sign at all (false only for tests of the receiver policy).
    pub sign: bool,
}

impl Default for BuildOpts {
    fn default() -> Self {
        Self {
            pad: true,
            intended_recipient: true,
            sign: true,
        }
    }
}

/// Padding packet body length so that header + body == `want` bytes, or None
/// when no body length gives exactly that total (new-format length encoding:
/// 1 tag byte + 1 length byte for bodies < 192, 2 for < 8384, else 5; so the
/// totals 194 and 8387 to 8389 cannot be hit).
fn padding_body_for_total(want: u64) -> Option<u64> {
    for h in [2u64, 3, 6] {
        if want < h {
            continue;
        }
        let body = want - h;
        let ok = match h {
            2 => body < 192,
            3 => (192..8384).contains(&body),
            _ => body >= 8384,
        };
        if ok {
            return Some(body);
        }
    }
    None
}

/// Total size of the inner packet sequence after padding: the smallest power of
/// two >= max(`MIN_PAD_BUCKET`, n + 2) whose padding packet can be encoded
/// exactly (review finding L4: for a few deficits no padding packet has exactly
/// that size; those messages move to the next class instead of leaving theirs).
pub fn padded_total(n: u64) -> u64 {
    padded_total_with_floor(n, 0)
}

/// [`padded_total`] for an inner sequence of `n` bytes that must not land in a
/// smaller class than one of `n + floor` bytes would (acks are padded as if
/// they carried the payload of the smallest ordinary message; review finding M3).
pub fn padded_total_with_floor(n: u64, floor: u64) -> u64 {
    let mut t = MIN_PAD_BUCKET;
    loop {
        if t >= n + floor + 2 && padding_body_for_total(t - n).is_some() {
            return t;
        }
        t *= 2;
    }
}

/// Build one OpenPGP message: PKESK v6 (anonymous) to every live encryption
/// subkey of `recipient_cert`, SEIPD v2 (AES-256, OCB), a one-pass signed
/// Literal Data packet carrying `payload`, a v6 signature with the Intended
/// Recipient Fingerprint of the recipient's primary key, and a trailing
/// Padding packet.
pub(crate) fn seal_message(
    signer: KeyPair,
    recipient_cert: &Cert,
    payload: &[u8],
    now_ms: i64,
    opts: &BuildOpts,
    pad_floor: u64,
) -> Result<Vec<u8>, SealError> {
    let live = live_encryption_subkeys(recipient_cert, now_ms)?;
    let p = policy();
    let vc = recipient_cert
        .with_policy(&p, st(now_ms))
        .map_err(|_| SealError::Crypto("recipient certificate is not valid"))?;
    let features = vc.features();
    let recipients: Vec<Recipient> = vc
        .keys()
        .subkeys()
        .filter(|ka| live.contains(&ka.key().fingerprint()))
        .map(|ka| Recipient::new(features.clone(), None, ka.key()))
        .collect();
    if recipients.is_empty() {
        return Err(SealError::RecipientKemExpired);
    }
    let mut sink = Vec::new();
    let c = |_| SealError::Crypto("could not build the OpenPGP message");
    {
        let message = Message::new(&mut sink);
        let message = Encryptor::for_recipients(message, recipients)
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .aead_algo(AEADAlgorithm::OCB)
            .build()
            .map_err(c)?;
        let message = if opts.pad {
            Padder::new(message)
                .with_policy(|n: u64| {
                    let total = padded_total_with_floor(n, pad_floor);
                    n + padding_body_for_total(total - n).unwrap_or(0)
                })
                .build()
                .map_err(c)?
        } else {
            message
        };
        let message = if opts.sign {
            let mut sb = Signer::new(message, signer)
                .map_err(c)?
                .creation_time(st(now_ms));
            if opts.intended_recipient {
                sb = sb.add_intended_recipient(recipient_cert);
            }
            sb.build().map_err(c)?
        } else {
            message
        };
        let mut message = LiteralWriter::new(message).build().map_err(c)?;
        message
            .write_all(payload)
            .map_err(|_| SealError::Crypto("write"))?;
        message.finalize().map_err(c)?;
    }
    Ok(sink)
}

// ----------------------------------------------------------------------- opening

/// What a successful decrypt-and-verify pass yields.
pub(crate) struct Opened {
    pub plaintext: Vec<u8>,
    /// The verified signer (primary-key fingerprint) when a certificate was
    /// available and the signature verified.
    pub signer: Option<Address>,
    /// Issuer fingerprints named by the signature.
    pub issuers: Vec<Address>,
}

#[derive(Default)]
struct State {
    /// The session key the frame was decrypted with (for the inner packet check).
    session: Option<(Option<SymmetricAlgorithm>, SessionKey)>,
    reject: Option<OpenError>,
    signer: Option<Address>,
    issuers: Vec<Address>,
    unverified: bool,
}

struct Helper<'a> {
    me: &'a mut Vec<KeyPair>,
    my_fp: Fingerprint,
    vt: SystemTime,
    pinned: &'a dyn Fn(&Address) -> Option<Cert>,
    extra: Option<&'a Cert>,
    allow_unverified: bool,
    st: Rc<RefCell<State>>,
}

impl Helper<'_> {
    fn reject(&self, e: OpenError) -> anyhow::Error {
        let mut s = self.st.borrow_mut();
        if s.reject.is_none() {
            s.reject = Some(e);
        }
        anyhow::anyhow!("rejected by AgentNet policy")
    }
}

impl VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        let p = policy();
        let mut out = Vec::new();
        for id in ids {
            let KeyHandle::Fingerprint(fp) = id else {
                continue;
            };
            let Some(b) = fp32(fp) else { continue };
            let addr = Address::from_fingerprint(&b);
            self.st.borrow_mut().issuers.push(addr);
            let cert = match (self.pinned)(&addr) {
                Some(c) => Some(c),
                None => self.extra.filter(|c| c.fingerprint() == *fp).cloned(),
            };
            let Some(c) = cert else { continue };
            match c.with_policy(&p, self.vt) {
                Err(_) => {
                    let _ = self.reject(OpenError::BadSignature);
                }
                Ok(vc) => {
                    if let RevocationStatus::Revoked(_) = vc.revocation_status() {
                        let _ = self.reject(OpenError::SenderRevoked);
                    } else if vc.alive().is_err() {
                        let _ = self.reject(OpenError::SenderExpired);
                    } else {
                        out.push(c);
                    }
                }
            }
        }
        Ok(out)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        let layers: Vec<MessageLayer> = structure.into_iter().collect();
        if layers
            .iter()
            .any(|l| matches!(l, MessageLayer::Compression { .. }))
        {
            return Err(self.reject(OpenError::Compressed));
        }
        let earlier = self.st.borrow().reject;
        if let Some(e) = earlier {
            return Err(self.reject(e));
        }
        let mut it = layers.into_iter();
        match it.next() {
            Some(MessageLayer::Encryption {
                sym_algo,
                aead_algo,
                ..
            }) => {
                if aead_algo.is_none() {
                    return Err(self.reject(OpenError::NotAead));
                }
                // exactly what AgentNet sends (ADR 0004; rPGP produces the same set)
                if sym_algo != SymmetricAlgorithm::AES256 || aead_algo != Some(AEADAlgorithm::OCB) {
                    return Err(self.reject(OpenError::UnsupportedCipher));
                }
            }
            _ => return Err(self.reject(OpenError::BadStructure)),
        }
        let results = match it.next() {
            Some(MessageLayer::SignatureGroup { results }) => results,
            _ => return Err(self.reject(OpenError::BadStructure)),
        };
        if it.next().is_some() {
            return Err(self.reject(OpenError::BadStructure));
        }
        if results.len() != 1 {
            return Err(self.reject(OpenError::WrongSignatureCount));
        }
        match &results[0] {
            Ok(good) => {
                let sig = good.sig;
                let key = good.ka.key();
                if sig.version() != 6
                    || key.pk_algo() != PublicKeyAlgorithm::Ed25519
                    || sig.typ() != SignatureType::Binary
                {
                    return Err(self.reject(OpenError::UnsupportedSignature));
                }
                let cert_fp = good.ka.cert().fingerprint();
                if key.fingerprint() != cert_fp {
                    // only the primary key signs AgentNet messages
                    return Err(self.reject(OpenError::UnsupportedSignature));
                }
                let Some(b) = fp32(&cert_fp) else {
                    return Err(self.reject(OpenError::UnsupportedSignature));
                };
                let mut any = false;
                let mut me = false;
                for f in sig.intended_recipients() {
                    any = true;
                    me |= *f == self.my_fp;
                }
                if !any {
                    return Err(self.reject(OpenError::MissingIntendedRecipient));
                }
                if !me {
                    return Err(self.reject(OpenError::WrongIntendedRecipient));
                }
                self.st.borrow_mut().signer = Some(Address::from_fingerprint(&b));
                Ok(())
            }
            Err(VerificationError::MissingKey { .. }) => {
                if self.allow_unverified {
                    self.st.borrow_mut().unverified = true;
                    Ok(())
                } else {
                    Err(self.reject(OpenError::UnknownSender))
                }
            }
            // A signature made after the verification time (a sender whose clock
            // is ahead by more than the permitted skew) is "from the future",
            // which the engine defers and re-evaluates, not a bad signature
            // (review finding L1).
            Err(VerificationError::BadSignature { error, .. })
                if matches!(
                    error.downcast_ref::<openpgp::Error>(),
                    Some(openpgp::Error::NotYetLive(_))
                ) =>
            {
                Err(self.reject(OpenError::FromFuture))
            }
            Err(_) => Err(self.reject(OpenError::BadSignature)),
        }
    }
}

impl DecryptionHelper for Helper<'_> {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        if !skesks.is_empty() {
            return Err(self.reject(OpenError::SkeskPresent));
        }
        if pkesks.len() > MAX_PKESKS {
            return Err(self.reject(OpenError::Malformed));
        }
        if pkesks.iter().any(|k| !matches!(k, PKESK::V6(_))) {
            return Err(self.reject(OpenError::PkeskNotV6));
        }
        for pkesk in pkesks {
            for pair in self.me.iter_mut() {
                if let Some((algo, sk)) = pkesk.decrypt(pair, sym_algo) {
                    if decrypt(algo, &sk) {
                        self.st.borrow_mut().session = Some((algo, sk));
                        return Ok(None);
                    }
                }
            }
        }
        Err(self.reject(OpenError::NotForUs))
    }
}

// ---------------------------------------------------- canonical frame grammar

/// The outer packet sequence of a frame, checked at packet level BEFORE any
/// decryption (review finding L2): binary (no ASCII armor), then PKESK v6
/// (1 to [`MAX_PKESKS`]), then exactly one SEIPD v2 (AES-256, OCB), and nothing
/// before, between or after (no Marker, no outer Padding, no trailing data).
/// Sequoia's parser does the parsing; this only inspects the packet tags.
fn check_outer(frame: &[u8]) -> Result<(), OpenError> {
    let mut ppr = PacketParserBuilder::from_bytes(frame)
        .map_err(|_| OpenError::Malformed)?
        .dearmor(Dearmor::Disabled)
        .build()
        .map_err(|_| OpenError::Malformed)?;
    let mut pkesks = 0usize;
    let mut seipd = false;
    while let PacketParserResult::Some(pp) = ppr {
        if seipd {
            // anything after the encrypted data
            return Err(OpenError::BadStructure);
        }
        match &pp.packet {
            Packet::PKESK(k) => {
                pkesks += 1;
                if pkesks > MAX_PKESKS {
                    return Err(OpenError::Malformed);
                }
                if !matches!(k, PKESK::V6(_)) {
                    return Err(OpenError::PkeskNotV6);
                }
            }
            Packet::SKESK(_) => return Err(OpenError::SkeskPresent),
            Packet::SEIP(SEIP::V2(s)) => {
                if s.symmetric_algo() != SymmetricAlgorithm::AES256
                    || s.aead() != AEADAlgorithm::OCB
                {
                    return Err(OpenError::UnsupportedCipher);
                }
                seipd = true;
            }
            Packet::SEIP(_) => return Err(OpenError::NotAead),
            Packet::CompressedData(_) => return Err(OpenError::Compressed),
            _ => return Err(OpenError::BadStructure),
        }
        // `next` does not recurse into containers
        ppr = pp.next().map_err(|_| OpenError::Malformed)?.1;
    }
    if !seipd || pkesks == 0 {
        return Err(OpenError::BadStructure);
    }
    Ok(())
}

/// The packet sequence INSIDE the encryption, checked at packet level after
/// the session key is known: one-pass signature, Literal Data, Signature and an
/// optional Padding, exactly (no Marker, no second signature, no compression).
fn check_inner(
    frame: &[u8],
    session: &Option<(Option<SymmetricAlgorithm>, SessionKey)>,
) -> Result<(), OpenError> {
    let Some((algo, sk)) = session else {
        return Err(OpenError::Malformed);
    };
    let mut ppr = PacketParserBuilder::from_bytes(frame)
        .map_err(|_| OpenError::Malformed)?
        .dearmor(Dearmor::Disabled)
        .build()
        .map_err(|_| OpenError::Malformed)?;
    let mut inner: Vec<Tag> = Vec::new();
    while let PacketParserResult::Some(mut pp) = ppr {
        if matches!(pp.packet, Packet::SEIP(_)) {
            pp.decrypt(*algo, sk).map_err(|_| OpenError::Malformed)?;
        } else if pp.recursion_depth() >= 1 {
            let tag = pp.packet.tag();
            if tag == Tag::CompressedData {
                return Err(OpenError::Compressed);
            }
            inner.push(tag);
        }
        ppr = pp.recurse().map_err(|_| OpenError::Malformed)?.1;
    }
    match inner.as_slice() {
        [Tag::OnePassSig, Tag::Literal, Tag::Signature]
        | [Tag::OnePassSig, Tag::Literal, Tag::Signature, Tag::Padding] => Ok(()),
        _ => Err(OpenError::BadStructure),
    }
}

/// A signed (not encrypted) message must be binary and exactly one-pass
/// signature, Literal Data, Signature (no armor, no cleartext signature
/// framework, no prefix-signature form).
fn signed_message_is_canonical(msg: &[u8]) -> bool {
    let Ok(builder) = PacketParserBuilder::from_bytes(msg) else {
        return false;
    };
    let Ok(mut ppr) = builder.dearmor(Dearmor::Disabled).build() else {
        return false;
    };
    let mut tags: Vec<Tag> = Vec::new();
    while let PacketParserResult::Some(pp) = ppr {
        tags.push(pp.packet.tag());
        match pp.next() {
            Ok((_, next)) => ppr = next,
            Err(_) => return false,
        }
    }
    tags == [Tag::OnePassSig, Tag::Literal, Tag::Signature]
}

/// Decrypt `frame` with `me` and verify the signature. `pinned` returns the
/// pinned certificate of an issuer fingerprint; `extra` is a candidate
/// certificate (the one embedded in the payload, second pass only). With
/// `allow_unverified` a signature made by a key for which no certificate is
/// available is not an error: the caller gets `signer == None` and the issuers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn open_message(
    frame: &[u8],
    me: Vec<KeyPair>,
    my_primary: &Fingerprint,
    now_ms: i64,
    max_plaintext: usize,
    pinned: &dyn Fn(&Address) -> Option<Cert>,
    extra: Option<&Cert>,
    allow_unverified: bool,
) -> Result<Opened, OpenError> {
    check_outer(frame)?;
    let p = policy();
    let state = Rc::new(RefCell::new(State::default()));
    let mut me = me;
    let helper = Helper {
        me: &mut me,
        my_fp: my_primary.clone(),
        vt: st(now_ms),
        pinned,
        extra,
        allow_unverified,
        st: state.clone(),
    };
    let fail = |state: &Rc<RefCell<State>>| state.borrow().reject.unwrap_or(OpenError::Malformed);
    let builder = DecryptorBuilder::from_bytes(frame).map_err(|_| OpenError::Malformed)?;
    let mut d = builder
        .with_policy(&p, Some(st(now_ms)), helper)
        .map_err(|_| fail(&state))?;
    let mut plaintext = Vec::new();
    let r = (&mut d)
        .take(max_plaintext as u64 + 1)
        .read_to_end(&mut plaintext);
    if r.is_err() {
        return Err(fail(&state));
    }
    if plaintext.len() > max_plaintext {
        return Err(OpenError::Malformed);
    }
    let s = state.borrow();
    if let Some(e) = s.reject {
        return Err(e);
    }
    check_inner(frame, &s.session)?;
    Ok(Opened {
        plaintext,
        signer: s.signer,
        issuers: s.issuers.clone(),
    })
}

// ------------------------------------------------------------ signed (not encrypted)

struct SigHelper {
    certs: Vec<Cert>,
    good: Rc<RefCell<Option<Address>>>,
    structure_ok: Rc<RefCell<bool>>,
    allow_missing: bool,
}

impl VerificationHelper for SigHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.certs.clone())
    }
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        let layers: Vec<MessageLayer> = structure.into_iter().collect();
        let [MessageLayer::SignatureGroup { results }] = layers.as_slice() else {
            return Err(anyhow::anyhow!("not a single signature group"));
        };
        if results.len() != 1 {
            return Err(anyhow::anyhow!("not exactly one signature"));
        }
        *self.structure_ok.borrow_mut() = true;
        match &results[0] {
            Ok(good) => {
                let sig = good.sig;
                let cert_fp = good.ka.cert().fingerprint();
                if sig.version() != 6
                    || good.ka.key().pk_algo() != PublicKeyAlgorithm::Ed25519
                    || sig.typ() != SignatureType::Binary
                    || good.ka.key().fingerprint() != cert_fp
                {
                    return Err(anyhow::anyhow!("unsupported signature"));
                }
                let b = fp32(&cert_fp).ok_or_else(|| anyhow::anyhow!("not v6"))?;
                *self.good.borrow_mut() = Some(Address::from_fingerprint(&b));
                Ok(())
            }
            Err(VerificationError::MissingKey { .. }) if self.allow_missing => Ok(()),
            Err(_) => Err(anyhow::anyhow!("bad signature")),
        }
    }
}

/// Sign `content` as one OpenPGP signed (not encrypted) message by the primary key.
pub(crate) fn sign_message(
    signer: KeyPair,
    content: &[u8],
    now_ms: i64,
) -> openpgp::Result<Vec<u8>> {
    let mut sink = Vec::new();
    let e = |x: anyhow::Error| x;
    {
        let message = Message::new(&mut sink);
        let message = Signer::new(message, signer)
            .map_err(e)?
            .creation_time(st(now_ms))
            .build()
            .map_err(e)?;
        let mut message = LiteralWriter::new(message).build().map_err(e)?;
        message.write_all(content).map_err(anyhow::Error::from)?;
        message.finalize().map_err(e)?;
    }
    Ok(sink)
}

/// Read the content of a signed message WITHOUT trusting it (no certificates
/// supplied). Returns the content only if the structure is one signature.
pub(crate) fn read_signed_unverified(msg: &[u8], max: usize) -> Option<Vec<u8>> {
    verify_signed(msg, vec![], true, max).map(|(c, _)| c)
}

/// Verify a signed message against `certs`; returns the content and the signer.
pub(crate) fn verify_signed_message(
    msg: &[u8],
    certs: Vec<Cert>,
    max: usize,
    now_ms: i64,
) -> Option<(Vec<u8>, Address)> {
    let (c, s) = verify_signed_at(msg, certs, false, max, now_ms)?;
    Some((c, s?))
}

fn verify_signed(
    msg: &[u8],
    certs: Vec<Cert>,
    allow_missing: bool,
    max: usize,
) -> Option<(Vec<u8>, Option<Address>)> {
    verify_signed_at(msg, certs, allow_missing, max, ms_of(SystemTime::now()))
}

fn verify_signed_at(
    msg: &[u8],
    certs: Vec<Cert>,
    allow_missing: bool,
    max: usize,
    now_ms: i64,
) -> Option<(Vec<u8>, Option<Address>)> {
    if !signed_message_is_canonical(msg) {
        return None;
    }
    let p = policy();
    let good = Rc::new(RefCell::new(None));
    let ok = Rc::new(RefCell::new(false));
    let h = SigHelper {
        certs,
        good: good.clone(),
        structure_ok: ok.clone(),
        allow_missing,
    };
    let mut v = VerifierBuilder::from_bytes(msg)
        .ok()?
        .with_policy(&p, Some(st(now_ms)), h)
        .ok()?;
    let mut out = Vec::new();
    (&mut v).take(max as u64 + 1).read_to_end(&mut out).ok()?;
    if out.len() > max || !*ok.borrow() {
        return None;
    }
    let signer = *good.borrow();
    if signer.is_none() && !allow_missing {
        return None;
    }
    Some((out, signer))
}
