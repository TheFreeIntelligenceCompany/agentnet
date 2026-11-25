//! Candidate MVP construction: HPKE (RFC 9180) base mode + inner Ed25519 signature.
//! Library primitives only: `hpke` (DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305),
//! `ed25519-dalek`, `sha2`. All wire parsing is non-panicking (no unwrap/indexing on untrusted data).
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

pub type Kem = X25519HkdfSha256;
pub type Kdf = HkdfSha256;
pub type Aead = ChaCha20Poly1305;
pub type KemSk = <Kem as KemTrait>::PrivateKey;
pub type KemPk = <Kem as KemTrait>::PublicKey;
pub type Enc = <Kem as KemTrait>::EncappedKey;

pub const HEADER: [u8; 4] = [b'A', b'N', 0x01, 0x01]; // magic, version, suite
pub const HEADER_LEN: usize = 4;
pub const ENC_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const SKEW_MS: u64 = 120_000;
pub const MIN_BUCKET: usize = 512;
const DOM_CONTACT: &[u8] = b"agentnet/v1/contact-record\0";
const DOM_ENVELOPE: &[u8] = b"agentnet/v1/envelope\0";
const DOM_HPKE_INFO: &[u8] = b"agentnet/v1/hpke\0";
const DOM_ADDR: &[u8] = b"agentnet/v1/address-checksum";
const DOM_TOPIC: &[u8] = b"agentnet/v1/inbox-topic";

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
pub fn now_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}
pub fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("system RNG failed");
    b
}
pub fn rand_u64() -> u64 {
    u64::from_le_bytes(rand_bytes::<8>())
}
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_slice());
    out
}
pub fn new_uuid_v4() -> String {
    let mut b = rand_bytes::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}
fn valid_uuid_v4(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            14 => *c == b'4',
            19 => matches!(*c, b'8' | b'9' | b'a' | b'b'),
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

// ---------------------------------------------------------------- addresses
pub fn address_of(pk: &[u8; 32]) -> String {
    let d = sha256(&[DOM_ADDR, pk]);
    let mut raw = [0u8; 36];
    raw[..32].copy_from_slice(pk);
    raw[32..].copy_from_slice(&d[..4]);
    format!("an1{}", BASE32_NOPAD.encode(&raw).to_lowercase())
}
pub fn parse_address(s: &str) -> Result<[u8; 32], String> {
    let rest = s.strip_prefix("an1").ok_or("missing an1 prefix")?;
    if rest.len() != 58 {
        return Err("bad length".into());
    }
    let raw = BASE32_NOPAD
        .decode(rest.to_uppercase().as_bytes())
        .map_err(|e| format!("base32: {e}"))?;
    let (pk_b, ck) = raw.split_at_checked(32).ok_or("short")?;
    let pk: [u8; 32] = pk_b.try_into().map_err(|_| "short pk")?;
    let d = sha256(&[DOM_ADDR, &pk]);
    if ck != d.get(..4).ok_or("hash")? {
        return Err("checksum mismatch".into());
    }
    if address_of(&pk) != s {
        return Err("non-canonical encoding".into());
    }
    Ok(pk)
}
pub fn inbox_topic(signing_pk: &[u8; 32], buckets: u16) -> String {
    let h = sha256(&[DOM_TOPIC, signing_pk]);
    let b = u16::from_be_bytes([h[0], h[1]]) % buckets.max(1);
    format!("/agentnet/1/inbox-{b:02x}/proto")
}

// ---------------------------------------------------------------- identity + contact
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ContactRecord {
    pub v: u32,
    pub signing_pk: String,
    pub kem_pk: String,
    pub inbox_buckets: u16,
    pub created_at: u64,
}
#[derive(Clone, Debug)]
pub struct SignedContact {
    pub record: Vec<u8>,
    pub sig: [u8; 64],
}
#[derive(Clone)]
pub struct PeerContact {
    pub address: String,
    pub signing_pk: [u8; 32],
    pub kem_pk: KemPk,
    pub inbox_buckets: u16,
}
impl PeerContact {
    pub fn topic(&self) -> String {
        inbox_topic(&self.signing_pk, self.inbox_buckets)
    }
}

pub fn verify_contact(address: &str, record: &[u8], sig: &[u8]) -> Result<PeerContact, String> {
    let pk = parse_address(address).map_err(|e| format!("address: {e}"))?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| format!("signing key: {e}"))?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| "signature length")?;
    let msg = [DOM_CONTACT, record].concat();
    vk.verify_strict(&msg, &Signature::from_bytes(&sig))
        .map_err(|e| format!("record signature: {e}"))?;
    let r: ContactRecord =
        serde_json::from_slice(record).map_err(|e| format!("record json: {e}"))?;
    if r.v != 1 {
        return Err(format!("unknown record version {}", r.v));
    }
    if unhex(&r.signing_pk).as_deref() != Some(&pk[..]) {
        return Err("record signing_pk != address key".into());
    }
    if r.inbox_buckets == 0 {
        return Err("inbox_buckets == 0".into());
    }
    let kem_b = unhex(&r.kem_pk).ok_or("kem_pk hex")?;
    let kem_pk = KemPk::from_bytes(&kem_b).map_err(|e| format!("kem_pk: {e}"))?;
    Ok(PeerContact {
        address: address.to_string(),
        signing_pk: pk,
        kem_pk,
        inbox_buckets: r.inbox_buckets,
    })
}

pub struct Identity {
    pub signing: SigningKey,
    pub kem_sk: KemSk,
    pub kem_pk: KemPk,
    pub inbox_buckets: u16,
    pub created_at: u64,
}
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    v: u32,
    signing_sk: String,
    kem_sk: String,
    inbox_buckets: u16,
    created_at: u64,
}
impl Identity {
    pub fn generate(inbox_buckets: u16) -> Identity {
        let signing = SigningKey::from_bytes(&rand_bytes::<32>());
        let (kem_sk, kem_pk) = Kem::gen_keypair();
        Identity {
            signing,
            kem_sk,
            kem_pk,
            inbox_buckets,
            created_at: now_ms(),
        }
    }
    pub fn signing_pk(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
    pub fn address(&self) -> String {
        address_of(&self.signing_pk())
    }
    pub fn topic(&self) -> String {
        inbox_topic(&self.signing_pk(), self.inbox_buckets)
    }
    pub fn kem_pk_bytes(&self) -> Vec<u8> {
        self.kem_pk.to_bytes().to_vec()
    }
    pub fn signed_contact(&self) -> SignedContact {
        let rec = ContactRecord {
            v: 1,
            signing_pk: hex(&self.signing_pk()),
            kem_pk: hex(&self.kem_pk_bytes()),
            inbox_buckets: self.inbox_buckets,
            created_at: self.created_at,
        };
        let record = serde_json::to_vec(&rec).unwrap_or_default();
        let sig = self
            .signing
            .sign(&[DOM_CONTACT, &record].concat())
            .to_bytes();
        SignedContact { record, sig }
    }
    pub fn contact(&self) -> PeerContact {
        let sc = self.signed_contact();
        verify_contact(&self.address(), &sc.record, &sc.sig)
            .expect("own contact record must verify")
    }
    pub fn save(&self, path: &Path) -> Result<(), String> {
        use std::os::unix::fs::OpenOptionsExt;
        let f = IdentityFile {
            v: 1,
            signing_sk: hex(&self.signing.to_bytes()),
            kem_sk: hex(&self.kem_sk.to_bytes()),
            inbox_buckets: self.inbox_buckets,
            created_at: self.created_at,
        };
        let tmp: PathBuf = path.with_extension("tmp");
        let mut fh = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("create: {e}"))?;
        fh.write_all(&serde_json::to_vec_pretty(&f).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        fh.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| format!("rename: {e}"))
    }
    pub fn load(path: &Path) -> Result<Identity, String> {
        use std::os::unix::fs::PermissionsExt;
        let md = std::fs::metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
        if md.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "refusing identity file with permissions {:o} (must be 0600)",
                md.permissions().mode() & 0o777
            ));
        }
        let f: IdentityFile =
            serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("identity json: {e}"))?;
        if f.v != 1 {
            return Err(format!("unknown identity file version {}", f.v));
        }
        let sk: [u8; 32] = unhex(&f.signing_sk)
            .ok_or("signing_sk hex")?
            .try_into()
            .map_err(|_| "signing_sk length")?;
        let kem_sk = KemSk::from_bytes(&unhex(&f.kem_sk).ok_or("kem_sk hex")?)
            .map_err(|e| format!("kem_sk: {e}"))?;
        let kem_pk = Kem::sk_to_pk(&kem_sk);
        Ok(Identity {
            signing: SigningKey::from_bytes(&sk),
            kem_sk,
            kem_pk,
            inbox_buckets: f.inbox_buckets,
            created_at: f.created_at,
        })
    }
}

/// Exclusive advisory lock on `<dir>/.lock` (std `File::try_lock`, flock(2) on unix). Held until dropped.
pub struct DirLock {
    _f: std::fs::File,
}
impl DirLock {
    pub fn acquire(dir: &Path) -> Result<DirLock, String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(".lock"))
            .map_err(|e| format!("open lock: {e}"))?;
        match f.try_lock() {
            Ok(()) => Ok(DirLock { _f: f }),
            Err(std::fs::TryLockError::WouldBlock) => Err(format!(
                "data dir {} is locked by another instance",
                dir.display()
            )),
            Err(std::fs::TryLockError::Error(e)) => Err(format!("lock error: {e}")),
        }
    }
}

// ---------------------------------------------------------------- envelope
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    pub v: u32,
    pub message_id: String,
    pub sender: String,
    pub recipient: String,
    #[serde(rename = "type")]
    pub typ: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub body: String,
}
impl Envelope {
    pub fn new(sender: &str, recipient: &str, typ: &str, body: String, ttl_ms: u64) -> Envelope {
        let now = now_ms();
        Envelope {
            v: 1,
            message_id: new_uuid_v4(),
            sender: sender.into(),
            recipient: recipient.into(),
            typ: typ.into(),
            conversation_id: None,
            correlation_id: None,
            created_at: now,
            expires_at: now + ttl_ms,
            body,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

// ---------------------------------------------------------------- padding
#[derive(Clone, Copy, Debug)]
pub enum PadPolicy {
    /// next power of two >= 512 (spec as given)
    Pow2,
    /// powers of two, but never above `cap` bytes of plaintext (last bucket == cap exactly)
    Pow2Capped(usize),
}
impl PadPolicy {
    /// padded plaintext length for `n` bytes of (len||sig||env); None when it cannot be sent
    pub fn bucket(&self, n: usize) -> Option<usize> {
        let mut b = MIN_BUCKET;
        while b < n {
            b = b.checked_mul(2)?;
        }
        match self {
            PadPolicy::Pow2 => Some(b),
            PadPolicy::Pow2Capped(cap) => {
                if n > *cap {
                    None
                } else {
                    Some(b.min(*cap))
                }
            }
        }
    }
}

// ---------------------------------------------------------------- seal
fn hpke_info(kem_pk: &KemPk) -> Vec<u8> {
    [DOM_HPKE_INFO, kem_pk.to_bytes().as_slice()].concat()
}
pub fn sign_envelope(signing: &SigningKey, env_bytes: &[u8]) -> [u8; 64] {
    signing.sign(&[DOM_ENVELOPE, env_bytes].concat()).to_bytes()
}
/// Seal exact envelope bytes: sign them with `signing`, pad, HPKE-encrypt to `rcpt`.
pub fn seal(
    signing: &SigningKey,
    rcpt: &KemPk,
    env_bytes: &[u8],
    pad: PadPolicy,
) -> Result<Vec<u8>, String> {
    seal_parts(&sign_envelope(signing, env_bytes), rcpt, env_bytes, pad)
}
/// Seal an existing (sig, envelope_bytes) pair to `rcpt` (used by the surreptitious-forwarding test).
pub fn seal_parts(
    sig: &[u8; 64],
    rcpt: &KemPk,
    env_bytes: &[u8],
    pad: PadPolicy,
) -> Result<Vec<u8>, String> {
    let inner = 64 + env_bytes.len();
    let inner_u32 = u32::try_from(inner).map_err(|_| "envelope too large")?;
    let padded = pad
        .bucket(4 + inner)
        .ok_or("plaintext exceeds padding policy cap")?;
    let mut pt = Vec::with_capacity(padded);
    pt.extend_from_slice(&inner_u32.to_be_bytes());
    pt.extend_from_slice(sig);
    pt.extend_from_slice(env_bytes);
    pt.resize(padded, 0);
    seal_plaintext(rcpt, &pt)
}
/// HPKE single-shot seal of an already-framed plaintext (also used by tests to build authenticated garbage).
pub fn seal_plaintext(rcpt: &KemPk, pt: &[u8]) -> Result<Vec<u8>, String> {
    let (enc, ct) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        rcpt,
        &hpke_info(rcpt),
        pt,
        &HEADER,
    )
    .map_err(|e| format!("hpke seal: {e}"))?;
    let mut frame = Vec::with_capacity(HEADER_LEN + ENC_LEN + ct.len());
    frame.extend_from_slice(&HEADER);
    frame.extend_from_slice(&enc.to_bytes());
    frame.extend_from_slice(&ct);
    Ok(frame)
}

// ---------------------------------------------------------------- open
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    Short,
    BadMagic,
    BadVersion,
    BadSuite,
    TooLarge,
    Hpke(String),
    BadPadding(&'static str),
    UnknownEnvelopeVersion(u64),
    Parse(String),
    BadMessageId,
    BadSenderAddress(String),
    BadRecipientAddress(String),
    BadSignature,
    WrongRecipient,
    Expired,
    FromFuture,
    BadTimes,
    Replay,
}
impl OpenError {
    pub fn kind(&self) -> &'static str {
        match self {
            OpenError::Short => "short_frame",
            OpenError::BadMagic => "bad_magic",
            OpenError::BadVersion => "bad_version",
            OpenError::BadSuite => "bad_suite",
            OpenError::TooLarge => "frame_too_large",
            OpenError::Hpke(_) => "hpke_open",
            OpenError::BadPadding(_) => "bad_padding",
            OpenError::UnknownEnvelopeVersion(_) => "unknown_envelope_version",
            OpenError::Parse(_) => "envelope_parse",
            OpenError::BadMessageId => "bad_message_id",
            OpenError::BadSenderAddress(_) => "bad_sender_address",
            OpenError::BadRecipientAddress(_) => "bad_recipient_address",
            OpenError::BadSignature => "bad_signature",
            OpenError::WrongRecipient => "wrong_recipient",
            OpenError::Expired => "expired",
            OpenError::FromFuture => "created_in_future",
            OpenError::BadTimes => "expires_before_created",
            OpenError::Replay => "replay",
        }
    }
}
impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Hpke(s)
            | OpenError::Parse(s)
            | OpenError::BadSenderAddress(s)
            | OpenError::BadRecipientAddress(s) => {
                write!(f, "{}: {s}", self.kind())
            }
            OpenError::BadPadding(s) => write!(f, "bad_padding: {s}"),
            OpenError::UnknownEnvelopeVersion(v) => write!(f, "unknown_envelope_version: {v}"),
            _ => write!(f, "{}", self.kind()),
        }
    }
}

pub struct Opened {
    pub sig: [u8; 64],
    pub env_bytes: Vec<u8>,
    pub env: Envelope,
}

/// Header parse + HPKE open + padding strip. Returns (sig, exact envelope bytes). No identity/time checks.
pub fn decrypt_frame(
    me: &Identity,
    frame: &[u8],
    max_frame: usize,
) -> Result<([u8; 64], Vec<u8>), OpenError> {
    if frame.len() > max_frame {
        return Err(OpenError::TooLarge);
    }
    if frame.len() < HEADER_LEN + ENC_LEN + TAG_LEN {
        return Err(OpenError::Short);
    }
    let (hdr, rest) = frame.split_at(HEADER_LEN);
    if hdr.get(0..2) != Some(&HEADER[0..2]) {
        return Err(OpenError::BadMagic);
    }
    if hdr.get(2) != Some(&HEADER[2]) {
        return Err(OpenError::BadVersion);
    }
    if hdr.get(3) != Some(&HEADER[3]) {
        return Err(OpenError::BadSuite);
    }
    let (enc_b, ct) = rest.split_at_checked(ENC_LEN).ok_or(OpenError::Short)?;
    let enc = Enc::from_bytes(enc_b).map_err(|e| OpenError::Hpke(e.to_string()))?;
    let pt = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &me.kem_sk,
        &enc,
        &hpke_info(&me.kem_pk),
        ct,
        hdr,
    )
    .map_err(|e| OpenError::Hpke(e.to_string()))?;
    let (len_b, body) = pt
        .split_at_checked(4)
        .ok_or(OpenError::BadPadding("no length field"))?;
    let inner =
        u32::from_be_bytes(len_b.try_into().map_err(|_| OpenError::BadPadding("len"))?) as usize;
    if inner <= 64 || inner > body.len() {
        return Err(OpenError::BadPadding("length field out of range"));
    }
    let (inner_b, pad) = body
        .split_at_checked(inner)
        .ok_or(OpenError::BadPadding("split"))?;
    if pad.iter().any(|b| *b != 0) {
        return Err(OpenError::BadPadding("non-zero padding"));
    }
    let (sig_b, env_b) = inner_b
        .split_at_checked(64)
        .ok_or(OpenError::BadPadding("short inner"))?;
    let sig: [u8; 64] = sig_b.try_into().map_err(|_| OpenError::BadPadding("sig"))?;
    Ok((sig, env_b.to_vec()))
}

#[derive(Deserialize)]
struct VOnly {
    v: u64,
}

/// Persisted "seen" set of (sender, message_id). Entries carry expires_at so the file can be pruned on load.
pub struct Dedupe {
    seen: HashSet<String>,
    file: Option<std::fs::File>,
}
impl Dedupe {
    pub fn memory() -> Dedupe {
        Dedupe {
            seen: HashSet::new(),
            file: None,
        }
    }
    pub fn open(path: &Path) -> Result<Dedupe, String> {
        let mut seen = HashSet::new();
        let cutoff = now_ms().saturating_sub(SKEW_MS);
        if let Ok(s) = std::fs::read_to_string(path) {
            for l in s.lines() {
                let mut it = l.split(' ');
                if let (Some(a), Some(b), Some(c)) = (
                    it.next(),
                    it.next(),
                    it.next().and_then(|x| x.parse::<u64>().ok()),
                ) {
                    if c >= cutoff {
                        seen.insert(format!("{a} {b}"));
                    }
                }
            }
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("dedupe open: {e}"))?;
        Ok(Dedupe {
            seen,
            file: Some(file),
        })
    }
    pub fn len(&self) -> usize {
        self.seen.len()
    }
    fn contains(&self, sender: &str, id: &str) -> bool {
        self.seen.contains(&format!("{sender} {id}"))
    }
    fn insert(&mut self, sender: &str, id: &str, expires_at: u64) {
        if self.seen.insert(format!("{sender} {id}")) {
            if let Some(f) = self.file.as_mut() {
                let _ = writeln!(f, "{sender} {id} {expires_at}");
                let _ = f.sync_data();
            }
        }
    }
}

pub const MAX_FRAME_DEFAULT: usize = 160 * 1024;

/// Full receive path. `now` is injected for testability. On success the (sender, message_id) is recorded.
pub fn open_frame(
    me: &Identity,
    my_addr: &str,
    frame: &[u8],
    now: u64,
    dd: &mut Dedupe,
) -> Result<Opened, OpenError> {
    let (sig, env_bytes) = decrypt_frame(me, frame, MAX_FRAME_DEFAULT)?;
    let ver: VOnly =
        serde_json::from_slice(&env_bytes).map_err(|e| OpenError::Parse(e.to_string()))?;
    if ver.v != 1 {
        return Err(OpenError::UnknownEnvelopeVersion(ver.v));
    }
    let env: Envelope =
        serde_json::from_slice(&env_bytes).map_err(|e| OpenError::Parse(e.to_string()))?;
    if !valid_uuid_v4(&env.message_id) {
        return Err(OpenError::BadMessageId);
    }
    let spk = parse_address(&env.sender).map_err(OpenError::BadSenderAddress)?;
    parse_address(&env.recipient).map_err(OpenError::BadRecipientAddress)?;
    let vk =
        VerifyingKey::from_bytes(&spk).map_err(|e| OpenError::BadSenderAddress(e.to_string()))?;
    vk.verify_strict(
        &[DOM_ENVELOPE, &env_bytes].concat(),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| OpenError::BadSignature)?;
    if env.recipient != my_addr {
        return Err(OpenError::WrongRecipient);
    }
    if env.expires_at <= env.created_at {
        return Err(OpenError::BadTimes);
    }
    if env.created_at > now.saturating_add(SKEW_MS) {
        return Err(OpenError::FromFuture);
    }
    if env.expires_at.saturating_add(SKEW_MS) < now {
        return Err(OpenError::Expired);
    }
    if dd.contains(&env.sender, &env.message_id) {
        return Err(OpenError::Replay);
    }
    dd.insert(&env.sender, &env.message_id, env.expires_at);
    Ok(Opened {
        sig,
        env_bytes,
        env,
    })
}
