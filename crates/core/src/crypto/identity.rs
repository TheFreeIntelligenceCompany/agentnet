//! Local agent identity: Ed25519 signing key + HPKE (X25519) KEM keys.
//!
//! The signing key and the KEM keys are generated independently and never
//! derived from each other. All secrets are zeroized on drop on a best-effort
//! basis (see the notes in `docs/protocol.md`), and `Debug` never prints them.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use hpke::kem::{Kem as _, X25519HkdfSha256};
use hpke::{Deserializable, Serializable};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use agentnet_transport::ContentTopic;

use super::address::{Address, DEFAULT_INBOX_BUCKETS, MAX_INBOX_BUCKETS, MIN_INBOX_BUCKETS};
use super::contact::SignedContactRecord;
use super::revocation::SignedRevocation;
use crate::error::{IdentityError, RevocationError};

type KemPrivateKey = <X25519HkdfSha256 as hpke::Kem>::PrivateKey;

/// Version of the identity file format.
pub const IDENTITY_FILE_VERSION: u64 = 1;
/// Maximum accepted size of an identity file / export (bytes).
pub const MAX_IDENTITY_FILE_LEN: usize = 256 * 1024;
/// Maximum number of retired KEM keys kept; the oldest are dropped first.
pub const MAX_PREVIOUS_KEMS: usize = 32;

/// Fill `buf` from the operating system RNG.
pub(crate) fn random_bytes(buf: &mut [u8]) -> Result<(), IdentityError> {
    getrandom::fill(buf).map_err(|_| IdentityError::Random)
}

/// An X25519 KEM key pair. The secret is kept as the 32 raw bytes (clamping is
/// done by the HPKE library on every load) and zeroized on drop.
pub(crate) struct KemKeypair {
    sk: Zeroizing<[u8; 32]>,
    pk: [u8; 32],
    /// When this key was created (becomes the contact record's `created_at`).
    created_at: i64,
    /// Key epoch (starts at 1, +1 per rotation).
    epoch: u64,
}

impl KemKeypair {
    fn from_secret(
        sk: Zeroizing<[u8; 32]>,
        created_at: i64,
        epoch: u64,
    ) -> Result<Self, IdentityError> {
        let key = KemPrivateKey::from_bytes(sk.as_slice())
            .map_err(|_| IdentityError::Malformed("invalid KEM secret key"))?;
        let pk_arr = X25519HkdfSha256::sk_to_pk(&key).to_bytes();
        let pk: [u8; 32] = pk_arr
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::Malformed("invalid KEM public key length"))?;
        Ok(Self {
            sk,
            pk,
            created_at,
            epoch,
        })
    }

    fn generate(created_at: i64, epoch: u64) -> Result<Self, IdentityError> {
        let mut sk = Zeroizing::new([0u8; 32]);
        random_bytes(sk.as_mut_slice())?;
        Self::from_secret(sk, created_at, epoch)
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn public_key(&self) -> &[u8; 32] {
        &self.pk
    }

    /// The HPKE private key object (zeroized on drop by the library).
    pub(crate) fn private_key(&self) -> Option<KemPrivateKey> {
        KemPrivateKey::from_bytes(self.sk.as_slice()).ok()
    }
}

struct RetiredKem {
    kem: KemKeypair,
    retire_at: i64,
}

/// The local agent's secret identity.
pub struct Identity {
    signing: SigningKey,
    address: Address,
    kem: KemKeypair,
    previous: Vec<RetiredKem>,
    inbox_buckets: u16,
    created_at: i64,
    kem_expires_at: Option<i64>,
    /// Epochs strictly below this are revoked (1 = none).
    min_valid_epoch: u64,
    /// Suites listed in the contact record this identity publishes.
    advertised_suites: Vec<u8>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("address", &self.address.to_string())
            .field("inbox_buckets", &self.inbox_buckets)
            .field("created_at", &self.created_at)
            .field("kem_expires_at", &self.kem_expires_at)
            .field("key_epoch", &self.kem.epoch)
            .field("previous_kems", &self.previous.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousKemFile {
    kem_sk: String,
    created_at: i64,
    retire_at: i64,
    /// 0 = unknown (file written before epochs existed; assigned on load).
    #[serde(default)]
    epoch: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFile {
    v: u64,
    address: String,
    signing_sk: String,
    kem_sk: String,
    kem_created_at: i64,
    inbox_buckets: u16,
    created_at: i64,
    kem_expires_at: Option<i64>,
    previous_kems: Vec<PreviousKemFile>,
    /// 0 = unknown (assigned on load).
    #[serde(default)]
    kem_epoch: u64,
    #[serde(default)]
    min_valid_epoch: u64,
}

#[derive(Deserialize)]
struct VersionOnly {
    v: u64,
}

impl Drop for PreviousKemFile {
    fn drop(&mut self) {
        self.kem_sk.zeroize();
    }
}
impl Drop for IdentityFile {
    fn drop(&mut self) {
        self.signing_sk.zeroize();
        self.kem_sk.zeroize();
    }
}

fn decode_secret(s: &str) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let mut v = Zeroizing::new(
        B64.decode(s)
            .map_err(|_| IdentityError::Malformed("secret key is not base64url"))?,
    );
    let mut out = Zeroizing::new([0u8; 32]);
    if v.len() != 32 {
        return Err(IdentityError::Malformed("secret key must be 32 bytes"));
    }
    out.copy_from_slice(&v);
    v.zeroize();
    Ok(out)
}

fn check_buckets(n: u16) -> Result<(), IdentityError> {
    if (MIN_INBOX_BUCKETS..=MAX_INBOX_BUCKETS).contains(&n) {
        Ok(())
    } else {
        Err(IdentityError::InvalidInboxBuckets)
    }
}

impl Identity {
    /// Generate a fresh identity (new signing key, new KEM key).
    pub fn generate(inbox_buckets: u16, now_ms: i64) -> Result<Self, IdentityError> {
        check_buckets(inbox_buckets)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        random_bytes(seed.as_mut_slice())?;
        let signing = SigningKey::from_bytes(&seed);
        let address = Address::from_verifying_key(&signing.verifying_key())
            .map_err(|_| IdentityError::Malformed("generated signing key is weak"))?;
        Ok(Self {
            signing,
            address,
            kem: KemKeypair::generate(now_ms, 1)?,
            previous: Vec::new(),
            inbox_buckets,
            created_at: now_ms,
            kem_expires_at: None,
            min_valid_epoch: 1,
            advertised_suites: vec![super::envelope::SUITE_ID],
        })
    }

    /// Generate with the default bucket count (16).
    pub fn generate_default(now_ms: i64) -> Result<Self, IdentityError> {
        Self::generate(DEFAULT_INBOX_BUCKETS, now_ms)
    }

    /// The agent's address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Number of inbox buckets this identity advertises.
    pub fn inbox_buckets(&self) -> u16 {
        self.inbox_buckets
    }

    /// Identity creation time (Unix ms).
    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Expiry of the current KEM key as advertised in the contact record.
    pub fn kem_expires_at(&self) -> Option<i64> {
        self.kem_expires_at
    }

    /// Creation time of the current KEM key (the contact record's `created_at`).
    pub fn kem_created_at(&self) -> i64 {
        self.kem.created_at
    }

    /// Epoch of the current KEM key (starts at 1; +1 per rotation).
    pub fn key_epoch(&self) -> u64 {
        self.kem.epoch
    }

    /// KEM epochs strictly below this value have been revoked by this identity.
    pub fn min_valid_epoch(&self) -> u64 {
        self.min_valid_epoch
    }

    /// Suites listed in the published contact record.
    pub fn advertised_suites(&self) -> &[u8] {
        &self.advertised_suites
    }

    /// Set the suites listed in the published contact record (the engine sets
    /// this from its message-protection registry). Not persisted.
    pub fn set_advertised_suites(&mut self, suites: Vec<u8>) {
        self.advertised_suites = suites;
    }

    /// Current KEM public key.
    pub fn kem_public_key(&self) -> [u8; 32] {
        self.kem.pk
    }

    /// Number of retired KEM keys still held.
    pub fn previous_kem_count(&self) -> usize {
        self.previous.len()
    }

    /// Content topic of this identity's inbox.
    pub fn inbox_topic(&self) -> ContentTopic {
        self.address.inbox_topic(self.inbox_buckets)
    }

    /// Create the signed, shareable contact record for the current KEM key.
    pub fn contact_record(&self) -> SignedContactRecord {
        SignedContactRecord::create(self, &self.advertised_suites)
    }

    /// Create a signed identity-revocation tombstone for this address
    /// (`reason`: 1..=256 bytes, no control characters). This only builds the
    /// document; persisting it and marking the local identity revoked is the
    /// caller's job (the daemon's `identity revoke`).
    pub fn create_revocation(
        &self,
        reason: &str,
        now_ms: i64,
    ) -> Result<SignedRevocation, RevocationError> {
        SignedRevocation::create(self, reason, now_ms)
    }

    /// Sign `domain || msg` with the Ed25519 signing key.
    pub(crate) fn sign(&self, domain: &[u8], msg: &[u8]) -> [u8; 64] {
        let mut m = Vec::with_capacity(domain.len() + msg.len());
        m.extend_from_slice(domain);
        m.extend_from_slice(msg);
        self.signing.sign(&m).to_bytes()
    }

    /// KEM keys usable for decryption at `now_ms`: the current key, then every
    /// retired key whose `retire_at` is still in the future.
    pub(crate) fn decryption_keys(&self, now_ms: i64) -> impl Iterator<Item = &KemKeypair> {
        std::iter::once(&self.kem).chain(
            self.previous
                .iter()
                .filter(move |p| p.retire_at > now_ms && p.kem.epoch >= self.min_valid_epoch)
                .map(|p| &p.kem),
        )
    }

    /// Replace the KEM key. The old key stays usable for decryption until
    /// `keep_previous_until_ms`. The signing key and address do not change.
    /// `new_expiry` is the `kem_expires_at` to advertise for the new key.
    pub fn rotate_kem(
        &mut self,
        now_ms: i64,
        keep_previous_until_ms: i64,
        new_expiry: Option<i64>,
    ) -> Result<(), IdentityError> {
        self.rotate_kem_with(now_ms, keep_previous_until_ms, new_expiry, false)
    }

    /// Replace the KEM key and increment `key_epoch`.
    ///
    /// Without `revoke_previous` the old key stays usable for decryption until
    /// `keep_previous_until_ms`. With it, *every* earlier KEM secret key is
    /// destroyed immediately (frames sealed to them can never be opened again,
    /// including undelivered ones: senders must re-seal after learning the new
    /// record) and the new record carries `revoked_kem_epochs_below = new epoch`.
    pub fn rotate_kem_with(
        &mut self,
        now_ms: i64,
        keep_previous_until_ms: i64,
        new_expiry: Option<i64>,
        revoke_previous: bool,
    ) -> Result<(), IdentityError> {
        let next_epoch = self
            .kem
            .epoch
            .checked_add(1)
            .ok_or(IdentityError::Malformed("key epoch overflow"))?;
        let fresh = KemKeypair::generate(now_ms, next_epoch)?;
        let old = std::mem::replace(&mut self.kem, fresh);
        if revoke_previous {
            // Dropping the keypairs zeroizes their secrets.
            drop(old);
            self.previous.clear();
            self.min_valid_epoch = next_epoch;
        } else {
            self.previous.push(RetiredKem {
                kem: old,
                retire_at: keep_previous_until_ms,
            });
            while self.previous.len() > MAX_PREVIOUS_KEMS {
                self.previous.remove(0);
            }
        }
        self.kem_expires_at = new_expiry;
        Ok(())
    }

    /// Drop retired KEM keys whose `retire_at` has passed.
    pub fn prune_retired(&mut self, now_ms: i64) {
        self.previous.retain(|p| p.retire_at > now_ms);
    }

    // ------------------------------------------------------------ persistence

    fn to_file_bytes(&self) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
        let seed = Zeroizing::new(self.signing.to_bytes());
        let f = IdentityFile {
            v: IDENTITY_FILE_VERSION,
            address: self.address.to_string(),
            signing_sk: B64.encode(seed.as_slice()),
            kem_sk: B64.encode(self.kem.sk.as_slice()),
            kem_created_at: self.kem.created_at,
            inbox_buckets: self.inbox_buckets,
            created_at: self.created_at,
            kem_expires_at: self.kem_expires_at,
            previous_kems: self
                .previous
                .iter()
                .map(|p| PreviousKemFile {
                    kem_sk: B64.encode(p.kem.sk.as_slice()),
                    created_at: p.kem.created_at,
                    retire_at: p.retire_at,
                    epoch: p.kem.epoch,
                })
                .collect(),
            kem_epoch: self.kem.epoch,
            min_valid_epoch: self.min_valid_epoch,
        };
        let bytes = serde_json::to_vec_pretty(&f)
            .map_err(|_| IdentityError::Malformed("serialization failed"))?;
        Ok(Zeroizing::new(bytes))
    }

    fn from_file_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() > MAX_IDENTITY_FILE_LEN {
            return Err(IdentityError::TooLarge);
        }
        let ver: VersionOnly = serde_json::from_slice(bytes)
            .map_err(|_| IdentityError::Malformed("not an identity JSON object"))?;
        if ver.v != IDENTITY_FILE_VERSION {
            return Err(IdentityError::UnsupportedVersion(ver.v));
        }
        let f: IdentityFile = serde_json::from_slice(bytes)
            .map_err(|e| IdentityError::Malformed(crate::error::json_reason(&e)))?;
        check_buckets(f.inbox_buckets)?;
        if f.previous_kems.len() > MAX_PREVIOUS_KEMS {
            return Err(IdentityError::Malformed("too many previous KEM keys"));
        }
        let seed = decode_secret(&f.signing_sk)?;
        let signing = SigningKey::from_bytes(&seed);
        let address = Address::from_verifying_key(&signing.verifying_key())
            .map_err(|_| IdentityError::Malformed("signing key is weak"))?;
        let stored: Address = f
            .address
            .parse()
            .map_err(|_| IdentityError::Malformed("invalid address"))?;
        if stored != address {
            return Err(IdentityError::AddressMismatch);
        }
        // Files written before epochs existed carry 0: number the retired keys
        // 1..=n in order and the current key n+1.
        let n_prev = u64::try_from(f.previous_kems.len()).unwrap_or(0);
        let cur_epoch = if f.kem_epoch == 0 {
            n_prev.saturating_add(1)
        } else {
            f.kem_epoch
        };
        let kem = KemKeypair::from_secret(decode_secret(&f.kem_sk)?, f.kem_created_at, cur_epoch)?;
        let mut previous = Vec::with_capacity(f.previous_kems.len());
        for (i, p) in f.previous_kems.iter().enumerate() {
            let epoch = if p.epoch == 0 {
                u64::try_from(i).unwrap_or(0).saturating_add(1)
            } else {
                p.epoch
            };
            if epoch >= cur_epoch {
                return Err(IdentityError::Malformed(
                    "retired KEM epoch is not below the current one",
                ));
            }
            previous.push(RetiredKem {
                kem: KemKeypair::from_secret(decode_secret(&p.kem_sk)?, p.created_at, epoch)?,
                retire_at: p.retire_at,
            });
        }
        let min_valid_epoch = f.min_valid_epoch.max(1);
        if min_valid_epoch > cur_epoch {
            return Err(IdentityError::Malformed(
                "min_valid_epoch is above the current epoch",
            ));
        }
        previous.retain(|p| p.kem.epoch >= min_valid_epoch);
        Ok(Self {
            signing,
            address,
            kem,
            previous,
            inbox_buckets: f.inbox_buckets,
            created_at: f.created_at,
            kem_expires_at: f.kem_expires_at,
            min_valid_epoch,
            advertised_suites: vec![super::envelope::SUITE_ID],
        })
    }

    /// Write the identity to `path` atomically with mode 0600.
    ///
    /// The data is written to a temp file in the same directory (created with
    /// mode 0600 from the start), fsynced, then moved into place. Without
    /// `overwrite`, an existing file at `path` is never replaced
    /// (`AlreadyExists`). Windows: no permission hardening is applied.
    pub fn save(&self, path: &Path, overwrite: bool) -> Result<(), IdentityError> {
        let bytes = self.to_file_bytes()?;
        write_private_file_atomic(path, &bytes, overwrite)
    }

    /// Load an identity from `path`. On unix the file must not be accessible
    /// by group or others.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let io = |source| IdentityError::Io {
            path: path.to_path_buf(),
            source,
        };
        let file = std::fs::File::open(path).map_err(io)?;
        let md = file.metadata().map_err(io)?;
        if !md.is_file() {
            return Err(IdentityError::NotRegularFile(path.to_path_buf()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = md.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(IdentityError::InsecurePermissions {
                    path: path.to_path_buf(),
                    mode,
                });
            }
        }
        let mut buf = Zeroizing::new(Vec::new());
        file.take(MAX_IDENTITY_FILE_LEN as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(io)?;
        Self::from_file_bytes(&buf)
    }

    /// Export the identity as an ASCII-armored age file encrypted to a
    /// passphrase (scrypt recipient).
    pub fn export_encrypted(&self, passphrase: &str) -> Result<Vec<u8>, IdentityError> {
        if passphrase.is_empty() {
            return Err(IdentityError::EmptyPassphrase);
        }
        let json = self.to_file_bytes()?;
        let recipient =
            age::scrypt::Recipient::new(age::secrecy::SecretString::from(passphrase.to_owned()));
        let armored =
            age::encrypt_and_armor(&recipient, &json).map_err(|_| IdentityError::Encrypt)?;
        Ok(armored.into_bytes())
    }

    /// Import an identity produced by [`Self::export_encrypted`]. Wrong
    /// passphrase and corrupted input are indistinguishable (`Decrypt`).
    pub fn import_encrypted(bytes: &[u8], passphrase: &str) -> Result<Self, IdentityError> {
        if bytes.len() > MAX_IDENTITY_FILE_LEN {
            return Err(IdentityError::TooLarge);
        }
        if passphrase.is_empty() {
            return Err(IdentityError::EmptyPassphrase);
        }
        let ident =
            age::scrypt::Identity::new(age::secrecy::SecretString::from(passphrase.to_owned()));
        let plain =
            Zeroizing::new(age::decrypt(&ident, bytes).map_err(|_| IdentityError::Decrypt)?);
        Self::from_file_bytes(&plain)
    }
}

fn io_err(path: &Path) -> impl Fn(std::io::Error) -> IdentityError + '_ {
    move |source| IdentityError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn write_private_file_atomic(
    path: &Path,
    data: &[u8],
    overwrite: bool,
) -> Result<(), IdentityError> {
    let dir: PathBuf = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path
        .file_name()
        .ok_or(IdentityError::Malformed("path has no file name"))?
        .to_string_lossy()
        .into_owned();
    if !overwrite && std::fs::symlink_metadata(path).is_ok() {
        return Err(IdentityError::AlreadyExists(path.to_path_buf()));
    }

    // Create the temp file exclusively, with the final mode from the start.
    let mut nonce = [0u8; 8];
    random_bytes(&mut nonce)?;
    let tmp = dir.join(format!(
        ".{name}.tmp-{}",
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(io_err(&tmp))?;

    let result = (|| -> Result<(), IdentityError> {
        f.write_all(data).map_err(io_err(&tmp))?;
        f.sync_all().map_err(io_err(&tmp))?;
        if overwrite {
            std::fs::rename(&tmp, path).map_err(io_err(path))?;
        } else {
            // hard_link fails atomically if `path` exists, unlike rename.
            match std::fs::hard_link(&tmp, path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(IdentityError::AlreadyExists(path.to_path_buf()));
                }
                Err(e) => return Err(io_err(path)(e)),
            }
            std::fs::remove_file(&tmp).map_err(io_err(&tmp))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    drop(f);
    result?;
    // Persist the directory entry (best effort; not supported everywhere).
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_validates_buckets() {
        assert!(Identity::generate(0, 0).is_err());
        assert!(Identity::generate(257, 0).is_err());
        assert!(Identity::generate(1, 0).is_ok());
        assert!(Identity::generate(256, 0).is_ok());
        assert_eq!(Identity::generate_default(0).unwrap().inbox_buckets(), 16);
    }

    #[test]
    fn debug_has_no_secrets() {
        let id = Identity::generate_default(1).unwrap();
        let s = format!("{id:?}");
        let seed = B64.encode(id.signing.to_bytes());
        let kem = B64.encode(id.kem.sk.as_slice());
        assert!(!s.contains(&seed) && !s.contains(&kem));
        assert!(s.contains(&id.address().to_string()));
    }

    #[test]
    fn file_roundtrip_in_memory() {
        let mut id = Identity::generate(32, 1000).unwrap();
        id.rotate_kem(2000, 9000, Some(50_000)).unwrap();
        let bytes = id.to_file_bytes().unwrap();
        let back = Identity::from_file_bytes(&bytes).unwrap();
        assert_eq!(back.address(), id.address());
        assert_eq!(back.kem_public_key(), id.kem_public_key());
        assert_eq!(back.previous_kem_count(), 1);
        assert_eq!(back.kem_expires_at(), Some(50_000));
        assert_eq!(back.inbox_buckets(), 32);
        assert_eq!(back.created_at(), 1000);
        assert_eq!(back.kem_created_at(), 2000);
    }

    #[test]
    fn file_validation() {
        let id = Identity::generate_default(1).unwrap();
        let good = String::from_utf8(id.to_file_bytes().unwrap().to_vec()).unwrap();
        // unknown version
        let bad = good.replacen("\"v\": 1", "\"v\": 2", 1);
        assert!(matches!(
            Identity::from_file_bytes(bad.as_bytes()),
            Err(IdentityError::UnsupportedVersion(2))
        ));
        // unknown field
        let bad = good.replacen("\"v\": 1,", "\"v\": 1, \"extra\": 1,", 1);
        assert!(Identity::from_file_bytes(bad.as_bytes()).is_err());
        // wrong address
        let other = Identity::generate_default(1).unwrap();
        let bad = good.replace(&id.address().to_string(), &other.address().to_string());
        assert!(matches!(
            Identity::from_file_bytes(bad.as_bytes()),
            Err(IdentityError::AddressMismatch)
        ));
        // bad buckets
        let bad = good.replace("\"inbox_buckets\": 16", "\"inbox_buckets\": 0");
        assert!(matches!(
            Identity::from_file_bytes(bad.as_bytes()),
            Err(IdentityError::InvalidInboxBuckets)
        ));
        // garbage never panics
        for g in [&b""[..], b"{", b"null", b"[]", b"{\"v\":1}", &[0xff, 0xfe]] {
            assert!(Identity::from_file_bytes(g).is_err());
        }
    }

    #[test]
    fn rotation_and_prune() {
        let mut id = Identity::generate_default(0).unwrap();
        let old = id.kem_public_key();
        id.rotate_kem(10, 100, None).unwrap();
        assert_ne!(id.kem_public_key(), old);
        assert_eq!(id.decryption_keys(50).count(), 2);
        assert_eq!(id.decryption_keys(100).count(), 1);
        id.prune_retired(99);
        assert_eq!(id.previous_kem_count(), 1);
        id.prune_retired(100);
        assert_eq!(id.previous_kem_count(), 0);
    }

    #[test]
    fn previous_keys_are_capped() {
        let mut id = Identity::generate_default(0).unwrap();
        for i in 0..(MAX_PREVIOUS_KEMS as i64 + 5) {
            id.rotate_kem(i, i64::MAX, None).unwrap();
        }
        assert_eq!(id.previous_kem_count(), MAX_PREVIOUS_KEMS);
    }
}
