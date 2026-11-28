//! Local agent identity: one RFC 9580 v6 OpenPGP certificate with its secret keys.
//!
//! The certificate has an Ed25519 primary key (certify + sign, no expiry) and
//! an X25519 encryption subkey with an expiry. Keys are generated fresh (an
//! `an1` Ed25519 key is never reused). Rotation adds a new encryption subkey
//! and retires the previous one (a standard subkey revocation, reason "key
//! retired"); the retired secret key is kept for decryption until its retire
//! time. Secret material lives in Sequoia's protected memory and is never
//! printed (`Debug` shows the address only).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use openpgp::crypto::KeyPair;
use openpgp::parse::Parse;
use openpgp::serialize::MarshalInto;
use openpgp::types::{PublicKeyAlgorithm, ReasonForRevocation};
use openpgp::{Cert, Fingerprint};

use agentnet_transport::ContentTopic;

use super::address::Address;
use super::contact::ContactRecord;
use super::pgp;
use super::revocation::SignedRevocation;
use crate::error::{IdentityError, RevocationError};

/// Version of the identity file format (version 1 was the HPKE format).
pub const IDENTITY_FILE_VERSION: u64 = 2;
/// Maximum accepted size of an identity file / export (bytes).
pub const MAX_IDENTITY_FILE_LEN: usize = 256 * 1024;
/// Maximum number of retired encryption subkeys kept.
pub const MAX_PREVIOUS_KEMS: usize = 32;
/// Default lifetime of an encryption subkey.
pub const DEFAULT_KEM_VALIDITY_DAYS: u64 = 365;

/// Fill `buf` from the operating system RNG.
pub(crate) fn random_bytes(buf: &mut [u8]) -> Result<(), IdentityError> {
    getrandom::fill(buf).map_err(|_| IdentityError::Random)
}

struct Retained {
    fp: Fingerprint,
    retire_at: i64,
}

/// The local agent's secret identity.
pub struct Identity {
    cert: Cert,
    address: Address,
    retained: Vec<Retained>,
    created_at: i64,
    kem_expires_at: Option<i64>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("address", &self.address.to_string())
            .field("created_at", &self.created_at)
            .field("kem_expires_at", &self.kem_expires_at)
            .field("retained_subkeys", &self.retained.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedFile {
    fingerprint: String,
    retire_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFile {
    v: u64,
    address: String,
    created_at: i64,
    kem_expires_at: Option<i64>,
    /// base64url of the binary transferable secret key (RFC 9580 section 10.2).
    certificate: String,
    retained_subkeys: Vec<RetainedFile>,
}

#[derive(Deserialize)]
struct VersionOnly {
    v: u64,
}

impl Drop for IdentityFile {
    fn drop(&mut self) {
        self.certificate.zeroize();
    }
}

fn crypto_err(_: impl std::fmt::Debug) -> IdentityError {
    IdentityError::Crypto("OpenPGP operation failed")
}

fn fp_hex(fp: &Fingerprint) -> String {
    fp.to_hex().to_ascii_lowercase()
}

impl Identity {
    /// Generate a fresh identity: new v6 certificate, encryption subkey valid
    /// for [`DEFAULT_KEM_VALIDITY_DAYS`] from `now_ms`.
    pub fn generate(now_ms: i64) -> Result<Self, IdentityError> {
        Self::generate_with(
            now_ms,
            Some(Duration::from_secs(DEFAULT_KEM_VALIDITY_DAYS * 86_400)),
        )
    }

    /// Alias of [`Self::generate`].
    pub fn generate_default(now_ms: i64) -> Result<Self, IdentityError> {
        Self::generate(now_ms)
    }

    /// Generate with an explicit encryption-subkey lifetime (`None`: no expiry).
    pub fn generate_with(
        now_ms: i64,
        enc_validity: Option<Duration>,
    ) -> Result<Self, IdentityError> {
        let cert = pgp::generate_cert(now_ms, enc_validity, None).map_err(crypto_err)?;
        let address = pgp::cert_address(&cert).map_err(|_| IdentityError::Crypto("address"))?;
        Ok(Self {
            cert,
            address,
            retained: Vec::new(),
            created_at: now_ms,
            kem_expires_at: enc_validity
                .map(|d| now_ms.saturating_add(i64::try_from(d.as_millis()).unwrap_or(i64::MAX))),
        })
    }

    /// The agent's address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Identity creation time (Unix ms).
    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Expiry of the current encryption subkey as published in the certificate.
    pub fn kem_expires_at(&self) -> Option<i64> {
        self.kem_expires_at
    }

    /// Number of retired encryption subkeys whose secret is still held.
    pub fn previous_kem_count(&self) -> usize {
        self.retained.len()
    }

    /// Content topic of this identity's inbox.
    pub fn inbox_topic(&self) -> ContentTopic {
        self.address.inbox_topic()
    }

    /// The shareable contact record: the public certificate (secret material
    /// removed, sanitized).
    pub fn contact_record(&self) -> ContactRecord {
        let public = self.cert.clone().strip_secret_key_material();
        let public = pgp::sanitize(public).unwrap_or(public_fallback(&self.cert));
        let public = match public.to_vec() {
            Ok(v) if v.len() <= pgp::MAX_CERT_LEN => public,
            // too many retired subkeys: drop the oldest retired ones
            _ => pgp::normalize(public.clone(), crate::clock::system_now_ms()).unwrap_or(public),
        };
        ContactRecord::from_cert(&public)
    }

    /// The public certificate (tests).
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn public_cert(&self) -> Cert {
        self.cert.clone().strip_secret_key_material()
    }

    /// An identity whose PRIMARY key expires `primary_validity` after creation
    /// (tests of expired certificates; real identities never expire).
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn generate_with_primary_expiry_for_tests(
        now_ms: i64,
        primary_validity: Duration,
    ) -> Result<Self, IdentityError> {
        let enc = Some(Duration::from_secs(DEFAULT_KEM_VALIDITY_DAYS * 86_400));
        let cert = pgp::generate_cert(now_ms, enc, Some(primary_validity)).map_err(crypto_err)?;
        let address = pgp::cert_address(&cert).map_err(|_| IdentityError::Crypto("address"))?;
        Ok(Self {
            cert,
            address,
            retained: Vec::new(),
            created_at: now_ms,
            kem_expires_at: None,
        })
    }

    /// The primary key's signing key pair (internal).
    pub(crate) fn signer(&self) -> Option<KeyPair> {
        pgp::primary_keypair(&self.cert)
    }

    /// The v6 fingerprint of the primary key.
    pub(crate) fn primary_fingerprint(&self) -> Fingerprint {
        self.cert.fingerprint()
    }

    /// Create the identity-revocation document for this identity: the public
    /// certificate carrying a primary-key revocation signature
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

    pub(crate) fn cert(&self) -> &Cert {
        &self.cert
    }

    /// Key pairs of every encryption subkey usable for decryption at `now_ms`:
    /// the current subkey (even past its expiry) and retired subkeys until
    /// their retire time.
    pub(crate) fn decryption_keypairs(&self, now_ms: i64) -> Vec<KeyPair> {
        let mut out = Vec::new();
        for ka in self.cert.keys().subkeys().unencrypted_secret() {
            let key = ka.key();
            if key.pk_algo() != PublicKeyAlgorithm::X25519 {
                continue;
            }
            let fp = key.fingerprint();
            if self
                .retained
                .iter()
                .any(|r| r.fp == fp && r.retire_at <= now_ms)
            {
                continue;
            }
            if let Ok(kp) = key.clone().into_keypair() {
                out.push(kp);
            }
        }
        out
    }

    /// Number of encryption subkeys usable for decryption at `now_ms`.
    pub fn decryption_key_count(&self, now_ms: i64) -> usize {
        self.decryption_keypairs(now_ms).len()
    }

    /// Replace the encryption subkey. The old subkey is retired (a standard
    /// subkey revocation, "key retired", so senders that merge the update stop
    /// encrypting to it) and stays usable for decryption until
    /// `keep_previous_until_ms`. The primary key and the address do not change.
    /// `new_expiry` is the absolute expiry (Unix ms) of the new subkey.
    pub fn rotate_kem(
        &mut self,
        now_ms: i64,
        keep_previous_until_ms: i64,
        new_expiry: Option<i64>,
    ) -> Result<(), IdentityError> {
        self.rotate_kem_with(now_ms, keep_previous_until_ms, new_expiry, false)
    }

    /// [`Self::rotate_kem`]; with `revoke_previous` every earlier encryption
    /// subkey is revoked as compromised (a hard subkey revocation) and its
    /// secret key destroyed immediately: frames sealed to it can never be
    /// opened again, including undelivered ones (senders must re-seal after
    /// merging the update).
    pub fn rotate_kem_with(
        &mut self,
        now_ms: i64,
        keep_previous_until_ms: i64,
        new_expiry: Option<i64>,
        revoke_previous: bool,
    ) -> Result<(), IdentityError> {
        let validity = match new_expiry {
            Some(e) => {
                let delta = e.saturating_sub(now_ms);
                if delta < 1000 {
                    return Err(IdentityError::Malformed(
                        "new expiry must be at least 1 second in the future",
                    ));
                }
                Some(Duration::from_millis(
                    u64::try_from(delta).unwrap_or(u64::MAX),
                ))
            }
            None => None,
        };
        let (reason, text): (_, &[u8]) = if revoke_previous {
            (ReasonForRevocation::KeyCompromised, b"compromised")
        } else {
            (ReasonForRevocation::KeyRetired, b"rotated")
        };
        let (cert, retired) =
            pgp::rotate_cert(&self.cert, now_ms, validity, reason, text).map_err(crypto_err)?;
        let mut retained: Vec<Retained> = Vec::new();
        let cert = if revoke_previous {
            // every earlier encryption subkey loses its secret now
            let mut gone: Vec<Fingerprint> = self.retained.iter().map(|r| r.fp.clone()).collect();
            gone.extend(retired);
            pgp::strip_subkey_secrets(&cert, &gone).map_err(crypto_err)?
        } else {
            for r in &self.retained {
                retained.push(Retained {
                    fp: r.fp.clone(),
                    retire_at: r.retire_at,
                });
            }
            for fp in retired {
                retained.push(Retained {
                    fp,
                    retire_at: keep_previous_until_ms,
                });
            }
            // Evicting an entry destroys its secret key as well (finding L7):
            // an entry that is no longer tracked would otherwise stay usable for
            // decryption forever.
            let mut evicted: Vec<Fingerprint> = Vec::new();
            while retained.len() > MAX_PREVIOUS_KEMS {
                evicted.push(retained.remove(0).fp);
            }
            if evicted.is_empty() {
                cert
            } else {
                pgp::strip_subkey_secrets(&cert, &evicted).map_err(crypto_err)?
            }
        };
        // The published record must still fit: revoked, unexpired subkeys are
        // never trimmed (finding M1), so fail instead of publishing a record that
        // receivers refuse. Nothing has been changed yet.
        let public = cert.clone().strip_secret_key_material();
        if let Err(e) = pgp::normalize(public, now_ms) {
            return match e {
                crate::error::ContactError::TooLarge => Err(IdentityError::CertificateTooLarge {
                    limit: pgp::MAX_CERT_LEN,
                }),
                _ => Err(IdentityError::Malformed("rotated certificate is not valid")),
            };
        }
        self.retained = retained;
        self.cert = cert;
        self.kem_expires_at = new_expiry;
        Ok(())
    }

    /// Destroy the secret keys of retired subkeys whose `retire_at` has passed.
    pub fn prune_retired(&mut self, now_ms: i64) {
        let gone: Vec<Fingerprint> = self
            .retained
            .iter()
            .filter(|r| r.retire_at <= now_ms)
            .map(|r| r.fp.clone())
            .collect();
        if gone.is_empty() {
            return;
        }
        if let Ok(c) = pgp::strip_subkey_secrets(&self.cert, &gone) {
            self.cert = c;
            self.retained.retain(|r| r.retire_at > now_ms);
        }
    }

    // ------------------------------------------------------------ persistence

    fn to_file_bytes(&self) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
        let tsk = Zeroizing::new(self.cert.as_tsk().to_vec().map_err(crypto_err)?);
        let f = IdentityFile {
            v: IDENTITY_FILE_VERSION,
            address: self.address.to_string(),
            created_at: self.created_at,
            kem_expires_at: self.kem_expires_at,
            certificate: B64.encode(tsk.as_slice()),
            retained_subkeys: self
                .retained
                .iter()
                .map(|r| RetainedFile {
                    fingerprint: fp_hex(&r.fp),
                    retire_at: r.retire_at,
                })
                .collect(),
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
        if ver.v == 1 {
            return Err(IdentityError::LegacyFormat);
        }
        if ver.v != IDENTITY_FILE_VERSION {
            return Err(IdentityError::UnsupportedVersion(ver.v));
        }
        let f: IdentityFile = serde_json::from_slice(bytes)
            .map_err(|e| IdentityError::Malformed(crate::error::json_reason(&e)))?;
        if f.retained_subkeys.len() > MAX_PREVIOUS_KEMS {
            return Err(IdentityError::Malformed("too many retired subkeys"));
        }
        let tsk = Zeroizing::new(
            B64.decode(&f.certificate)
                .map_err(|_| IdentityError::Malformed("certificate is not base64url"))?,
        );
        let cert = Cert::from_bytes(tsk.as_slice())
            .map_err(|_| IdentityError::Malformed("not an OpenPGP secret key"))?;
        let address = pgp::cert_address(&cert)
            .map_err(|_| IdentityError::Malformed("certificate is not a v6 Ed25519 key"))?;
        let stored: Address = f
            .address
            .parse()
            .map_err(|_| IdentityError::Malformed("invalid address"))?;
        if stored != address {
            return Err(IdentityError::AddressMismatch);
        }
        if pgp::primary_keypair(&cert).is_none() {
            return Err(IdentityError::Malformed(
                "the primary secret key is missing",
            ));
        }
        let mut retained = Vec::new();
        for r in &f.retained_subkeys {
            let fp = Fingerprint::from_hex(&r.fingerprint)
                .map_err(|_| IdentityError::Malformed("invalid retired subkey fingerprint"))?;
            retained.push(Retained {
                fp,
                retire_at: r.retire_at,
            });
        }
        Ok(Self {
            cert,
            address,
            retained,
            created_at: f.created_at,
            kem_expires_at: f.kem_expires_at,
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
    /// passphrase (scrypt recipient). The `age` tool is an existing, reviewed
    /// file-encryption format; AgentNet defines nothing around it.
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
        // ASCII-armored age expands plaintext by ~37%; plaintext is still
        // bounded by `MAX_IDENTITY_FILE_LEN` inside `from_file_bytes`.
        if bytes.len() > MAX_IDENTITY_FILE_LEN * 2 {
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

    /// The raw secret-key bytes of the identity file, for the test that checks
    /// that no debug output contains them.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn secret_fragments_for_tests(&self) -> Vec<String> {
        let tsk = self.cert.as_tsk().to_vec().unwrap_or_default();
        let b = B64.encode(&tsk);
        // a fragment from the middle of the secret part
        vec![
            b[b.len() / 2..b.len() / 2 + 24].to_string(),
            hex_of(&tsk[tsk.len() / 2..tsk.len() / 2 + 8]),
        ]
    }
}

#[cfg(any(test, feature = "test-support"))]
fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn public_fallback(c: &Cert) -> Cert {
    c.clone().strip_secret_key_material()
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
