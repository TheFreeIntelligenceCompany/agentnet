//! The data directory: layout, permissions, lock, tokens.
//!
//! ```text
//! <data dir>/            0700
//!   identity.json        0600   secret keys (written by `agentnet init`)
//!   agentnet.toml        0600   configuration
//!   agentnet.db          0600   engine store (SQLite, WAL)
//!   webhook.db           0600   webhook dispatcher cursor
//!   lock                 0600   exclusive advisory lock, held for the daemon's life
//!   agentnet.sock        0600   control + event socket
//!   control.token        0600   socket token (64 hex chars)
//!   mcp-http.token       0600   bearer token of the HTTP MCP endpoint
//! ```

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use fs4::fs_std::FileExt;

use crate::error::DaemonError;

/// Longest path of a Unix socket we accept (macOS limit is 104 including NUL).
pub const MAX_SOCKET_PATH: usize = 100;
/// Largest token / secret file we read.
const MAX_SECRET_FILE: u64 = 4096;

/// Paths inside one data directory.
#[derive(Clone, Debug)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    /// Wrap a path (nothing is touched).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    /// The directory itself.
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// `identity.json`
    pub fn identity(&self) -> PathBuf {
        self.root.join("identity.json")
    }
    /// `agentnet.toml`
    pub fn config(&self) -> PathBuf {
        self.root.join("agentnet.toml")
    }
    /// `agentnet.db`
    pub fn db(&self) -> PathBuf {
        self.root.join("agentnet.db")
    }
    /// `webhook.db`
    pub fn webhook_db(&self) -> PathBuf {
        self.root.join("webhook.db")
    }
    /// `lock`
    pub fn lock(&self) -> PathBuf {
        self.root.join("lock")
    }
    /// `agentnet.sock`
    pub fn socket(&self) -> PathBuf {
        self.root.join("agentnet.sock")
    }
    /// `control.token`
    pub fn control_token(&self) -> PathBuf {
        self.root.join("control.token")
    }
    /// `mcp-http.token`
    pub fn mcp_token(&self) -> PathBuf {
        self.root.join("mcp-http.token")
    }

    /// Create the directory (and parents) with mode 0700 if it does not exist.
    pub fn create_private(&self) -> Result<(), DaemonError> {
        if self.root.exists() {
            return self.check_dir_perms();
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.root)
            .map_err(|e| DaemonError::io(format!("creating {}", self.root.display()), e))?;
        // `recursive` applies the mode to every created component; enforce it
        // on the leaf regardless of the umask.
        std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| DaemonError::io(format!("chmod {}", self.root.display()), e))?;
        Ok(())
    }

    /// Fail unless the directory exists and is not accessible by group/others.
    pub fn check_dir_perms(&self) -> Result<(), DaemonError> {
        let md = std::fs::metadata(&self.root).map_err(|e| {
            DaemonError::DataDir(format!(
                "cannot access {} ({e}); run `agentnet init` first",
                self.root.display()
            ))
        })?;
        if !md.is_dir() {
            return Err(DaemonError::DataDir(format!(
                "{} is not a directory",
                self.root.display()
            )));
        }
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(DaemonError::DataDir(format!(
                "{} has mode {mode:03o}; it must not be accessible by group or others \
                 (fix with `chmod 700`)",
                self.root.display()
            )));
        }
        Ok(())
    }

    /// Take the exclusive advisory lock. Fails with [`DaemonError::Locked`]
    /// when another process (or another holder in this process) has it.
    pub fn acquire_lock(&self) -> Result<DataDirLock, DaemonError> {
        let path = self.lock();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| DaemonError::io(format!("opening {}", path.display()), e))?;
        match FileExt::try_lock_exclusive(&file) {
            Ok(true) => {}
            Ok(false) => return Err(DaemonError::Locked(path)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(DaemonError::Locked(path))
            }
            Err(e) => return Err(DaemonError::io(format!("locking {}", path.display()), e)),
        }
        Ok(DataDirLock { file, path })
    }
}

/// Holds the exclusive lock until dropped.
#[derive(Debug)]
pub struct DataDirLock {
    file: File,
    path: PathBuf,
}

impl DataDirLock {
    /// Path of the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DataDirLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

/// Lower-case hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 15)] as char);
    }
    s
}

/// Decode lower- or upper-case hex; `None` on any malformed input.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let val = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    b.chunks(2)
        .map(|p| Some(val(p[0])? << 4 | val(p[1])?))
        .collect()
}

/// `n` random bytes from the OS.
pub fn random_bytes(n: usize) -> Result<Vec<u8>, DaemonError> {
    let mut v = vec![0u8; n];
    getrandom::fill(&mut v).map_err(|e| {
        DaemonError::io(
            "reading the OS random number generator",
            std::io::Error::other(e.to_string()),
        )
    })?;
    Ok(v)
}

/// Create `path` with mode 0600, failing if it already exists.
pub fn create_secret_file(path: &Path, contents: &[u8]) -> Result<(), DaemonError> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| DaemonError::io(format!("creating {}", path.display()), e))?;
    f.write_all(contents)
        .and_then(|()| f.sync_all())
        .map_err(|e| DaemonError::io(format!("writing {}", path.display()), e))
}

/// Read a small secret file. Refuses non-regular files, files readable by
/// group/others, and files over 4 KiB. The caller must not log the result.
pub fn read_secret_file(path: &Path) -> Result<Vec<u8>, DaemonError> {
    let io = |e| DaemonError::io(format!("reading {}", path.display()), e);
    let mut f = File::open(path).map_err(io)?;
    let md = f.metadata().map_err(io)?;
    if !md.is_file() {
        return Err(DaemonError::DataDir(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mode = md.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(DaemonError::DataDir(format!(
            "{} has mode {mode:03o}; secrets must be mode 600 (fix with `chmod 600`)",
            path.display()
        )));
    }
    if md.len() > MAX_SECRET_FILE {
        return Err(DaemonError::DataDir(format!(
            "{} is too large",
            path.display()
        )));
    }
    let mut buf = Vec::new();
    (&mut f)
        .take(MAX_SECRET_FILE + 1)
        .read_to_end(&mut buf)
        .map_err(io)?;
    Ok(buf)
}

/// Return the hex token stored at `path`, creating it (32 random bytes, 0600)
/// when it does not exist.
pub fn ensure_token(path: &Path) -> Result<String, DaemonError> {
    match read_secret_file(path) {
        Ok(bytes) => {
            let t = String::from_utf8(bytes)
                .map_err(|_| DaemonError::DataDir(format!("{} is not text", path.display())))?
                .trim()
                .to_owned();
            if t.len() < 32 {
                return Err(DaemonError::DataDir(format!(
                    "{} holds a token shorter than 32 characters; delete it to regenerate",
                    path.display()
                )));
            }
            Ok(t)
        }
        Err(DaemonError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            let t = hex_encode(&random_bytes(32)?);
            create_secret_file(path, t.as_bytes())?;
            Ok(t)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let b = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex_encode(&b), "0001abff");
        assert_eq!(hex_decode("0001ABff").as_deref(), Some(&b[..]));
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let t = tempfile::tempdir().unwrap();
        let d = DataDir::new(t.path());
        let l = d.acquire_lock().unwrap();
        assert!(matches!(d.acquire_lock(), Err(DaemonError::Locked(_))));
        drop(l);
        let _again = d.acquire_lock().unwrap();
    }

    #[test]
    fn dir_perms_and_tokens() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("home");
        let d = DataDir::new(&root);
        d.create_private().unwrap();
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(d.check_dir_perms().is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let tok = ensure_token(&d.control_token()).unwrap();
        assert_eq!(tok.len(), 64);
        assert_eq!(ensure_token(&d.control_token()).unwrap(), tok);
        let mode = std::fs::metadata(d.control_token())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::set_permissions(d.control_token(), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(ensure_token(&d.control_token()).is_err());
    }
}
