//! Architectural rules of owner condition 12: all cryptography sits behind
//! `agentnet_core::crypto`. The engine, the transport, the MCP server and the
//! daemon must not reference the cryptographic crates, so that replacing or
//! extending the scheme touches `crates/core/src/crypto/` only.

use std::path::{Path, PathBuf};

/// The crates whose use is confined to the crypto module (Rust identifiers).
const CRYPTO_CRATES: [&str; 4] = ["sequoia_openpgp", "openssl", "openssl_sys", "age"];
/// The same crates as written in Cargo manifests.
const CRYPTO_PACKAGES: [&str; 4] = ["sequoia-openpgp", "openssl", "openssl-sys", "age"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// True if `line` uses crate `name` as a path (`name::`) or imports it
/// (`use name`, `extern crate name`), ignoring words that merely end in it
/// (`message::`, `usage::`).
fn references(line: &str, name: &str) -> bool {
    let code = line.split("//").next().unwrap_or("");
    let bytes = code.as_bytes();
    let mut from = 0;
    while let Some(i) = code[from..].find(name) {
        let start = from + i;
        let end = start + name.len();
        let before_ok = start == 0 || {
            let c = bytes[start - 1];
            !(c.is_ascii_alphanumeric() || c == b'_')
        };
        let after = code[end..].chars().next();
        let after_ok = after.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        let is_path = code[end..].starts_with("::");
        let is_import = code[..start].trim_end().ends_with("use")
            || code[..start].trim_end().ends_with("extern crate");
        if before_ok && after_ok && (is_path || is_import) {
            return true;
        }
        from = end;
    }
    false
}

#[test]
fn only_the_crypto_module_references_the_cryptographic_crates() {
    let root = workspace_root();
    let mut files = Vec::new();
    for krate in ["core", "transport", "mcp", "daemon", "cli"] {
        rust_files(&root.join("crates").join(krate).join("src"), &mut files);
    }
    // integration tests and examples of the non-core crates
    for krate in ["transport", "mcp", "daemon", "cli"] {
        rust_files(&root.join("crates").join(krate).join("tests"), &mut files);
        rust_files(
            &root.join("crates").join(krate).join("examples"),
            &mut files,
        );
    }
    // core's integration tests may use the OpenPGP library only in the published
    // vector tests, which exist to exercise the library directly
    rust_files(&root.join("crates/core/tests"), &mut files);
    assert!(files.len() > 50, "walked {} files", files.len());

    let crypto_dir = root.join("crates/core/src/crypto");
    let vectors = root.join("crates/core/tests/vectors.rs");
    let this = root.join("crates/core/tests/architecture.rs");
    let mut violations = Vec::new();
    for f in &files {
        if f.starts_with(&crypto_dir) || *f == vectors || *f == this {
            continue;
        }
        let text = std::fs::read_to_string(f).expect("read source");
        for (n, line) in text.lines().enumerate() {
            for c in CRYPTO_CRATES {
                if references(line, c) {
                    violations.push(format!("{}:{}: {}", f.display(), n + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "cryptographic crates referenced outside crates/core/src/crypto/:\n{}",
        violations.join("\n")
    );
}

#[test]
fn the_reference_matcher_works() {
    assert!(references(
        "use sequoia_openpgp::cert::Cert;",
        "sequoia_openpgp"
    ));
    assert!(references(
        "let k = openssl::pkey::PKey::generate_ed25519();",
        "openssl"
    ));
    assert!(references("use age;", "age"));
    assert!(references("age::encrypt(&r, b)", "age"));
    assert!(!references("let m = message::new();", "age"));
    assert!(!references("// uses openssl:: in a comment", "openssl"));
    assert!(!references("fn usage::x()", "age"));
}

fn dependencies_section(manifest: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            inside = t.contains("dependencies");
            continue;
        }
        if inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[test]
fn transport_mcp_daemon_and_cli_do_not_depend_on_the_cryptographic_crates() {
    let root = workspace_root();
    for krate in ["transport", "mcp", "daemon", "cli"] {
        let manifest = std::fs::read_to_string(root.join("crates").join(krate).join("Cargo.toml"))
            .expect("manifest");
        let deps = dependencies_section(&manifest);
        for p in CRYPTO_PACKAGES {
            let used = deps.lines().any(|l| {
                let name = l.split(['=', ' ', '.']).next().unwrap_or("").trim();
                name == p
            });
            assert!(!used, "crates/{krate}/Cargo.toml depends on {p}");
        }
    }
    // the transport crate does not even depend on agentnet-core
    let t = std::fs::read_to_string(root.join("crates/transport/Cargo.toml")).unwrap();
    assert!(!dependencies_section(&t).contains("agentnet-core"));
}

#[test]
fn the_engine_goes_through_the_message_protection_trait() {
    // `ingest`, `send`, `system` and `node` must not call the free
    // `protection::seal` / `protection::open` wrappers (which pin the default scheme).
    let src = workspace_root().join("crates/core/src");
    for f in [
        "ingest.rs",
        "send.rs",
        "system.rs",
        "node.rs",
        "api_impl.rs",
    ] {
        let text = std::fs::read_to_string(src.join(f)).unwrap();
        for bad in [
            "protection::seal(",
            "protection::open(",
            "OpenPgpProtection",
        ] {
            assert!(!text.contains(bad), "{f} references {bad}");
        }
    }
}

/// The webhook request signature is a standard HMAC-SHA256 (not message
/// protection). The rule is: the message-protection cryptography crates are
/// confined to `crates/core/src/crypto/` (tests above); the `hmac` crate is
/// confined to the daemon's webhook module, and no other crate depends on it.
#[test]
fn hmac_is_used_only_for_the_webhook_request_signature() {
    let root = workspace_root();
    for krate in ["core", "transport", "mcp", "cli"] {
        let manifest = std::fs::read_to_string(root.join("crates").join(krate).join("Cargo.toml"))
            .expect("manifest");
        let used = dependencies_section(&manifest)
            .lines()
            .any(|l| l.split(['=', ' ', '.']).next().unwrap_or("").trim() == "hmac");
        assert!(!used, "crates/{krate}/Cargo.toml depends on hmac");
    }
    let mut files = Vec::new();
    rust_files(&root.join("crates/daemon/src"), &mut files);
    assert!(!files.is_empty());
    for f in &files {
        if f.file_name().is_some_and(|n| n == "webhook.rs") {
            continue;
        }
        let text = std::fs::read_to_string(f).expect("read source");
        for (n, line) in text.lines().enumerate() {
            assert!(
                !references(line, "hmac"),
                "{}:{}: hmac outside webhook.rs",
                f.display(),
                n + 1
            );
        }
    }
}
