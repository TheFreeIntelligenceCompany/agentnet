# Third-party notices

AgentNet is MIT licensed (`LICENSE`). A distributed `agentnet` binary contains third-party code. This file is the notice
that must accompany it (see `docs/licensing.md`; the maintainers' reading, not legal advice).

## Sequoia OpenPGP (LGPL-2.0-or-later)

This program uses **sequoia-openpgp 2.5.0** and **buffered-reader 1.4.1** (from the Sequoia PGP project), which are free
software licensed under the **GNU Library General Public License, version 2 or (at your option) any later version**. The
library and its use in this program are covered by that licence; a copy is in `sequoia-openpgp-2.5.0/LICENSE.txt` of the crate
and must be shipped with every binary release.

* Library source: https://gitlab.com/sequoia-pgp/sequoia, and crates.io (`sequoia-openpgp` 2.5.0, `buffered-reader` 1.4.1).
* Source of this program: the AgentNet repository, at the commit named in the release notes (a release must fill it in:
  `commit: <hash>`; none exists yet because no release has been made).
* You may modify Sequoia and rebuild this program with your modified copy: obtain the AgentNet source at that commit, point the
  dependency at your copy (for example `[patch.crates-io] sequoia-openpgp = { path = "/path/to/your/sequoia-openpgp" }`), and run
  `cargo build --release --locked` (build prerequisites are in `README.md`: OpenSSL 3 development files, libclang, pkg-config).
  The AgentNet terms (MIT) permit modification for your own use and reverse engineering for debugging such modifications.

## OpenSSL 3 (Apache-2.0)

Cryptographic operations of Sequoia are provided by OpenSSL 3 (through the `ossl` and `openssl-sys` crates), linked dynamically as
a system library. OpenSSL 3 is licensed under the Apache License 2.0. If a release bundles OpenSSL, the Apache-2.0 text and
OpenSSL's attributions must be shipped with it.

## Other components

Dependencies are listed with their declared licences in `docs/dependency-audit.md` and can be regenerated with
`cargo metadata --locked`. Notable: SQLite (public-domain dedication, bundled C source), `ring` (Apache-2.0 AND ISC, with
BoringSSL and other notices in its source), `webpki-roots` (CDLA-Permissive-2.0), `age` (MIT OR Apache-2.0), Unicode data tables
(Unicode-3.0). Each crate's own licence files are in its source package.
