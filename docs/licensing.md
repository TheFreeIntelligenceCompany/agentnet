# Licensing

Status: describes the position after ADR 0004 (OpenPGP cutover). **This is the maintainers' reading of the licence texts, not legal
advice.** No release has been made and none is being made now: publishing binaries or packages needs the repository holder's separate
approval. This document says what a release would have to contain; it does not publish anything.

Licence texts quoted below were read from the crate sources in the cargo registry (`sequoia-openpgp-2.5.0/LICENSE.txt`,
`ossl-1.5.5/LICENSE.txt`) and from the OpenSSL installation used for the build (`/opt/homebrew/opt/openssl@3/LICENSE.txt`), not from memory.

## 1. The project licence

AgentNet's own source is **MIT** (`LICENSE`, `license = "MIT"` in `Cargo.toml`). Dependencies are Cargo dependencies, not copied code,
so the repository's source licence is unaffected by them. A distributed **binary** is a different object: Cargo links Rust dependencies
statically, so the `agentnet` binary contains Sequoia's code. Its licence is the one that matters in section 2.

What the binary links (macOS arm64 debug build, `otool -L target/debug/agentnet`): `libssl.3.dylib` and `libcrypto.3.dylib` (OpenSSL 3,
dynamic), `Security.framework`, `CoreFoundation.framework`, `libiconv`, `libSystem`. Everything else, including `sequoia-openpgp`,
`buffered-reader`, `ossl`/`openssl-sys` bindings, SQLite (bundled C source) and `ring`, is compiled in.

## 2. LGPL-2.0-or-later: `sequoia-openpgp 2.5.0` and `buffered-reader 1.4.1`

Both crates declare `LGPL-2.0-or-later` and ship the same `LICENSE.txt`: a short Sequoia notice ("under the terms of the GNU Library
General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
version") followed by the **GNU Library General Public License, version 2, June 1991**. Source: crates.io, repository
`https://gitlab.com/sequoia-pgp/sequoia` (`repository` field of both manifests).

### 2.1 What the licence says (quoted from the shipped file)

Section 5: "However, linking a 'work that uses the Library' with the Library creates an executable that is a derivative of the Library
(because it contains portions of the Library), rather than a 'work that uses the library'. The executable is therefore covered by this
License. Section 6 states terms for distribution of such executables."

Section 6: "As an exception to the Sections above, you may also compile or link a 'work that uses the Library' with the Library to produce
a work containing portions of the Library, and distribute that work under terms of your choice, provided that the terms permit
modification of the work for the customer's own use and reverse engineering for debugging such modifications."

"You must give prominent notice with each copy of the work that the Library is used in it and that the Library and its use are covered
by this License. You must supply a copy of this License. If the work during execution displays copyright notices, you must include the
copyright notice for the Library among them, as well as a reference directing the user to the copy of this License. Also, you must do
one of these things:"

* "a) Accompany the work with the complete corresponding machine-readable source code for the Library including whatever changes were
  used in the work (which must be distributed under Sections 1 and 2 above); and, if the work is an executable linked with the Library,
  with the complete machine-readable 'work that uses the Library', as object code and/or source code, so that the user can modify the
  Library and then relink to produce a modified executable containing the modified Library."
* "b) Accompany the work with a written offer, valid for at least three years, to give the same user the materials specified in
  Subsection 6a, above, for a charge no more than the cost of performing this distribution."
* "c) If distribution of the work is made by offering access to copy from a designated place, offer equivalent access to copy the above
  specified materials from the same place."
* "d) Verify that the user has already received a copy of these materials or that you have already sent this user a copy."

"For an executable, the required form of the 'work that uses the Library' must include any data and utility programs needed for
reproducing the executable from it. However, as a special exception, the source code distributed need not include anything that is
normally distributed (in either source or binary form) with the major components (compiler, kernel, and so on) of the operating system
on which the executable runs, unless that component itself accompanies the executable."

### 2.2 How this project satisfies it (the mechanism)

1. **Terms of the work.** AgentNet's terms are MIT: they permit modification for the user's own use and contain no restriction on
   reverse engineering, which is what section 6 first requires. (A release must not add an EULA or terms that restrict either.)
2. **Complete corresponding source is public.** The whole application is public under MIT, with a committed `Cargo.lock`
   (`--locked` builds), exact pins on the cryptographic dependencies (`sequoia-openpgp =2.5.0`) and the build instructions in the
   README. A recipient can obtain the exact source of the released binary, replace Sequoia with a modified copy
   (for example a `[patch.crates-io] sequoia-openpgp = { path = "..." }` entry, or a vendored copy of the crate) and rebuild with
   `cargo build --release --locked` to obtain "a modified executable containing the modified Library". That is the 6a/6c relink
   requirement met by providing source and the build recipe instead of object files.
3. **Offer from a designated place (6c).** The release notes name the public repository and the exact commit (and the crates.io
   source of `sequoia-openpgp`/`buffered-reader` at the versions in `Cargo.lock`) as the place from which the source is available,
   for as long as the release is offered.
4. **Notice and licence text.** Each release artefact carries `THIRD-PARTY-NOTICES.md` (repository root), which names the library,
   states that it is used and covered by the LGPL, says where its source is, and the release includes the licence text.

### 2.3 Caveats, stated plainly

* Rust has no stable ABI and links statically, so "relink with a modified Library" is satisfied here by *rebuilding from source*, not
  by swapping a shared object. Whether a lawyer accepts source-plus-recipe as the section 6a "work that uses the Library ... so that the
  user can modify the Library and then relink" is an interpretation question. This document does not claim it is settled.
* The licence says "or any later version". The shipped text is version 2; this project does not elect a later version. LGPL-3.0 adds
  installation-information duties for consumer products; not analysed.
* The binary does not, to the maintainers' knowledge, display copyright notices at run time, which makes the sentence about run-time
  notices moot. This was not exhaustively verified; if an "about"/`--version` screen listing libraries is ever added, it must list
  Sequoia and point to the licence text.
* Container images and any bundled copy of OpenSSL are distributions of their own: each carries the same notice and source-offer
  duties (and the OS-component exception quoted above stops applying to a component that itself accompanies the executable).

### 2.4 Scoped exception in the dependency policy

`deny.toml` does not allow LGPL globally. It has two exceptions pinned to exact versions
(`sequoia-openpgp@2.5.0`, `buffered-reader@1.4.1`, each `LGPL-2.0-or-later`), so a version bump or a new copyleft crate fails
`cargo deny check licenses` and is re-reviewed. The `openssl-sys` ban is lifted only for the direct dependents `ossl` and
`sequoia-openpgp`. `cargo deny check`: advisories ok, bans ok, licenses ok, sources ok (`results/adr0004/cargo-deny.txt`).

## 3. OpenSSL 3

`openssl-sys 0.9.118` (MIT) and `ossl 1.5.5` (Apache-2.0) are Rust bindings. The OpenSSL library itself is a system library, linked
**dynamically** (macOS check above; Linux: `libssl.so.3`, UNTESTED here). OpenSSL 3.x is licensed under the **Apache License 2.0**
(`LICENSE.txt` of the installation used: "Apache License, Version 2.0, January 2004"; the version used for the local build was
OpenSSL 3.6.4).

* If the release does **not** include OpenSSL (the user installs `libssl3`/Homebrew `openssl@3`): state the requirement in the
  release notes; no OpenSSL licence text is required from us because we do not redistribute it.
* If a release (tarball with the library, container image, installer) **does** include OpenSSL: include the Apache-2.0 text and
  OpenSSL's NOTICE-type attributions from that installation, and state the OpenSSL version and its source location.
* Static linking or vendoring OpenSSL (the `openssl-src` route) is not used and is UNTESTED.
* Open question for counsel, UNVERIFIED by the maintainers (not looked up in a source text for this document): Apache-2.0 and
  GPL-2.0-only are commonly described as incompatible; Sequoia is LGPL-2.0-or-later (with the "or later" option) and itself offers the
  OpenSSL backend, and OpenSSL is a system library here, but this project has not checked whether the combination raises an issue.
  The repository holder accepted the Sequoia/OpenSSL packaging in ADR 0004.

## 4. Other notable licences in the shipped graph

Counts and expressions: `docs/dependency-audit.md`. In short: almost everything is MIT and/or Apache-2.0 (dual). Notable:

| Component | Licence (as declared in its manifest) | Note |
|---|---|---|
| SQLite (bundled by `libsqlite3-sys 0.40.0`, SQLite 3.54.1) | wrapper `MIT`; the SQLite source states "The author disclaims copyright to this source code" with a blessing (read in `sqlite3/sqlite3.c`) | public-domain dedication |
| `ring 0.17.14` (rustls) | `Apache-2.0 AND ISC`; its tree also has `LICENSE-BoringSSL`, `LICENSE-other-bits` | include in notices |
| `webpki-roots` | `CDLA-Permissive-2.0` | Mozilla root certificate data |
| `age 0.12.1` | `MIT OR Apache-2.0` | passphrase-encrypted identity export only |
| `bindgen`, `clang-sys`, `lalrpop` ... | build-time only, not linked | permissive; not in the binary |
| `Unicode-3.0` crates | data tables | include licence text |
| `OR LGPL-2.1-or-later`, `OR GPL-2.0-only` alternatives (3 crates) | dual-licensed with a permissive option | the permissive option is the one used |

The rPGP crates used by the interoperability test (`pgp`, `rpgpie`, `tests/interop-rpgp`) are **not** linked into the shipped
binary (workspace-excluded crate) and are `MIT OR Apache-2.0`.

## 5. Release checklist (to be satisfied before any binary is distributed)

1. Repository holder's approval to publish (AGENTS.md).
2. Build with `cargo build --release --locked` from a tagged commit; record the commit hash, OS, architecture and the OpenSSL version.
3. Ship in the release: the binary; `LICENSE` (MIT); `THIRD-PARTY-NOTICES.md`; the LGPL text (copy of
   `sequoia-openpgp-2.5.0/LICENSE.txt`); licence texts for any other bundled component (and the Apache-2.0 text plus attributions
   if OpenSSL itself is bundled); the AgentNet source reference (public repository URL, tag and commit); the build instructions
   (README prerequisites: OpenSSL 3 headers, libclang, pkg-config; `OPENSSL_DIR`).
4. State in the release notes: that Sequoia (LGPL-2.0-or-later) is linked, where its source is, and how to rebuild with a modified
   Sequoia (section 2.2 step 2); how to obtain the source (designated place) and for how long it will stay available.
5. Run `cargo deny check` (expect `ok` for all four) and attach the output; regenerate the licence list if `Cargo.lock` changed
   (`docs/dependency-audit.md`), and review any new advisory against `sequoia-openpgp`/`buffered-reader` before tagging.
6. Do not add terms that restrict modification or reverse engineering of the binary. Do not describe the product as audited.
7. Container images: apply the same list to every layer that contains OpenSSL or other copyleft components.
8. Re-read this document against the exact versions in `Cargo.lock`; the `deny.toml` exceptions are version-pinned for that purpose.
