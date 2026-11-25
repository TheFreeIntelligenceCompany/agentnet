# A1 path (1): official Rust bindings to native Logos Delivery (FFI)

Status: discovery spike, written 2026-11-25. Everything below is either backed by a file under
`results/a1-ffi/` (paths relative to the repo root), a source `file:line` in `upstream/logos-delivery-rust-bindings`
(abbreviated `RB/`) or `upstream/logos-delivery` (`LD/`, a shallow clone of master `88bd0e5`, other agent's clone, read only),
or is labelled **UNTESTED**.

Architecture of every test run: **linux/arm64** (colima VM, native; no amd64/qemu used for the final result).
Host is macOS arm64. All network tests are container-to-container on a private docker bridge on one host
(**not** cross-machine, **not** NAT, **not** Tailscale).

## 1. Verdict (short)

- It builds and runs on linux/arm64, but only after a workaround for an arm64 toolchain bug in the upstream build path (section 6, F3), and a
  from-scratch build takes about an hour of wall clock in this VM.
- Two nodes on a private bridge (cluster 7777, no preset, discovery off, `nat=none`, static dial) exchanged 100/100 numbered messages in each direction
  with 0 duplicates; p50 6.4 ms, p99 111-132 ms (section 7.2).
- Native embedding is **not** a clean "link a Rust crate" story today: you build a 295 MB (57 MB stripped) Nim shared library from a pinned
  `logos-delivery` rev with a Nim toolchain, ship it next to your binary, and accept an unstable-by-declaration API surface (the useful parts of
  peer management and store are "kernel API ... may change at any time", `LD/library/BUILD.md`). Starting and stopping a node inside one process
  **leaks about 24.5 MB RSS and 4 file descriptors per cycle** (section 7.1), so the only safe lifecycle today is one node per process.
- Recommendation (details in section 9): do not make in-process native embedding the MVP's primary path. Use the local-daemon adapter for the MVP
  and keep this crate as a documented future option behind the transport trait; if native is attempted, run the node in a **child process** that you can kill.

## 2. Pins (exact)

| Item | Pin | Evidence |
|---|---|---|
| Bindings repo | `https://github.com/logos-messaging/logos-delivery-rust-bindings` @ `d60fcfd40f2b860000c4df8db4f2f95a6c6f1fad` (master HEAD, 2026-11-20) | `git -C upstream/logos-delivery-rust-bindings rev-parse HEAD` |
| Crate used | `logos-delivery 0.1.0` (workspace member of the bindings repo), consumed as git dep with `rev=` | `spike/transport-ffi/Cargo.toml`, `Cargo.lock` |
| Native lib source | `logos-messaging/logos-delivery` @ `0f2188c09779cc84116db344bbb43ccfe6a27c35` (commit "docs: changelog for v0.39.1 (#4427)", 2026-10-06), recorded in `RB/LOGOS_DELIVERY_REV`; library reports nimble version 0.39.1 (`RB/logos-delivery/MIN_LIBRARY_VERSION`) | `results/a1-ffi/lib-build-6-clean.log` line ~123 |
| Nim | 2.2.6, `nimble.lock` entry (git rev `372826d4317f1f8cb99abd750698f4a00c5cd39a`, checksum `b3179cff...`); **built natively from source tag v2.2.6** on arm64 (workaround) | `results/a1-ffi/nim-native-build.log`, `toolchain-versions.log` |
| Nimble | 0.26.0 (downloaded `nimble-linux_aarch64.tar.gz` by `scripts/install_nimble.sh`) | `lib-build-6-clean.log` line ~487 |
| RLN | `librln_v2.0.2.a` **prebuilt download** from vacp2p/zerokit v2.0.2 release (`aarch64-unknown-linux-gnu-stateless-rln.tar.gz`), zerokit submodule `ea80f39b...`; no Rust build of RLN was needed | `lib-build-4-FAILED-nimscript-segv.log` lines 9-15 |
| Rust | 1.92.0 (image `rust:1.92-bookworm`; Debian 12.13; gcc/g++ 12.2.0; cmake 3.25.1; patchelf 0.14.3; GNU make 4.3; git 2.39.5) | `toolchain-versions.log` |
| Docker | server 29.5.2 linux/arm64; context `colima` | `docker version` |

The Nim dependency graph (about 50 packages) is pinned by `nimble.lock` with sha1 checksums; all fetched from GitHub at build time (network required).

## 3. Source audit

### 3.1 Canonical location and naming

- `waku-org/waku-rust-bindings` redirects to `logos-messaging/logos-delivery-rust-bindings` (`gh api repos/waku-org/waku-rust-bindings` returns `full_name: logos-messaging/logos-delivery-rust-bindings`, not archived, `pushed_at 2026-11-24`; raw output in `results/a1-ffi-gh-meta.log`; clone log `results/a1-ffi-clone.log`).
  The repo description is still "Rust wrapper over nwaku ffi"; the README still describes `logos-messaging-nim` and `libwaku.h` (`RB/README.md`).
- The org `logos-messaging` hosts `logos-delivery` (pushed 2026-11-25), `logos-delivery-go-bindings`, `logos-delivery-python-bindings`, `logos-delivery-nodejs-bindings`, `logos-chat`, `nim-sds`, `sds-rs`, `nim-ffi`, `sds-go-bindings` (`results/a1-ffi-gh-meta.log`).
  `specs` is archived (2026-06-05).

### 3.2 Two generations of bindings live in one repo

| | legacy `waku-sys` + `waku-bindings` 1.0.0 | new `logos-delivery` 0.1.0 |
|---|---|---|
| Native target | `libwaku` (static, `make libwaku STATIC=1` of a vendored submodule) | `liblogosdelivery` (shared, built separately; `LOGOS_DELIVERY_LIB_DIR`) |
| Pinned native source | submodule `waku-sys/vendor` -> `logos-messaging-nim` @ `4117449b9af6c0304a6115dd4bc0d1d745159685` (2025-02-06, nwaku v0.35 era; `RB/.gitmodules`, `git submodule status`) | `LOGOS_DELIVERY_REV` = `0f2188c0...` (2026-10-06, v0.39.1) |
| Interface | C header `libwaku.h`, JSON strings, one global event callback | nim-ffi generated, CBOR requests/replies, per-event listener registry (`RB/logos-delivery/src/generated/ffi.rs`) |
| Added | PR #134 "add async logos-delivery crate with reliable channels" 2026-10-09 | #135 store query + connected peers info 2026-11-17 |
| crates.io | `waku-sys 0.6.0`, `waku-bindings 0.6.0`, both 2024-02-19 (nothing newer; versions 1.0.0 in the repo were never published) | **not published** (`crates.io/api/v1/crates/logos-delivery`: "does not exist") |
| Resolvable today | **No.** `cargo generate-lockfile` with `waku-bindings = "=0.6.0"` fails: `core2 = "^0.4.0"` is yanked (via multiaddr 0.17 -> multihash 0.17). Open PR #132 ("bump multiaddr to 0.18 so the crate can be resolved") is unmerged. | yes, as git dependency |

Evidence: `results/a1-ffi/waku-bindings-0.6.0-resolve.log`, `results/a1-ffi/audit-meta.log`. I did **not** attempt to build the legacy crate (it pins a 21-month-old nwaku and
cannot be resolved without patching); marked **UNTESTED**. The rest of this document is about the new `logos-delivery` crate, which is what a new integration would use.

### 3.3 Maintenance, releases, licences, CI

- Last commit on bindings master: 2026-11-20 `d60fcfd` (key rotation of the nix cache). Previous: 2026-11-17 store query, 2026-10-09 async crate. Between 2025-12-16 and 2026-02-05 only licence/CI commits; the only tag/release is `v0.5.0` (2023-12-11). **No release has been cut for either generation since 2024-02**; consumers must pin a git rev.
- Open PR #137 (2026-11-24) bumps to logos-delivery `v0.41.0-rc.0`. `logos-delivery` itself: stable `v0.40.0` (2026-11-13), `v0.41.0-rc.2` pre-release (2026-11-24), master `0.41.0`. The pinned rev is **188 commits behind master** and one stable minor behind (`gh api .../compare`, `audit-meta.log`).
- Licence: both repos carry `LICENSE-MIT` and `LICENSE-APACHE` ("Copyright (c) 2025-2026 Logos"); crate manifest `license = "MIT OR Apache-2.0"` (`RB/logos-delivery/Cargo.toml`); `logos-delivery` GitHub licence field `Apache-2.0`, nimble file says "MIT or Apache License 2.0". Transitive Nim/C dependency licences (about 50 packages, zerokit, boringssl, leopard-rs, miniupnp, libnatpmp, nim-lsquic) were **not** audited: UNTESTED.
- CI (`.github/workflows/main.yml`): jobs Build/Test/Lint plus a `logos-delivery` job on `ubuntu-latest` and `macos-latest` that builds the library **with nix** (`nix build` of the `liblogosdelivery` flake output at `LOGOS_DELIVERY_REV`) and runs `cargo test -p logos-delivery -- --test-threads=1`. Latest `CI` runs on master (2026-11-20, 2026-11-17) and on PR #137: success. The Release workflow (`release.yml`) is invalid ("likely failed because of a workflow file issue"; it has no `runs-on`), so publishing is not wired.
  Consequence: upstream CI exercises only the nix path on x86_64 Linux and (presumably) Apple Silicon macOS runners; the Makefile/nimble path on Linux arm64 that I used is not covered by it (inference from the workflow file, not tested upstream-side).
- Open issues that indicate gaps (not breakage): #131 generated bindings not marked generated, 102 functions return `Result<_, String>`, 16 return an always-empty `String`, no rustdoc; #128/#130 request prebuilt library artifacts / externally packaged lib; the real breakage signal is the unresolvable legacy crate (above).

### 3.4 Native library (what "libwaku" is now)

`libwaku`/`libwaku.h` no longer exists in `logos-delivery` master (`LD/library/` contains only `liblogosdelivery*.h`, `README.md`, `BUILD.md`). Header audited for the legacy comparison: `results/a1-ffi/libwaku-v0.35.h` (225 lines, from nwaku `4117449`). Current surface is `liblogosdelivery` in two tiers (`LD/library/BUILD.md` "Library Headers"): a **stable** messaging / reliable-channels API, and an **advanced kernel API (`waku_*`) "Use at your own risk, may change at any time"**.

## 4. Feature inventory (libwaku legacy vs liblogosdelivery vs Rust crates)

Legend: Y = exposed; K = exposed only via the "kernel" tier that upstream calls unstable; N = not exposed; "raw" = present in the crate's `pub(crate)`/private generated layer but unreachable from the public API.
`ffi.rs` = `RB/logos-delivery/src/generated/ffi.rs`. `api.rs` = `.../generated/api.rs`. `lib.rs`/`node.rs`/`config.rs`/... = `RB/logos-delivery/src/`.

| Feature | libwaku v0.35 (legacy, `libwaku-v0.35.h`) | liblogosdelivery @0f2188c (`ffi.rs`) | legacy `waku-bindings` 1.0.0 | new `logos-delivery` crate public API | Notes |
|---|---|---|---|---|---|
| node create / start / stop / destroy | `waku_new`:26, `waku_start`:31, `waku_stop`:35, `waku_destroy`:40 | `logosdelivery_create_node`:11, `_start_node`:12, `_stop_node`:13, `_destroy`:22, `logosdelivery_shutdown`:114 | Y (`node/mod.rs:57-100`) | Y: `DeliveryNode::start` `node.rs:145`, `shutdown` `node.rs:427`; destroy on last drop `node.rs:104-129` | `logosdelivery_shutdown` (stop all contexts, join threads) is exposed as `LogosDeliveryCtx::shutdown` `api.rs:1256` but `mod generated` is private (`lib.rs:39`): **not callable** |
| config: static peers | CLI/JSON only | flat conf key `staticnode`; kernel `waku_connect` (`ffi.rs:47`) | `connect()` `node/mod.rs:~112` | K: `DeliveryNode::connect` `node.rs:336`; arbitrary key via `DeliveryConfig::option` `config.rs:104` | In this spike static peers = dial after start (section 7) |
| config: discovery toggles | JSON keys | `discv5Discovery`, `dnsDiscovery`, `peerExchange` flat keys (my config, `src/main.rs` `cfg()`); `waku_start_discv5`:~63, `waku_dns_discovery`:62, `waku_peer_exchange_request`:65 | struct fields `node/config.rs:35-60` | only via free-form `option(key, value)` `config.rs:104`; the library rejects unknown flat keys (master test `LD/tests/api/test_conf.nim:679` expects `{"bogusKey":1}` to be an error; I did not test this at the pinned rev, but every key I used was accepted) | `preset` default is `"logos.dev"` (`config.rs:42`): **a default `DeliveryConfig` points at a public preset**; private mode needs `.no_preset()` `config.rs:63` |
| cluster id / shards | `clusterId`, `shards` JSON | same keys; autosharding needs `numShardsInNetwork` and `shards` (`RB/logos-delivery/tests/node.rs:11-29`) | `cluster_id`, `shards` `config.rs:23-32` | via `option()` | static sharding vs autosharding behaviour **UNTESTED** beyond autosharding with 8 shards |
| NAT traversal control | `nat` key | `nat` flat key | no field | via `option("nat","none")` | **default node tries UPnP/NAT-PMP against the local gateway** (see section 6, F8) |
| relay subscribe / publish | `waku_relay_subscribe`:82, `waku_relay_publish`:69 | `logosdelivery_subscribe`:23, `_send`:25 (content-topic API, relay or lightpush chosen by the node); kernel `waku_relay_subscribe`:82, `waku_relay_publish`:84 | Y `node/relay.rs` | Y: `subscribe` `node.rs:221`, `publish` `node.rs:241`, `publish_ephemeral` `node.rs:246` | kernel relay calls are "raw" (private) in the crate; the content-topic API is what is exposed |
| filter | `waku_filter_subscribe`:99, `_unsubscribe`:105, `_unsubscribe_all`:111 | kernel `waku_filter_*` `ffi.rs:90-92` | Y `node/filter.rs` | **N (raw)** | |
| lightpush | `waku_lightpush_publish`:76 | kernel `waku_lightpush_publish` `ffi.rs:89` | Y `node/lightpush.rs` | **N (raw)**; the messaging `send` may fall back to lightpush internally (log line `Lightpush request has not been published to any peers`, `results/a1-ffi/run-dev1/B.stdout.log.gz`) | |
| store query | `waku_store_query`:125 | kernel `waku_store_query` `ffi.rs:88` | Y `node/store.rs`, `mod.rs:~165` | K: `store_query` `node.rs:366`, `store_query_pages` `node.rs:390`, types `store.rs:13-70` | **UNTESTED by me**; upstream test `tests/node.rs:180` exists. Needs a store-enabled peer; durable history is a property of the *peer*, not this crate |
| peer management | connect/dial/disconnect/peerstore `libwaku.h:132-165` | kernel `waku_*` `ffi.rs:32-75` | Y `node/peers.rs` | K: `connect`, `connected_peers_info` `node.rs:336-357`, `listen_addresses` `node.rs:318`; no disconnect/ping/peer-id/ENR | `connect()` can return Ok when the dial failed (F7) |
| events callback | single `waku_set_event_callback`:48 | per-event listener registry `logosdelivery_add_event_listener`/`_remove_` (declared in `liblogosdelivery.h:55-70`, imported `node.rs:28-36`); 12 event names `events.rs:111-125` | single closure `node/context.rs:44-62` | `DeliveryNode::events()` -> `tokio::sync::broadcast` cap 1024 (`node.rs:24,205`), `messages()` stream `node.rs:210` | listener is not user-pluggable: the crate registers its own `extern "C"` `on_event` (`node.rs:58`) |
| error reporting | return code + string | `RET_OK/ERR/MISSING_CALLBACK/STALE_WARN` (`generated/api.rs:40-46`) | `LibwakuResponse` | `DeliveryError` enum, `#[non_exhaustive]`, **string payloads** (`error.rs:1-32`) | library-level errors arrive as free text; see F7 for a call that reports success on failure |
| delivery status of a send | none | `message_queued/sent/propagated/error` events (`events.rs:40-61`) | none | `DeliveryEvent::Message*` `events.rs:40-61` | observed: `MessagePropagated` count equals publishes; `MessageSent` never seen in the relay-only topology (`results/a1-ffi/run-final-2node-100`) |
| reliable channels / SDS (segmentation, ack, retry) | N | `logosdelivery_channel_create/_exists/_send/_close` `ffi.rs:102-109`, events `onChannelMessage*` | N | Y: `Channel`, `ChannelEvent::{Received,Sent,Error,Lost}` `channel.rs:10-157`, `create_channel` `node.rs:410` | channels are created **unencrypted** (cipher fn-pointers fixed to 0, `channel.rs:49-58`, README "Limits" `logos-delivery/README.md:70`); two nodes in one process share SDS persistence so a channel message between them is rejected as replay (`README.md:71`). **UNTESTED by me** |
| higher-level send API | N | `logosdelivery_send` (messaging API, "Messaging / Reliable Channels" tier) | N | `publish` | no application-level encryption, addressing, or identity anywhere in this layer |
| encryption of payloads | legacy crate depends on `aes-gcm`/`secp256k1` (`waku-bindings/Cargo.toml`) for payload helpers (not audited) | none in C API (channel cipher hook only: `liblogosdelivery.h:72-100`) | partially | **N** | AgentNet needs its own authenticated encryption above this (consistent with AGENTS.md: no home-grown crypto) |
| RLN rate limiting | JSON `rln-relay` | `LD` flag; library built with RLN (`DISABLE_RLN=false`), RLN disabled in my config | `RLNConfig` `config.rs:70-100` | `option()` only | not exercised; `DISABLE_RLN=true` build option exists (`LD/Makefile:~567`) |
| node info / ENR / peer id / metrics | `waku_get_my_enr`, `_peerid`, `_metrics` | `logosdelivery_get_node_info` and kernel `waku_get_my_*` `ffi.rs:69-71` | Y | N (raw) | peer id is only obtainable by parsing `listen_addresses()` |
| service discovery plugin | N | `set/clear_service_discovery_plugin`, `get_discovery_requirements` `ffi.rs:28-34` | N | N (raw) | |

## 5. FFI safety audit (new `logos-delivery` crate; legacy crate noted where it differs)

**Callback threading.**
- Per-request result callbacks (`on_result`, `api.rs:48-75`) are invoked from the Nim "FFI thread" that owns the node (nim-ffi dispatcher; `api.rs:121-129` comment: "mutex-guarded MPSC queue ... single FFI thread that dispatches every handler").
- Event callbacks (`on_event`, `node.rs:58-81`) run on "a dedicated event thread and must be fast, non-blocking and thread-safe" (`LD/library/liblogosdelivery.h:55-57`, `LD/library/declare_lib.nim:7-9` "nim-ffi's event thread"). Observed: the process has a constant 7 threads across 20 node lifecycles (`results/a1-ffi/run-final-lifecycle/result.jsonl`), so the Nim worker/event threads are recycled, not joined (also stated in `ffi.rs:18-19`: "nim-ffi recycles the worker rather than joining it, so an unstopped node keeps running").
- Neither callback touches a tokio runtime: results go through a `flume::bounded(1)` channel (`api.rs:103`, `flume::Sender::send` is runtime-agnostic and non-blocking for capacity 1), events through `broadcast::Sender::send` (`node.rs:66`), which never blocks. This satisfies "never block across FFI".

**Closure/user_data lifetime.**
- Results: `Box::into_raw(Box::new(tx))` per call (`api.rs:103`), reclaimed with `Box::from_raw` inside the terminal callback (`api.rs:61`) or immediately on `RET_MISSING_CALLBACK` (`api.rs:105-107`). `RET_STALE_WARN` (progress ping) is ignored without reclaiming (`api.rs:56-57`). If the awaiting future is dropped (timeout/`select!`), the box is still reclaimed by the late callback and the failed `send` is discarded (`api.rs:63-75`): sound. If a request is accepted but the callback **never** fires (context destroyed with the request in flight), the box leaks (no code path reclaims it): minor.
- Events: one `Arc<broadcast::Sender>` leaked with `Arc::into_raw` and passed as `user_data` to every listener (`node.rs:154,161-168`); freed in `Inner::drop` only after `logosdelivery_remove_event_listener` returns for each id, which the library documents as "returns after the last delivery to this listener" (`node.rs:109-119`). Correct *if* that documentation holds; I did not test it under load with concurrent drop.
- The request buffers (`req_bytes`, CBOR) are owned by the Rust future and passed as raw pointers (`api.rs:149-151`); the Nim side must copy before returning. Assumed, not verified.
- `logosdelivery_create_node`'s return value is discarded (`let _ = ...; 0`, `api.rs:148-150,160-162`): a create that fails to invoke its callback is only detected by the call timeout (default 60 s, `config.rs:46`; my spike used 30 s).

**Memory ownership across the boundary.** All strings in/out are CBOR/JSON byte runs with explicit length; the callback `msg` pointer is "valid only for the duration of the call" (`liblogosdelivery.h:42-44`) and the crate copies immediately (`api.rs:28-35`, `node.rs:62`). The library allocates with Nim's allocator (refc, `--mm:refc` in the build line, `lib-build-6-clean.log` line ~1136); Rust never frees Nim memory and vice versa, so there is no allocator-mixing hazard. `logosdelivery_version` returns a thread-owned buffer that must be copied (`liblogosdelivery.h:38-40`; the crate's `version.rs` does).

**Panics across FFI.** There is **no `catch_unwind` anywhere** in the repo (`grep -rn catch_unwind RB --include=*.rs` returns nothing). In the new crate the callback bodies contain no panicking operations on their normal path (JSON parse errors are logged; `Box::from_raw` of a pointer the crate itself created). Since Rust 1.81 a panic escaping an `extern "C"` function aborts the process rather than unwinding into Nim, so a bug would kill the host process, not corrupt it. Elsewhere: `Inner::ctx()` `expect("ctx is only taken on drop")` `node.rs:99-101`; `BlockingDeliveryNode` methods panic inside a tokio runtime by design (`blocking.rs:1-10`).
  Legacy crate: the trampoline calls `.expect("could not retrieve response")` / `.expect("invalid response obtained from libwaku")` on library output inside the `extern "C"` callback (`waku-bindings/src/macros.rs:19-24`), and the default event callback **panics** if the user never set one (`node/context.rs:22-32`), i.e. a stray event before `set_event_callback` aborts the process.

**Tokio integration.** The new crate is runtime-agnostic: futures await a `flume` channel with `tokio::time::timeout` (`api.rs:109-113`); `blocking.rs` drives the async API through a caller-supplied `Handle` with bounded `crossbeam` queues and `try_send` (drop with a warning, `blocking.rs:29-37,133-190`). Public events use a 1024-slot `broadcast` channel; a slow receiver gets `Lagged(n)` and skips events (`node.rs:24,209-218`). The legacy crate passes a **stack-allocated closure pointer** to the library and awaits a `Notify` (`macros.rs:50-68`); if the future is cancelled while awaiting, the later callback writes through a dangling pointer (use-after-free). That is a design flaw of the legacy crate, not exercised by me.

**Shutdown / cancel.** `shutdown()` = `stop_node` with a call timeout (`node.rs:427-434`); dropping the last clone destroys the context. `Drop` cannot await: on a runtime thread it spawns a plain `std::thread` that removes listeners, calls `logosdelivery_destroy`, and frees the event `Arc` (`node.rs:121-128`), so a process that exits right after dropping can lose the cleanup (the doc says to `shutdown().await` first). In-flight requests are not cancelled by dropping their futures (the Nim side keeps running, result discarded). Observed shutdown wall time 0.33-2.1 s (section 7.1).

**`Send`/`Sync`.** `unsafe impl Send/Sync for LogosDeliveryCtx` (`api.rs:130-132`) and for `Inner` (`node.rs:93-96`), justified in comments by the Nim-side mutex-guarded queue and thread-confined handlers. Plausible for the call path; but the same comment concedes "Nim-side reentrancy guard", and the library's two in-process nodes share persistence (`README.md:71`) and ports (`RB/logos-delivery/tests/node.rs:11-17`, "Persistency is a process-wide singleton"), so **multiple nodes per process is not a supported shape**.

**Observed contradiction with "start/stop is safe":** 20 start/stop cycles in one process completed without crash or hang but leak (section 7.1). The Rust side is not the cause as far as I can tell (the same leak occurs whether or not `shutdown()` is called before drop and independent of a 1.5 s vs 8 s settle time, `results/a1-ffi/run-dev-lifecycle/variant-*.txt`); root cause in Nim not investigated.

## 6. Build record

### 6.1 Final recipe

Files: `spike/transport-ffi/Dockerfile`, `Cargo.toml`, `Cargo.lock` (committed lockfile), `src/main.rs`, `.cargo/config.toml` (rpath `$ORIGIN`), `run-two-nodes.sh`.

```
cd spike/transport-ffi
docker build --platform linux/arm64 -t ffi-spike:pinned -f Dockerfile .        # lib stage (Nim) then app stage (cargo) then run stage
```
Stages: `lib` (rust:1.92-bookworm + apt `cmake patchelf pkg-config libssl-dev`; shallow fetch of the pinned logos-delivery commit; zerokit submodule; **native Nim 2.2.6 build on aarch64**; `make LOG_LEVEL=ERROR liblogosdelivery`), `app` (fresh `rust:1.92-bookworm`, `COPY --from=lib` only the `.so`, `LOGOS_DELIVERY_LIB_DIR=/libdir LOGOS_DELIVERY_RELOCATABLE=1 cargo build --release --locked`), `run` (`debian:bookworm-slim` + `ca-certificates procps libgomp1 libstdc++6`).

**System packages**: build image needs, beyond what `rust:1.92-bookworm` already ships (gcc/g++ 12.2, make, git, curl, libssl-dev, pkg-config): **`cmake`** (Leopard-RS, built by the Nim deps) is the one I know to be required; `patchelf` is required only when *not* using `LOGOS_DELIVERY_RELOCATABLE=1` (build.rs absolute-soname stamping, `RB/logos-delivery/build.rs:36-58`); `pkg-config` and `libssl-dev` were installed but I did not test that they are necessary. Runtime image needs **`libgomp1`** (OpenMP from Leopard) and `libstdc++6`; `debian:bookworm-slim` alone fails: `error while loading shared libraries: libgomp.so.1: cannot open shared object file` (my first run image; fixed in the Dockerfile).

**Toolchains actually used**: rustc/cargo 1.92.0, Nim 2.2.6 (aarch64, built from source tag v2.2.6 by `build_all.sh`), nimble 0.26.0, gcc 12.2.0, cmake 3.25.1 (`results/a1-ffi/toolchain-versions.log`). Build flags of the library: `nim c --out:build/liblogosdelivery.so --threads:on --app:lib --opt:speed --noMain --mm:refc ... -d:chronicles_log_level=ERROR` (full line in `lib-build-6-clean.log` ~1136).

### 6.2 Timings (single run each; noisy - other containers on the same colima VM were active, and my own tests ran concurrently during part of it)

| Step | Wall time | Source |
|---|---|---|
| apt + fetch pinned logos-delivery + zerokit submodule | about 1-2 min | `lib-build-6-clean.log` steps 7-11 (cached in this run; first run `lib-build-3` log) |
| native Nim 2.2.6 build (`build_all.sh`: csources -> koch boot -> tools) | 14 m 15 s (clean-build run, contended); about 3 min in an uncontended manual run | `lib-build-6-clean.log:475`, `nim-native-build.log` |
| `make liblogosdelivery` (nimble setup of about 50 deps + Nim -> C -> gcc -> link) | 26 m 19 s (user 70 m 55 s) | `lib-build-6-clean.log:1528-1530`; an uncontended manual run took about 15 min (20:11 -> 20:26, `lib-build-5-...log`) |
| `lib` stage total, started 20:29:50Z, finished 21:28:14Z | **58 m 24 s** (includes about 15 min of docker layer commit overhead) | `lib-build-6-clean.start/.end` |
| `cargo build --release --locked` | 6 m 51 s in the Dockerfile (git dependency pulls the bindings repo **and 72 nested submodule updates of the legacy nwaku vendor tree**, `app-build-2.log` "Updating git submodule" lines); 1 m 49 s when already cached | `app-build-2.log:242`, `cargo-build-in-dev-container.log` |
| `app` + `run` stage docker commits | about 50 min of wall time was spent in the legacy (non-buildx) builder committing multi-GB layers (this is a colima/IO artifact, not build work) | `app-build-2.start/.end`, abandoned `app-build-1` log |

Total from nothing to a runnable image: about **2 h** wall in this environment including layer commits; the CPU-bound portion (Nim + C + cargo) is about 45-50 min.

### 6.3 Artifacts

- `ffi-spike` release binary: **1,978,352 bytes**, ELF aarch64, dynamically links `liblogosdelivery.so` (via `DT_RUNPATH $ORIGIN`).
- `liblogosdelivery.so`: **295,115,696 bytes** unstripped (debug_info), **57,006,712 bytes** after `strip` (`app-build-2.log`, last lines). Earlier TRACE-log build: 304,304,536 / 58,907,256 (`lib-artifact.log`).
- `ldd` (release binary and library, `app-build-2.log` lines 247-261): `liblogosdelivery.so`, `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, `libstdc++.so.6`, `libgomp.so.1`, `ld-linux-aarch64.so.1`. RLN is statically linked (`librln_v2.0.2.a`, 30.6 MB prebuilt), so no extra `.so`.
- Exported surface: 61 `logosdelivery_*`/`waku_*` dynamic symbols in the first (TRACE-log) build (`nm -D`, `lib-artifact.log`); not re-counted on the final build.
- Runtime image `ffi-spike:pinned`: 557 MB on disk (140 MB compressed).

### 6.4 Failures encountered and resolutions

| # | Failure | Cause | Resolution |
|---|---|---|---|
| F1 | `/bin/sh: time: not found` (`lib-build-1-FAILED-sh-time-keyword.log`) | my Dockerfile used bash `time` under `sh` | `SHELL ["/bin/bash","-o","pipefail","-c"]` |
| F2 | `make: *** No rule to make target 'update'` (`lib-build-2-FAILED-no-make-update-target.log`) | at the pinned rev the Makefile is nimble-based (`nimble setup --localdeps`), no `update` target; the old nimbus-build-system flow is gone (`pinned-makefile-inspect.log`) | removed step; `make liblogosdelivery` does everything |
| F3 | `Error: Could not read package info file in .../json_serialization.nimble ... Evaluating as NimScript file failed with: Segmentation fault (core dumped)` after 10 m 17 s (`lib-build-3-FAILED-nimscript-segv-x64-nim.log`); on retry the same error for a **different** package (`boringssl.nimble`) after 5 m (`lib-build-4-FAILED-nimscript-segv.log`) | `nimble setup` on aarch64 logs "Downloading Nim 2.2.6 from nim-lang.org ... Extracting **nim-2.2.6-linux_x64.tar.xz**" (`lib-build-4...log:14-17`): it installs an **x86-64 `nim` binary** into `nimbledeps/pkgs2/nim-2.2.6-*/bin/nim` (`file`: ELF 64-bit x86-64) on an aarch64 host; it only runs because colima registers qemu-user binfmt, and qemu-user segfaults randomly when nimble evaluates `.nimble` files. `ps` showed `/usr/bin/qemu-x86_64 .../nim`. Individual evaluations succeeded when repeated by hand (6/6), i.e. flaky, not deterministic | **Workaround (resolved):** build Nim 2.2.6 natively (`git clone --branch v2.2.6; sh build_all.sh`) and pre-seed `nimbledeps/pkgs2/nim-2.2.6-b3179cff.../` with it + a `nimblemeta.json`; nimble then logs "using .../nim for compilation" and does not download. Verified in a from-scratch Dockerfile build (`lib-build-6-clean.log:494`). On a real arm64 *host without qemu* the x86 binary would fail with `Exec format error` instead of segfaulting (inference). amd64 emulation was **not** tried (unnecessary once arm64 worked) |
| F4 | `libgomp.so.1: cannot open shared object file` running in `debian:bookworm-slim` | runtime dep from Leopard (OpenMP) | `apt-get install libgomp1 libstdc++6` in run stage |
| F5 | docker legacy builder spent ~5 min per layer commit on a 5 GB stage | `FROM lib AS app` carried the whole toolchain image | `app` stage restarted from `rust:1.92-bookworm` + `COPY --from=lib` of the single `.so` |
| F6 | node writes **TRACE/DEBUG logs to stdout** (386 lines for 2 start/stop cycles, `smoke-lifecycle2.log`) although `logLevel: "ERROR"` is accepted by the config | chronicles level is a compile-time switch (`-d:chronicles_log_level=TRACE` hard-coded in `logos_delivery.nimble:163-190`); no runtime filtering | Makefile var `LOG_LEVEL=ERROR` (Makefile:84) makes it quiet: `stdout.log` is **0 bytes** in the final runs. For an MCP stdio server this matters (stdout must carry protocol frames only): the default build would corrupt it, so a log-quiet library build or fd-level redirection is mandatory |

### 6.5 Clean rebuild reproducibility

- The Dockerfile build `lib-build-6-clean` was run from an empty Nim/nimble state (no cached Nim, no `nimbledeps`) after the failed attempts; the apt layer and the git clone layers of the *first* attempts were reused by docker's layer cache, everything from the Nim step onward was built fresh. It produced a working library (`295,115,696` bytes), which then passed all runtime tests below. So: **clean rebuild of the native library from the Dockerfile reproduced successfully once**; I did not rebuild twice and compare hashes (bit-for-bit reproducibility **UNTESTED**; the `.so` embeds a git hash and build timestamp via `-d:git_version`, and `Cargo.lock` is committed so the Rust side is locked).
- It depends on live network access to GitHub (about 60 repositories), `nim-lang.org` is **not** needed after the workaround, and a prebuilt RLN archive is fetched from a GitHub release. There is no vendoring or checksum for that RLN download that I could find in `scripts/build_rln.sh` (not audited line by line).

### 6.6 macOS arm64 (host) - UNTESTED for the native library

- `RB/logos-delivery/build.rs` supports `macos` (`install_name_tool -id` stamping, lines 31-57 and 107-111); the library Makefile has Darwin branches (`LD/Makefile:560-562` produces `liblogosdelivery.dylib`, `LD/config.nims:112-115` uses `-mcpu=apple-m1` on macosx arm64); the upstream CI runs the `logos-delivery` job on `macos-latest` via nix; the legacy `.cargo/config.toml` adds CoreFoundation/Security link flags (`RB/.cargo/config.toml`) but the new crate does not appear to need them.
- Not attempted: the host has no Nim, nimble, cmake or nix (`which` returned "not found"), and installing them is outside this task's rules. `cargo check --locked` of the spike crate **does** succeed on the macOS host without the library (the build script only warns, `results/a1-ffi/macos-cargo-check.log`: "Finished `dev` profile ... in 4m 12s"), but linking a binary that starts a node would fail without `liblogosdelivery.dylib`.
- Linux arm64: **tested** (this document). Linux x86_64: **UNTESTED** (the `qemu` amd64 attempt was unnecessary; note upstream's own CI covers the x86_64 nix path, so x86_64 is the least risky target, but it is not evidence I produced).

## 7. Runtime results (all linux/arm64, containers on one colima VM)

Binary: `ffi-spike` from image `ffi-spike:pinned`. Config (`src/main.rs` `cfg()`): `no_preset`, cluster id 7777, `numShardsInNetwork 8`, `shards 0..7`, `discv5Discovery false`, `dnsDiscovery false`, `peerExchange false`, `nat none`, relay mode "Core", content topic `/agentnet-spike/1/bench/proto`. Nodes dial each other by exact container IP (private bridge `ffi-net`, no public bootstrap, no discovery). I did not capture packets, so "no public fallback" is **UNTESTED** at packet level (config-level only).

### 7.1 Start/stop 20x in one process (`ffi-spike lifecycle --iters 20`; `results/a1-ffi/run-final-lifecycle/`)

- 20/20 cycles completed, rc=0, no crash, no hang, stdout empty (quiet build), no errors.
- Per-cycle (start -> subscribe -> `listen_addresses` -> `shutdown().await` -> drop -> 1.5 s settle): start 0.33-8.8 s (median about 1.9 s, first cycle 8.8 s includes page-in of the 295 MB library; large variance not explained, VM was shared), shutdown 0.33-2.1 s (median about 0.38 s).
- Resource trend: **RSS 77.6 MB after cycle 0 -> 544.0 MB after cycle 19 (about +24.5 MB per cycle, perfectly linear), fds 21 -> 97 (+4 per cycle), threads constant at 7.** Process baseline before the first start: 5.7 MB RSS, 10 fds.
- Variants (4 cycles each, dev build): dropping without `shutdown()` and a longer settle (8 s) give the identical per-cycle growth (`run-dev-lifecycle/variant-*.txt`). So repeated in-process start/stop is functionally fine but **not leak-free**; a long-lived daemon that restarts its node in place will grow without bound (about 25 MB per restart). Root cause not found (Nim-side; `logosdelivery_shutdown()` could not be tried because it is not reachable from the crate).

### 7.2 Two nodes, 100 numbered messages each way (`results/a1-ffi/run-final-2node-100/`)

Topology: containers `ffi-a` (listen 20001) and `ffi-b` (dials A's tcp multiaddr incl. peer id), one docker bridge, one host (**localhost-class, not cross-machine**). Each sends a "hello" barrier then 100 messages at 50 ms intervals with 64-byte padding; each receives via the crate's broadcast channel -> my bounded `mpsc(256)` with `try_send` (drops counted).

| | A | B |
|---|---|---|
| sent ok / publish errors | 100 / 0 | 100 / 0 |
| received unique from peer / duplicates / missing | 100 / 0 / 0 | 100 / 0 / 0 |
| end-to-end latency ms (payload build -> consumer sees event) min / p50 / p95 / p99 / max | 1.3 / 6.4 / 63.0 / 132.2 / 164.9 | 1.6 / 6.4 / 51.9 / 110.8 / 177.5 |
| publish call ms p50 / p95 / max | 1.9 / 25.7 / 56.9 | 1.5 / 15.9 / 51.6 |
| my mpsc drops / broadcast `Lagged` | 0 / 0 | 0 / 0 |
| startup ms (create+start) / shutdown ms | 2863 / 1384 | 1251 / 1337 |
| connect (dial) ms | n/a | 573 |
| RSS (process, steady state) | 81.9 MB | 81.9 MB |
| `MessagePropagated` events | 104 | 101 |

Notes: n=100 per direction, one run; latency uses the shared VM clock (both containers share the kernel clock, so no skew); "integrity" was checked structurally (format, sender id, sequence, timestamp parse), **not** by byte-comparing the padding - a limitation of this spike binary. Each node also receives its **own** published messages as `MessageReceived` events (`recv_selfecho` 104 and 101: 100 data + hellos), so a consumer must filter by sender.

Burst (`results/a1-ffi/run-final-2node-burst/`, 500 messages each way, no inter-send delay, `--queue-cap 256`): 500/500 both directions, 0 duplicates, p50 5.0/4.6 ms, p95 17.2/38.7 ms, p99 26.9/124.5 ms; sends finished in 2.0-2.3 s (about 215-250 msg/s per node, payload 64 B + header); 0 bridge drops.

Backpressure (`results/a1-ffi/run-final-2node-backpressure/`, 300 messages each way burst, **queue-cap 4, consumer sleeping 30 ms per event**): the node and the FFI callbacks kept running (sends completed in 1.7-2.4 s, 0 errors, no hang, clean exit); my bounded queue dropped 838 and 848 *events* (counted, includes non-message events) and the application saw only 29 and 16 of 300 messages. This shows the intended property (the callback side never blocks or panics; drops are counted at the bridge) and also that with a slow consumer almost everything is lost: **the library has no application-visible backpressure** - the consumer must keep up or the data is gone (there is no pull API; Store would be the recovery path, **UNTESTED**).

### 7.3 Not run (UNTESTED)

Offline recipient / Store recovery; publisher or relay restart and reconnect; duplicates after reconnect; ordering under loss; reliable channels across two processes; store query; filter/lightpush; payload size limits and oversize rejection; Tailscale; real cross-host/NAT; idle bandwidth and CPU; packet-level proof of "no public fallback"; sustained message rate beyond 500-message bursts; amd64; bit-for-bit rebuild.

## 8. Bugs, edge cases and limitations found

1. **nimble 0.26.0 on aarch64 Linux installs an x86-64 Nim** (F3). Build is unusable without a workaround on arm64; not documented upstream, and not covered by upstream CI (which uses nix). Likely also hits arm64 Linux users without qemu as an exec-format error.
2. **Default build logs to stdout at TRACE** and `logLevel` config does not filter (F6): breaks any stdout-framed protocol (MCP stdio) unless built with `LOG_LEVEL=ERROR`.
3. **`DeliveryNode::connect()` returned `Ok` while the dial had failed** (`/dns4/<docker-name>` did not resolve inside the node: `Address resolution completed ... resolvedAddresses=[]`, then `Connecting peer failed`, `Finished dialing multiple peers ... successfulConns=0`; `results/a1-ffi/run-dev1/B.stdout.log.gz` lines 161-172, and B's `connect_ms 27` with later `peersOnTopic=0`). The first two-node attempt therefore sat in my hello barrier for 90 s and every send ended with `Unable to send within retry time window`, with only that string as diagnostic (`run-dev1/*.result.jsonl`). The spike now verifies success with `connected_peers_info()`. Use IP multiaddrs or verify peers; DNS multiaddrs under docker's embedded resolver were not reliable here.
4. **A default-configured node probes the local gateway via UPnP/NAT-PMP** (`NAT port mapping failed ... plum: mapping 0 failed`, 2 s per protocol, which also made `start` take about 8 s; `smoke-lifecycle2.log` lines 91-92) and its ENR/discovery defaults assume a public network (`DeliveryConfig::default()` uses `preset "logos.dev"`, `config.rs:42`). Private mode needs `no_preset()` plus `nat none`, `discv5Discovery false`, `dnsDiscovery false`, `peerExchange false`, and these keys are not typed in the crate (free-form `option()`).
5. **Start/stop leak**: about 24.5 MB RSS and 4 fds per cycle (section 7.1).
6. **Own messages are delivered back to the publisher** (section 7.2).
7. **No release/versioning**: bindings pinned by git rev only; the version guard only checks the coarse nimble version (`version.rs:1-12`, README "The nimble version is coarse"); open PR #137 moves the pin to a `v0.41.0-rc.0` pre-release. The 188-commit gap to master is unverified for API compatibility (UNTESTED with a newer lib).
8. **Unstable API surface**: peer connect/info, store query, listen addresses are kernel-tier ("may change at any time"). Filter and lightpush are not exposed by the crate at all; reliable channels have no encryption hook exposed (`channel.rs:49-58`).
9. **One node per process in practice** (shared persistence/ports; README `Limits`), and in-process restart leaks.
10. **Size**: the library is 295 MB unstripped / 57 MB stripped, plus libstdc++/libgomp.
11. **Supply chain**: build downloads nimble binary, an RLN static archive, and about 60 git repositories at build time; no vendoring.
12. Legacy `waku-bindings` crate cannot currently be resolved from crates.io (yanked `core2`), pins an nwaku from 2025-02, and has panic-in-callback and dangling-closure issues (section 5).

## 9. Recommendation: native embedding vs local-daemon adapter

**Viability today: partial.** The native path works end to end on linux/arm64 for the basic private two-node case, performance and footprint are fine for the MVP (about 82 MB RSS per node, sub-10 ms median local latency, 500-message bursts delivered without loss), and the maintainers are active (commits in the last week, CI green on master, a new async crate with reliable channels). But:

- The build is a heavyweight, network-dependent, multi-toolchain process whose arm64 variant is broken out of the box (F3), takes tens of minutes of CPU, and yields a 295 MB library. That is a poor fit for "install a local service" on user machines unless AgentNet ships prebuilt per-platform artifacts (issues #128/#130 ask upstream for exactly this; not available).
- The embedding contract is weak: unpublished crate, git-rev pinning, a library that logs to stdout by default, success-reported-on-failure in `connect`, an in-process restart leak, one-node-per-process semantics, and the useful peer/store functions in an explicitly unstable tier.
- Everything AgentNet needs above transport (identity, authenticated encryption, addressing, ack/retry semantics for tasks) is absent at this layer in any case.

**Recommended decision for the ADR:** keep the **local-daemon adapter (path 3) as the MVP transport**, behind a narrow transport trait (`subscribe(topic)`, `publish(topic, bytes)`, event stream, `peers()`, `store_query`, health). Keep this FFI path as a **documented, optional second implementation** that is only worth enabling if all of the following hold: a pinned, prebuilt, stripped `liblogosdelivery` per target is available (or AgentNet builds and caches it in CI with the native-Nim workaround), the node runs as a **supervised child process** (restart = new process, which sidesteps the leak and the one-node-per-process constraint and keeps library stdout off the MCP stdio), and the unstable kernel calls used are covered by a version gate in CI. Re-evaluate when upstream publishes the crate, ships library artifacts, and fixes arm64 nimble.

If the team insists on in-process embedding for the MVP, the minimum bar is: build with `LOG_LEVEL=ERROR`; never restart a node in-process; one node per process; verify every `connect` against `connected_peers_info`; use IP multiaddrs; filter own-message echo; wrap the crate behind a bounded queue with drop counters exactly as in `src/main.rs`; treat `Lagged` as data loss; and plan for crashes of the whole host process (no `catch_unwind`, library aborts take the process down).

## 10. Files

- Source/scripts: `spike/transport-ffi/{Dockerfile,Cargo.toml,Cargo.lock,.cargo/config.toml,src/main.rs,run-two-nodes.sh}`.
- Raw results and logs: `results/a1-ffi/` (failed and successful build logs, `run-*` directories with `*.result.jsonl` one-JSON-object-per-line outputs, `containers.txt` with container start/finish times), `results/a1-ffi-clone.log`, `results/a1-ffi-gh-meta.log`.
- Reproduce the two-node test: `spike/transport-ffi/run-two-nodes.sh ffi-spike:pinned - $PWD/results/a1-ffi/run-x --count 100 --interval-ms 50 --linger-ms 5000 --drain-ms 10000`.
- Reproduce lifecycle: `docker run --rm ffi-spike:pinned lifecycle --iters 20 > stdout.log 2> result.jsonl`.
- Container/network cleanup: all `ffi-*` containers and the `ffi-net` network were removed; images `ffi-lib:pinned`, `ffi-lib:pre-make`, `ffi-spike:pinned` kept as build cache.
