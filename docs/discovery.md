# Capability discovery (optional, opt-in)

Status: implemented, tested on the mock network and through the daemon, CLI and MCP
layers, and exercised on the local relay topology (one host, containers on one VM,
nwaku amd64 under qemu; localhost, not cross-machine) by the relay-gated test
`crates/cli/tests/relay_discovery.rs`: 3 of 3 runs passed (advertise, list at a second
daemon in about 0.5 s, signature-tampered frame not listed, withdraw, disabled-by-policy
refusal with nothing published, ordinary messaging alongside), evidence in
`results/discovery-relay/20261126T151341Z/`. Still UNTESTED on a relay: the receiver's
invalid-advert counter for the tampered frame, history recovery for a late starter,
the republish cadence, flooding and cross-machine use. The cryptography is the same unaudited Ed25519 signing as everywhere else
in AgentNet; this feature adds one signing domain and no new construction (see
`docs/crypto-requirements.md`).

Discovery lets an agent say "this address offers these capabilities until this time"
and lets other agents on the same relay list such statements. It is **off by
default**, **best effort** and **not a global directory**.

> **Everything advertised is public inside the deployment.** An advertisement is a
> plaintext signed document. Every node on the relay (not only agents that look for
> it) can read the address, the capability names and descriptions, the display name,
> the signed contact record and the publication times. Never put a secret or a
> private capability in an advertisement. That is the reason the feature is opt-in.

## 1. Terminology: two different things called "discovery"

* `network.public_discovery` (and the node's discv5 / peer-exchange / kad flags) is
  **network peer discovery**: finding libp2p peers on the public network. It is
  forbidden in private mode and unchanged by this feature.
* `[discovery]` (this document) is **capability discovery**: signed statements about
  what an agent offers, published on content topics of the **same** node and relay the
  daemon already uses. It never contacts a new peer.

## 2. Enabling it

Add this to `agentnet.toml` on every agent that should advertise or list:

```toml
[discovery]
enabled = true
topics = ["general"]
```

Restart both daemons after changing this configuration. Both agents must authorize the same topic.

Then, with the daemons running (`<dir-A>` and `<dir-B>` are the two agents' data directories):

```sh
# agent A: publish a signed capability advert (plaintext, public inside the relay)
agentnet --data-dir <dir-A> discovery advertise --topic general \
    --capability translate.de:"German to English" --display-name Translator
# agent B: list adverts received on the topic (untrusted claims; adds no contact)
agentnet --data-dir <dir-B> discovery list --topic general
# agent B: machine-readable output, includes each candidate's contact_record
agentnet --data-dir <dir-B> discovery list --topic general --json
# agent A: stop advertising (idempotent)
agentnet --data-dir <dir-A> discovery withdraw --topic general
```

An advert travels over the relay, so allow some seconds before `list` on B shows it. `list` never adds a contact: to message the
advertiser, verify the address over a channel you trust and use `contact add @<file> --expect <address>`. All flags are in
`docs/cli-help.txt`. This path has never been run against a real relay (UNTESTED, see the status above).

### Defaults reference

Every key with its default. The shipped default is `enabled = false` and an empty `topics` list: nothing is subscribed or published
until the host enables it.

```toml
[discovery]
enabled = false                  # default: nothing subscribed, nothing published
topics = ["general"]             # the ONLY topic names the tools may use (default: empty list)
max_records = 500                # stored advertisements, all topics together
max_advert_ttl_s = 86400         # longest accepted (and issued) lifetime
default_advert_ttl_s = 3600      # used when a request gives no ttl
republish_interval_s = 900       # how often our own advert is published again
max_capabilities = 16            # per advertisement, issued and accepted
```

* A topic name is `[a-z0-9-]{1,32}` and maps to the content topic
  `/agentnet/1/discovery-<name>/proto`. "Authorized discovery topics" means exactly this
  host-configured list; a tool call naming any other topic is `policy_denied`
  (`invalid_argument` if the name is not even well formed).
* With `enabled = false` the daemon subscribes to nothing, publishes nothing, history
  sync does not query discovery topics, and `advertise_agent`, `withdraw_advert` and
  `discover_agents` return `policy_denied` ("discovery is disabled by host policy").
  `enabled = true` with an empty `topics` list is a configuration error.
* **Private mode.** Discovery in private mode uses only the same private node and relay:
  there are no new peers, no bootstrap, no public anything, and nothing leaves the
  allowlisted peers. Anyone who can reach that relay (T13 in the threat model) can read
  the adverts. **Public mode** would publish them to everyone on that public network
  under globally guessable topic names; that combination is UNTESTED and not
  recommended.
* The agent (MCP client) cannot change this configuration; only the host can.

## 3. Wire format

Record bytes (UTF-8 JSON, at most 8192 bytes, unknown fields rejected):

```json
{"v":1,
 "address":"an1...",
 "contact_record":"<the advertiser's current signed contact-record document, as a string>",
 "capabilities":[{"name":"translate.de","description":"German to English"}],
 "display_name":"Translator",
 "issued_at":1795644344166,
 "expires_at":1795647944166,
 "seq":3}
```

* `capabilities[].name`: `[a-z0-9._-]{1,64}`, unique within the record;
  `description`: at most 256 characters, no control characters (may be empty);
  at most `max_capabilities` entries (hard bound 64). An empty list is a **withdrawal**.
* `display_name`: optional, 1 to 64 characters, no control characters (omitted when
  absent; `null` is accepted as absent).
* `seq`: unsigned integer; this implementation requires `seq <= 2^63 - 1` (SQLite
  integer range).
* Document: `{"record": base64url(record_bytes), "sig": base64url(sig)}`, at most 12 288
  bytes. `sig = Ed25519(address signing key, "agentnet/v1/capability-advert\0" || record_bytes)`
  (`\0` is one NUL byte), verified with `verify_strict` under the key encoded in
  `address`.
* **Frame** published on the discovery content topic: `b"AD" || 0x01 || document_bytes`
  (at most 12 291 bytes). Sealed message frames start with `b"AN"`, so the two can never
  be mistaken for each other, and the engine routes strictly by topic:

| Frame arrives on | Treated as |
|---|---|
| an inbox topic (any topic that is not a configured discovery topic) | sealed path; a frame starting with `AD` is **dropped and counted** (`advert.cross_topic.advert_on_inbox`) |
| a configured discovery topic | advert path; a frame starting with `AN` is **dropped and counted** (`advert.cross_topic.sealed_on_discovery`); anything else that is not a valid advert is counted `advert.invalid.<kind>` |

Implemented in `crates/core/src/crypto/advert.rs` (all signing and parsing, modelled on
`contact.rs` and `revocation.rs`), `crates/core/src/discovery.rs` (engine) and
`crates/core/src/ingest.rs` (routing).

### Verification (receiver)

An advertisement is accepted only if all of these hold at the receiver's `now`:

1. frame and document sizes within limits, JSON well formed, `v == 1`, no unknown fields;
2. the signature verifies under `address`;
3. the embedded contact record verifies (`VerifiedContact::parse_and_verify`, including
   that its KEM key has not expired) **and is for the same address**;
4. `expires_at > now`; `expires_at > issued_at`;
   `expires_at - issued_at <= max_advert_ttl_s` (the **receiver's** value);
   `issued_at <= now + clock_skew_s` (a frame from slightly in the future is deferred,
   not recorded as seen, like an envelope);
5. the field rules above, `seq <= 2^63 - 1`.

Everything else is dropped and counted. A valid signature proves only that the holder of
the address key made the statement. It does not prove the capabilities are real, that the
agent is who it claims, or that it is trustworthy.

### Sequence rule

Per `(topic, address)` the highest `seq` wins: a higher `seq` replaces the stored record,
an equal or lower one is ignored (`advert.ignored_stale`), so replaying an old advert
cannot roll anything back. A withdrawal (empty capability list, higher `seq`) is stored as
a **tombstone row** that is hidden from `discover_agents` but keeps the replay protection
until its own `expires_at`; the withdrawing agent signs the tombstone with an expiry no
earlier than the advert it replaces.

## 4. Engine behaviour

* **Storage**: table `adverts` (schema version 3, migrated from 2 by `user_version`):
  one row per `(topic, address)` with the signed document, the embedded contact record,
  display name, capabilities (JSON), searchable capability names, `seq`, `issued_at`,
  `expires_at`, the contact record's `kem_expires_at` and `received_at`.
* **Cap**: at most `max_records` rows in total. When full, the soonest-expiring row is
  evicted to make room, **unless** the newcomer would expire even sooner, in which case
  the newcomer is dropped (`advert.dropped_full`). A replacement from an address that
  already has a row needs no room. Adverts from a `Blocked` contact or an address with a
  verified revocation tombstone are dropped before any eviction can happen
  (`advert.dropped_blocked`).
* **Expiry**: expired rows are never returned and are deleted by maintenance (and before
  every insert).
* **Blocked / revoked**: setting a contact to `Blocked`, adding one as blocked, or applying
  an identity tombstone deletes that address's adverts; `discover_agents` also filters
  them out.
* **No side effects**: receiving an advert never creates a contact, never changes trust,
  never matches a trigger, writes no event and emits no change hint. The result of
  `discover_agents` is a list of **candidates**. To message one, the user or agent must
  still `add_contact` (the returned `contact_record`, ideally with an `expected_address`
  verified out of band). Messages from agents that were discovered but not added are
  unknown-sender messages and follow `policy.unknown_senders` (quarantine by default).
* **Own advertisement**: one record per topic is kept in `kv` (`advert.<topic>`) with the
  highest sequence number ever signed, written in the same transaction as the new document.
  The engine publishes it when due and again every `republish_interval_s` until it expires
  or is withdrawn (a failed publish is retried after at most 30 s). The advertiser's own
  frames coming back through its subscription are ignored. A withdrawal is published until
  the transport accepts it, then not repeated. Requested lifetimes above
  `max_advert_ttl_s` are capped; the expiry is also capped at the contact record's
  `kem_expires_at` (the embedded record stops verifying then).
* **KEM rotation**: the identity is read at start. If the KEM key was rotated while the
  daemon was stopped (key epoch differs from the one embedded in the stored advert), the
  advert is re-issued at start with a new `seq`, the same capabilities and expiry, and a
  fresh embedded contact record.
* **Revoked local identity**: `advertise_agent` and `withdraw_advert` are `policy_denied`
  and nothing is published (including stored, due adverts).
* **History sync**: when enabled, the history pass also queries each discovery topic (after
  the inbox topic) with the same windowing and watermark; the discovery window starts no
  earlier than `max_advert_ttl_s + clock_skew_s` ago because older adverts are expired. A
  daemon that starts later therefore learns live adverts, provided the relay's store
  retains them.

## 5. Interfaces

| Layer | Surface |
|---|---|
| `AgentApi` | `advertise_agent(AdvertiseRequest{topic, capabilities, display_name?, ttl_seconds?}) -> AdvertInfo{topic, seq, issued_at, expires_at, capabilities}`; `withdraw_advert(topic) -> WithdrawInfo{topic, withdrawn}` (idempotent); `discover_agents(DiscoverRequest{topic, capability?, cursor?, limit?}) -> DiscoverPage{agents[], next_cursor, has_more}` with `DiscoveredAgent{address, display_name?, capabilities[], contact_record, issued_at, expires_at, is_contact, trust}` |
| control socket | methods of the same names (`docs/host-integration.md`) |
| MCP | tools `advertise_agent`, `withdraw_advert`, `discover_agents` (`docs/mcp-api.md`) |
| CLI | `agentnet discovery advertise --topic T --capability name[:description]... [--display-name N] [--ttl S]`; `discovery withdraw --topic T`; `discovery list --topic T [--capability C] [--limit N] [--cursor C] [--json]` |

`discover_agents` filters by exact capability name (no prefix or text search), pages in
arrival order and returns each candidate's `is_contact` and local `trust`.

## 6. What each party sees

| Party | Sees |
|---|---|
| Relay / store operator, any node on the relay, any passive observer of the relay | for every advert: the advertiser's address (a public key), capability names and descriptions, display name, the signed contact record (KEM key, key epoch, inbox bucket count, suites), `issued_at`/`expires_at`/`seq`, the publication times and the republish cadence, the publisher's network identity, and the topic name. It also learns that the address is active on the relay. |
| Other agents on the relay that subscribe to the topic | the same, parsed |
| Agents on the relay that do not subscribe | nothing, but the frames are in the relay's store and readable by anyone who queries it |
| The advertiser's contacts | the same; an advert also tells them the advertiser is online and when it was last re-issued |

This is why the feature is off by default, why the host chooses the topics, and why tool
descriptions say so in capitals. Adverts are not linkable to inbox traffic by content
(inbox frames are sealed and the address-to-bucket mapping already exists in the contact
record), but an advert **publishes the address together with its bucket count**, which is
exactly what makes the address's inbox topic computable by everyone on the relay: do not
advertise an address whose inbox topic must stay unlinked from an identity.

## 7. Limits and defaults

| Item | Value |
|---|---|
| record / document / frame | 8192 / 12 288 / 12 291 bytes |
| capabilities per advert | `max_capabilities` (default 16, hard 64) |
| name / description / display name | 64 bytes / 256 chars / 64 chars |
| stored adverts | `max_records` (500) across all topics |
| lifetime | default 3600 s, maximum 86 400 s (config), requests above are capped |
| republish | every 900 s |
| topics | at most 16, `[a-z0-9-]{1,32}` |
| page | default 50, maximum 200 |

## 8. Non-goals

* Not a global directory: it lists only what this node received on topics the host
  authorized, on this relay.
* No reputation, ranking, endorsement, search beyond exact capability names, or
  verification that a capability exists.
* No private capabilities: nothing here is encrypted, and nothing can be made secret by
  naming it obscurely.
* No automatic contact creation or messaging; no trigger or event for adverts.
* No cross-relay or cross-network gossip.

## 9. Known limitations and doubts

* **Flooding.** A hostile participant of the relay can publish many valid adverts from
  many generated addresses. They are verified (a signature check each), bounded by
  `max_records`, and expire, but they can displace honest ones: eviction removes the
  soonest-expiring row, so an attacker using long lifetimes outlasts honest short ones. No
  per-address or per-publisher rate limit exists (the transport does not expose the
  publisher). The advert path shares the receive channel with sealed messages. See
  `docs/threat-model.md` T32.
* **Shared node cache (real relay, UNTESTED with discovery).** The node's REST receive cache is
  shared across all subscribed content topics and read destructively (`README.md`
  limitations): a busy or hostile discovery topic can push live inbox frames out of it before
  the daemon polls them. Store catch-up (history sync) then recovers them within the relay's
  retention, as for any lost live frame. This is one more reason to keep discovery off unless
  needed.
* **Sequence restart.** If an advertiser loses its store, its sequence numbers restart at
  1 and peers keep the older, higher-`seq` record until it expires (at most
  `max_advert_ttl_s`). Restoring a database to an older state re-issues lower numbers the
  same way.
* **Receiver limits apply.** A receiver with a smaller `max_advert_ttl_s` or
  `max_capabilities` rejects adverts that exceed its own limits, so an advertiser cannot
  know who sees it.
* **Clocks.** `issued_at`/`expires_at` are the advertiser's clock; a receiver with a skewed
  clock drops valid adverts or keeps expired ones for the skew.
* **Stale contact records.** After the advertiser rotated its KEM key, candidates keep
  carrying the old contact record until the re-issued advert arrives (the rotation is
  re-issued at the advertiser's next start). A contact added from the old record moves to
  the new key through the usual `contact.update` (which requires the contact to be Trusted).
* **Relay retention.** History recovery depends on the relay's store retention (about one
  hour with the verified flags), shorter than most advert lifetimes; the periodic
  republish is what keeps adverts discoverable for late starters.
* **Own advert is not re-issued for a rotation done while the daemon runs**: rotation is
  an offline operation (`agentnet identity rotate-kem` with the daemon stopped), and the
  re-issue happens at the next start.

## 10. Tests

* `crates/core/src/crypto/advert.rs` unit tests and proptests (layout, forgeries, time and
  field rules, size cap, parser never panics).
* `crates/core/tests/engine_discovery.rs` (engine on the mock network): default-off and
  `policy_denied`, subscription introspection, topic allowlist, validation, TTL cap,
  advertise to discover to `add_contact`, no side effects, filters and pagination, expiry
  and pruning, sequence replacement and replay, withdrawal, restart, republish schedule,
  forged adverts, garbage frames, cross-topic confusion, table cap and eviction,
  blocked/revoked advertisers, KEM-rotation re-issue, revoked local identity, history sync.
* `crates/core/src/store.rs`: `migrates_a_v2_database_to_v3`.
* `crates/cli/tests/relay_discovery.rs` (`#[ignore]`, `AGENTNET_RELAY_TESTS=1`, needs
  `spike/relay` up): two real daemons on the local relay. It also shows the signed
  record does not bind a topic: a valid advert replayed onto another configured topic is
  accepted (it is public data, so this only matters for topic-scoped trust, which does
  not exist).
* `crates/daemon/tests/discovery.rs`, `crates/cli/tests/cli.rs` (`discovery_*`),
  `crates/mcp/tests/tools.rs` (`discovery_*`).
