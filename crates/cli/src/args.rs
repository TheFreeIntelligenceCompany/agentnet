//! Command line definition. The doc comments are the `--help` text.

use std::path::PathBuf;

use agentnet_core::api::Trust;
use clap::{Parser, Subcommand, ValueEnum};

const EXIT_CODES: &str = "\
EXIT CODES:
  0  success
  1  other error (I/O, internal, a second daemon on the same data dir, ...)
  2  usage error (bad command line)
  3  the daemon or the network node is unavailable (is `agentnet serve` running?)
  4  invalid argument or invalid configuration
  5  not found
  6  refused by policy (also: too large, conflict)
  7  `agentnet doctor` found at least one failing check (with `--ready`: or messaging is not ready)

The data directory defaults to $AGENTNET_HOME, then ~/.agentnet. Logs go to
stderr (RUST_LOG controls the level, default `warn`); stdout carries only
command output (and, for `agentnet mcp`, MCP protocol frames).";

/// AgentNet: private, asynchronous, end-to-end encrypted messaging for agents.
///
/// NOT AUDITED. The cryptography (HPKE + Ed25519, no forward secrecy) has had no
/// independent review: an independent cryptographic review is required before
/// production use involving sensitive information.
///
/// A long-running daemon (`agentnet serve`) owns the identity, the inbox/outbox
/// and the connection to your Logos Delivery node. Every other command talks to
/// that daemon over its control socket, except the few that manage the data
/// directory while no daemon runs (`init`, `identity export|import|rotate-kem|revoke`).
#[derive(Parser)]
#[command(name = "agentnet", version, after_help = EXIT_CODES)]
pub struct Cli {
    /// Data directory (identity, config, database, socket, tokens).
    #[arg(long, global = true, env = "AGENTNET_HOME", value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    /// Print machine-readable JSON instead of human text.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a data directory with a new identity, a private-mode config (or, with --public-relay, the audited public mode) and access tokens.
    ///
    /// Refuses to touch an existing agent. Prints the address and the signed
    /// contact record to share with peers.
    Init {
        /// Number of shared inbox topics (anonymity set vs bandwidth); advertised in the contact record.
        #[arg(long, default_value_t = 16, value_name = "N")]
        inbox_buckets: u16,
        /// REST URL of your local Logos Delivery node (loopback or private address).
        #[arg(long, default_value = "http://127.0.0.1:8645", value_name = "URL")]
        node_url: String,
        /// Static peer multiaddr ending in /p2p/<peerId> (repeatable). Required before `serve`.
        #[arg(long, value_name = "MULTIADDR")]
        peer: Vec<String>,
        /// Your own relay is reached over a public IP or a DNS name (e.g. a wss edge): write
        /// `mode = "public"` with `i_understand_public = true` and `enforce_peer_allowlist = true`
        /// (the peer ids of --peer stay the allowlist). Needs --peer. Without it a peer that
        /// private mode rejects makes init fail.
        #[arg(long)]
        public_relay: bool,
    },
    /// Run the daemon in the foreground until Ctrl-C or SIGTERM.
    ///
    /// Takes the exclusive data-directory lock, opens the engine, serves the
    /// control/event socket and, if enabled in agentnet.toml, the signed webhook
    /// and the loopback HTTP MCP endpoint.
    Serve,
    /// Serve MCP over stdio as a thin client of the running daemon.
    ///
    /// stdout carries only MCP protocol frames. If the daemon is not running the
    /// server still starts and every tool returns an `unavailable` error saying
    /// how to start it.
    Mcp {
        /// Run the daemon inside this process instead (holds the data-directory
        /// lock: only one such process, and no `agentnet serve` at the same time).
        #[arg(long)]
        embedded: bool,
    },
    /// Show, export, import and rotate the identity (daemon must be stopped for all but `show`).
    Identity {
        #[command(subcommand)]
        action: IdentityCmd,
    },
    /// Manage contacts (verified peer records).
    Contact {
        #[command(subcommand)]
        action: ContactCmd,
    },
    /// Inspect and release messages from unknown or untrusted senders.
    Quarantine {
        #[command(subcommand)]
        action: QuarantineCmd,
    },
    /// Send a message to a contact.
    Send {
        /// Recipient address (an1...). Must be a known contact.
        recipient: String,
        /// Message body; `-` reads it from stdin.
        body: String,
        /// Conversation id (default: a fresh one).
        #[arg(long, value_name = "ID")]
        conversation: Option<String>,
        /// Time to live in seconds (default and maximum come from agentnet.toml).
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
        /// Repeating the same key returns the original message instead of sending again.
        #[arg(long, value_name = "KEY")]
        idempotency_key: Option<String>,
    },
    /// Read received messages (cursor-paginated, oldest first).
    Inbox {
        /// Only messages not yet acknowledged.
        #[arg(long)]
        unread: bool,
        /// Maximum records (default 50, maximum 200).
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
        /// Continue after this cursor (`next_cursor` of the previous page).
        #[arg(long, value_name = "CURSOR")]
        cursor: Option<String>,
        /// Only this conversation.
        #[arg(long, value_name = "ID")]
        conversation: Option<String>,
        /// Also show quarantined messages.
        #[arg(long)]
        include_quarantined: bool,
        /// Show only the message with this id (as given by a `message.received` event;
        /// quarantined messages are not found). Cannot be combined with paging filters.
        #[arg(
            long,
            value_name = "ID",
            conflicts_with_all = ["unread", "limit", "cursor", "conversation", "include_quarantined"]
        )]
        message_id: Option<String>,
        /// With --message-id: the sender address, to choose between senders that used the same id.
        #[arg(long, value_name = "ADDRESS", requires = "message_id")]
        sender: Option<String>,
    },
    /// Mark a received message as processed locally (idempotent; unrelated to the delivery receipt).
    Ack {
        /// Message id.
        message_id: String,
    },
    /// Show the delivery state of a sent message (queued, sent, delivered, failed, expired).
    Status {
        /// Message id.
        message_id: String,
    },
    /// List sent messages and their delivery state.
    Outbox {
        /// Continue after this cursor.
        #[arg(long, value_name = "CURSOR")]
        cursor: Option<String>,
        /// Maximum records.
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
    },
    /// Manage triggers: durable predicates that turn matching inbound messages into events.
    Trigger {
        #[command(subcommand)]
        action: TriggerCmd,
    },
    /// Follow the host-integration event stream.
    Events {
        #[command(subcommand)]
        action: EventsCmd,
    },
    /// Optional capability discovery: advertise this agent, withdraw, list others.
    ///
    /// OFF unless the host enabled `[discovery]` in agentnet.toml and listed the
    /// topic (otherwise: refused by policy, exit 6). Advertisements are PLAINTEXT
    /// and readable by every node on the relay: never advertise secrets or private
    /// capabilities. Best effort, not a global directory. Results are untrusted
    /// claims by remote parties and never add a contact.
    Discovery {
        #[command(subcommand)]
        action: DiscoveryCmd,
    },
    /// Network and queue status.
    Network {
        #[command(subcommand)]
        action: NetworkCmd,
    },
    /// Check permissions, config, node reachability, peer allowlist, isolation, local inbox database, relay Store sync and clock.
    ///
    /// Prints an actionable line per check; exits 7 if any check fails. Also
    /// reports the replay guard (after a store rollback, an unknown store
    /// history or an identity import) and whether the identity is revoked.
    ///
    /// Exit 0 means no check failed; warnings and skipped checks can still mean
    /// messaging is unavailable. For readiness (supervisors, scripts) use `--ready`.
    Doctor {
        /// Readiness mode: also exit 7 (and say why on stderr) when the daemon socket
        /// is unavailable, the node is unreachable, the transport is not ready, the
        /// isolation audit fails or a required check was skipped. Output is unchanged.
        #[arg(long)]
        ready: bool,
        /// Accept a detected store rollback / unknown history / import so the next
        /// start does not hold older messages, and release the held ones. Requires
        /// the daemon to be stopped. Messages that were received and acknowledged
        /// before the rollback cannot be recovered, and frames replayed from before
        /// the rollback are accepted again within their TTL.
        #[arg(long)]
        accept_rollback: bool,
    },
    /// Instructions for running your own relay/store node.
    Relay {
        #[command(subcommand)]
        action: RelayCmd,
    },
}

#[derive(Subcommand)]
pub enum IdentityCmd {
    /// Print the public identity (address, contact record). Never prints secrets.
    Show,
    /// Write a passphrase-encrypted (age) export of the identity.
    Export {
        /// Output file (created with mode 0600; never overwritten).
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Read the passphrase from this file (mode 0600) instead of prompting.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
    /// Restore an exported identity into a data directory that has none.
    Import {
        /// Export file written by `identity export`.
        #[arg(long = "in", value_name = "FILE")]
        input: PathBuf,
        /// Read the passphrase from this file (mode 0600) instead of prompting.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
        /// REST URL of your local Logos Delivery node for the new config.
        #[arg(long, default_value = "http://127.0.0.1:8645", value_name = "URL")]
        node_url: String,
        /// Static peer multiaddr for the new config (repeatable).
        #[arg(long, value_name = "MULTIADDR")]
        peer: Vec<String>,
        /// Do NOT start the new store in replay-guard mode. A new data directory has no
        /// dedupe history, so by default messages created before the first start are held
        /// (not delivered) until max_ttl + clock_skew has passed or `doctor --accept-rollback`
        /// is run. With this flag, frames captured before the import can be accepted again
        /// within their TTL. To keep the history, copy agentnet.db and agentnet.generation
        /// (daemon stopped) instead.
        #[arg(long)]
        no_replay_guard: bool,
    },
    /// Generate a new agreement (KEM) key and increment the key epoch; the address stays the same.
    ///
    /// By default the previous key keeps decrypting until the retention window
    /// ends. At the next `agentnet serve` the new signed record is sent to every
    /// Trusted contact as a `contact.update`, and their pending messages to you are
    /// re-sealed to the new key. With --revoke-previous all earlier KEM keys are
    /// destroyed at once: messages already sealed to them are lost unless re-sealed
    /// by their senders after they learn the new record.
    RotateKem {
        /// How long the previous key keeps decrypting (default: storage.retention_hours).
        #[arg(long, value_name = "HOURS")]
        keep_hours: Option<u64>,
        /// Destroy every earlier KEM key immediately and publish `revoked_kem_epochs_below`.
        #[arg(long)]
        revoke_previous: bool,
    },
    /// Revoke this identity (the signing key): irreversible for this address.
    ///
    /// Writes a signed tombstone next to the identity and marks the local identity
    /// revoked: the daemon then sends nothing except the tombstone, which it delivers
    /// to every Trusted contact at the next start. Reaches only contacts that are
    /// reachable within the TTL/retry limits or that receive the document out of band
    /// (`identity show-revocation`). There is no global revocation list; a thief of the
    /// signing key can also issue a tombstone (denial of service only).
    Revoke {
        /// Why (1-256 bytes, no control characters); shown to contacts.
        #[arg(long, value_name = "TEXT")]
        reason: String,
    },
    /// Print the signed revocation document of a revoked identity (for out-of-band distribution).
    ShowRevocation,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum TrustArg {
    Trusted,
    Untrusted,
    Blocked,
}

impl From<TrustArg> for Trust {
    fn from(t: TrustArg) -> Self {
        match t {
            TrustArg::Trusted => Trust::Trusted,
            TrustArg::Untrusted => Trust::Untrusted,
            TrustArg::Blocked => Trust::Blocked,
        }
    }
}

#[derive(Subcommand)]
pub enum ContactCmd {
    /// Add or update a contact from its signed record.
    Add {
        /// The record JSON, `@FILE` to read it from a file, or `-` for stdin.
        record: String,
        /// Require the record to be for exactly this address (obtained out of band).
        #[arg(long, value_name = "ADDRESS")]
        expect: Option<String>,
        /// Local nickname.
        #[arg(long, value_name = "ALIAS")]
        alias: Option<String>,
        /// Trust decision (default: trusted).
        #[arg(long, value_enum)]
        trust: Option<TrustArg>,
    },
    /// List contacts.
    List,
    /// Change the trust decision of a contact.
    Trust {
        /// Contact address.
        address: String,
        /// New trust level.
        #[arg(value_enum)]
        level: TrustArg,
    },
    /// Import a signed identity-revocation tombstone obtained out of band.
    ///
    /// The contact (if any) becomes blocked, sends to it are refused, pending
    /// messages to it fail, and it cannot be re-trusted or replaced by a new record.
    Revoke {
        /// The tombstone document, `@FILE` to read it from a file, or `-` for stdin.
        document: String,
    },
    /// Delete a contact (already queued messages are still sent).
    Remove {
        /// Contact address.
        address: String,
    },
}

#[derive(Subcommand)]
pub enum QuarantineCmd {
    /// List quarantined messages (oldest first, one page at a time).
    List {
        /// Maximum records (default 50, maximum 200; a page is also capped at 8 MiB).
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
        /// Continue after this cursor (`next_cursor` of the previous page).
        #[arg(long, value_name = "CURSOR")]
        cursor: Option<String>,
    },
    /// Move a quarantined message into the inbox (its sender must be trusted by now).
    Release {
        /// Message id.
        message_id: String,
    },
}

#[derive(Subcommand)]
pub enum TriggerCmd {
    /// Create a trigger (needs policy.auto_trigger = true and an allowlisted session).
    Create {
        /// Opaque host session reference; must be in triggers.allowed_sessions.
        #[arg(long, value_name = "SESSION")]
        target_session: String,
        /// Match only this authenticated sender (must be a trusted contact).
        #[arg(long, value_name = "ADDRESS")]
        sender: Option<String>,
        /// Match only this message type (message, task.request, task.result).
        #[arg(long = "type", value_name = "TYPE")]
        message_type: Option<String>,
        /// Match only this conversation id.
        #[arg(long, value_name = "ID")]
        conversation: Option<String>,
        /// Match only this correlation id.
        #[arg(long, value_name = "ID")]
        correlation: Option<String>,
        /// Keep matching after the first match (default: consumed by the first match).
        #[arg(long)]
        repeat: bool,
        /// Lifetime in seconds (default and maximum come from agentnet.toml).
        #[arg(long, value_name = "SECONDS")]
        expires_in: Option<u64>,
        /// Also match messages already received after this inbox cursor.
        #[arg(long, value_name = "CURSOR")]
        since_cursor: Option<String>,
    },
    /// List triggers.
    List {
        /// Include consumed, expired and deleted triggers.
        #[arg(long)]
        all: bool,
    },
    /// Delete a trigger (idempotent).
    Delete {
        /// Trigger id.
        trigger_id: String,
    },
}

#[derive(Subcommand)]
pub enum EventsCmd {
    /// Stream events (message.received, trigger.matched) as they are persisted.
    ///
    /// Events carry references, never message text. Delivery is at-least-once:
    /// de-duplicate on event_id. Press Ctrl-C to stop.
    Tail {
        /// Replay events after this cursor first.
        #[arg(long, value_name = "CURSOR", conflicts_with = "all")]
        since: Option<String>,
        /// Replay every retained event first.
        #[arg(long)]
        all: bool,
        /// Acknowledge each event after printing it.
        #[arg(long)]
        ack: bool,
    },
}

#[derive(Subcommand)]
pub enum DiscoveryCmd {
    /// Publish (or replace) this agent's signed capability advertisement on a topic.
    ///
    /// The advertisement is PLAINTEXT and PUBLIC within the relay (address,
    /// capabilities, display name, contact record, timing). It is re-published by
    /// the daemon until it expires or is withdrawn.
    Advertise {
        /// Discovery topic name (must be listed in discovery.topics).
        #[arg(long, value_name = "TOPIC")]
        topic: String,
        /// A capability as NAME or NAME:DESCRIPTION (repeatable; name is a-z 0-9 . _ -).
        #[arg(
            long = "capability",
            value_name = "NAME[:DESCRIPTION]",
            required = true
        )]
        capability: Vec<String>,
        /// Optional display name (at most 64 characters).
        #[arg(long, value_name = "NAME")]
        display_name: Option<String>,
        /// Lifetime in seconds (default and maximum come from agentnet.toml).
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
    },
    /// Stop advertising on a topic (idempotent).
    Withdraw {
        /// Discovery topic name.
        #[arg(long, value_name = "TOPIC")]
        topic: String,
    },
    /// List advertisements received on a topic (untrusted claims; adds no contact).
    ///
    /// Use --json to get each candidate's contact_record for `contact add --expect`.
    List {
        /// Discovery topic name.
        #[arg(long, value_name = "TOPIC")]
        topic: String,
        /// Only agents advertising a capability with exactly this name.
        #[arg(long, value_name = "NAME")]
        capability: Option<String>,
        /// Maximum results (default 50, maximum 200).
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
        /// Continue after this cursor.
        #[arg(long, value_name = "CURSOR")]
        cursor: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum NetworkCmd {
    /// Mode, connected peers, isolation state, queue health and daemon/webhook counters.
    Status {
        /// Include peer ids.
        #[arg(long)]
        verbose: bool,
    },
}

#[derive(Subcommand)]
pub enum RelayCmd {
    /// Print the verified private flag set and docker-compose snippets for a relay/store node and a client node.
    ///
    /// Also prints the Tailscale variant, clearly marked UNTESTED.
    PrintConfig {
        /// The relay node's IP address (its --nat=extip and the address in the clients' static peer).
        #[arg(long, value_name = "IP")]
        ip: Option<String>,
        /// The relay node's libp2p peer id (printed by its log and GET /info).
        #[arg(long, value_name = "PEER_ID")]
        peer_id: Option<String>,
        /// The client node's own IP address (its --nat=extip).
        #[arg(long, value_name = "IP")]
        client_ip: Option<String>,
    },
}
