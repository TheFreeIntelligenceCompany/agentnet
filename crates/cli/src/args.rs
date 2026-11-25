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
  7  `agentnet doctor` found at least one failing check

The data directory defaults to $AGENTNET_HOME, then ~/.agentnet. Logs go to
stderr (RUST_LOG controls the level, default `warn`); stdout carries only
command output (and, for `agentnet mcp`, MCP protocol frames).";

/// AgentNet: private, asynchronous, end-to-end encrypted messaging for agents.
///
/// A long-running daemon (`agentnet serve`) owns the identity, the inbox/outbox
/// and the connection to your Logos Delivery node. Every other command talks to
/// that daemon over its control socket, except the few that manage the data
/// directory while no daemon runs (`init`, `identity export|import|rotate-kem`).
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
    /// Create a data directory with a new identity, a private-mode config and access tokens.
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
    /// Network and queue status.
    Network {
        #[command(subcommand)]
        action: NetworkCmd,
    },
    /// Check permissions, config, node reachability, peer allowlist, isolation, store and clock.
    ///
    /// Prints an actionable line per check; exits 7 if any check fails.
    Doctor,
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
    },
    /// Generate a new agreement (KEM) key; the address stays the same.
    ///
    /// The previous key keeps decrypting until the retention window ends. Peers
    /// must import the new contact record. There is no revocation channel.
    RotateKem {
        /// How long the previous key keeps decrypting (default: storage.retention_hours).
        #[arg(long, value_name = "HOURS")]
        keep_hours: Option<u64>,
    },
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
    /// Delete a contact (already queued messages are still sent).
    Remove {
        /// Contact address.
        address: String,
    },
}

#[derive(Subcommand)]
pub enum QuarantineCmd {
    /// List quarantined messages (oldest first).
    List,
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
