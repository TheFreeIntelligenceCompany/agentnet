//! The `agentnet` command line.
//!
//! Logs go to stderr (never stdout). Human output is the default; `--json`
//! prints one machine-readable JSON document per command (`events tail` prints
//! one JSON object per line).

mod args;
mod doctor;
mod relay;
mod render;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentnet_core::api::*;
use agentnet_daemon::datadir::read_secret_file;
use agentnet_daemon::error::DaemonError;
use agentnet_daemon::{offline, Daemon, EventStream, RemoteAgent};
use args::*;
use clap::Parser;
use serde::Serialize;
use serde_json::json;

/// Exit codes (also printed in `agentnet --help`).
pub mod exit {
    pub const OK: i32 = 0;
    pub const ERROR: i32 = 1;
    pub const USAGE: i32 = 2; // returned by clap itself
    pub const UNAVAILABLE: i32 = 3;
    pub const INVALID: i32 = 4;
    pub const NOT_FOUND: i32 = 5;
    pub const DENIED: i32 = 6;
    pub const DOCTOR_FAILED: i32 = 7;
}

pub struct CliError {
    pub code: i32,
    pub kind: &'static str,
    pub message: String,
}

impl CliError {
    fn new(code: i32, kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            kind,
            message: message.into(),
        }
    }
    fn other(message: impl Into<String>) -> Self {
        Self::new(exit::ERROR, "error", message)
    }
}

impl From<ApiError> for CliError {
    fn from(e: ApiError) -> Self {
        let (code, kind) = match e.code {
            ErrorCode::Unavailable => (exit::UNAVAILABLE, "unavailable"),
            ErrorCode::InvalidArgument => (exit::INVALID, "invalid_argument"),
            ErrorCode::NotFound => (exit::NOT_FOUND, "not_found"),
            ErrorCode::PolicyDenied => (exit::DENIED, "policy_denied"),
            ErrorCode::TooLarge => (exit::DENIED, "too_large"),
            ErrorCode::Conflict => (exit::DENIED, "conflict"),
            ErrorCode::Internal => (exit::ERROR, "internal"),
        };
        Self::new(code, kind, e.message)
    }
}

impl From<DaemonError> for CliError {
    fn from(e: DaemonError) -> Self {
        match e {
            DaemonError::Config(m) => Self::new(
                exit::INVALID,
                "invalid_config",
                format!("invalid configuration: {m}"),
            ),
            other => Self::other(other.to_string()),
        }
    }
}

type CliResult<T> = Result<T, CliError>;

fn default_data_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(h) => PathBuf::from(h).join(".agentnet"),
        None => PathBuf::from(".agentnet"),
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    // Logs go to stderr only: for `agentnet mcp`, stdout carries protocol frames.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing();
    let json = cli.json;
    let code = match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            if json {
                println!(
                    "{}",
                    json!({"error": {"code": e.kind, "message": e.message}})
                );
            }
            eprintln!("error: {}", e.message);
            e.code
        }
    };
    std::process::exit(code);
}

fn print_json<T: Serialize>(v: &T) {
    match serde_json::to_string(v) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("error: cannot encode output: {e}"),
    }
}

fn emit<T: Serialize>(json: bool, v: &T, human: impl FnOnce(&T) -> String) {
    if json {
        print_json(v);
    } else {
        let s = human(v);
        println!("{}", s.trim_end());
    }
}

fn read_text_arg(arg: &str, what: &str) -> CliResult<String> {
    const MAX: u64 = 1024 * 1024;
    if arg == "-" {
        let mut s = String::new();
        std::io::stdin()
            .take(MAX)
            .read_to_string(&mut s)
            .map_err(|e| CliError::other(format!("reading {what} from stdin: {e}")))?;
        return Ok(s);
    }
    if let Some(path) = arg.strip_prefix('@') {
        let md =
            std::fs::metadata(path).map_err(|e| CliError::other(format!("reading {path}: {e}")))?;
        if md.len() > MAX {
            return Err(CliError::new(
                exit::INVALID,
                "invalid_argument",
                format!("{path} is too large"),
            ));
        }
        return std::fs::read_to_string(path)
            .map_err(|e| CliError::other(format!("reading {path}: {e}")));
    }
    Ok(arg.to_owned())
}

fn passphrase(file: Option<&Path>, confirm: bool) -> CliResult<String> {
    let raw = match file {
        Some(p) => {
            let b = read_secret_file(p)?;
            String::from_utf8(b).map_err(|_| {
                CliError::new(
                    exit::INVALID,
                    "invalid_argument",
                    "passphrase file is not UTF-8",
                )
            })?
        }
        None => {
            let p = rpassword::prompt_password("Passphrase: ").map_err(|e| {
                CliError::other(format!(
                    "cannot read a passphrase from the terminal ({e}); use --passphrase-file"
                ))
            })?;
            if confirm {
                let again = rpassword::prompt_password("Repeat passphrase: ")
                    .map_err(|e| CliError::other(format!("cannot read a passphrase ({e})")))?;
                if again != p {
                    return Err(CliError::new(
                        exit::INVALID,
                        "invalid_argument",
                        "the passphrases do not match",
                    ));
                }
            }
            p
        }
    };
    let p = raw.trim_end_matches(['\n', '\r']).to_owned();
    if p.is_empty() {
        return Err(CliError::new(
            exit::INVALID,
            "invalid_argument",
            "the passphrase is empty",
        ));
    }
    Ok(p)
}

async fn run(cli: Cli) -> CliResult<i32> {
    let dir = cli.data_dir.clone().unwrap_or_else(default_data_dir);
    let json = cli.json;
    let remote = || RemoteAgent::new(&dir);
    match cli.command {
        Command::Init {
            inbox_buckets,
            node_url,
            peer,
        } => {
            let rep = offline::init_data_dir(&dir, &node_url, &peer, inbox_buckets)?;
            let out = json!({
                "data_dir": dir,
                "address": rep.identity.agent_id,
                "contact_record": rep.identity.contact_record,
                "peers_configured": !rep.peers_missing,
            });
            emit(json, &out, |_| {
                let mut s = format!(
                    "Created {} (directory 0700, files 0600)\nAddress: {}\nContact record (share it with peers; they must verify the address out of band):\n{}\n",
                    dir.display(),
                    rep.identity.agent_id,
                    rep.identity.contact_record
                );
                if rep.peers_missing {
                    s.push_str("\nWARNING: no peers configured. Private mode needs at least one static peer:\nadd `peers = [\"/ip4/<ip>/tcp/60000/p2p/<peerId>\"]` to agentnet.toml (see `agentnet relay print-config`).\n");
                }
                s.push_str("\nNext: agentnet serve");
                s
            });
        }
        Command::Serve => {
            let d = Daemon::start(&dir).await?;
            eprintln!(
                "agentnet daemon running for {} (socket {}); stop with Ctrl-C or SIGTERM",
                d.node().address(),
                d.socket_path().display()
            );
            if let Some(a) = d.http_addr() {
                eprintln!(
                    "HTTP MCP on http://{a}/mcp (bearer token in {})",
                    dir.join("mcp-http.token").display()
                );
            }
            d.run_until_signal().await?;
        }
        Command::Mcp { embedded } => {
            if embedded {
                let d = Daemon::start(&dir).await?;
                let api = d.api();
                let r = agentnet_mcp::serve_stdio(api).await;
                d.shutdown().await;
                r.map_err(|e| CliError::other(e.to_string()))?;
            } else {
                agentnet_mcp::serve_stdio(Arc::new(remote()))
                    .await
                    .map_err(|e| CliError::other(e.to_string()))?;
            }
        }
        Command::Identity { action } => match action {
            IdentityCmd::Show => {
                let i = offline::show_identity(&dir)?;
                emit(json, &i, |i| {
                    format!(
                        "Address: {}\nInbox topic: {}\nCreated: {}\nKEM key expires: {}\nContact record:\n{}",
                        i.agent_id,
                        i.inbox_topic,
                        render::time(i.created_at),
                        i.kem_expires_at.map(render::time).unwrap_or_else(|| "never".into()),
                        i.contact_record
                    )
                });
            }
            IdentityCmd::Export {
                out,
                passphrase_file,
            } => {
                let pass = passphrase(passphrase_file.as_deref(), true)?;
                let i = offline::export_identity(&dir, &out, &pass)?;
                let v = json!({"address": i.agent_id, "file": out});
                emit(json, &v, |_| {
                    format!("Exported the identity of {} to {} (age passphrase-encrypted, mode 0600).\nKeep the passphrase safe; do not run the same identity in two places.", i.agent_id, out.display())
                });
            }
            IdentityCmd::Import {
                input,
                passphrase_file,
                node_url,
                peer,
                no_replay_guard,
            } => {
                let pass = passphrase(passphrase_file.as_deref(), false)?;
                let bytes = std::fs::read(&input)
                    .map_err(|e| CliError::other(format!("reading {}: {e}", input.display())))?;
                let rep = offline::import_identity(
                    &dir,
                    &bytes,
                    &pass,
                    &node_url,
                    &peer,
                    !no_replay_guard,
                )?;
                let v = json!({"address": rep.identity.agent_id, "data_dir": dir, "peers_configured": !rep.peers_missing, "replay_guard": !no_replay_guard});
                emit(json, &v, |_| {
                    let mut s = format!(
                        "Imported identity {} into {}",
                        rep.identity.agent_id,
                        dir.display()
                    );
                    if no_replay_guard {
                        s.push_str("\nWARNING: --no-replay-guard: this directory has no dedupe history; frames captured before the import can be accepted again within their TTL.");
                    } else {
                        s.push_str("\nReplay guard: messages created before the first start are held until max_ttl + clock_skew has passed (or `agentnet doctor --accept-rollback`). To keep dedupe history, copy agentnet.db and agentnet.generation instead.");
                    }
                    if rep.peers_missing {
                        s.push_str(
                            "\nNo peers configured: edit agentnet.toml before `agentnet serve`.",
                        );
                    }
                    s
                });
            }
            IdentityCmd::RotateKem {
                keep_hours,
                revoke_previous,
            } => {
                let i = offline::rotate_kem(&dir, keep_hours, revoke_previous)?;
                emit(json, &i, |i| {
                    let mut s = format!(
                        "Rotated the agreement key of {} (key epoch {}).",
                        i.agent_id, i.key_epoch
                    );
                    if revoke_previous {
                        s.push_str(" All earlier KEM keys were destroyed: messages already sealed to them are lost unless their senders re-seal them after learning the new record.");
                    } else {
                        s.push_str(
                            " The previous key keeps decrypting until the retention window ends.",
                        );
                    }
                    s.push_str(&format!("\nAt the next `agentnet serve` every Trusted contact is sent the new record; you can also give it to peers directly:\n{}", i.contact_record));
                    s
                });
            }
            IdentityCmd::Revoke { reason } => {
                let r = offline::revoke_identity(&dir, &reason)?;
                let v = json!({"address": r.identity.agent_id, "revocation": r.document});
                emit(json, &v, |_| {
                    format!(
                        "Revoked {}. This is irreversible for this address; the daemon now sends nothing except this notice, which goes to every Trusted contact at the next `agentnet serve`.\nIt reaches only contacts that are reachable within the TTL/retry limits or that get it out of band; there is no global revocation list. Distribute it:\n{}",
                        r.identity.agent_id, r.document
                    )
                });
            }
            IdentityCmd::ShowRevocation => match offline::show_revocation(&dir)? {
                Some(doc) => {
                    let v = json!({"revocation": doc});
                    emit(json, &v, |_| doc.clone());
                }
                None => {
                    return Err(CliError::new(
                        exit::NOT_FOUND,
                        "not_found",
                        "this identity has not been revoked",
                    ))
                }
            },
        },
        Command::Contact { action } => {
            let r = remote();
            match action {
                ContactCmd::Add {
                    record,
                    expect,
                    alias,
                    trust,
                } => {
                    let doc = read_text_arg(&record, "contact record")?;
                    let c = r
                        .add_contact(AddContactRequest {
                            contact_record: doc,
                            expected_address: expect,
                            alias,
                            trust: trust.map(Into::into),
                        })
                        .await?;
                    emit(json, &c, render::contact_line);
                }
                ContactCmd::Revoke { document } => {
                    let doc = read_text_arg(&document, "revocation document")?;
                    let info = r.import_revocation(doc.trim()).await?;
                    emit(json, &info, |i| {
                        format!(
                            "{} {} (reason: {}); the contact is blocked and cannot be re-trusted",
                            if i.newly_revoked {
                                "revoked"
                            } else {
                                "already revoked:"
                            },
                            i.address,
                            render::clean(&i.reason)
                        )
                    });
                }
                ContactCmd::List => {
                    let l = r.list_contacts().await?;
                    emit(json, &l, |l| {
                        if l.is_empty() {
                            "no contacts".to_owned()
                        } else {
                            l.iter()
                                .map(render::contact_line)
                                .collect::<Vec<_>>()
                                .join("\n")
                        }
                    });
                }
                ContactCmd::Trust { address, level } => {
                    let c = r.set_contact_trust(&address, level.into()).await?;
                    emit(json, &c, render::contact_line);
                }
                ContactCmd::Remove { address } => {
                    let removed = r.remove_contact(&address).await?;
                    emit(json, &json!({"removed": removed}), |_| {
                        if removed {
                            format!("removed {address}")
                        } else {
                            format!("{address} was not a contact")
                        }
                    });
                }
            }
        }
        Command::Quarantine { action } => {
            let r = remote();
            match action {
                QuarantineCmd::List => {
                    let l = r.list_quarantined().await?;
                    emit(json, &l, |l| {
                        if l.is_empty() {
                            "quarantine is empty".to_owned()
                        } else {
                            l.iter()
                                .map(render::inbox_record)
                                .collect::<Vec<_>>()
                                .join("\n")
                        }
                    });
                }
                QuarantineCmd::Release { message_id } => {
                    let n = r.release_quarantined(&message_id).await?;
                    emit(json, &json!({"released": n}), |_| {
                        if n > 0 {
                            format!("released {n} message(s) into the inbox")
                        } else {
                            "nothing released (is the sender a trusted contact?)".to_owned()
                        }
                    });
                }
            }
        }
        Command::Send {
            recipient,
            body,
            conversation,
            ttl,
            idempotency_key,
        } => {
            let body = if body == "-" {
                read_text_arg("-", "message body")?
            } else {
                body
            };
            let res = remote()
                .send_message(SendMessageRequest {
                    recipient,
                    body,
                    conversation_id: conversation,
                    ttl_seconds: ttl,
                    idempotency_key,
                    ..Default::default()
                })
                .await?;
            emit(json, &res, |r| {
                format!(
                    "{} message_id={} conversation={} expires={}{}",
                    render::state(r.status),
                    r.message_id,
                    r.conversation_id,
                    render::time(r.expires_at),
                    if r.deduplicated {
                        " (deduplicated)"
                    } else {
                        ""
                    }
                )
            });
        }
        Command::Inbox {
            unread,
            limit,
            cursor,
            conversation,
            include_quarantined,
        } => {
            let res = remote()
                .read_inbox(ReadInboxRequest {
                    cursor,
                    limit,
                    unread_only: unread,
                    conversation_id: conversation,
                    include_quarantined,
                })
                .await?;
            emit(json, &res, |r| {
                let mut s = String::new();
                for rec in &r.records {
                    s.push_str(&render::inbox_record(rec));
                    s.push('\n');
                }
                if r.records.is_empty() {
                    s.push_str("inbox is empty\n");
                }
                if let Some(c) = &r.next_cursor {
                    s.push_str(&format!(
                        "next_cursor={c}{}",
                        if r.has_more { " (more available)" } else { "" }
                    ));
                }
                s
            });
        }
        Command::Ack { message_id } => {
            let r = remote().acknowledge_message(message_id).await?;
            emit(json, &r, |r| {
                format!(
                    "{} {}",
                    r.message_id,
                    if r.newly_acknowledged {
                        "acknowledged"
                    } else {
                        "already acknowledged"
                    }
                )
            });
        }
        Command::Status { message_id } => {
            let s = remote().get_message_status(message_id).await?;
            emit(json, &s, render::status);
        }
        Command::Outbox { cursor, limit } => {
            let p = remote().read_outbox(PageRequest { cursor, limit }).await?;
            emit(json, &p, |p| {
                let mut s = String::new();
                for r in &p.records {
                    s.push_str(&format!(
                        "{} {} to {} attempts={} {}\n",
                        render::state(r.status.state),
                        r.status.message_id,
                        r.status.recipient,
                        r.status.attempts,
                        render::clean(&render::truncate(&r.body, 60))
                    ));
                }
                if p.records.is_empty() {
                    s.push_str("outbox is empty\n");
                }
                if let Some(c) = &p.next_cursor {
                    s.push_str(&format!(
                        "next_cursor={c}{}",
                        if p.has_more { " (more available)" } else { "" }
                    ));
                }
                s
            });
        }
        Command::Trigger { action } => {
            let r = remote();
            match action {
                TriggerCmd::Create {
                    target_session,
                    sender,
                    message_type,
                    conversation,
                    correlation,
                    repeat,
                    expires_in,
                    since_cursor,
                } => {
                    let t = r
                        .create_trigger(CreateTriggerRequest {
                            sender,
                            message_type,
                            conversation_id: conversation,
                            correlation_id: correlation,
                            target_session,
                            once: Some(!repeat),
                            expires_in_seconds: expires_in,
                            since_cursor,
                        })
                        .await?;
                    emit(json, &t, render::trigger);
                }
                TriggerCmd::List { all } => {
                    let l = r.list_triggers(all).await?;
                    emit(json, &l, |l| {
                        if l.is_empty() {
                            "no triggers".to_owned()
                        } else {
                            l.iter().map(render::trigger).collect::<Vec<_>>().join("\n")
                        }
                    });
                }
                TriggerCmd::Delete { trigger_id } => {
                    let d = r.delete_trigger(trigger_id).await?;
                    emit(json, &d, |d| {
                        if d.deleted {
                            format!("deleted {}", d.trigger_id)
                        } else {
                            format!("{} did not exist or was already deleted", d.trigger_id)
                        }
                    });
                }
            }
        }
        Command::Events { action } => match action {
            EventsCmd::Tail { since, ack, all } => {
                let r = remote();
                let start = if since.is_some() || all {
                    since
                } else {
                    // Default: only new events. Find the current end of the log.
                    let mut cur: Option<String> = None;
                    loop {
                        let page = r
                            .read_events(PageRequest {
                                cursor: cur.clone(),
                                limit: Some(200),
                            })
                            .await?;
                        if let Some(c) = page.next_cursor {
                            cur = Some(c);
                        }
                        if !page.has_more {
                            break;
                        }
                    }
                    cur
                };
                let mut s = EventStream::connect(&dir, start).await?;
                loop {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => break,
                        ev = s.next() => match ev? {
                            Some(ev) => {
                                if json {
                                    print_json(&ev);
                                } else {
                                    println!("{}", render::event(&ev));
                                }
                                if ack {
                                    s.ack(&ev.cursor).await?;
                                }
                            }
                            None => {
                                return Err(CliError::new(exit::UNAVAILABLE, "unavailable", "the daemon closed the event stream"));
                            }
                        },
                    }
                }
            }
        },
        Command::Network { action } => match action {
            NetworkCmd::Status { verbose } => {
                let r = remote();
                let st = r.network_status(verbose).await?;
                let daemon = r.daemon_status().await.ok();
                let out = json!({"network": st, "daemon": daemon});
                emit(json, &out, |_| render::network(&st, daemon.as_ref()));
            }
        },
        Command::Doctor { accept_rollback } => {
            if accept_rollback {
                let had = offline::accept_rollback(&dir)?;
                eprintln!(
                    "{}",
                    if had {
                        "accepted: the next start will not hold older messages (held messages are released); frames replayed from before the rollback may be accepted again within their TTL"
                    } else {
                        "nothing to accept: no rollback, unknown history or import marker was found"
                    }
                );
            }
            let checks = doctor::run(&dir).await;
            let failed = checks.iter().any(|c| c.level == doctor::Level::Fail);
            emit(json, &checks, |cs| render::doctor(cs));
            if failed {
                return Ok(exit::DOCTOR_FAILED);
            }
        }
        Command::Relay { action } => match action {
            RelayCmd::PrintConfig {
                ip,
                peer_id,
                client_ip,
            } => {
                let ip = ip.unwrap_or_else(|| "<RELAY_IP>".into());
                let peer_id = peer_id.unwrap_or_else(|| "<RELAY_PEER_ID>".into());
                let client_ip = client_ip.unwrap_or_else(|| "<CLIENT_IP>".into());
                let cfg = relay::build(&ip, &peer_id, &client_ip);
                emit(json, &cfg, relay::render_text);
            }
        },
    }
    Ok(exit::OK)
}
