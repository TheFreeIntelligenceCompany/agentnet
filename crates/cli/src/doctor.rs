//! `agentnet doctor`: actionable diagnostics.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use agentnet_core::api::{AgentApi, ErrorCode, ReadInboxRequest};
use agentnet_daemon::client::agentnet_command;
use agentnet_daemon::{DaemonConfig, DataDir, RemoteAgent};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Ok,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
    /// What to do about it (empty when fine).
    pub fix: String,
}

fn check(
    name: &'static str,
    level: Level,
    detail: impl Into<String>,
    fix: impl Into<String>,
) -> Check {
    Check {
        name,
        level,
        detail: detail.into(),
        fix: fix.into(),
    }
}

fn mode_of(p: &Path) -> Option<u32> {
    std::fs::metadata(p)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

/// Parse an HTTP IMF-fixdate (`Tue, 25 Nov 2026 12:00:00 GMT`) to unix seconds.
pub fn parse_http_date(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 6 || parts[5] != "GMT" {
        return None;
    }
    let day: i64 = parts[1].parse().ok()?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == parts[2])? as i64
        + 1;
    let year: i64 = parts[3].parse().ok()?;
    let hms: Vec<i64> = parts[4].split(':').filter_map(|x| x.parse().ok()).collect();
    if hms.len() != 3 {
        return None;
    }
    // days from civil (Howard Hinnant)
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hms[0] * 3600 + hms[1] * 60 + hms[2])
}

fn replay_guard_check(dir: &Path, dd: &DataDir) -> Check {
    let accept = format!("`{}`", agentnet_command(dir, "doctor --accept-rollback"));
    use agentnet_core::guard::{inspect, SidecarState};
    let name = "replay guard";
    let r = match inspect(&dd.db()) {
        Ok(r) => r,
        Err(e) => {
            return check(
                name,
                Level::Warn,
                format!("could not inspect the store: {e}"),
                "",
            )
        }
    };
    if let Some(g) = &r.active {
        return check(
            name,
            Level::Warn,
            format!(
                "ACTIVE ({}): messages created before the guard started are held, not delivered or acknowledged; {} held now; it lapses by itself at unix ms {}",
                g.reason, r.held, g.until
            ),
            format!("if the store was restored on purpose: stop the daemon and run {accept} (accepts replay exposure for already-received messages)"),
        );
    }
    if r.rollback_suspected {
        return check(
            name,
            Level::Warn,
            "the database is OLDER than its generation sidecar: the store looks rolled back; the next start enters guard mode",
            format!("if intended, run {accept} with the daemon stopped"),
        );
    }
    if r.unknown_history {
        return check(
            name,
            Level::Warn,
            "the generation sidecar is missing next to a non-empty database: store history is unknown; the next start enters guard mode",
            format!("if intended, run {accept} with the daemon stopped"),
        );
    }
    if matches!(&r.sidecar, SidecarState::Present(s) if s.guard.is_some()) {
        return check(
            name,
            Level::Warn,
            "this data directory was created by `identity import`: the first start enters guard mode (no dedupe history)",
            format!("wait for max_ttl + clock_skew after the first start, or run {accept}"),
        );
    }
    check(
        name,
        Level::Ok,
        match r.db_generation {
            Some(g) => format!("inactive (store generation {g})"),
            None => "inactive (no store yet)".to_owned(),
        },
        "",
    )
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(0))
        .unwrap_or(0)
}

/// Days before expiry at which `doctor` starts to warn about the encryption subkey.
pub const KEM_EXPIRY_WARN_DAYS: i64 = 30;

/// The live encryption subkey's expiry. Nothing rotates it automatically: a
/// subkey that has expired makes the agent unreachable for new senders.
/// `None` when the subkey never expires (nothing to report).
pub fn kem_expiry_check(dir: &Path, expires_at_ms: Option<i64>, now_ms: i64) -> Option<Check> {
    let exp = expires_at_ms?;
    let fix = format!(
        "rotate it with the daemon stopped: `{}`",
        agentnet_command(dir, "identity rotate-kem")
    );
    let day_ms = 86_400_000;
    let left = exp - now_ms;
    Some(if left <= 0 {
        check(
            "encryption subkey",
            Level::Fail,
            format!(
                "the encryption subkey expired {} day(s) ago: new senders cannot encrypt to this agent",
                (-left) / day_ms
            ),
            fix,
        )
    } else if left < KEM_EXPIRY_WARN_DAYS * day_ms {
        check(
            "encryption subkey",
            Level::Warn,
            format!(
                "the encryption subkey expires in {} day(s); nothing rotates it automatically",
                left / day_ms
            ),
            fix,
        )
    } else {
        check(
            "encryption subkey",
            Level::Ok,
            format!("expires in {} day(s)", left / day_ms),
            "",
        )
    })
}

/// Probe of the relay Store path through what the daemon already reports: the
/// time of the last history pass that read every page without a Store failure
/// (`last_history_sync_at`). The watermark does not advance after a failed
/// pass, so an old value means the Store has not answered recently.
pub fn history_sync_check(
    last_ok_ms: Option<i64>,
    now_ms: i64,
    interval_s: u64,
    recovery_pending: bool,
) -> Check {
    let name = "history sync";
    let fix = "check the relay's Store (docs/runbook.md section 6.4): the node's /health, its store flags and the `last history sync` line of `network status`; until a pass completes, messages sent while this daemon was offline are not recovered";
    let stale_after_s = interval_s.saturating_mul(4).max(60);
    match last_ok_ms {
        None => check(
            name,
            Level::Warn,
            "no history sync has completed yet (just started, or the relay Store has not answered)",
            fix,
        ),
        Some(t) => {
            let age_s = (now_ms - t).max(0) / 1000;
            let stale = u64::try_from(age_s).unwrap_or(0) > stale_after_s;
            if stale || recovery_pending {
                check(
                    name,
                    Level::Warn,
                    format!(
                        "last successful relay Store sync {age_s} s ago (interval {interval_s} s){}",
                        if recovery_pending {
                            "; recovery pending"
                        } else {
                            ""
                        }
                    ),
                    fix,
                )
            } else {
                check(
                    name,
                    Level::Ok,
                    format!(
                        "last successful relay Store sync {age_s} s ago (interval {interval_s} s)"
                    ),
                    "",
                )
            }
        }
    }
}

/// Detail prefix of the `isolation` check in plain public mode. `--ready`
/// accepts this one skip: the check is not applicable there, but the line still
/// says plainly that nothing is audited.
const NOT_AUDITED: &str = "not audited in public mode";

/// The `peers == allowlist` line for an audited allowlist. A CONNECTED foreign
/// peer is a failure (an isolation violation); a foreign peer the node merely
/// knows, without a connection, is a warning that clears on node restart.
fn peers_check(foreign_connected: u32, foreign_known: u32, connected: u32) -> Check {
    if foreign_connected > 0 {
        check(
            "peers == allowlist",
            Level::Fail,
            format!(
                "{foreign_connected} connected peer(s) outside the allowlist (isolation violation); {foreign_known} more known but not connected"
            ),
            "restart the node with the verified flags so it drops the foreign peer; check its discovery flags first",
        )
    } else if foreign_known > 0 {
        check(
            "peers == allowlist",
            Level::Warn,
            format!(
                "the node knows {foreign_known} peer(s) outside the allowlist; they are known, not connected (0 connected foreign peers); the entry clears when the node restarts"
            ),
            "the node should only know the peers in agentnet.toml; check its discovery flags, then restart the node to clear stale entries",
        )
    } else if connected == 0 {
        check(
            "peers == allowlist",
            Level::Warn,
            "no peer connected yet",
            "start the relay first; the node redials with backoff",
        )
    } else {
        check(
            "peers == allowlist",
            Level::Ok,
            format!("{connected} connected, all in the allowlist"),
            "",
        )
    }
}

/// The `isolation` line. `audited` is true in private mode and in public mode
/// with `network.enforce_peer_allowlist`.
fn isolation_check(audited: bool, violation: Option<&str>) -> Check {
    if let Some(v) = violation {
        check("isolation", Level::Fail, v.to_owned(), "the node is connected to a peer outside agentnet.toml: restart it with the verified flags")
    } else if audited {
        check(
            "isolation",
            Level::Ok,
            "no isolation violation reported",
            "",
        )
    } else {
        check(
            "isolation",
            Level::Skip,
            format!("{NOT_AUDITED}; the node may be connected to any peer"),
            "to audit your own relay on a public address set network.enforce_peer_allowlist = true (and list the relay in network.peers)",
        )
    }
}

/// Checks that must be `ok` for messaging to work (`doctor --ready`). In plain
/// public mode the `isolation` line is a deliberate skip (see [`NOT_AUDITED`])
/// and does not block readiness; it never counts as `ok`.
const REQUIRED: [&str; 5] = [
    "daemon socket",
    "node reachable",
    "isolation",
    "transport ready",
    "local inbox database",
];

/// The conditions that make the instance not ready: one line per required
/// check that is not `ok` (warned, skipped, failed or not run), plus every
/// other failed check. Empty means ready.
pub fn readiness_failures(dir: &Path, checks: &[Check]) -> Vec<String> {
    let mut out = Vec::new();
    for name in REQUIRED {
        match checks.iter().find(|c| c.name == name) {
            Some(c) if c.level == Level::Ok => {}
            Some(c)
                if name == "isolation"
                    && c.level == Level::Skip
                    && c.detail.starts_with(NOT_AUDITED) => {}
            Some(c) => {
                let state = match c.level {
                    Level::Skip => "skipped",
                    Level::Warn => "warning",
                    Level::Fail => "FAILED",
                    Level::Ok => "ok",
                };
                let mut line = format!("{name}: {state}: {}", c.detail);
                if !c.fix.is_empty() {
                    line.push_str(&format!(" -> {}", c.fix));
                }
                out.push(line);
            }
            None => out.push(format!(
                "{name}: not run (it needs a readable config and a running daemon) -> fix the failing or skipped checks above, then run `{}` again",
                agentnet_command(dir, "doctor --ready")
            )),
        }
    }
    for c in checks {
        if c.level == Level::Fail && !REQUIRED.contains(&c.name) {
            out.push(format!("{}: FAILED: {}", c.name, c.detail));
        }
    }
    out
}

pub async fn run(dir: &Path) -> Vec<Check> {
    let dd = DataDir::new(dir);
    let mut out = Vec::new();

    // 1. permissions
    match std::fs::metadata(dir) {
        Err(e) => {
            out.push(check(
                "data dir",
                Level::Fail,
                format!("{} is not accessible ({e})", dir.display()),
                format!(
                    "run `{}` or pass the right --data-dir",
                    agentnet_command(dir, "init")
                ),
            ));
            return out;
        }
        Ok(_) => {
            let mut bad = Vec::new();
            if mode_of(dir).is_some_and(|m| m & 0o077 != 0) {
                bad.push(format!(
                    "{} is {:03o} (want 700)",
                    dir.display(),
                    mode_of(dir).unwrap_or(0)
                ));
            }
            for p in [
                dd.identity(),
                dd.config(),
                dd.db(),
                dd.control_token(),
                dd.mcp_token(),
                dd.lock(),
                dd.webhook_db(),
            ] {
                if let Some(m) = mode_of(&p) {
                    if m & 0o077 != 0 {
                        bad.push(format!("{} is {m:03o} (want 600)", p.display()));
                    }
                }
            }
            if bad.is_empty() {
                out.push(check(
                    "data dir permissions",
                    Level::Ok,
                    "directory 0700, files 0600",
                    "",
                ));
            } else {
                out.push(check(
                    "data dir permissions",
                    Level::Fail,
                    bad.join("; "),
                    "chmod 700 the directory and chmod 600 the files listed",
                ));
            }
        }
    }

    // 2. config
    let cfg = match DaemonConfig::load(&dd.config()) {
        Ok(c) => {
            out.push(check(
                "config",
                Level::Ok,
                format!(
                    "{} valid ({} mode, {} peer(s))",
                    dd.config().display(),
                    c.network.mode.as_str(),
                    c.network.peers.len()
                ),
                "",
            ));
            Some(c)
        }
        Err(e) => {
            out.push(check(
                "config",
                Level::Fail,
                e.to_string(),
                "edit agentnet.toml (see docs/configuration.md)",
            ));
            None
        }
    };

    // 3. identity
    let identity = match agentnet_daemon::offline::show_identity(dir) {
        Ok(i) => {
            out.push(check(
                "identity",
                Level::Ok,
                format!("address {}", i.agent_id),
                "",
            ));
            out.extend(kem_expiry_check(dir, i.kem_expires_at, now_ms()));
            Some(i)
        }
        Err(e) => {
            out.push(check(
                "identity",
                Level::Fail,
                e.to_string(),
                format!(
                    "run `{}` or `{}`",
                    agentnet_command(dir, "init"),
                    agentnet_command(dir, "identity import --in <FILE>")
                ),
            ));
            None
        }
    };

    // 3b. revocation, replay guard, single-instance warning
    if dd.revocation().exists() {
        out.push(check(
            "identity revoked",
            Level::Warn,
            "this identity has been revoked (revocation.json): the daemon sends nothing except its revocation notice",
            format!(
                "use a new identity (`agentnet --data-dir <new dir> init`); `{}` prints the notice to distribute out of band",
                agentnet_command(dir, "identity show-revocation")
            ),
        ));
    }
    out.push(replay_guard_check(dir, &dd));
    out.push(check(
        "single instance",
        Level::Warn,
        "the same identity running in two data directories cannot be detected or prevented (the data-dir lock only covers one directory); both would receive, persist and acknowledge every message independently and may both fire triggers",
        "run each identity in exactly one place; to move it, stop the old daemon first and copy agentnet.db + agentnet.generation or use `identity export/import`",
    ));

    // 4. daemon socket
    let remote = RemoteAgent::new(dir);
    let daemon_up = match remote.get_identity().await {
        Ok(i) => {
            let same = identity.as_ref().is_none_or(|f| f.agent_id == i.agent_id);
            if same {
                out.push(check(
                    "daemon socket",
                    Level::Ok,
                    "daemon answers on agentnet.sock",
                    "",
                ));
            } else {
                out.push(check(
                    "daemon socket",
                    Level::Fail,
                    "the running daemon has a different identity than identity.json",
                    format!("stop it and run `{}`", agentnet_command(dir, "serve")),
                ));
            }
            true
        }
        Err(e) => {
            let lvl = if e.code == ErrorCode::Unavailable {
                Level::Warn
            } else {
                Level::Fail
            };
            out.push(check(
                "daemon socket",
                lvl,
                e.message,
                format!("run `{}`", agentnet_command(dir, "serve")),
            ));
            false
        }
    };

    // 5. node reachable + clock
    if let Some(cfg) = &cfg {
        let url = format!("{}/health", cfg.network.node_url.trim_end_matches('/'));
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build();
        let mut node_date = None;
        match client {
            Ok(c) => match c.get(&url).send().await {
                Ok(r) => {
                    node_date = r
                        .headers()
                        .get("date")
                        .and_then(|v| v.to_str().ok())
                        .and_then(parse_http_date);
                    if r.status().is_success() {
                        out.push(check(
                            "node reachable",
                            Level::Ok,
                            format!("{} answered {}", cfg.network.node_url, r.status().as_u16()),
                            "",
                        ));
                    } else {
                        out.push(check(
                            "node reachable",
                            Level::Warn,
                            format!(
                                "{} answered http {}",
                                cfg.network.node_url,
                                r.status().as_u16()
                            ),
                            "check the node's health: its relay may have no peers yet",
                        ));
                    }
                }
                Err(_) => out.push(check(
                    "node reachable",
                    Level::Fail,
                    format!(
                        "cannot reach the Logos Delivery node at {}",
                        cfg.network.node_url
                    ),
                    "start the node (see `agentnet relay print-config`) or fix network.node_url",
                )),
            },
            Err(e) => out.push(check("node reachable", Level::Fail, e.to_string(), "")),
        }
        // clock
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
            .unwrap_or(0);
        if now < 1_735_689_600 {
            out.push(check(
                "clock",
                Level::Fail,
                "the system clock is before 2025-01-01",
                "set the system clock (NTP)",
            ));
        } else if let Some(nd) = node_date {
            let skew = (now - nd).abs();
            if skew > 15 {
                out.push(check(
                    "clock",
                    Level::Fail,
                    format!("clock differs from the node's by {skew} s; the Store silently drops messages more than 20 s off"),
                    "enable NTP on this host and on the node's host",
                ));
            } else {
                out.push(check(
                    "clock",
                    Level::Ok,
                    format!("within {skew} s of the node's clock"),
                    "",
                ));
            }
        } else {
            out.push(check(
                "clock",
                Level::Ok,
                "plausible (the node sent no Date header to compare)",
                "",
            ));
        }

        // 6. peers / isolation / store via the daemon
        if daemon_up {
            match remote.network_status(true).await {
                Ok(st) => {
                    let audited = cfg.network.mode == agentnet_daemon::Mode::Private
                        || cfg.network.enforce_peer_allowlist;
                    out.push(isolation_check(audited, st.isolation_violation.as_deref()));
                    if audited {
                        out.push(peers_check(
                            st.foreign_connected_peers,
                            st.foreign_known_peers,
                            st.connected_peers,
                        ));
                    } else {
                        out.push(check(
                            "peers == allowlist",
                            Level::Skip,
                            "public mode: no allowlist audit (set network.enforce_peer_allowlist to audit)",
                            "",
                        ));
                    }
                    out.push(history_sync_check(
                        st.last_history_sync_at,
                        now_ms(),
                        cfg.delivery.history_sync_interval_s,
                        st.detail.contains("history recovery pending"),
                    ));
                    if st.ready {
                        out.push(check("transport ready", Level::Ok, st.detail.clone(), ""));
                    } else {
                        out.push(check(
                            "transport ready",
                            Level::Warn,
                            st.detail.clone(),
                            "messages queue locally until the node is ready",
                        ));
                    }
                }
                Err(e) => out.push(check("network status", Level::Fail, e.message, "")),
            }
            match remote
                .read_inbox(ReadInboxRequest {
                    limit: Some(1),
                    ..Default::default()
                })
                .await
            {
                Ok(_) => out.push(check(
                    "local inbox database",
                    Level::Ok,
                    "inbox query works (this tests the local database, not the relay Store)",
                    "",
                )),
                Err(e) => out.push(check(
                    "local inbox database",
                    Level::Fail,
                    e.message,
                    "check disk space and permissions of agentnet.db",
                )),
            }
        } else {
            for n in [
                "isolation",
                "peers == allowlist",
                "history sync",
                "local inbox database",
            ] {
                out.push(check(
                    n,
                    Level::Skip,
                    "needs the running daemon",
                    format!("run `{}`", agentnet_command(dir, "serve")),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_date() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date("Tue, 25 Nov 2026 12:00:00 GMT"),
            Some(1_795_608_000)
        );
        assert_eq!(parse_http_date("nonsense"), None);
    }

    fn c(name: &'static str, level: Level) -> Check {
        check(name, level, "d", "do x")
    }

    fn healthy() -> Vec<Check> {
        REQUIRED
            .iter()
            .map(|n| c(n, Level::Ok))
            .chain([
                c("single instance", Level::Warn),
                c("history sync", Level::Ok),
            ])
            .collect()
    }

    fn set(h: &mut [Check], name: &str, level: Level) {
        h.iter_mut().find(|x| x.name == name).unwrap().level = level;
    }

    #[test]
    fn ready_when_every_required_check_is_ok_even_with_the_single_instance_warning() {
        assert!(readiness_failures(Path::new("/d"), &healthy()).is_empty());
    }

    #[test]
    fn not_ready_when_the_daemon_socket_is_unavailable() {
        let mut h = healthy();
        set(&mut h, "daemon socket", Level::Warn);
        let f = readiness_failures(Path::new("/d"), &h);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].starts_with("daemon socket: warning"), "{f:?}");
        assert!(f[0].contains("do x"), "{f:?}");
    }

    #[test]
    fn not_ready_when_the_transport_is_not_ready() {
        let mut h = healthy();
        set(&mut h, "transport ready", Level::Warn);
        let f = readiness_failures(Path::new("/d"), &h);
        assert!(f.iter().any(|l| l.starts_with("transport ready")), "{f:?}");
    }

    #[test]
    fn not_ready_when_the_isolation_audit_fails() {
        let mut h = healthy();
        set(&mut h, "isolation", Level::Fail);
        let f = readiness_failures(Path::new("/d"), &h);
        assert!(
            f.iter().any(|l| l.starts_with("isolation: FAILED")),
            "{f:?}"
        );
    }

    #[test]
    fn not_ready_when_a_required_check_was_skipped_or_not_run() {
        let mut h = healthy();
        set(&mut h, "local inbox database", Level::Skip);
        h.retain(|x| x.name != "node reachable");
        let f = readiness_failures(Path::new("/d"), &h);
        assert!(
            f.iter()
                .any(|l| l.starts_with("local inbox database: skipped")),
            "{f:?}"
        );
        assert!(
            f.iter().any(|l| l.starts_with("node reachable: not run")),
            "{f:?}"
        );
    }

    #[test]
    fn peers_line_separates_connected_foreign_peers_from_merely_known_ones() {
        let c = peers_check(2, 1, 3);
        assert_eq!(c.level, Level::Fail);
        assert!(
            c.detail.contains("2 connected peer(s) outside"),
            "{}",
            c.detail
        );
        assert!(
            !c.detail.contains("known, not connected (0"),
            "{}",
            c.detail
        );
        let k = peers_check(0, 3, 1);
        assert_eq!(k.level, Level::Warn);
        assert!(k.detail.contains("3 peer(s) outside"), "{}", k.detail);
        assert!(k.detail.contains("known, not connected"), "{}", k.detail);
        assert_eq!(peers_check(0, 0, 0).level, Level::Warn);
        let ok = peers_check(0, 0, 2);
        assert_eq!(
            (ok.level, ok.detail.as_str()),
            (Level::Ok, "2 connected, all in the allowlist")
        );
    }

    #[test]
    fn isolation_line_in_each_mode() {
        let a = isolation_check(true, None);
        assert_eq!(
            (a.level, a.detail.as_str()),
            (Level::Ok, "no isolation violation reported")
        );
        let v = isolation_check(true, Some("peer X outside"));
        assert_eq!(v.level, Level::Fail);
        let p = isolation_check(false, None);
        assert_eq!(p.level, Level::Skip);
        assert!(p.detail.starts_with(NOT_AUDITED) && !p.detail.contains("no isolation violation"));
        assert!(p.fix.contains("enforce_peer_allowlist"), "{}", p.fix);
    }

    #[test]
    fn ready_in_plain_public_mode_never_claims_isolation_ok() {
        let mut h = healthy();
        let p = isolation_check(false, None);
        h.iter_mut().find(|x| x.name == "isolation").unwrap().level = p.level;
        h.iter_mut().find(|x| x.name == "isolation").unwrap().detail = p.detail.clone();
        assert!(readiness_failures(Path::new("/d"), &h).is_empty());
        // The generic "needs the running daemon" skip still blocks readiness.
        let mut h = healthy();
        set(&mut h, "isolation", Level::Skip);
        let f = readiness_failures(Path::new("/d"), &h);
        assert!(
            f.iter().any(|l| l.starts_with("isolation: skipped")),
            "{f:?}"
        );
    }

    #[test]
    fn history_sync_probe_levels() {
        let now = 10_000_000;
        let fresh = history_sync_check(Some(now - 20_000), now, 15, false);
        assert_eq!(fresh.level, Level::Ok);
        assert!(fresh.detail.contains("20 s ago"), "{}", fresh.detail);
        // 15 s interval: stale after max(4 * 15, 60) = 60 s
        let stale = history_sync_check(Some(now - 61_000), now, 15, false);
        assert_eq!(stale.level, Level::Warn);
        assert!(stale.fix.contains("Store"), "{}", stale.fix);
        assert_eq!(
            history_sync_check(Some(now - 100_000), now, 60, false).level,
            Level::Ok
        );
        assert_eq!(history_sync_check(None, now, 15, false).level, Level::Warn);
        assert_eq!(
            history_sync_check(Some(now - 1000), now, 15, true).level,
            Level::Warn
        );
    }

    #[test]
    fn kem_expiry_levels() {
        let d = Path::new("/data/agent");
        let now = 1_000_000_000_000;
        let day = 86_400_000;
        assert!(kem_expiry_check(d, None, now).is_none());
        let ok = kem_expiry_check(d, Some(now + 31 * day), now).unwrap();
        assert_eq!(ok.level, Level::Ok);
        let warn = kem_expiry_check(d, Some(now + 29 * day), now).unwrap();
        assert_eq!(warn.level, Level::Warn);
        assert!(warn.detail.contains("29 day"), "{}", warn.detail);
        assert!(
            warn.fix.contains("identity rotate-kem") && warn.fix.contains("--data-dir"),
            "{}",
            warn.fix
        );
        let fail = kem_expiry_check(d, Some(now - 2 * day), now).unwrap();
        assert_eq!(fail.level, Level::Fail);
        assert!(fail.fix.contains("identity rotate-kem"), "{}", fail.fix);
        assert_eq!(
            kem_expiry_check(d, Some(now), now).unwrap().level,
            Level::Fail
        );
    }
}
