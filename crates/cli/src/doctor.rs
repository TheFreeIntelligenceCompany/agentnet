//! `agentnet doctor`: actionable diagnostics.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use agentnet_core::api::{AgentApi, ErrorCode, ReadInboxRequest};
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

fn peer_id(maddr: &str) -> Option<&str> {
    let mut it = maddr.split('/');
    let mut last = None;
    while let Some(s) = it.next() {
        if s == "p2p" {
            last = it.next();
        }
    }
    last
}

fn replay_guard_check(dd: &DataDir) -> Check {
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
            "if the store was restored on purpose: stop the daemon and run `agentnet doctor --accept-rollback` (accepts replay exposure for already-received messages)",
        );
    }
    if r.rollback_suspected {
        return check(
            name,
            Level::Warn,
            "the database is OLDER than its generation sidecar: the store looks rolled back; the next start enters guard mode",
            "if intended, run `agentnet doctor --accept-rollback` with the daemon stopped",
        );
    }
    if r.unknown_history {
        return check(
            name,
            Level::Warn,
            "the generation sidecar is missing next to a non-empty database: store history is unknown; the next start enters guard mode",
            "if intended, run `agentnet doctor --accept-rollback` with the daemon stopped",
        );
    }
    if matches!(&r.sidecar, SidecarState::Present(s) if s.guard.is_some()) {
        return check(
            name,
            Level::Warn,
            "this data directory was created by `identity import`: the first start enters guard mode (no dedupe history)",
            "wait for max_ttl + clock_skew after the first start, or run `agentnet doctor --accept-rollback`",
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
                "run `agentnet init` or pass the right --data-dir",
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
            Some(i)
        }
        Err(e) => {
            out.push(check(
                "identity",
                Level::Fail,
                e.to_string(),
                "run `agentnet init` or `agentnet identity import`",
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
            "use a new identity (`agentnet init` in a new data dir); `agentnet identity show-revocation` prints the notice to distribute out of band",
        ));
    }
    out.push(replay_guard_check(&dd));
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
                    "stop it and run `agentnet serve` with this data dir",
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
                "run `agentnet serve`",
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
                    if let Some(v) = &st.isolation_violation {
                        out.push(check("isolation", Level::Fail, v.clone(), "the node is connected to a peer outside agentnet.toml: restart it with the verified flags"));
                    } else {
                        out.push(check(
                            "isolation",
                            Level::Ok,
                            "no isolation violation reported",
                            "",
                        ));
                    }
                    if cfg.network.mode == agentnet_daemon::Mode::Private {
                        let allow: Vec<&str> = cfg
                            .network
                            .peers
                            .iter()
                            .filter_map(|p| peer_id(p))
                            .collect();
                        let peers = st.peers.clone().unwrap_or_default();
                        let outside: Vec<&String> = peers
                            .iter()
                            .filter(|p| !allow.iter().any(|a| p.contains(a)))
                            .collect();
                        if !outside.is_empty() {
                            out.push(check(
                                "peers == allowlist",
                                Level::Fail,
                                format!("{} peer(s) outside the allowlist", outside.len()),
                                "the node must only know the peers in agentnet.toml; check its discovery flags",
                            ));
                        } else if st.connected_peers == 0 {
                            out.push(check(
                                "peers == allowlist",
                                Level::Warn,
                                "no peer connected yet",
                                "start the relay first; the node redials with backoff",
                            ));
                        } else {
                            out.push(check(
                                "peers == allowlist",
                                Level::Ok,
                                format!("{} connected, all in the allowlist", st.connected_peers),
                                "",
                            ));
                        }
                    } else {
                        out.push(check(
                            "peers == allowlist",
                            Level::Skip,
                            "public mode: no allowlist audit",
                            "",
                        ));
                    }
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
                Ok(_) => out.push(check("store query", Level::Ok, "inbox query works", "")),
                Err(e) => out.push(check(
                    "store query",
                    Level::Fail,
                    e.message,
                    "check disk space and permissions of agentnet.db",
                )),
            }
        } else {
            for n in ["isolation", "peers == allowlist", "store query"] {
                out.push(check(
                    n,
                    Level::Skip,
                    "needs the running daemon",
                    "run `agentnet serve`",
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

    #[test]
    fn peer_ids() {
        assert_eq!(peer_id("/ip4/1.2.3.4/tcp/1/p2p/16Uiu2X"), Some("16Uiu2X"));
        assert_eq!(peer_id("/ip4/1.2.3.4/tcp/1"), None);
    }
}
