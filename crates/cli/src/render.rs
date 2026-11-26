//! Human-readable rendering. Remote content is untrusted: control characters
//! (including terminal escape sequences) are neutralised before printing.

use agentnet_core::api::*;
use serde_json::Value;

use crate::doctor::{Check, Level};

/// Replace control characters (except newline and tab) so remote text cannot
/// drive the terminal.
pub fn clean(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect()
}

pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(n).collect();
        t.push_str("...");
        t
    }
}

/// `YYYY-MM-DD HH:MM:SS UTC` for unix milliseconds.
pub fn time(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // civil from days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn state(s: DeliveryState) -> &'static str {
    match s {
        DeliveryState::Queued => "queued",
        DeliveryState::Sent => "sent",
        DeliveryState::Delivered => "delivered",
        DeliveryState::Failed => "failed",
        DeliveryState::Expired => "expired",
    }
}

pub fn trust(t: Trust) -> &'static str {
    match t {
        Trust::Trusted => "trusted",
        Trust::Untrusted => "untrusted",
        Trust::Blocked => "blocked",
        Trust::Unknown => "unknown",
    }
}

pub fn contact_line(c: &ContactInfo) -> String {
    format!(
        "{} {}{}",
        c.address,
        trust(c.trust),
        c.alias
            .as_deref()
            .map(|a| format!(" alias={}", clean(a)))
            .unwrap_or_default()
    )
}

pub fn inbox_record(r: &InboxRecord) -> String {
    format!(
        "{} from {} [{}] {}{}{}\n    {}",
        r.message_id,
        r.sender,
        trust(r.sender_trust),
        r.message_type,
        if r.acknowledged { " (acked)" } else { "" },
        if r.quarantined { " (QUARANTINED)" } else { "" },
        clean(&r.body).replace('\n', "\n    ")
    )
}

pub fn status(s: &MessageStatus) -> String {
    let mut out = format!(
        "{}  message_id={} to {} attempts={}",
        state(s.state),
        s.message_id,
        s.recipient,
        s.attempts
    );
    if let Some(t) = s.sent_at {
        out.push_str(&format!("\n  sent at {}", time(t)));
    }
    if let Some(t) = s.delivered_at {
        out.push_str(&format!(
            "\n  delivered (authenticated receipt) at {}",
            time(t)
        ));
    }
    if let Some(t) = s.next_attempt_at {
        out.push_str(&format!("\n  next attempt {}", time(t)));
    }
    out.push_str(&format!("\n  expires {}", time(s.expires_at)));
    if let Some(e) = &s.last_error {
        out.push_str(&format!("\n  last error: {}", clean(e)));
    }
    out
}

pub fn trigger(t: &TriggerInfo) -> String {
    let mut filters = Vec::new();
    for (k, v) in [
        ("sender", &t.sender),
        ("type", &t.message_type),
        ("conversation", &t.conversation_id),
        ("correlation", &t.correlation_id),
    ] {
        if let Some(v) = v {
            filters.push(format!("{k}={}", clean(v)));
        }
    }
    format!(
        "{} {:?} session={} once={} matches={} expires={} {}",
        t.trigger_id,
        t.state,
        clean(&t.target_session),
        t.once,
        t.match_count,
        time(t.expires_at),
        filters.join(" ")
    )
}

pub fn event(e: &EventRecord) -> String {
    format!(
        "{} {} cursor={} message={}{}{}",
        e.event_id,
        match e.event_type {
            EventType::MessageReceived => "message.received",
            EventType::TriggerMatched => "trigger.matched",
        },
        e.cursor,
        e.message_id,
        e.trigger_id
            .as_deref()
            .map(|t| format!(" trigger={t}"))
            .unwrap_or_default(),
        e.target_session
            .as_deref()
            .map(|t| format!(" session={}", clean(t)))
            .unwrap_or_default()
    )
}

pub fn network(st: &NetworkStatus, daemon: Option<&Value>) -> String {
    let mut s = format!(
        "mode: {}\nready: {}\nconnected peers: {}\n",
        st.mode, st.ready, st.connected_peers
    );
    match &st.isolation_violation {
        Some(v) => s.push_str(&format!("ISOLATION VIOLATION: {}\n", clean(v))),
        None => s.push_str("isolation: ok\n"),
    }
    let q = &st.queue;
    s.push_str(&format!(
        "queue: outbox queued={} sent-unacked={}, inbox unread={} quarantined={}, events unacked={}, active triggers={}\n",
        q.outbox_queued, q.outbox_sent_unacked, q.inbox_unread, q.inbox_quarantined, q.events_unacked, q.active_triggers
    ));
    if let Some(t) = st.last_live_poll_at {
        s.push_str(&format!("last live poll: {}\n", time(t)));
    }
    if let Some(t) = st.last_history_sync_at {
        s.push_str(&format!("last history sync: {}\n", time(t)));
    }
    if !st.detail.is_empty() {
        s.push_str(&format!("detail: {}\n", clean(&st.detail)));
    }
    if let Some(p) = &st.peers {
        for peer in p {
            s.push_str(&format!("peer: {}\n", clean(peer)));
        }
    }
    if let Some(d) = daemon {
        s.push_str(&format!(
            "daemon: version {} uptime {}s\n",
            d["version"].as_str().unwrap_or("?"),
            d["uptime_s"].as_u64().unwrap_or(0)
        ));
        let w = &d["webhook"];
        if w["enabled"] == Value::Bool(true) {
            s.push_str(&format!(
                "webhook: delivered={} retries={} parked={}{}\n",
                w["delivered"],
                w["retries"],
                w["parked"],
                w["last_error"]
                    .as_str()
                    .map(|e| format!(" last_error={e}"))
                    .unwrap_or_default()
            ));
        } else {
            s.push_str("webhook: disabled\n");
        }
    }
    s
}

pub fn doctor(checks: &[Check]) -> String {
    let mut s = String::new();
    for c in checks {
        let tag = match c.level {
            Level::Ok => "ok  ",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
            Level::Skip => "skip",
        };
        s.push_str(&format!("[{tag}] {}: {}\n", c.name, clean(&c.detail)));
        if !c.fix.is_empty() && c.level != Level::Ok {
            s.push_str(&format!("       -> {}\n", c.fix));
        }
    }
    let fails = checks.iter().filter(|c| c.level == Level::Fail).count();
    let warns = checks.iter().filter(|c| c.level == Level::Warn).count();
    s.push_str(&format!("{fails} failing, {warns} warning(s)"));
    s
}

/// One discovery candidate. Every remote-controlled field is neutralised and
/// truncated: it is an untrusted claim, never an instruction.
pub fn discovered(a: &DiscoveredAgent) -> String {
    let mut out = format!(
        "{} [{}]",
        a.address,
        if a.is_contact {
            trust(a.trust)
        } else {
            "not a contact"
        }
    );
    if let Some(n) = &a.display_name {
        out.push_str(&format!(" claims name {:?}", truncate(&clean(n), 64)));
    }
    out.push_str(&format!("\n    expires {}", time(a.expires_at)));
    for c in &a.capabilities {
        out.push_str(&format!(
            "\n    claims capability {}{}",
            truncate(&clean(&c.name), 64),
            if c.description.is_empty() {
                String::new()
            } else {
                format!(": {}", truncate(&clean(&c.description), 256))
            }
        ));
    }
    out
}
