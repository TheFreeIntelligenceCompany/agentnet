//! Test 9: logical clients sharing the two REST nodes; one poller per (node, topic) fans out to all clients on that bucket.
use crate::crypto::*;
use crate::net::*;
use crate::suite::{subscribe_with_cb, TTL};
use crate::{lk, log, Checker, Ctx, TestResult};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Cl {
    id: Identity,
    addr: String,
    node: &'static str,
    dd: Mutex<Dedupe>,
    fails: Mutex<BTreeMap<String, u64>>,
    ok: Mutex<u64>,
}
#[derive(Default)]
struct Shared {
    sent: HashMap<String, (Instant, usize)>,
    delivered: HashMap<String, Vec<f64>>,
}

async fn run_load(ctx: &Ctx, n: usize, poll_ms: u64, ck: &mut Checker) -> Value {
    let per = 10usize;
    let clients: Vec<Arc<Cl>> = (0..n)
        .map(|i| {
            let id = Identity::generate(16);
            Arc::new(Cl {
                addr: id.address(),
                id,
                node: if i % 2 == 0 { NA } else { NB },
                dd: Mutex::new(Dedupe::memory()),
                fails: Mutex::new(BTreeMap::new()),
                ok: Mutex::new(0),
            })
        })
        .collect();
    let contacts: Vec<PeerContact> = clients.iter().map(|c| c.id.contact()).collect();
    let shared = Arc::new(Mutex::new(Shared::default()));
    // group clients by (node, topic); every node polls ALL 16 bucket topics (empty groups just drain stale/unrelated messages)
    let mut groups: BTreeMap<(&'static str, String), Vec<Arc<Cl>>> = BTreeMap::new();
    for node in [NA, NB] {
        for b in 0..16 {
            groups.insert((node, format!("/agentnet/1/inbox-{b:02x}/proto")), vec![]);
        }
    }
    for c in &clients {
        groups
            .entry((c.node, c.id.topic()))
            .or_default()
            .push(c.clone());
    }
    let mut pollers = vec![];
    for ((node, topic), members) in &groups {
        let effective_poll = if members.is_empty() {
            poll_ms.max(500)
        } else {
            poll_ms
        };
        let (members, sh) = (members.clone(), shared.clone());
        let cb: Callback = Arc::new(move |raw: Raw| {
            for c in &members {
                match open_frame(&c.id, &c.addr, &raw.payload, now_ms(), &mut lk(&c.dd)) {
                    Ok(o) => {
                        *lk(&c.ok) += 1;
                        let mut s = lk(&sh);
                        let lat = s
                            .sent
                            .get(&o.env.message_id)
                            .map(|(t, _)| raw.recv.duration_since(*t).as_secs_f64() * 1e3);
                        s.delivered
                            .entry(o.env.message_id)
                            .or_default()
                            .push(lat.unwrap_or(f64::NAN));
                    }
                    Err(e) => *lk(&c.fails).entry(e.kind().into()).or_default() += 1,
                }
            }
        });
        pollers.push(subscribe_with_cb_ms(ctx, node, topic, effective_poll, cb).await);
    }
    log!(
        "run n={n} poll={poll_ms}ms: {} (node,topic) pollers for {} clients",
        pollers.len(),
        n
    );
    crate::suite::ensure_mesh(ctx).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let t_start = Instant::now();
    let stats_task = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        docker(&[
            "stats",
            "--no-stream",
            "--format",
            "{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}}",
            "an-r1",
            "an-na",
            "an-nb",
        ])
        .await
        .1
    });
    let sem = Arc::new(tokio::sync::Semaphore::new(ctx.pub_conc));
    let mut tasks = vec![];
    let contacts = Arc::new(contacts);
    for (i, cl) in clients.iter().enumerate() {
        let (cl, contacts, sh, sem, api) = (
            cl.clone(),
            contacts.clone(),
            shared.clone(),
            sem.clone(),
            ctx.api.clone(),
        );
        tasks.push(tokio::spawn(async move {
            let mut errs: Vec<String> = vec![];
            let mut ok = 0usize;
            for k in 0..per {
                let j = if n == 1 {
                    0
                } else {
                    (i + 1 + (rand_u64() as usize % (n - 1))) % n
                };
                let e = Envelope::new(
                    &cl.addr,
                    &contacts[j].address,
                    "chat",
                    format!("load|{i}|{k}"),
                    TTL,
                );
                let frame = match seal(
                    &cl.id.signing,
                    &contacts[j].kem_pk,
                    &e.to_bytes(),
                    PadPolicy::Pow2,
                ) {
                    Ok(f) => f,
                    Err(er) => {
                        errs.push(er);
                        continue;
                    }
                };
                let _p = sem.acquire().await;
                lk(&sh)
                    .sent
                    .insert(e.message_id.clone(), (Instant::now(), j));
                match api.publish(cl.node, &contacts[j].topic(), &frame).await {
                    Ok(()) => ok += 1,
                    Err(er) => errs.push(er),
                }
                drop(_p);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            (ok, errs)
        }));
    }
    let (mut published, mut perrs) = (0usize, vec![]);
    for t in tasks {
        if let Ok((o, e)) = t.await {
            published += o;
            perrs.extend(e);
        }
    }
    let send_secs = t_start.elapsed().as_secs_f64();
    let docker_stats = stats_task.await.unwrap_or_default();
    tokio::time::sleep(Duration::from_millis(3000 + poll_ms * 2)).await;
    let mut agg = PollStats::default();
    let mut max_batch = 0;
    for p in pollers {
        let s = p.finish().await;
        agg.polls += s.polls;
        agg.nonempty += s.nonempty;
        agg.msgs += s.msgs;
        agg.errors += s.errors;
        max_batch = max_batch.max(s.max_batch);
        if !s.last_error.is_empty() {
            agg.last_error = s.last_error;
        }
    }
    // accounting
    let s = lk(&shared);
    let sent_n = s.sent.len();
    let delivered: HashSet<&String> = s.delivered.keys().collect();
    let app_dups = s.delivered.values().filter(|v| v.len() > 1).count();
    let missing: Vec<&String> = s.sent.keys().filter(|k| !delivered.contains(k)).collect();
    let lat: Vec<f64> = s
        .delivered
        .values()
        .filter_map(|v| v.first().copied())
        .filter(|x| x.is_finite())
        .collect();
    // expected trial-decrypt failures: each node that has a poller for the bucket sees the message once
    let mut by_topic_node: HashMap<(String, &str), usize> = HashMap::new();
    for c in &clients {
        *by_topic_node.entry((c.id.topic(), c.node)).or_default() += 1;
    }
    let mut expected_fail = 0usize;
    for (_, (_, to)) in s.sent.iter() {
        let t = contacts[*to].topic();
        for node in [NA, NB] {
            if let Some(cnt) = by_topic_node.get(&(t.clone(), node)) {
                expected_fail += cnt - usize::from(clients[*to].node == node);
            }
        }
    }
    let mut obs: BTreeMap<String, u64> = BTreeMap::new();
    for c in &clients {
        for (k, v) in lk(&c.fails).iter() {
            *obs.entry(k.clone()).or_default() += v;
        }
    }
    let hpke_fail = obs.get("hpke_open").copied().unwrap_or(0);
    let replays = obs.get("replay").copied().unwrap_or(0);
    let total_ok: u64 = clients.iter().map(|c| *lk(&c.ok)).sum();
    log!("  n={n}: sent {sent_n} published_ok {published} delivered {} missing {} app_dups {app_dups} replay_rejects {replays} hpke_fail observed {hpke_fail} expected {expected_fail} other {:?}", delivered.len(), missing.len(), obs);
    ck.check(
        published == sent_n && perrs.is_empty(),
        format!(
            "n={n}: all {sent_n} publishes accepted ({:?})",
            perrs.iter().take(3).collect::<Vec<_>>()
        ),
    );
    // delivery is a measurement, not an assertion of the design: record it, but fail the test only on integrity problems
    ck.check(
        app_dups == 0 && total_ok as usize == delivered.len(),
        format!("n={n}: no duplicate application deliveries"),
    );
    json!({"clients": n, "msgs_per_client": per, "poll_ms": poll_ms, "rest_cache_capacity": 50, "pollers": groups.len(), "publish_concurrency": ctx.pub_conc, "per_client_pacing_ms": 20,
        "sent": sent_n, "published_ok": published, "publish_errors": perrs.iter().take(5).collect::<Vec<_>>(), "delivered_unique": delivered.len(),
        "delivery_rate": delivered.len() as f64 / sent_n.max(1) as f64, "missing": missing.len(), "app_level_duplicates": app_dups, "wire_replays_rejected": replays,
        "trial_decrypt_failures_observed": hpke_fail, "trial_decrypt_failures_expected_if_no_loss": expected_fail, "other_rejections": obs, "latency": lat_summary(lat),
        "send_phase_secs": send_secs, "poll_polls_total": agg.polls, "poll_nonempty": agg.nonempty, "max_batch_in_one_poll": max_batch, "poll_errors": agg.errors, "poll_last_error": agg.last_error,
        "messages_read_from_rest_caches": agg.msgs, "docker_stats_1.2s_into_send_phase": docker_stats.lines().collect::<Vec<_>>(), "empty_bucket_poll_ms": poll_ms.max(500)})
}

async fn subscribe_with_cb_ms(
    ctx: &Ctx,
    node: &'static str,
    topic: &str,
    poll_ms: u64,
    cb: Callback,
) -> Poller {
    let c2 = Ctx {
        api: ctx.api.clone(),
        out: ctx.out.clone(),
        work: ctx.work.clone(),
        poll_ms,
        load_runs: vec![],
        pub_conc: ctx.pub_conc,
    };
    subscribe_with_cb(&c2, node, topic, cb).await
}

pub async fn load(ctx: &Ctx) -> TestResult {
    let mut ck = Checker::default();
    let mut runs = vec![];
    for (n, poll) in ctx.load_runs.clone() {
        runs.push(run_load(ctx, n, poll, &mut ck).await);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let data = json!({"note": "clients alternate NA/NB; each (node,topic) has ONE poller fanning out to every logical client in that bucket (GET is destructive, cache of 50 is shared by all topics on a node). n=1 sends to itself (loopback). The poll=1000ms n=100 run is a deliberate control to show cache-overflow loss.", "runs": runs});
    ck.done("load", data)
}
