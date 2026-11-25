//! Tests 1-6, 8, 10 and the micro-benchmark.
use crate::crypto::*;
use crate::net::*;
use crate::{lk, log, Checker, Ctx, TestResult};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const WAKU_MAX_MSG: usize = 153_600;
/// Largest payload the node accepts for a content topic of this length (formula fitted to E3 and verified in `boundaries`).
pub fn max_payload(topic: &str) -> usize {
    WAKU_MAX_MSG - (topic.len() + 51)
}
pub const TTL: u64 = 10 * 60 * 1000;

// ------------------------------------------------------------------ helpers
pub struct Ep {
    pub id: Identity,
    pub addr: String,
    pub dd: Mutex<Dedupe>,
    pub rx: Mutex<EpRx>,
}
#[derive(Default)]
pub struct EpRx {
    pub ok: Vec<RxOk>,
    pub errs: BTreeMap<String, u64>,
    pub err_samples: BTreeMap<String, String>,
}
pub struct RxOk {
    pub id: String,
    pub sender: String,
    pub body: String,
    pub corr: Option<String>,
    pub env_bytes: Vec<u8>,
    pub sig: [u8; 64],
    pub lat_ms: Option<f64>,
}
impl Ep {
    pub fn new(buckets: u16) -> Arc<Ep> {
        let id = Identity::generate(buckets);
        Arc::new(Ep {
            addr: id.address(),
            id,
            dd: Mutex::new(Dedupe::memory()),
            rx: Mutex::new(EpRx::default()),
        })
    }
    pub fn contact(&self) -> PeerContact {
        self.id.contact()
    }
}
pub type SentMap = Arc<Mutex<HashMap<String, Instant>>>;
pub fn ep_cb(ep: Arc<Ep>, sent: SentMap) -> Callback {
    Arc::new(move |raw: Raw| {
        let r = open_frame(&ep.id, &ep.addr, &raw.payload, now_ms(), &mut lk(&ep.dd));
        let mut rx = lk(&ep.rx);
        match r {
            Ok(o) => {
                let lat_ms = lk(&sent)
                    .get(&o.env.message_id)
                    .map(|t| raw.recv.duration_since(*t).as_secs_f64() * 1e3);
                rx.ok.push(RxOk {
                    id: o.env.message_id,
                    sender: o.env.sender,
                    body: o.env.body,
                    corr: o.env.correlation_id,
                    env_bytes: o.env_bytes,
                    sig: o.sig,
                    lat_ms,
                });
            }
            Err(e) => {
                *rx.errs.entry(e.kind().into()).or_default() += 1;
                rx.err_samples
                    .entry(e.kind().into())
                    .or_insert_with(|| e.to_string());
            }
        }
    })
}
/// Keep both client nodes subscribed to a never-removed keeper topic (removing the last REST subscription drops the node
/// out of R1's relay mesh: observed) and wait until R1 reports both as mesh peers on shard 0.
pub async fn ensure_mesh(ctx: &Ctx) -> f64 {
    let t = Instant::now();
    // Never DELETE a REST subscription: removing one content topic drops the node's whole shard-0 relay subscription (observed),
    // and the mesh then needs 6-18 s to re-form. Instead stay subscribed to the keeper topic and all 16 inbox buckets, and drain
    // whatever stale messages the shared 50-slot caches hold before each test.
    let mut drained = 0;
    for n in [NA, NB] {
        let mut topics = vec!["/agentnet/1/keeper/proto".to_string()];
        topics.extend((0..16).map(|b| format!("/agentnet/1/inbox-{b:02x}/proto")));
        for tp in topics {
            if let Err(e) = ctx.api.subscribe(n, &tp).await {
                log!("  subscribe {n} {tp}: {e}");
            }
            drained += ctx.api.poll(n, &tp).await.map(|v| v.len()).unwrap_or(0);
        }
    }
    while ctx.api.r1_mesh_peers().await < 2 && t.elapsed() < Duration::from_secs(90) {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    // end-to-end canary: R1 listing both nodes as mesh peers is not sufficient (observed 40% loss right after that condition),
    // so require 5 consecutive canary round trips (NA->NB and NB->NA via the keeper topic) before real traffic starts.
    let mut streak = 0;
    let mut canary_fails = 0;
    while streak < 5 && t.elapsed() < Duration::from_secs(240) {
        let mut all_ok = true;
        for (from, to) in [(NA, NB), (NB, NA)] {
            let payload = rand_bytes::<16>().to_vec();
            let sent_ok = ctx
                .api
                .publish(from, "/agentnet/1/keeper/proto", &payload)
                .await
                .is_ok();
            let mut got = false;
            let t2 = Instant::now();
            while sent_ok && !got && t2.elapsed() < Duration::from_millis(1500) {
                if let Ok(v) = ctx.api.poll(to, "/agentnet/1/keeper/proto").await {
                    got = v.iter().any(|m| {
                        B64.decode(&m.payload)
                            .map(|p| p == payload)
                            .unwrap_or(false)
                    });
                }
                if !got {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            let _ = ctx.api.poll(from, "/agentnet/1/keeper/proto").await;
            if !got {
                all_ok = false;
                canary_fails += 1;
            }
        }
        streak = if all_ok { streak + 1 } else { 0 };
    }
    let secs = t.elapsed().as_secs_f64();
    log!("  canary: 5 consecutive bidirectional round trips reached after {canary_fails} failed canaries");
    log!("  mesh ready: R1 has {} mesh peers on shard 0 after {secs:.2}s; drained {drained} stale cached messages", ctx.api.r1_mesh_peers().await);
    tokio::time::sleep(Duration::from_secs(1)).await;
    secs
}
pub async fn subscribe_with_cb(ctx: &Ctx, node: &'static str, topic: &str, cb: Callback) -> Poller {
    if let Err(e) = ctx.api.subscribe(node, topic).await {
        log!("  subscribe {node} {topic} failed: {e}");
    }
    spawn_poller(
        ctx.api.clone(),
        node,
        topic.to_string(),
        Duration::from_millis(ctx.poll_ms),
        cb,
    )
}

/// Seal + local size check + publish. Returns the wire frame.
pub async fn send_env(
    ctx: &Ctx,
    node: &str,
    from: &Identity,
    to: &PeerContact,
    env: &Envelope,
    pad: PadPolicy,
    sent: Option<&SentMap>,
) -> Result<Vec<u8>, String> {
    let frame = seal(&from.signing, &to.kem_pk, &env.to_bytes(), pad)?;
    let topic = to.topic();
    if frame.len() > max_payload(&topic) {
        return Err(format!(
            "local reject: frame {} B > node limit {} B",
            frame.len(),
            max_payload(&topic)
        ));
    }
    if let Some(s) = sent {
        lk(s).insert(env.message_id.clone(), Instant::now());
    }
    ctx.api.publish(node, &topic, &frame).await?;
    Ok(frame)
}
pub fn mk_body(dir: &str, seq: u32) -> String {
    let pad = "x".repeat(100);
    format!(
        "{dir}|{seq}|{pad}|{}",
        hex(&sha256(&[format!("{dir}|{seq}|{pad}").as_bytes()]))
    )
}
pub fn check_body(b: &str) -> Option<(String, u32)> {
    let p: Vec<&str> = b.split('|').collect();
    if let [dir, seq, pad, sum] = p.as_slice() {
        let s: u32 = seq.parse().ok()?;
        (hex(&sha256(&[format!("{dir}|{seq}|{pad}").as_bytes()])) == *sum)
            .then(|| (dir.to_string(), s))
    } else {
        None
    }
}
fn fnow() -> u64 {
    now_ms()
}

// ------------------------------------------------------------------ 1. round trip
pub async fn roundtrip(ctx: &Ctx) -> TestResult {
    let mut ck = Checker::default();
    let (a, b) = (Ep::new(16), Ep::new(16));
    let (ca, cb_) = (a.contact(), b.contact());
    let (ta, tb) = (a.id.topic(), b.id.topic());
    log!("A={} topic {ta}\nB={} topic {tb}", a.addr, b.addr);
    let sent: SentMap = Arc::new(Mutex::new(HashMap::new()));
    let pa = subscribe_with_cb(ctx, NA, &ta, ep_cb(a.clone(), sent.clone())).await;
    let pb = subscribe_with_cb(ctx, NB, &tb, ep_cb(b.clone(), sent.clone())).await;
    ensure_mesh(ctx).await;
    let n = 100u32;
    let (mut ab_ids, mut ba_ids) = (vec![], vec![]);
    let (mut pub_ms, mut fails) = (vec![], vec![]);
    for seq in 0..n {
        let mut e = Envelope::new(&a.addr, &b.addr, "chat", mk_body("a2b", seq), TTL);
        e.conversation_id = Some("conv-1".into());
        let t = Instant::now();
        match send_env(ctx, NA, &a.id, &cb_, &e, PadPolicy::Pow2, Some(&sent)).await {
            Ok(_) => ab_ids.push(e.message_id.clone()),
            Err(er) => fails.push(format!("a2b {seq}: {er}")),
        }
        pub_ms.push(t.elapsed().as_secs_f64() * 1e3);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    for seq in 0..n {
        let mut e = Envelope::new(&b.addr, &a.addr, "chat", mk_body("b2a", seq), TTL);
        e.conversation_id = Some("conv-1".into());
        e.correlation_id = ab_ids.get(seq as usize).cloned();
        let t = Instant::now();
        match send_env(ctx, NB, &b.id, &ca, &e, PadPolicy::Pow2, Some(&sent)).await {
            Ok(_) => ba_ids.push(e.message_id.clone()),
            Err(er) => fails.push(format!("b2a {seq}: {er}")),
        }
        pub_ms.push(t.elapsed().as_secs_f64() * 1e3);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (sa, sb) = (pa.finish().await, pb.finish().await);
    let mut dirs = vec![];
    for (name, rcv, dir, ids, sender) in [
        ("A->B", &b, "a2b", &ab_ids, &a.addr),
        ("B->A", &a, "b2a", &ba_ids, &b.addr),
    ] {
        let rx = lk(&rcv.rx);
        let mut seqs = HashSet::new();
        let (mut integ, mut corr_bad, mut wrong_sender) = (0, 0, 0);
        let mut lat = vec![];
        let mut ids_seen = HashSet::new();
        for m in &rx.ok {
            if &m.sender != sender {
                wrong_sender += 1;
            }
            match check_body(&m.body) {
                Some((d, s)) if d == dir => {
                    seqs.insert(s);
                    if dir == "b2a" && m.corr.as_ref() != ab_ids.get(s as usize) {
                        corr_bad += 1;
                    }
                }
                _ => integ += 1,
            }
            ids_seen.insert(m.id.clone());
            if let Some(l) = m.lat_ms {
                lat.push(l);
            }
        }
        let app_dups = rx.ok.len() - ids_seen.len();
        let replays = rx.errs.get("replay").copied().unwrap_or(0);
        let missing: Vec<u32> = (0..n).filter(|s| !seqs.contains(s)).collect();
        log!("{name}: sent {} delivered_unique {} app_dups {app_dups} replay_rejects {replays} integrity_fail {integ} errs {:?}", ids.len(), seqs.len(), rx.errs);
        ck.check(
            ids.len() == n as usize,
            format!("{name}: all {n} publishes accepted"),
        );
        ck.check(
            seqs.len() == n as usize,
            format!(
                "{name}: 100/100 decrypted+signature-verified+integrity ok (got {})",
                seqs.len()
            ),
        );
        ck.check(
            app_dups == 0 && integ == 0 && corr_bad == 0 && wrong_sender == 0,
            format!("{name}: no app-level dups/integrity/correlation/sender failures"),
        );
        dirs.push(json!({"direction": name, "sent": ids.len(), "delivered_unique": seqs.len(), "delivery_rate": seqs.len() as f64 / n as f64,
            "duplicates_delivered_to_app": app_dups, "wire_duplicates_rejected_by_dedupe": replays, "integrity_failures": integ, "correlation_mismatch": corr_bad,
            "other_open_errors": rx.errs, "missing_seqs": missing, "latency": lat_summary(lat)}));
    }
    ck.check(fails.is_empty(), format!("no publish failures ({fails:?})"));
    let f1 = {
        let (s, _) = (lk(&sent).len(), 0);
        s
    };
    let data = json!({"note": "localhost/container network, amd64 nwaku image under qemu; latency = poller receive Instant - Instant before publish call (includes HTTP publish, relay hop(s) and poll interval)",
        "poll_ms": ctx.poll_ms, "publish_pacing_ms": 25, "A": a.addr, "B": b.addr, "topic_A": ta, "topic_B": tb, "messages_tracked": f1,
        "results": dirs, "publish_call_ms": lat_summary(pub_ms), "poll_stats_A": sa, "poll_stats_B": sb, "publish_failures": fails});
    ck.done("roundtrip", data)
}

// ------------------------------------------------------------------ 2. wrong recipient
pub async fn wrong_recipient(ctx: &Ctx) -> TestResult {
    let mut ck = Checker::default();
    let (a, b) = (Ep::new(16), Ep::new(16));
    let mut c = Ep::new(16);
    let mut tries = 1;
    while c.id.topic() != b.id.topic() {
        c = Ep::new(16);
        tries += 1;
    }
    let d = loop {
        let d = Ep::new(16);
        if d.id.topic() != b.id.topic() {
            break d;
        }
    };
    let tb = b.id.topic();
    log!(
        "B topic {tb}; C topic {} (same bucket, {tries} identities generated); D topic {}",
        c.id.topic(),
        d.id.topic()
    );
    let sent: SentMap = Arc::new(Mutex::new(HashMap::new()));
    // B polls its topic via NB, C polls the SAME topic via NA (a shared node would need a shared poller: GET is destructive)
    let pb = subscribe_with_cb(ctx, NB, &tb, ep_cb(b.clone(), sent.clone())).await;
    let pc = subscribe_with_cb(ctx, NA, &tb, ep_cb(c.clone(), sent.clone())).await;
    ensure_mesh(ctx).await;
    let mut frames = vec![];
    for seq in 0..10 {
        let e = Envelope::new(&a.addr, &b.addr, "chat", mk_body("a2b", seq), TTL);
        match send_env(
            ctx,
            NA,
            &a.id,
            &b.contact(),
            &e,
            PadPolicy::Pow2,
            Some(&sent),
        )
        .await
        {
            Ok(f) => frames.push(f),
            Err(er) => ck.check(false, format!("publish {seq}: {er}")),
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (sb, sc) = (pb.finish().await, pc.finish().await);
    let (rb, rc) = (lk(&b.rx), lk(&c.rx));
    log!(
        "B ok {} errs {:?}; C ok {} errs {:?} sample {:?}",
        rb.ok.len(),
        rb.errs,
        rc.ok.len(),
        rc.errs,
        rc.err_samples
    );
    ck.check(rb.ok.len() == 10, "B (intended, same bucket) opened 10/10");
    ck.check(
        rc.ok.is_empty(),
        "C (same bucket topic, different key) opened 0 messages",
    );
    ck.check(
        rc.errs.get("hpke_open").copied() == Some(10),
        "C: 10/10 rejected with HPKE open error",
    );
    // pure-crypto check with D in a different bucket, plus tamper of info binding: same frame, other recipient
    let mut dd = Dedupe::memory();
    let dres: Vec<String> = frames
        .iter()
        .map(|f| {
            open_frame(&d.id, &d.addr, f, now_ms(), &mut dd)
                .err()
                .map(|e| e.kind().to_string())
                .unwrap_or("OPENED".into())
        })
        .collect();
    ck.check(
        dres.iter().all(|k| k == "hpke_open"),
        "D (other bucket, in-process) 10/10 hpke_open",
    );
    let data = json!({"B_ok": rb.ok.len(), "B_errs": rb.errs, "C_ok": rc.ok.len(), "C_errs": rc.errs, "C_error_sample": rc.err_samples,
        "D_in_process_results": dres, "poll_stats_B": sb, "poll_stats_C": sc, "topic": tb,
        "note": "B reads via NB, C reads the same topic via NA; if both used one node they would race on the destructive GET (share one poller per (node,topic))"});
    ck.done("wrong-recipient", data)
}

// ------------------------------------------------------------------ 3. forgery
pub async fn forgery(ctx: &Ctx) -> TestResult {
    let mut ck = Checker::default();
    let (a, b, c, m) = (Ep::new(16), Ep::new(16), Ep::new(16), Ep::new(16));
    let (tb, tc) = (b.id.topic(), c.id.topic());
    let sent: SentMap = Arc::new(Mutex::new(HashMap::new()));
    let pb = subscribe_with_cb(ctx, NB, &tb, ep_cb(b.clone(), sent.clone())).await;
    // C reads through NA (distinct node from B's NB, so no GET race even if the buckets coincide)
    let pc = subscribe_with_cb(ctx, NA, &tc, ep_cb(c.clone(), sent.clone())).await;
    ensure_mesh(ctx).await;
    // (a) control: honest A->B
    let honest = Envelope::new(&a.addr, &b.addr, "chat", "honest".into(), TTL);
    let f_honest = send_env(ctx, NA, &a.id, &b.contact(), &honest, PadPolicy::Pow2, None).await;
    ck.check(f_honest.is_ok(), "honest A->B published");
    // (b) forgery: envelope claims sender=A, signed by M's key, sealed to B
    let forged = Envelope::new(&a.addr, &b.addr, "chat", "forged by M".into(), TTL);
    let f_forged = send_env(ctx, NA, &m.id, &b.contact(), &forged, PadPolicy::Pow2, None).await;
    ck.check(f_forged.is_ok(), "forged M->B (claims sender=A) published");
    // (c) surreptitious forwarding: B re-seals A's valid (sig, envelope) to C
    tokio::time::sleep(Duration::from_secs(1)).await;
    let honest_rx = lk(&b.rx)
        .ok
        .iter()
        .find(|o| o.body == "honest")
        .map(|o| (o.sig, o.env_bytes.clone()));
    ck.check(honest_rx.is_some(), "B opened the honest A->B message");
    let (fwd_published, fwd_err) = match honest_rx {
        Some((sig, env_bytes)) => {
            match seal_parts(&sig, &c.contact().kem_pk, &env_bytes, PadPolicy::Pow2) {
                Ok(frame) => {
                    let r = ctx.api.publish(NB, &tc, &frame).await;
                    (r.is_ok(), r.err())
                }
                Err(e) => (false, Some(e)),
            }
        }
        None => (false, Some("no honest message".to_string())),
    };
    ck.check(
        fwd_published,
        format!("forwarded frame (B re-sealed A's envelope to C) published {fwd_err:?}"),
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (sb, sc) = (pb.finish().await, pc.finish().await);
    let (rb, rc) = (lk(&b.rx), lk(&c.rx));
    log!(
        "B ok {:?} errs {:?}; C ok {} errs {:?}",
        rb.ok.iter().map(|o| o.body.clone()).collect::<Vec<_>>(),
        rb.errs,
        rc.ok.len(),
        rc.errs
    );
    ck.check(
        rb.ok.len() == 1 && rb.ok.first().map(|o| o.body.as_str()) == Some("honest"),
        "B accepted exactly the honest message",
    );
    ck.check(
        rb.errs.get("bad_signature").copied() == Some(1),
        "B rejected the forged message with bad_signature",
    );
    ck.check(rc.ok.is_empty() && rc.errs.get("wrong_recipient").copied() == Some(1), "C rejected the forwarded message with wrong_recipient (signature itself valid: checked before recipient)");
    drop((rb, rc));

    // contact-record / address attacks (in-process)
    let sc_a = a.id.signed_contact();
    let mut results = vec![];
    let mut case =
        |ck: &mut Checker, name: &str, r: Result<PeerContact, String>, expect_ok: bool| {
            let got = r
                .as_ref()
                .map(|_| "accepted".to_string())
                .unwrap_or_else(|e| format!("rejected: {e}"));
            ck.check(
                r.is_ok() == expect_ok,
                format!("contact case '{name}': {got}"),
            );
            results.push(json!({"case": name, "result": got, "expected_ok": expect_ok}));
        };
    case(
        &mut ck,
        "valid record",
        verify_contact(&a.addr, &sc_a.record, &sc_a.sig),
        true,
    );
    let mut tampered = sc_a.record.clone();
    if let Some(x) = tampered.iter_mut().find(|x| **x == b'1') {
        *x = b'2';
    }
    case(
        &mut ck,
        "record byte tampered",
        verify_contact(&a.addr, &tampered, &sc_a.sig),
        false,
    );
    case(
        &mut ck,
        "A's record presented under B's address",
        verify_contact(&b.addr, &sc_a.record, &sc_a.sig),
        false,
    );
    let mut bad_ck = a.addr.clone().into_bytes();
    if let Some(x) = bad_ck.last_mut() {
        *x = if *x == b'a' { b'b' } else { b'a' };
    }
    case(
        &mut ck,
        "address with altered checksum char",
        verify_contact(&String::from_utf8_lossy(&bad_ck), &sc_a.record, &sc_a.sig),
        false,
    );
    case(
        &mut ck,
        "uppercase (non-canonical) address",
        verify_contact(&a.addr.to_uppercase(), &sc_a.record, &sc_a.sig),
        false,
    );
    // M substitutes its own KEM key into a record claiming A's signing key, signed by M
    let mut rec: ContactRecord = serde_json::from_slice(&sc_a.record).unwrap_or(ContactRecord {
        v: 1,
        signing_pk: String::new(),
        kem_pk: String::new(),
        inbox_buckets: 16,
        created_at: 0,
    });
    rec.kem_pk = hex(&m.id.kem_pk_bytes());
    let rb2 = serde_json::to_vec(&rec).unwrap_or_default();
    let msig = m.id.signing.clone();
    use ed25519_dalek::Signer;
    let s2 = msig
        .sign(&[b"agentnet/v1/contact-record\0".as_slice(), &rb2].concat())
        .to_bytes();
    case(
        &mut ck,
        "KEM-key substitution: A's pk + M's kem_pk, signed by M",
        verify_contact(&a.addr, &rb2, &s2),
        false,
    );
    let s3 =
        a.id.signing
            .sign(&[b"agentnet/v1/contact-record\0".as_slice(), &rb2].concat())
            .to_bytes();
    case(
        &mut ck,
        "control: A itself signs a record with a different kem_pk (legit key rotation shape)",
        verify_contact(&a.addr, &rb2, &s3),
        true,
    );
    let data = json!({"B_ok": lk(&b.rx).ok.len(), "B_errs": lk(&b.rx).errs, "C_ok": lk(&c.rx).ok.len(), "C_errs": lk(&c.rx).errs, "contact_cases": results,
        "poll_stats_B": sb, "poll_stats_C": sc});
    ck.done("forgery", data)
}

// ------------------------------------------------------------------ 4. tamper
pub async fn tamper(_ctx: &Ctx) -> TestResult {
    let mut ck = Checker::default();
    let (a, b) = (Ep::new(16), Ep::new(16));
    let e = Envelope::new(&a.addr, &b.addr, "chat", "tamper target".into(), TTL);
    let frame = seal(
        &a.id.signing,
        &b.contact().kem_pk,
        &e.to_bytes(),
        PadPolicy::Pow2,
    )
    .unwrap_or_default();
    let mut dd = Dedupe::memory();
    ck.check(
        open_frame(&b.id, &b.addr, &frame, now_ms(), &mut Dedupe::memory()).is_ok(),
        format!("control: untampered frame ({} B) opens", frame.len()),
    );
    let len = frame.len();
    // every single bit of the frame
    let mut by_region: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    for i in 0..len {
        let region = if i < HEADER_LEN {
            "header"
        } else if i < HEADER_LEN + ENC_LEN {
            "enc"
        } else if i >= len - TAG_LEN {
            "tag"
        } else {
            "ciphertext_body"
        };
        for bit in 0..8 {
            let mut f = frame.clone();
            if let Some(x) = f.get_mut(i) {
                *x ^= 1 << bit;
            }
            let r = open_frame(&b.id, &b.addr, &f, now_ms(), &mut dd);
            let ent = by_region.entry(region).or_default();
            ent.0 += 1;
            match r {
                Err(er) => {
                    ent.1 += 1;
                    *kinds.entry(er.kind().into()).or_default() += 1;
                }
                Ok(_) => log!("  !! bit flip byte {i} bit {bit} ACCEPTED"),
            }
        }
    }
    for (r, (t, rej)) in &by_region {
        ck.check(
            t == rej,
            format!("single-bit flips in {r}: {rej}/{t} rejected"),
        );
    }
    // truncation at every length, and extension
    let mut trunc_rej = 0;
    let mut trunc_kinds: BTreeMap<String, u64> = BTreeMap::new();
    for l in 0..len {
        match open_frame(
            &b.id,
            &b.addr,
            frame.get(..l).unwrap_or(&[]),
            now_ms(),
            &mut dd,
        ) {
            Err(e) => {
                trunc_rej += 1;
                *trunc_kinds.entry(e.kind().into()).or_default() += 1;
            }
            Ok(_) => log!("  !! truncation to {l} ACCEPTED"),
        }
    }
    ck.check(
        trunc_rej == len,
        format!("truncation to every length 0..{len}: {trunc_rej}/{len} rejected"),
    );
    let mut ext_rej = 0;
    for extra in 1..=64 {
        let mut f = frame.clone();
        f.extend(std::iter::repeat_n(0u8, extra));
        if open_frame(&b.id, &b.addr, &f, now_ms(), &mut dd).is_err() {
            ext_rej += 1;
        }
    }
    ck.check(
        ext_rej == 64,
        format!("extension by 1..=64 bytes: {ext_rej}/64 rejected"),
    );
    // random garbage frames: no panics
    let mut panics = 0;
    let mut rk: BTreeMap<String, u64> = BTreeMap::new();
    for i in 0..1000 {
        let n = (rand_u64() % 2048) as usize;
        let mut f = vec![0u8; n];
        let _ = getrandom::fill(&mut f);
        if i % 2 == 0 && n >= 4 {
            f[..4].copy_from_slice(&HEADER);
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            open_frame(&b.id, &b.addr, &f, now_ms(), &mut Dedupe::memory())
        })) {
            Ok(Ok(_)) => *rk.entry("ACCEPTED".into()).or_default() += 1,
            Ok(Err(e)) => *rk.entry(e.kind().into()).or_default() += 1,
            Err(_) => panics += 1,
        }
    }
    ck.check(
        panics == 0 && !rk.contains_key("ACCEPTED"),
        format!("1000 random frames: panics={panics}, outcomes={rk:?}"),
    );
    // authenticated garbage: valid HPKE seal to B of random plaintext (reaches padding/parse/signature paths)
    let mut gk: BTreeMap<String, u64> = BTreeMap::new();
    let mut gpanics = 0;
    for i in 0..1000 {
        let n = (rand_u64() % 1100) as usize;
        let mut pt = vec![0u8; n];
        let _ = getrandom::fill(&mut pt);
        if i % 3 == 0 && n >= 8 {
            let inner = (n - 4).min(64 + (rand_u64() % 400) as usize) as u32;
            pt[..4].copy_from_slice(&inner.to_be_bytes());
            let start = 4 + inner as usize;
            if let Some(tail) = pt.get_mut(start..) {
                tail.fill(0);
            }
        }
        let f = seal_plaintext(&b.contact().kem_pk, &pt).unwrap_or_default();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            open_frame(&b.id, &b.addr, &f, now_ms(), &mut Dedupe::memory())
        })) {
            Ok(Ok(_)) => *gk.entry("ACCEPTED".into()).or_default() += 1,
            Ok(Err(e)) => *gk.entry(e.kind().into()).or_default() += 1,
            Err(_) => gpanics += 1,
        }
    }
    ck.check(
        gpanics == 0 && !gk.contains_key("ACCEPTED"),
        format!("1000 authenticated-garbage plaintexts: panics={gpanics}, outcomes={gk:?}"),
    );
    let data = json!({"frame_len": len, "bit_flips_by_region": by_region.iter().map(|(k, v)| (k.to_string(), json!({"flips": v.0, "rejected": v.1}))).collect::<BTreeMap<_, _>>(),
        "bit_flip_rejection_kinds": kinds, "truncations": {"lengths_tested": len, "rejected": trunc_rej, "kinds": trunc_kinds}, "extensions_rejected_of_64": ext_rej,
        "random_frames": {"n": 1000, "panics": panics, "outcomes": rk}, "authenticated_garbage": {"n": 1000, "panics": gpanics, "outcomes": gk}});
    ck.done("tamper", data)
}

// ------------------------------------------------------------------ 5. replay
pub async fn replay(ctx: &Ctx) -> TestResult {
    let mut ck = Checker::default();
    let (a, b) = (Ep::new(16), Ep::new(16));
    let tb = b.id.topic();
    let ddpath = ctx.work.join(format!("replay-dedupe-{}.txt", now_ms()));
    let _ = std::fs::remove_file(&ddpath);
    let bdd = Dedupe::open(&ddpath).unwrap_or_else(|_| Dedupe::memory());
    *lk(&b.dd) = bdd;
    let sent: SentMap = Arc::new(Mutex::new(HashMap::new()));
    let pb = subscribe_with_cb(ctx, NB, &tb, ep_cb(b.clone(), sent.clone())).await;
    ensure_mesh(ctx).await;
    let t0 = now_ns();
    let e = Envelope::new(&a.addr, &b.addr, "chat", "replay me".into(), TTL);
    let frame = send_env(ctx, NA, &a.id, &b.contact(), &e, PadPolicy::Pow2, None)
        .await
        .unwrap_or_default();
    tokio::time::sleep(Duration::from_secs(1)).await;
    // (1) identical frame re-published with a fresh Waku timestamp (distinct Waku message hash)
    let r2 = ctx.api.publish(NA, &tb, &frame).await;
    ck.check(
        r2.is_ok(),
        format!("re-publish of identical frame accepted by node ({r2:?})"),
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = pb.finish().await;
    {
        let rb = lk(&b.rx);
        ck.check(
            rb.ok.len() == 1,
            format!(
                "live: exactly 1 accepted of the 2 deliveries (accepted {})",
                rb.ok.len()
            ),
        );
        ck.check(
            rb.errs.get("replay").copied() == Some(1),
            format!("live: second delivery rejected as replay ({:?})", rb.errs),
        );
    }
    // (2) frames taken from a Store query after live receipt
    tokio::time::sleep(Duration::from_secs(1)).await;
    let st = ctx
        .api
        .store_all(NB, &tb, t0.saturating_sub(2_000_000_000), now_ns())
        .await;
    let mut store_results = vec![];
    match st {
        Ok(entries) => {
            for en in &entries {
                if let Some(m) = &en.message {
                    let p = B64.decode(&m.payload).unwrap_or_default();
                    let r = open_frame(&b.id, &b.addr, &p, now_ms(), &mut lk(&b.dd));
                    store_results.push(json!({"hash": en.message_hash, "ts": m.timestamp, "result": r.map(|_| "ACCEPTED".to_string()).unwrap_or_else(|e| e.kind().to_string())}));
                }
            }
            ck.check(
                entries.len() == 2,
                format!(
                    "store returned {} entries for the topic (expect 2: original + re-publish)",
                    entries.len()
                ),
            );
            ck.check(
                store_results.iter().all(|r| r["result"] == "replay"),
                "store-fetched copies all rejected as replay",
            );
        }
        Err(er) => ck.check(false, format!("store query failed: {er}")),
    }
    // (3) restart: reload dedupe from file
    let lines = std::fs::read_to_string(&ddpath)
        .map(|s| s.lines().count())
        .unwrap_or(0);
    ck.check(
        lines == 1,
        format!("dedupe file has 1 line (one accepted message): {lines}"),
    );
    drop(std::mem::replace(&mut *lk(&b.dd), Dedupe::memory()));
    let mut reloaded = Dedupe::open(&ddpath).unwrap_or_else(|_| Dedupe::memory());
    let after = open_frame(&b.id, &b.addr, &frame, now_ms(), &mut reloaded);
    ck.check(
        matches!(after, Err(OpenError::Replay)),
        format!(
            "after restart (reloaded {} entries from file): replay still rejected -> {:?}",
            reloaded.len(),
            after.as_ref().err().map(|e| e.kind())
        ),
    );
    // control: without the persisted set the frame is accepted (shows the dedupe is the only thing stopping it)
    let ctl = open_frame(&b.id, &b.addr, &frame, now_ms(), &mut Dedupe::memory());
    ck.check(
        ctl.is_ok(),
        "control: fresh empty dedupe accepts the same frame (dedupe is the defence)",
    );
    let data = json!({"dedupe_file": ddpath.display().to_string(), "dedupe_lines": lines, "live_errs": lk(&b.rx).errs, "store_results": store_results,
        "after_restart": after.map(|_| "ACCEPTED".to_string()).unwrap_or_else(|e| e.kind().to_string())});
    ck.done("replay", data)
}

// ------------------------------------------------------------------ 6. expiry / skew / version / unknown fields
pub async fn expiry(_ctx: &Ctx) -> TestResult {
    let mut ck = Checker::default();
    let (a, b) = (Ep::new(16), Ep::new(16));
    let bc = b.contact();
    let now = fnow();
    let mut cases: Vec<(String, Vec<u8>, &str)> = vec![];
    let base = |f: &dyn Fn(&mut Envelope)| {
        let mut e = Envelope::new(&a.addr, &b.addr, "chat", "t".into(), TTL);
        f(&mut e);
        e.to_bytes()
    };
    cases.push(("control: valid".into(), base(&|_| {}), "OK"));
    cases.push((
        "expires_at 5 min in the past (created 10 min ago)".into(),
        base(&|e| {
            e.created_at = now - 600_000;
            e.expires_at = now - 300_000;
        }),
        "expired",
    ));
    cases.push((
        "expires_at 60 s in the past (inside +-120 s skew)".into(),
        base(&|e| {
            e.created_at = now - 600_000;
            e.expires_at = now - 60_000;
        }),
        "OK",
    ));
    cases.push((
        "expires_at 130 s in the past (outside skew)".into(),
        base(&|e| {
            e.created_at = now - 600_000;
            e.expires_at = now - 130_000;
        }),
        "expired",
    ));
    cases.push((
        "created_at 10 min in the future".into(),
        base(&|e| {
            e.created_at = now + 600_000;
            e.expires_at = now + 1_200_000;
        }),
        "created_in_future",
    ));
    cases.push((
        "created_at 60 s in the future (inside skew)".into(),
        base(&|e| {
            e.created_at = now + 60_000;
            e.expires_at = now + 660_000;
        }),
        "OK",
    ));
    cases.push((
        "created_at 130 s in the future (outside skew)".into(),
        base(&|e| {
            e.created_at = now + 130_000;
            e.expires_at = now + 730_000;
        }),
        "created_in_future",
    ));
    cases.push((
        "expires_at == created_at".into(),
        base(&|e| {
            e.expires_at = e.created_at;
        }),
        "expires_before_created",
    ));
    cases.push((
        "v = 2".into(),
        base(&|e| e.v = 2),
        "unknown_envelope_version",
    ));
    cases.push((
        "v = 0".into(),
        base(&|e| e.v = 0),
        "unknown_envelope_version",
    ));
    cases.push((
        "message_id not a uuid v4".into(),
        base(&|e| e.message_id = "not-a-uuid".into()),
        "bad_message_id",
    ));
    cases.push((
        "sender not an address".into(),
        base(&|e| e.sender = "bob".into()),
        "bad_sender_address",
    ));
    let mut v: Value = serde_json::from_slice(&base(&|_| {})).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.insert(
            "x_future_field".into(),
            json!({"a": [1, 2, 3], "b": "ignored"}),
        );
    }
    cases.push((
        "unknown extra JSON field (signed by sender)".into(),
        serde_json::to_vec(&v).unwrap_or_default(),
        "OK",
    ));
    if let Some(o) = v.as_object_mut() {
        o.insert("v".into(), json!("1"));
    }
    cases.push((
        "v as string \"1\"".into(),
        serde_json::to_vec(&v).unwrap_or_default(),
        "envelope_parse",
    ));
    if let Some(o) = v.as_object_mut() {
        o.remove("v");
    }
    cases.push((
        "v missing".into(),
        serde_json::to_vec(&v).unwrap_or_default(),
        "envelope_parse",
    ));
    let mut deep = base(&|_| {});
    deep.pop(); // strip closing brace
    deep.extend_from_slice(b",\"x\":");
    deep.extend(std::iter::repeat_n(b'[', 50_000));
    deep.extend(std::iter::repeat_n(b']', 50_000));
    deep.push(b'}');
    cases.push((
        "unknown field nested 50000 deep (skipped iteratively by serde_json; no stack overflow)"
            .into(),
        deep,
        "OK",
    ));
    let mut trail = base(&|_| {});
    trail.extend_from_slice(b" garbage");
    cases.push((
        "trailing garbage after JSON".into(),
        trail,
        "envelope_parse",
    ));
    cases.push((
        "empty envelope bytes (inner length 64 = signature only)".into(),
        vec![],
        "bad_padding",
    ));
    let mut deepbody = base(&|_| {});
    let at = String::from_utf8_lossy(&deepbody)
        .find("\"body\":\"t\"")
        .unwrap_or(0);
    deepbody.truncate(at);
    deepbody.extend_from_slice(b"\"body\":");
    deepbody.extend(std::iter::repeat_n(b'[', 50_000));
    deepbody.extend(std::iter::repeat_n(b']', 50_000));
    deepbody.push(b'}');
    cases.push((
        "body field = 50000-deep array (wrong type)".into(),
        deepbody,
        "envelope_parse",
    ));
    let mut rows = vec![];
    for (name, env_bytes, expect) in cases {
        let got = match seal(&a.id.signing, &bc.kem_pk, &env_bytes, PadPolicy::Pow2) {
            Ok(f) => open_frame(&b.id, &b.addr, &f, now_ms(), &mut Dedupe::memory())
                .map(|_| "OK".to_string())
                .unwrap_or_else(|e| e.kind().to_string()),
            Err(e) => format!("seal error: {e}"),
        };
        ck.check(
            got == expect,
            format!("{name}: got {got}, expected {expect}"),
        );
        rows.push(json!({"case": name, "got": got, "expected": expect}));
    }
    // oversized frame
    let big = vec![0u8; MAX_FRAME_DEFAULT + 1];
    let r = open_frame(&b.id, &b.addr, &big, now_ms(), &mut Dedupe::memory());
    ck.check(
        matches!(r, Err(OpenError::TooLarge)),
        "frame > 160 KiB rejected before any crypto",
    );
    let data = json!({"skew_ms": SKEW_MS, "policy": "reject only unknown envelope `v`; unknown extra JSON fields are ignored (serde default) but still covered by the signature because the exact received bytes are verified; expires_at accepted until expires_at+skew; created_at accepted up to now+skew; no max-TTL rule implemented", "cases": rows});
    ck.done("expiry", data)
}

// ------------------------------------------------------------------ 8. boundaries
fn env_overhead(a: &str, b: &str) -> usize {
    Envelope::new(a, b, "chat", String::new(), TTL)
        .to_bytes()
        .len()
}
fn frame_len(a: &Ep, b: &PeerContact, body_len: usize, pad: PadPolicy) -> Option<usize> {
    let e = Envelope::new(&a.addr, &b.address, "chat", "a".repeat(body_len), TTL);
    seal(&a.id.signing, &b.kem_pk, &e.to_bytes(), pad)
        .ok()
        .map(|f| f.len())
}
fn max_body(a: &Ep, b: &PeerContact, pad: PadPolicy, limit: usize) -> usize {
    let (mut lo, mut hi) = (0usize, 400_000usize);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if frame_len(a, b, mid, pad).is_some_and(|l| l <= limit) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}
pub async fn boundaries(ctx: &Ctx) -> TestResult {
    let mut ck = Checker::default();
    let (a, b) = (Ep::new(16), Ep::new(16));
    let bc = b.contact();
    let tb = b.id.topic();
    let sent: SentMap = Arc::new(Mutex::new(HashMap::new()));
    let pb = subscribe_with_cb(ctx, NB, &tb, ep_cb(b.clone(), sent.clone())).await;
    ensure_mesh(ctx).await;
    // (a) raw node limit for this topic length: bisect random payload sizes
    let ok_at = |n: usize| {
        let api = ctx.api.clone();
        let tb = tb.clone();
        async move {
            let mut p = vec![0u8; n];
            let _ = getrandom::fill(&mut p);
            api.publish(NA, &tb, &p).await
        }
    };
    let (mut lo, mut hi) = (100_000usize, 153_700usize);
    while lo + 1 < hi {
        let mid = (lo + hi) / 2;
        if ok_at(mid).await.is_ok() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let pmax = lo;
    let mut over = vec![];
    for n in [
        pmax + 1,
        pmax + 2,
        pmax + 20,
        pmax + 100,
        200_000,
        2_000_000,
    ] {
        over.push(json!({"payload_bytes": n, "result": ok_at(n).await.err().unwrap_or("accepted".into())}));
    }
    log!("raw payload limit for topic {tb} ({} chars): max accepted {pmax} B; formula 153600-(len+51) = {}", tb.len(), max_payload(&tb));
    ck.check(
        pmax == max_payload(&tb),
        format!(
            "measured max payload {pmax} == formula {}",
            max_payload(&tb)
        ),
    );
    // (b) body limits for both padding policies
    let overhead = env_overhead(&a.addr, &b.addr);
    let pol_cap = PadPolicy::Pow2Capped(pmax - 52);
    let mb_pow2 = max_body(&a, &bc, PadPolicy::Pow2, pmax);
    let mb_cap = max_body(&a, &bc, pol_cap, pmax);
    log!("envelope JSON overhead (empty body) = {overhead} B; max ASCII body: pow2 = {mb_pow2} B, pow2 capped at plaintext {} = {mb_cap} B", pmax - 52);
    let mut table = vec![];
    for bl in [
        0usize,
        1,
        100,
        400,
        1_000,
        10_000,
        60_000,
        65_000,
        100_000,
        mb_pow2,
        mb_pow2 + 1,
        140_000,
        mb_cap,
        mb_cap + 1,
    ] {
        let f = frame_len(&a, &bc, bl, PadPolicy::Pow2);
        let fc = frame_len(&a, &bc, bl, pol_cap);
        table.push(json!({"body_len": bl, "frame_len_pow2": f, "fits_pow2": f.is_some_and(|x| x <= pmax), "frame_len_capped": fc, "fits_capped": fc.is_some_and(|x| x <= pmax),
            "base64_len_pow2": f.map(|x| x.div_ceil(3) * 4)}));
    }
    // (c) send the max bodies over the relay; verify decrypt; then oversize rejected locally, and bypass shows node's text
    let mut sends = vec![];
    for (name, pad, mb) in [
        ("pow2", PadPolicy::Pow2, mb_pow2),
        ("pow2_capped", pol_cap, mb_cap),
    ] {
        let body = "a".repeat(mb);
        let e = Envelope::new(&a.addr, &b.addr, "chat", body.clone(), TTL);
        let r = send_env(ctx, NA, &a.id, &bc, &e, pad, Some(&sent)).await;
        ck.check(
            r.is_ok(),
            format!("{name}: max body {mb} B published ({:?})", r.as_ref().err()),
        );
        let over_env = Envelope::new(&a.addr, &b.addr, "chat", "a".repeat(mb + 1), TTL);
        let ro = send_env(ctx, NA, &a.id, &bc, &over_env, pad, None).await;
        ck.check(
            ro.as_ref()
                .is_err_and(|e| e.contains("local reject") || e.contains("exceeds")),
            format!(
                "{name}: body {} rejected locally before publish: {:?}",
                mb + 1,
                ro.as_ref().err()
            ),
        );
        // bypass local check: publish the too-large Pow2 frame directly
        let big = seal(
            &a.id.signing,
            &bc.kem_pk,
            &over_env.to_bytes(),
            PadPolicy::Pow2,
        )
        .unwrap_or_default();
        let bypass = ctx.api.publish(NA, &tb, &big).await;
        ck.check(
            bypass.is_err(),
            format!(
                "{name}: bypassing the local check, node refuses the {} B frame: {:?}",
                big.len(),
                bypass.as_ref().err()
            ),
        );
        sends.push(json!({"policy": name, "max_body": mb, "published": r.is_ok(), "oversize_local_reject": ro.err(), "bypass_frame_len": big.len(), "bypass_node_response": bypass.err()}));
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    // (d) unicode byte-exact
    let uni = "emoji \u{1F980} \u{1F469}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466} \u{1F1EF}\u{1F1F5}; RTL: \u{5E9}\u{5DC}\u{5D5}\u{5DD} \u{5E2}\u{5D5}\u{5DC}\u{5DD} \u{645}\u{631}\u{62D}\u{628}\u{627} \u{202E}override\u{202C}; NUL: \0\0 ctl: \u{1}\u{7f}\u{1f}; sep: \u{2028}\u{2029}; bom: \u{feff}; quotes: \" \\ / \u{8}\u{c}\n\r\t; combining: e\u{301}".to_string();
    let ue = Envelope::new(&a.addr, &b.addr, "chat", uni.clone(), TTL);
    let ue_bytes = ue.to_bytes();
    let ur = send_env(ctx, NA, &a.id, &bc, &ue, PadPolicy::Pow2, Some(&sent)).await;
    ck.check(ur.is_ok(), "unicode envelope published");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = pb.finish().await;
    let rb = lk(&b.rx);
    let got_uni = rb.ok.iter().find(|o| o.id == ue.message_id);
    ck.check(
        got_uni.is_some_and(|o| o.body.as_bytes() == uni.as_bytes()),
        "unicode body round-trips byte-exact (String == String)",
    );
    ck.check(
        got_uni.is_some_and(|o| o.env_bytes == ue_bytes),
        "unicode envelope bytes received == bytes sealed (signature covers exact bytes)",
    );
    ck.check(
        rb.ok.iter().any(|o| o.body.len() == mb_pow2),
        format!("max pow2 body ({mb_pow2} B) decrypted at B"),
    );
    ck.check(
        rb.ok.iter().any(|o| o.body.len() == mb_cap),
        format!("max capped body ({mb_cap} B) decrypted at B"),
    );
    let nul_escaped = String::from_utf8_lossy(&ue_bytes).contains("\\u0000");
    ck.check(
        nul_escaped,
        "NUL appears as \\u0000 escape in the envelope JSON",
    );
    let data = json!({"topic": tb, "topic_len": tb.len(), "node_limit_bytes": WAKU_MAX_MSG, "measured_max_payload_bytes": pmax, "formula": "153600 - (topic_len + 51)",
        "oversize_probe": over, "envelope_json_overhead_bytes_empty_body": overhead, "max_ascii_body_pow2": mb_pow2, "max_ascii_body_pow2_capped": mb_cap,
        "cap_plaintext_bytes": pmax - 52, "frame_overhead_bytes": "4 header + 32 enc + 16 tag = 52; plaintext = 4 len + 64 sig + envelope + padding",
        "table": table, "relay_sends": sends, "b_errs": rb.errs, "unicode_body_utf8_len": uni.len()});
    ck.done("boundaries", data)
}

// ------------------------------------------------------------------ 10. relay-visible metadata
pub async fn metadata(ctx: &Ctx) -> TestResult {
    let mut ck = Checker::default();
    let (a, b) = (Ep::new(16), Ep::new(16));
    let bc = b.contact();
    let tb = b.id.topic();
    let sent: SentMap = Arc::new(Mutex::new(HashMap::new()));
    let pb = subscribe_with_cb(ctx, NB, &tb, ep_cb(b.clone(), sent.clone())).await;
    ensure_mesh(ctx).await;
    let t0 = now_ns();
    let overhead = {
        let mut t = Envelope::new(&a.addr, &b.addr, "task-request", String::new(), TTL);
        t.conversation_id = Some("conv-secret-0".into());
        t.to_bytes().len()
    };
    let cap512 = 512 - 4 - 64 - overhead; // body bytes that still fit the 512 bucket
    let lens = [1usize, cap512 - 1, cap512 + 50];
    let mut wire = vec![];
    for (i, bl) in lens.iter().enumerate() {
        let mut e = Envelope::new(&a.addr, &b.addr, "task-request", "z".repeat(*bl), TTL);
        e.conversation_id = Some(format!("conv-secret-{i}"));
        match send_env(ctx, NA, &a.id, &bc, &e, PadPolicy::Pow2, Some(&sent)).await {
            Ok(f) => wire.push((*bl, f.len(), e.message_id.clone(), f)),
            Err(er) => ck.check(false, format!("publish body {bl}: {er}")),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = pb.finish().await;
    let entries = ctx
        .api
        .store_all(R1, &tb, t0.saturating_sub(2_000_000_000), now_ns())
        .await;
    let mut dump = vec![];
    let mut store_lens = vec![];
    match &entries {
        Ok(es) => {
            for en in es {
                let m = en.message.as_ref();
                let plen = m.map(|m| B64.decode(&m.payload).map(|p| p.len()).unwrap_or(0));
                store_lens.push(plen.unwrap_or(0));
                let hdr = m
                    .and_then(|m| B64.decode(&m.payload).ok())
                    .map(|p| hex(p.get(..4).unwrap_or(&[])));
                let recomputed = m.map(|m| {
                    waku_hash(
                        en.pubsub_topic.as_deref().unwrap_or(PUBSUB),
                        &B64.decode(&m.payload).unwrap_or_default(),
                        &m.content_topic,
                        m.timestamp,
                    )
                });
                ck.check(recomputed.as_deref() == Some(en.message_hash.as_str()), format!("store hash {} == locally recomputed sha256(pubsub||payload||contentTopic||ts)", en.message_hash));
                dump.push(json!({"messageHash": en.message_hash, "pubsubTopic": en.pubsub_topic, "contentTopic": m.map(|m| m.content_topic.clone()), "timestamp_ns": m.map(|m| m.timestamp),
                    "payload_bytes": plen, "version": m.and_then(|m| m.version), "meta": m.and_then(|m| m.meta.clone()), "ephemeral": m.and_then(|m| m.ephemeral),
                    "payload_first4_hex(cleartext header)": hdr}));
            }
        }
        Err(e) => ck.check(false, format!("R1 store query: {e}")),
    }
    log!(
        "R1 store entries for topic {tb}:\n{}",
        serde_json::to_string_pretty(&dump).unwrap_or_default()
    );
    ck.check(
        store_lens.len() == 3,
        format!(
            "R1 store holds the 3 messages ({} entries)",
            store_lens.len()
        ),
    );
    let expect: Vec<usize> = wire.iter().map(|w| w.1).collect();
    ck.check(
        store_lens == expect,
        format!("store payload lengths {store_lens:?} == sealed frame lengths {expect:?}"),
    );
    ck.check(
        wire.len() == 3 && wire[0].1 == wire[1].1,
        format!(
            "bodies of {} B and {} B (same 512 bucket) -> identical payload length {}",
            lens[0],
            lens[1],
            wire.first().map(|w| w.1).unwrap_or(0)
        ),
    );
    ck.check(
        wire.len() == 3 && wire[2].1 > wire[1].1,
        format!(
            "body {} B (next bucket) -> payload {} B",
            lens[2],
            wire.get(2).map(|w| w.1).unwrap_or(0)
        ),
    );
    let rb = lk(&b.rx);
    ck.check(rb.ok.len() == 3, "B decrypted all 3");
    // does any envelope plaintext leak into the stored payload?
    let sample_env = Envelope::new(&a.addr, &b.addr, "task-request", "z".into(), TTL);
    let leaks: Vec<&str> = [
        sample_env.sender.as_str(),
        sample_env.recipient.as_str(),
        "task-request",
        "conv-secret",
        "zzzz",
        "message_id",
        "agentnet/v1",
    ]
    .into_iter()
    .filter(|needle| {
        wire.iter().any(|w| {
            w.3.windows(needle.len())
                .any(|win| win == needle.as_bytes())
        })
    })
    .collect();
    ck.check(
        leaks.is_empty(),
        format!("no envelope plaintext strings found in the 3 wire payloads (leaks: {leaks:?})"),
    );
    let data = json!({"recipient_topic": tb, "r1_store_dump": dump, "body_lens": lens, "frame_lens": expect, "bucket_512_body_capacity": cap512, "envelope_overhead": overhead,
        "visible_to_relay_and_store": ["pubsub topic (shard 66/0)", "content topic = recipient's inbox bucket (stable per recipient: 1 of 16 buckets, linkable over time)", "waku timestamp (publisher clock, ns)", "payload length (padding bucket: 512,1024,...)", "cleartext 4-byte frame header 'AN',0x01,0x01", "random 32-byte HPKE enc (unlinkable per message)", "waku message hash", "version/meta/ephemeral fields (all default)", "publisher's network address at the node it publishes through (not in store; UNTESTED beyond noting)"],
        "NOT_visible_in_payload": ["envelope.v", "message_id", "sender address", "recipient address (only the bucket is visible)", "type", "conversation_id", "correlation_id", "created_at", "expires_at", "body", "inner Ed25519 signature", "true body length within a bucket"]});
    ck.done("metadata", data)
}

// ------------------------------------------------------------------ micro-benchmark
pub async fn bench(_ctx: &Ctx) -> TestResult {
    let mut ck = Checker::default();
    let (a, b, c) = (Ep::new(16), Ep::new(16), Ep::new(16));
    let e = Envelope::new(&a.addr, &b.addr, "chat", "bench".into(), TTL);
    let eb = e.to_bytes();
    let frame = seal(&a.id.signing, &b.contact().kem_pk, &eb, PadPolicy::Pow2).unwrap_or_default();
    let n = 10_000u32;
    // 10 000 ops in 20 batches of 500; report mean over all ops, plus min and median batch mean (the host is shared and noisy)
    let time = |f: &mut dyn FnMut()| {
        let mut per_batch = vec![];
        for _ in 0..20 {
            let t = Instant::now();
            for _ in 0..n / 20 {
                f();
            }
            per_batch.push(t.elapsed().as_secs_f64() * 1e6 / (n / 20) as f64);
        }
        per_batch.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mean = per_batch.iter().sum::<f64>() / per_batch.len() as f64;
        json!({"mean_us": mean, "min_batch_us": per_batch[0], "median_batch_us": per_batch[10]})
    };
    // failed open by a non-recipient (the trial-decrypt cost)
    let mut fails = 0;
    let fail_us = time(&mut || {
        if decrypt_frame(&c.id, &frame, MAX_FRAME_DEFAULT).is_err() {
            fails += 1;
        }
    });
    ck.check(
        fails == n,
        format!("10000/10000 trial-opens by non-recipient failed ({fails})"),
    );
    let ok_us = time(&mut || {
        let _ = decrypt_frame(&b.id, &frame, MAX_FRAME_DEFAULT);
    });
    let mut count = 0;
    let full_us = time(&mut || {
        if open_frame(&b.id, &b.addr, &frame, now_ms(), &mut Dedupe::memory()).is_ok() {
            count += 1;
        }
    });
    ck.check(count == n, "10000 full opens (fresh dedupe) succeeded");
    let bc = b.contact();
    let seal_us = time(&mut || {
        let _ = seal(&a.id.signing, &bc.kem_pk, &eb, PadPolicy::Pow2);
    });
    let hdr_us = time(&mut || {
        let _ = decrypt_frame(&c.id, &frame[..40], MAX_FRAME_DEFAULT);
    });
    let data = json!({"n": n, "build": if cfg!(debug_assertions) { "DEBUG (numbers not representative; use --release)" } else { "release" }, "frame_len": frame.len(),
        "failed_open_non_recipient_us": fail_us, "successful_hpke_open_us": ok_us, "full_open_frame_incl_sig_verify_us": full_us, "seal_us": seal_us, "short_frame_reject_us": hdr_us,
        "host": "macOS arm64 native (not under qemu)"});
    log!(
        "{}",
        serde_json::to_string_pretty(&data).unwrap_or_default()
    );
    ck.done("bench", data)
}
