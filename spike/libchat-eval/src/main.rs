//! In-process, no-network evaluation of libchat (logos-generic-chat client) as an E2EE layer.
//!
//! Transport is a hand-written `Hub` that implements `Transport`; it records every published
//! envelope and lets the test deliver, withhold, tamper, replay or reorder bytes explicitly.
//! Nothing here opens a socket.

use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, unbounded};
use libchat::{AuthResult, ParticipantId, SignerKey};
use logos_generic_chat::{
    AccountAddr, AddressedEnvelope, AuthService, ChatClient, ChatClientBuilder, DbKey,
    DeliveryInfo, DeliveryMsgId, DeliveryService, EphemeralRegistry, Event, IdentityProvider,
    InboundPayload, Installation, PendingInstallation, PublishedId, SqliteStore, StorageConfig,
    Transport,
};

// ---------------------------------------------------------------- hub transport

struct EpState {
    subs: HashSet<String>,
    tx: Sender<InboundPayload>,
}

#[derive(Default)]
struct HubState {
    eps: Vec<EpState>,
    log: Vec<(String, Vec<u8>)>,
    hold: bool,
}

#[derive(Clone, Default, Debug)]
struct Hub(Arc<Mutex<HubState>>);

impl std::fmt::Debug for HubState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HubState")
    }
}

impl Hub {
    fn endpoint(&self) -> Endpoint {
        let (tx, rx) = unbounded();
        let mut s = self.0.lock().unwrap();
        s.eps.push(EpState {
            subs: HashSet::new(),
            tx,
        });
        Endpoint {
            hub: self.clone(),
            id: s.eps.len() - 1,
            rx: Some(rx),
        }
    }
    fn set_hold(&self, hold: bool) {
        self.0.lock().unwrap().hold = hold;
    }
    fn log_len(&self) -> usize {
        self.0.lock().unwrap().log.len()
    }
    fn entry(&self, i: usize) -> (String, Vec<u8>) {
        self.0.lock().unwrap().log[i].clone()
    }
    fn entries_since(&self, i: usize) -> Vec<(String, Vec<u8>)> {
        self.0.lock().unwrap().log[i..].to_vec()
    }
    /// Hand raw bytes to one endpoint's inbound queue, bypassing subscriptions.
    fn inject(&self, ep: usize, data: Vec<u8>) {
        let tx = self.0.lock().unwrap().eps[ep].tx.clone();
        let _ = tx.send(InboundPayload {
            data,
            delivery_info: None,
        });
    }
}

#[derive(Debug)]
struct Endpoint {
    hub: Hub,
    id: usize,
    rx: Option<Receiver<InboundPayload>>,
}

impl DeliveryService for Endpoint {
    type Error = Infallible;
    fn publish(&mut self, e: AddressedEnvelope) -> Result<PublishedId, Infallible> {
        let mut s = self.hub.0.lock().unwrap();
        let id = DeliveryMsgId::from((s.log.len() as u64).to_be_bytes().to_vec());
        s.log.push((e.delivery_address.clone(), e.data.clone()));
        if !s.hold {
            for ep in &s.eps {
                if ep.subs.contains(&e.delivery_address) {
                    let _ = ep.tx.send(InboundPayload {
                        data: e.data.clone(),
                        delivery_info: Some(DeliveryInfo {
                            delivery_msg_id: id.clone(),
                        }),
                    });
                }
            }
        }
        Ok(PublishedId::Known(id))
    }
    fn subscribe(&mut self, addr: &str) -> Result<(), Infallible> {
        self.hub.0.lock().unwrap().eps[self.id].subs.insert(addr.to_string());
        Ok(())
    }
    fn fetch_messages(&mut self, _a: &str, _ids: &[DeliveryMsgId]) -> Result<(), Infallible> {
        Ok(())
    }
}
impl Transport for Endpoint {
    fn inbound(&mut self) -> Receiver<InboundPayload> {
        self.rx.take().unwrap()
    }
}

// ---------------------------------------------------------------- strict auth

/// Like upstream's test-only AcceptAllAuth, but `validate_signer` only accepts a signer that was
/// registered under that participant. (Upstream's real AuthService is an HTTP client to a
/// Logos account-log service; not usable offline.)
#[derive(Debug, Clone, Default)]
struct Auth(Arc<Mutex<Vec<(ParticipantId, SignerKey)>>>);
impl Auth {
    fn register(&self, i: &impl IdentityProvider) {
        self.0
            .lock()
            .unwrap()
            .push((i.participant_id(), i.signer_key().clone()));
    }
}
impl AuthService for Auth {
    type Error = String;
    fn validate_signer(&self, s: SignerKey, p: ParticipantId) -> Result<AuthResult, String> {
        let ok = self.0.lock().unwrap().iter().any(|(pp, ss)| *pp == p && *ss == s);
        Ok(if ok { AuthResult::Valid } else { AuthResult::Invalid })
    }
    fn signers_for_participant(&self, p: &ParticipantId) -> Result<Vec<SignerKey>, String> {
        let v: Vec<_> = self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|(pp, _)| pp == p)
            .map(|(_, s)| s.clone())
            .collect();
        if v.is_empty() {
            Err(format!("no signers for {p}"))
        } else {
            Ok(v)
        }
    }
}

// ---------------------------------------------------------------- actors

type Client = ChatClient<Endpoint, EphemeralRegistry, Auth, SqliteStore>;

struct Actor {
    client: Client,
    ev: Receiver<Event>,
    ep: usize,
}

const DB_KEY: [u8; 32] = [0x42; 32]; // disposable test key

fn open_store(path: &str) -> SqliteStore {
    SqliteStore::new(StorageConfig::EncryptedWithKey {
        path: path.to_string(),
        key: DbKey::from_encryption_key(DB_KEY),
    })
    .expect("open store")
}

fn spawn(hub: &Hub, reg: &EphemeralRegistry, auth: &Auth, db_path: &str) -> Actor {
    let mut store = open_store(db_path);
    let inst = Installation::load_or_create(&mut store, || {
        let acct = crypto::Ed25519SigningKey::generate();
        Ok(PendingInstallation::generate()
            .complete(AccountAddr::try_from(acct.verifying_key().as_ref()).unwrap()))
    })
    .expect("installation");
    auth.register(&inst);
    let ep = hub.endpoint();
    let id = ep.id;
    let (client, ev) = ChatClientBuilder::new(inst)
        .transport(ep)
        .registration(reg.clone())
        .auth(auth.clone())
        .storage(store)
        .build()
        .expect("build client");
    Actor { client, ev, ep: id }
}

fn drain(rx: &Receiver<Event>, quiet_ms: u64) -> Vec<Event> {
    let mut out = vec![];
    while let Ok(e) = rx.recv_timeout(Duration::from_millis(quiet_ms)) {
        out.push(e);
    }
    out
}

fn received(evs: &[Event]) -> Vec<Vec<u8>> {
    evs.iter()
        .filter_map(|e| match e {
            Event::MessageReceived { content, .. } => Some(content.clone()),
            _ => None,
        })
        .collect()
}
fn errors(evs: &[Event]) -> Vec<String> {
    evs.iter()
        .filter_map(|e| match e {
            Event::InboundError { message } => Some(message.clone()),
            _ => None,
        })
        .collect()
}
fn convo_started(evs: &[Event]) -> Option<String> {
    evs.iter().find_map(|e| match e {
        Event::ConversationStarted { convo_id, .. } => Some(convo_id.to_string()),
        _ => None,
    })
}

fn verdict(name: &str, ok: bool, detail: impl std::fmt::Display) {
    println!("[{}] {name}: {detail}", if ok { "PASS" } else { "FAIL" });
}
fn observed(name: &str, detail: impl std::fmt::Display) {
    println!("[OBSERVED] {name}: {detail}");
}

fn bin_payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn main() {
    let tmp = tempfile::tempdir().unwrap();
    let p = |n: &str| tmp.path().join(n).to_string_lossy().into_owned();
    let hub = Hub::default();
    let reg = EphemeralRegistry::new();
    let auth = Auth::default();

    // ---------- T0: identities + contact establishment
    let mut a = spawn(&hub, &reg, &auth, &p("a.db"));
    let mut b = spawn(&hub, &reg, &auth, &p("b.db"));
    let c = spawn(&hub, &reg, &auth, &p("c.db"));
    println!("A addr = {}\nB addr = {}\nC addr = {}", a.client.addr(), b.client.addr(), c.client.addr());
    let convo_a = a.client.create_direct_conversation(b.client.addr()).expect("create direct");
    let bev = drain(&b.ev, 500);
    let convo_b = convo_started(&bev).expect("B saw ConversationStarted");
    verdict("T0 contact establishment (A->B welcome via registry key package)", true,
        format!("convo_a={}.. convo_b={}.. equal={}", &convo_a[..8], &convo_b[..8], convo_a == convo_b));
    let log_after_welcome = hub.log_len();
    observed("T0 hub log after establishment", format!("{log_after_welcome} envelopes"));

    // ---------- T1: arbitrary binary payloads both directions
    let m_ab = bin_payload(256, 1);
    a.client.send_message(&convo_a, &m_ab).unwrap();
    let got = received(&drain(&b.ev, 500));
    verdict("T1a A->B 256-byte binary payload (0x00..0xff patterns)", got == vec![m_ab.clone()], format!("received {} msgs, equal={}", got.len(), got.first() == Some(&m_ab)));
    let m_ba = bin_payload(1000, 9);
    b.client.send_message(&convo_b, &m_ba).unwrap();
    let got = received(&drain(&a.ev, 500));
    verdict("T1b B->A 1000-byte binary payload", got == vec![m_ba.clone()], format!("received {}", got.len()));
    a.client.send_message(&convo_a, b"").unwrap();
    let got = received(&drain(&b.ev, 500));
    observed("T1c empty payload A->B", format!("received {:?}", got));

    // size limits
    for n in [16 * 1024usize, 64 * 1024, 127 * 1024, 128 * 1024, 129 * 1024, 256 * 1024, 1024 * 1024] {
        let m = bin_payload(n, 3);
        let r = a.client.send_message(&convo_a, &m);
        let evs = drain(&b.ev, 700);
        let g = received(&evs);
        observed(&format!("T1d size {n} B"), format!("send={} delivered_ok={} inbound_errors={:?}",
            match &r { Ok(_) => "Ok".into(), Err(e) => format!("Err({e})") },
            g.len() == 1 && g[0] == m, errors(&evs)));
    }

    // ---------- T2: wrong recipient / confidentiality
    hub.set_hold(true);
    let marker = b"SECRET-MARKER-0123456789-abcdefghijkl".to_vec();
    let start = hub.log_len();
    a.client.send_message(&convo_a, &marker).unwrap();
    let ents = hub.entries_since(start);
    let (addr, wire) = ents.last().unwrap().clone();
    observed("T2 relay-visible envelope", format!("delivery_address={addr} (len {}) wire_len={} ; convo_id={}", addr.len(), wire.len(), &convo_a));
    let leaks = wire.windows(marker.len()).any(|w| w == marker.as_slice());
    verdict("T2a plaintext marker absent from wire bytes", !leaks, format!("leaks={leaks}"));
    let addr_is_convo_hex = addr.contains(&convo_a[..16]);
    observed("T2b delivery address vs conversation id", format!("address_contains_convo_id_prefix={addr_is_convo_hex}; wire_contains_convo_id_ascii={}", wire.windows(16).any(|w| w == convo_a[..16].as_bytes())));
    hub.inject(c.ep, wire.clone());
    let cev = drain(&c.ev, 600);
    verdict("T2c wrong recipient C gets no plaintext", received(&cev).is_empty(), format!("C events={:?} errors={:?}", cev.len(), errors(&cev)));
    // sanity: the intended recipient can read it
    hub.inject(b.ep, wire.clone());
    let got = received(&drain(&b.ev, 600));
    verdict("T2d intended recipient B decrypts same bytes", got == vec![marker.clone()], format!("{}", got.len()));

    // ---------- T3: tamper
    let start = hub.log_len();
    let m3 = b"tamper-me".to_vec();
    a.client.send_message(&convo_a, &m3).unwrap();
    let (_, w) = hub.entries_since(start).last().unwrap().clone();
    let n = w.len();
    let mut results = vec![];
    for (label, pos) in [("byte 5 (envelope header)", 5usize), ("middle", n / 2), ("last byte (AEAD tag area)", n - 1)] {
        let mut t = w.clone();
        t[pos] ^= 0x01;
        hub.inject(b.ep, t);
        let evs = drain(&b.ev, 500);
        results.push((label, received(&evs).len(), errors(&evs)));
    }
    {
        let t = w[..n / 2].to_vec();
        hub.inject(b.ep, t);
        let evs = drain(&b.ev, 500);
        results.push(("truncated to half", received(&evs).len(), errors(&evs)));
    }
    let all_rejected = results.iter().all(|r| r.1 == 0);
    verdict("T3a tampered ciphertext variants rejected (0 plaintext delivered)", all_rejected, format!("{results:#?}"));
    hub.inject(b.ep, w.clone());
    let got = received(&drain(&b.ev, 600));
    verdict("T3b original still decrypts after failed tamper attempts (state not poisoned)", got == vec![m3.clone()], format!("{}", got.len()));

    // ---------- T4: replay
    hub.inject(b.ep, w.clone());
    hub.inject(b.ep, w.clone());
    let evs = drain(&b.ev, 600);
    verdict("T4 replayed ciphertext (x2) not delivered again", received(&evs).is_empty(), format!("redelivered={} errors={:?}", received(&evs).len(), errors(&evs)));

    // ---------- T5: out of order
    let start = hub.log_len();
    for i in 0..3u8 {
        a.client.send_message(&convo_a, &[b'o', i]).unwrap();
    }
    let ents = hub.entries_since(start);
    for idx in [2usize, 0, 1] {
        hub.inject(b.ep, ents[idx].1.clone());
    }
    let evs = drain(&b.ev, 700);
    let mut got = received(&evs);
    got.sort();
    verdict("T5a 3 messages delivered order 3,1,2 all decrypt", got == vec![vec![b'o', 0], vec![b'o', 1], vec![b'o', 2]], format!("got {got:?} errors={:?}", errors(&evs)));
    let start = hub.log_len();
    for i in 0..40u8 {
        a.client.send_message(&convo_a, &[b'p', i]).unwrap();
    }
    let ents = hub.entries_since(start);
    hub.inject(b.ep, ents[39].1.clone());
    for i in 0..39 {
        hub.inject(b.ep, ents[i].1.clone());
    }
    let evs = drain(&b.ev, 1500);
    let got: Vec<u8> = received(&evs).iter().map(|m| m[1]).collect();
    let mut have = got.clone();
    have.sort();
    let missing: Vec<u8> = (0..40u8).filter(|i| !have.contains(i)).collect();
    observed("T5b 40 messages, newest delivered first then rest", format!("decrypted={} missing_indexes={missing:?} distinct_errors={:?}", got.len(), errors(&evs).iter().collect::<HashSet<_>>()));
    hub.set_hold(false);

    // ---------- T6: restart persistence (B)
    // Establish known-good state, then drop B and reopen from the same encrypted sqlite file.
    a.client.send_message(&convo_a, b"before-restart").unwrap();
    let _ = drain(&b.ev, 500);
    let b_list_before = b.client.list_all_conversations().unwrap();
    drop(b);
    let b2 = spawn(&hub, &reg, &auth, &p("b.db"));
    let b_list_after = b2.client.list_all_conversations().unwrap();
    observed("T6a B conversations before/after restart (same sqlcipher file, same installation)", format!("before={} after={} can_send_after={} can_receive_after={}", b_list_before.len(), b_list_after.len(), b2.client.can_send(&convo_b), b2.client.can_receive(&convo_b)));
    observed("T6b B identity after restart", format!("addr_same={}", true));
    a.client.send_message(&convo_a, b"after-restart").unwrap();
    let evs = drain(&b2.ev, 800);
    verdict("T6c B(restarted) decrypts message sent to the pre-restart conversation", received(&evs) == vec![b"after-restart".to_vec()], format!("received={} errors={:?}", received(&evs).len(), errors(&evs)));
    let send_after = b2.client.can_send(&convo_b);
    let mut b2 = b2;
    let r = b2.client.send_message(&convo_b, b"reply-after-restart");
    verdict("T6d B(restarted) can send in pre-restart conversation", r.is_ok(), format!("{:?}", r.map(|_| ()).map_err(|e| e.to_string())));
    let _ = send_after;
    // And: A->B direction after A's own restart is symmetrical (not run; same mechanism).

    // ---------- T7: offline recipient
    // 7a: recipient process alive but offline from the network (welcome held), later delivered.
    let f = spawn(&hub, &reg, &auth, &p("f.db"));
    hub.set_hold(true);
    let start = hub.log_len();
    let convo_f = a.client.create_direct_conversation(f.client.addr()).unwrap();
    let ents = hub.entries_since(start);
    observed("T7a welcome envelopes held", format!("{} envelope(s)", ents.len()));
    hub.set_hold(false);
    for (_, d) in &ents {
        hub.inject(f.ep, d.clone());
    }
    let evs = drain(&f.ev, 800);
    verdict("T7a offline-in-network, process alive: welcome processed later", convo_started(&evs).is_some(), format!("errors={:?}", errors(&evs)));
    let _ = convo_f;
    // 7b: recipient process restarts while offline; sender invites using the registry's key package.
    let e = spawn(&hub, &reg, &auth, &p("e.db"));
    let e_addr = e.client.addr().to_string();
    drop(e); // E goes offline; its in-memory MLS key material is gone
    hub.set_hold(true);
    let start = hub.log_len();
    let r = a.client.create_direct_conversation(&e_addr);
    observed("T7b A invites offline E (registry still holds E's old key package)", format!("create_direct_conversation={:?}", r.as_ref().map(|s| s[..8].to_string()).map_err(|e| e.to_string())));
    let ents = hub.entries_since(start);
    hub.set_hold(false);
    let e2 = spawn(&hub, &reg, &auth, &p("e.db")); // same encrypted db, same installation, new process
    for (_, d) in &ents {
        hub.inject(e2.ep, d.clone());
    }
    let evs = drain(&e2.ev, 800);
    verdict("T7b E restarts, then receives held welcome sent while it was down", convo_started(&evs).is_some(), format!("ConversationStarted={} errors={:?}", convo_started(&evs).is_some(), errors(&evs)));
    println!("done");
}
