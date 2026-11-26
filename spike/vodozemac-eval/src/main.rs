//! Spike A1 (fallback): in-process runtime evaluation of vodozemac 0.11.2 (Olm).
//!
//! Everything runs in one process with no network. Two "peers" are plain
//! `Account` / `Session` objects; "offline", "crash" and "two processes" are
//! simulated with encrypted pickles and by dropping or duplicating objects.
//!
//! Verdict convention (see docs/spike/notes-vodozemac.md):
//!   PASS            the property held / the behaviour is safe
//!   FAIL            the property did not hold, or a hazard was confirmed that an
//!                   application must compensate for
//!   NOT EXPRESSIBLE cannot be exercised through the public API (reason given)

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use vodozemac::olm::{
    Account, AccountPickle, DecryptionError, Message, OlmMessage, PreKeyMessage, Session,
    SessionConfig, SessionPickle,
};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature};

const PASS: &str = "PASS";
const FAIL: &str = "FAIL";
const NE: &str = "NOT EXPRESSIBLE";
const CFG: fn() -> SessionConfig = SessionConfig::version_1;
const PK: [u8; 32] = *b"0123456789abcdef0123456789abcdef";

// ---------------------------------------------------------------- reporting

struct Sub {
    name: String,
    verdict: &'static str,
    detail: String,
}

struct Test {
    id: u32,
    title: String,
    subs: Vec<Sub>,
    notes: Vec<String>,
    evidence: Map<String, Value>,
}

impl Test {
    fn new(id: u32, title: &str) -> Self {
        println!("\n=== T{id}: {title}");
        Test {
            id,
            title: title.into(),
            subs: vec![],
            notes: vec![],
            evidence: Map::new(),
        }
    }
    fn note(&mut self, s: impl AsRef<str>) {
        println!("   . {}", s.as_ref());
        self.notes.push(s.as_ref().to_string());
    }
    fn sub(&mut self, name: &str, verdict: &'static str, detail: impl AsRef<str>) {
        println!("  [{verdict}] {name}: {}", detail.as_ref());
        self.subs.push(Sub {
            name: name.into(),
            verdict,
            detail: detail.as_ref().into(),
        });
    }
    fn check(&mut self, name: &str, ok: bool, detail: impl AsRef<str>) {
        self.sub(name, if ok { PASS } else { FAIL }, detail);
    }
    fn ev(&mut self, k: &str, v: Value) {
        self.evidence.insert(k.into(), v);
    }
    fn overall(&self) -> &'static str {
        if self.subs.iter().any(|s| s.verdict == FAIL) {
            FAIL
        } else if self.subs.iter().any(|s| s.verdict == PASS) {
            PASS
        } else {
            NE
        }
    }
    fn json(&self) -> Value {
        json!({
            "id": self.id, "title": self.title, "verdict": self.overall(),
            "subs": self.subs.iter().map(|s| json!({"name": s.name, "verdict": s.verdict, "detail": s.detail})).collect::<Vec<_>>(),
            "notes": self.notes, "evidence": self.evidence,
        })
    }
}

fn err_txt<E: std::fmt::Display + std::fmt::Debug>(e: &E) -> String {
    format!("{e} [{e:?}]")
}

fn okerr<T, E: std::fmt::Display + std::fmt::Debug>(r: &Result<T, E>) -> String {
    match r {
        Ok(_) => "OK".to_string(),
        Err(e) => err_txt(e),
    }
}

fn variant<E: std::fmt::Debug>(e: &E) -> String {
    format!("{e:?}")
        .chars()
        .take_while(|c| c.is_alphanumeric())
        .collect()
}

// ------------------------------------------------------------------ helpers

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
}

fn payload(seed: u64, n: usize) -> Vec<u8> {
    Rng(seed | 1).bytes(n)
}

#[derive(Clone)]
struct Wire {
    kind: usize,
    bytes: Vec<u8>,
}
impl Wire {
    fn of(m: &OlmMessage) -> Wire {
        let (kind, bytes) = m.to_parts();
        Wire { kind, bytes }
    }
    fn msg(&self) -> OlmMessage {
        OlmMessage::from_parts(self.kind, &self.bytes).expect("wire decode")
    }
    fn is_prekey(&self) -> bool {
        self.kind == 0
    }
}

fn enc(s: &mut Session, p: &[u8]) -> Wire {
    Wire::of(&s.encrypt(p).expect("encrypt"))
}
fn dec(s: &mut Session, w: &Wire) -> Result<Vec<u8>, DecryptionError> {
    s.decrypt(&w.msg())
}
fn prekey(w: &Wire) -> PreKeyMessage {
    match w.msg() {
        OlmMessage::PreKey(p) => p,
        OlmMessage::Normal(_) => panic!("expected pre-key message"),
    }
}

fn acct_pickle(a: &Account) -> String {
    a.pickle().encrypt(&PK)
}
fn acct_load(s: &str) -> Account {
    Account::from_pickle(AccountPickle::from_encrypted(s, &PK).expect("account unpickle"))
}
fn sess_pickle(s: &Session) -> String {
    s.pickle().encrypt(&PK)
}
fn sess_load(s: &str) -> Session {
    Session::from_pickle(SessionPickle::from_encrypted(s, &PK).expect("session unpickle"))
}
fn sess_clone(s: &Session) -> Session {
    Session::from_pickle(s.pickle())
}
fn acct_clone(a: &Account) -> Account {
    Account::from_pickle(a.pickle())
}

fn otk_list(a: &Account) -> Vec<Curve25519PublicKey> {
    let mut v: Vec<_> = a.one_time_keys().into_iter().collect();
    v.sort_by_key(|(k, _)| *k);
    v.into_iter().map(|(_, k)| k).collect()
}

struct Pair {
    a: Account,
    b: Account,
    sa: Session,
    sb: Session,
    first: Wire,
}

/// A and B with an established session: A pre-key message -> B inbound -> B reply -> A decrypts.
fn pair() -> Pair {
    let a = Account::new();
    let mut b = Account::new();
    b.generate_one_time_keys(10);
    b.generate_fallback_key();
    let otk = otk_list(&b)[0];
    b.mark_keys_as_published();
    let mut sa = a
        .create_outbound_session(CFG(), b.curve25519_key(), otk)
        .unwrap();
    let first = enc(&mut sa, b"hello b");
    let pk = prekey(&first);
    let r = b
        .create_inbound_session(CFG(), a.curve25519_key(), &pk)
        .unwrap();
    let mut sb = r.session;
    let w = enc(&mut sb, b"hello a");
    dec(&mut sa, &w).unwrap();
    Pair {
        a,
        b,
        sa,
        sb,
        first,
    }
}

/// Chain-position fields of a normal message: (ratchet key bytes, chain index).
fn ratchet_and_index(bytes: &[u8]) -> (Vec<u8>, u64) {
    // layout: version(1) | 0x0a 0x20 ratchet_key(32) | 0x10 varint(chain_index) | ...
    let rk = bytes[3..35].to_vec();
    let (mut idx, mut shift, mut i) = (0u64, 0, 36);
    loop {
        let b = bytes[i];
        idx |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        i += 1;
    }
    (rk, idx)
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}

fn us(d: Duration, n: usize) -> f64 {
    d.as_secs_f64() * 1e6 / n as f64
}

// ------------------------------------------------------------------- bundle
// Application-defined (NOT part of vodozemac): signed key bundle. The library only offers
// `Account::sign` and `Ed25519PublicKey::verify` (verify_strict); the format is ours.

#[derive(Serialize, Deserialize, Clone)]
struct SignedKey {
    key: String,
    sig: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct Bundle {
    v: u32,
    ed25519: String,
    curve25519: String,
    identity_sig: String,
    otks: Vec<SignedKey>,
    fallback: Option<SignedKey>,
}

fn id_msg(ed: &Ed25519PublicKey, cv: &Curve25519PublicKey) -> Vec<u8> {
    let mut m = b"agentnet-olm-eval/v1/identity\0".to_vec();
    m.extend_from_slice(ed.as_bytes());
    m.extend_from_slice(cv.as_bytes());
    m
}
fn key_msg(label: &[u8], ident: &Curve25519PublicKey, key: &Curve25519PublicKey) -> Vec<u8> {
    let mut m = b"agentnet-olm-eval/v1/".to_vec();
    m.extend_from_slice(label);
    m.push(0);
    m.extend_from_slice(ident.as_bytes());
    m.extend_from_slice(key.as_bytes());
    m
}

/// Generate keys, sign them, mark as published. Returns the bundle of the *newly generated* keys.
fn make_bundle(acct: &mut Account, new_otks: usize, new_fallback: bool) -> Bundle {
    if new_otks > 0 {
        acct.generate_one_time_keys(new_otks);
    }
    if new_fallback {
        acct.generate_fallback_key();
    }
    let ik = acct.identity_keys();
    let otks = otk_list(acct)
        .into_iter()
        .map(|k| SignedKey {
            key: k.to_base64(),
            sig: acct.sign(key_msg(b"otk", &ik.curve25519, &k)).to_base64(),
        })
        .collect();
    let fallback = acct.fallback_key().into_values().next().map(|k| SignedKey {
        key: k.to_base64(),
        sig: acct
            .sign(key_msg(b"fallback", &ik.curve25519, &k))
            .to_base64(),
    });
    acct.mark_keys_as_published();
    Bundle {
        v: 1,
        ed25519: ik.ed25519.to_base64(),
        curve25519: ik.curve25519.to_base64(),
        identity_sig: acct.sign(id_msg(&ik.ed25519, &ik.curve25519)).to_base64(),
        otks,
        fallback,
    }
}

struct Verified {
    ed: Ed25519PublicKey,
    cv: Curve25519PublicKey,
    otks: Vec<Curve25519PublicKey>,
    fallback: Option<Curve25519PublicKey>,
}

fn verify_bundle(b: &Bundle, pinned_ed: Option<&Ed25519PublicKey>) -> Result<Verified, String> {
    let ed = Ed25519PublicKey::from_base64(&b.ed25519).map_err(|e| format!("ed25519 key: {e}"))?;
    if let Some(p) = pinned_ed {
        if *p != ed {
            return Err(
                "ed25519 key does not match the pinned/expected key for this address".into(),
            );
        }
    }
    let cv = Curve25519PublicKey::from_base64(&b.curve25519)
        .map_err(|e| format!("curve25519 key: {e}"))?;
    let sig =
        Ed25519Signature::from_base64(&b.identity_sig).map_err(|e| format!("identity sig: {e}"))?;
    ed.verify(&id_msg(&ed, &cv), &sig)
        .map_err(|e| format!("identity signature invalid: {e}"))?;
    let mut otks = vec![];
    for k in &b.otks {
        let key = Curve25519PublicKey::from_base64(&k.key).map_err(|e| e.to_string())?;
        let sig = Ed25519Signature::from_base64(&k.sig).map_err(|e| e.to_string())?;
        ed.verify(&key_msg(b"otk", &cv, &key), &sig)
            .map_err(|e| format!("otk signature invalid: {e}"))?;
        otks.push(key);
    }
    let fallback = match &b.fallback {
        Some(k) => {
            let key = Curve25519PublicKey::from_base64(&k.key).map_err(|e| e.to_string())?;
            let sig = Ed25519Signature::from_base64(&k.sig).map_err(|e| e.to_string())?;
            ed.verify(&key_msg(b"fallback", &cv, &key), &sig)
                .map_err(|e| format!("fallback signature invalid: {e}"))?;
            Some(key)
        }
        None => None,
    };
    Ok(Verified {
        ed,
        cv,
        otks,
        fallback,
    })
}

// ---------------------------------------------------------------------- T1

fn t1() -> Test {
    let mut t = Test::new(
        1,
        "Identity = Olm Account; signed key bundle; what the app must add",
    );
    let mut b = Account::new();
    let ik = b.identity_keys();
    t.note(format!(
        "Account::new(); identity_keys(): curve25519={} ed25519={}",
        ik.curve25519.to_base64(),
        ik.ed25519.to_base64()
    ));
    let bundle = make_bundle(&mut b, 4, true);
    let json = serde_json::to_string(&bundle).unwrap();
    t.note(format!(
        "bundle JSON ({} bytes) with 4 OTKs + 1 fallback key",
        json.len()
    ));
    t.ev("bundle_json_bytes", json!(json.len()));
    t.ev("bundle_example", serde_json::to_value(&bundle).unwrap());
    t.note(format!(
        "after mark_keys_as_published(): one_time_keys().len()={} fallback_key().len()={} stored_one_time_key_count()={} (the Account no longer lists published public keys; the app must keep its own copy)",
        b.one_time_keys().len(), b.fallback_key().len(), b.stored_one_time_key_count()
    ));
    t.check(
        "account no longer exposes published OTK public keys",
        false,
        "one_time_keys()/fallback_key() return only UNPUBLISHED keys; the app must store the public keys it published (needed to rebuild a static contact record)",
    );

    let pinned = ik.ed25519;
    match verify_bundle(&bundle, Some(&pinned)) {
        Ok(v) => t.check(
            "valid bundle verifies (identity self-signature + each OTK + fallback, verify_strict)",
            v.otks.len() == 4
                && v.fallback.is_some()
                && v.cv == ik.curve25519
                && v.ed == ik.ed25519,
            "4 OTK signatures + fallback signature + identity binding verified",
        ),
        Err(e) => t.sub("valid bundle verifies", FAIL, e),
    }

    // OTK substituted by an attacker (relay-level MITM) keeping the genuine signature.
    let mut evil = bundle.clone();
    let attacker = Account::new();
    let mut atk = attacker;
    atk.generate_one_time_keys(1);
    evil.otks[0].key = otk_list(&atk)[0].to_base64();
    t.check(
        "substituted OTK rejected",
        verify_bundle(&evil, Some(&pinned)).is_err(),
        format!("{:?}", verify_bundle(&evil, Some(&pinned)).err()),
    );
    // Identity curve key substituted.
    let mut evil2 = bundle.clone();
    evil2.curve25519 = atk.curve25519_key().to_base64();
    t.check(
        "substituted identity Curve25519 key rejected (identity signature binds curve25519 to ed25519)",
        verify_bundle(&evil2, Some(&pinned)).is_err(),
        format!("{:?}", verify_bundle(&evil2, Some(&pinned)).err()),
    );
    // Fully attacker-generated, self-consistent bundle.
    let evil3 = make_bundle(&mut atk, 2, true);
    let self_consistent = verify_bundle(&evil3, None).is_ok();
    let with_pin = verify_bundle(&evil3, Some(&pinned));
    t.check(
        "attacker's own self-signed bundle rejected by the address pin",
        with_pin.is_err(),
        format!(
            "without a pinned key the attacker bundle verifies={self_consistent} (signatures alone prove nothing about WHO); with the expected Ed25519 key pinned: {:?}",
            with_pin.err()
        ),
    );
    t.note("What vodozemac provides: Account::sign / Ed25519PublicKey::verify and key generation. What it does NOT provide: a bundle format, binding of the Ed25519 key to an AgentNet address, contact verification, key expiry/revocation, one-time-key directory. In AgentNet the address is the signing key, so the pin check is 'bundle.ed25519 == address key'; the identity self-signature (domain-separated, ours) is what ties the Curve25519 identity key to that address.");
    t
}

// ---------------------------------------------------------------------- T2

fn t2() -> Test {
    let mut t = Test::new(
        2,
        "Offline establishment, 3 pre-key messages, reply, binary payloads",
    );
    let mut b = Account::new();
    let bundle = make_bundle(&mut b, 5, true);
    let b_pickle = acct_pickle(&b);
    let b_curve = b.curve25519_key();
    drop(b); // B is gone: only its published bundle and its pickle on disk remain.
    t.note("B generated+published bundle, pickled itself (encrypted) and was dropped: offline");

    let a = Account::new();
    let v = verify_bundle(&bundle, None).unwrap();
    let mut sa = a.create_outbound_session(CFG(), v.cv, v.otks[0]).unwrap();
    let sizes = [0usize, 1024, 100 * 1024];
    let sent: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(i, n)| payload(10 + i as u64, *n))
        .collect();
    let wires: Vec<Wire> = sent.iter().map(|p| enc(&mut sa, p)).collect();
    t.check(
        "A sends 3 pre-key messages (all type 0) without B being touched",
        wires.iter().all(|w| w.is_prekey()),
        format!(
            "types={:?} wire sizes={:?}",
            wires.iter().map(|w| w.kind).collect::<Vec<_>>(),
            wires.iter().map(|w| w.bytes.len()).collect::<Vec<_>>()
        ),
    );

    // B returns.
    let mut b = acct_load(&b_pickle);
    t.check(
        "B restored from encrypted pickle has same identity",
        b.curve25519_key() == b_curve,
        "ok",
    );
    let pk0 = prekey(&wires[0]);
    let r = b
        .create_inbound_session(CFG(), pk0.identity_key(), &pk0)
        .unwrap();
    let mut sb = r.session;
    let mut ok = r.plaintext == sent[0];
    for i in 1..3 {
        ok &= dec(&mut sb, &wires[i])
            .map(|p| p == sent[i])
            .unwrap_or(false);
    }
    t.check("B inbound session from first pre-key message decrypts all 3, byte-exact (0 B, 1 KiB, 100 KiB)", ok, format!("session_id equal={}", sa.session_id() == sb.session_id()));

    let replies: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(i, n)| payload(20 + i as u64, *n))
        .collect();
    let rw: Vec<Wire> = replies.iter().map(|p| enc(&mut sb, p)).collect();
    let kinds: Vec<usize> = rw.iter().map(|w| w.kind).collect();
    let mut ok = true;
    for (w, p) in rw.iter().zip(&replies) {
        ok &= dec(&mut sa, w).map(|x| &x == p).unwrap_or(false);
    }
    t.check(
        "B reply (3 messages, same sizes) decrypted by A byte-exact",
        ok,
        format!("reply wire types={kinds:?} (1 = normal message)"),
    );
    let w = enc(&mut sa, b"after-reply");
    t.check(
        "after A receives a reply, A's next message is a normal message (not pre-key)",
        !w.is_prekey() && dec(&mut sb, &w).unwrap() == b"after-reply",
        format!("type={}", w.kind),
    );
    t
}

// ---------------------------------------------------------------------- T3

fn t3() -> Test {
    let mut t = Test::new(3, "One-time key exhaustion and fallback key");
    // S1: directory-style claiming (each OTK handed out once), 2 OTKs + fallback, 3 senders.
    let mut b = Account::new();
    let bundle = make_bundle(&mut b, 2, true);
    let v = verify_bundle(&bundle, None).unwrap();
    let mut senders: Vec<Account> = (0..4).map(|_| Account::new()).collect();
    let claims = [
        v.otks[0],
        v.otks[1],
        v.fallback.unwrap(),
        v.fallback.unwrap(),
    ];
    let mut firsts = vec![];
    for (i, s) in senders.iter_mut().enumerate() {
        let mut sess = s.create_outbound_session(CFG(), v.cv, claims[i]).unwrap();
        firsts.push((
            enc(&mut sess, format!("from sender {i}").as_bytes()),
            s.curve25519_key(),
        ));
    }
    t.note(format!(
        "B stored_one_time_key_count before = {}",
        b.stored_one_time_key_count()
    ));
    let mut results = vec![];
    for (i, (w, ik)) in firsts.iter().enumerate() {
        let pk = prekey(w);
        match b.create_inbound_session(CFG(), *ik, &pk) {
            Ok(r) => results.push(format!(
                "sender {i}: OK ({} bytes plaintext)",
                r.plaintext.len()
            )),
            Err(e) => results.push(format!("sender {i}: ERR {}", err_txt(&e))),
        }
    }
    t.note(format!(
        "B stored_one_time_key_count after 4 inbound = {}",
        b.stored_one_time_key_count()
    ));
    for r in &results {
        t.note(r.clone());
    }
    t.check(
        "third and fourth sender can still establish via the fallback key (fallback is reusable)",
        results.iter().all(|r| r.contains("OK")),
        "OTK1->s0, OTK2->s1, fallback->s2 and s3",
    );
    // What FS is lost: replaying the captured pre-key messages against a LATER copy of B's account.
    let later = acct_pickle(&b);
    let mut replay = vec![];
    for (i, (w, ik)) in firsts.iter().enumerate() {
        let mut bl = acct_load(&later);
        let pk = prekey(w);
        replay.push(match bl.create_inbound_session(CFG(), *ik, &pk) {
            Ok(_) => format!("sender {i}: pre-key message STILL establishes a session from the later account state"),
            Err(e) => format!("sender {i}: later state cannot re-establish: {}", err_txt(&e)),
        });
    }
    for r in &replay {
        t.note(r.clone());
    }
    t.check(
        "OTK-established sessions cannot be re-derived from a later account state",
        replay[0].contains("cannot") && replay[1].contains("cannot"),
        "OTK private key deleted on use",
    );
    t.check(
        "fallback-established first flight is NOT re-derivable from a later account state (forward secrecy of the first flight)",
        replay[2].contains("cannot") && replay[3].contains("cannot"),
        "the fallback private key stays in the account (current + previous) and is not removed on use; a replayed pre-key message to it also creates a duplicate session",
    );
    t.ev("exhaustion_results", json!(results));
    t.ev("replay_against_later_state", json!(replay));

    // S2: static bundle in a contact record: two senders pick the same OTK.
    let mut b = Account::new();
    let bundle = make_bundle(&mut b, 2, false);
    let v = verify_bundle(&bundle, None).unwrap();
    let (a1, a2) = (Account::new(), Account::new());
    let mut s1 = a1.create_outbound_session(CFG(), v.cv, v.otks[0]).unwrap();
    let mut s2 = a2.create_outbound_session(CFG(), v.cv, v.otks[0]).unwrap();
    let (w1, w2) = (enc(&mut s1, b"first"), enc(&mut s2, b"second"));
    let r1 = b.create_inbound_session(CFG(), a1.curve25519_key(), &prekey(&w1));
    let r2 = b.create_inbound_session(CFG(), a2.curve25519_key(), &prekey(&w2));
    let r2s = match &r2 {
        Ok(_) => "OK".to_string(),
        Err(e) => err_txt(e),
    };
    t.note(format!(
        "static bundle, no fallback, two senders use the same OTK: first={} second={}",
        r1.is_ok(),
        r2s
    ));
    t.check(
        "static bundle without fallback: two senders using the same OTK both establish",
        r2.is_ok(),
        format!("error on 2nd sender: {r2s} (no 'out of keys' signal at the sender: the sender cannot know the OTK was consumed)"),
    );
    // S3: fallback rotation.
    let mut b = Account::new();
    let bundle0 = make_bundle(&mut b, 0, true);
    let fk0 = verify_bundle(&bundle0, None).unwrap().fallback.unwrap();
    let a = Account::new();
    let mut sa = a
        .create_outbound_session(CFG(), b.curve25519_key(), fk0)
        .unwrap();
    let w = enc(&mut sa, b"old fallback");
    let mut ok_after = vec![];
    for n in 1..=3 {
        make_bundle(&mut b, 0, true); // rotate fallback: keeps current + previous only
        let mut bc = acct_clone(&b);
        ok_after.push(format!(
            "after {n} fallback rotation(s): {}",
            match bc.create_inbound_session(CFG(), a.curve25519_key(), &prekey(&w)) {
                Ok(_) => "old-fallback first flight still accepted".to_string(),
                Err(e) => format!("rejected: {}", err_txt(&e)),
            }
        ));
    }
    for r in &ok_after {
        t.note(r.clone());
    }
    t.check(
        "fallback rotation: the account keeps current+previous fallback keys only (a contact record older than one rotation stops working)",
        ok_after[0].contains("accepted") && ok_after[1].contains("rejected"),
        ok_after.join(" | "),
    );
    t.note(format!(
        "limits: Account::max_number_of_one_time_keys()={} (keys the app should keep published); internal store cap 5000 (oldest silently dropped, reported in OneTimeKeyGenerationResult::removed)",
        Account::new().max_number_of_one_time_keys()
    ));
    t
}

// ---------------------------------------------------------------------- T4

fn t4() -> Test {
    let mut t = Test::new(4, "Persistence and crash safety");
    // (a) full persistence round trip
    let mut p = pair();
    for i in 0..2 {
        let w = enc(&mut p.sa, format!("a->b {i}").as_bytes());
        dec(&mut p.sb, &w).unwrap();
        let w = enc(&mut p.sb, format!("b->a {i}").as_bytes());
        dec(&mut p.sa, &w).unwrap();
    }
    let w = enc(&mut p.sa, b"a->b tail");
    dec(&mut p.sb, &w).unwrap();
    let (pa, pb, psa, psb) = (
        acct_pickle(&p.a),
        acct_pickle(&p.b),
        sess_pickle(&p.sa),
        sess_pickle(&p.sb),
    );
    t.ev("pickle_chars", json!({"account_a": pa.len(), "account_b": pb.len(), "session_a": psa.len(), "session_b": psb.len()}));
    t.note(format!(
        "encrypted pickle sizes (base64 chars): account A={} B={}, session A={} B={}",
        pa.len(),
        pb.len(),
        psa.len(),
        psb.len()
    ));
    let wrong = {
        let mut k = PK;
        k[0] ^= 1;
        k
    };
    let bad = SessionPickle::from_encrypted(&psa, &wrong)
        .err()
        .map(|e| e.to_string());
    let corrupt = {
        let mut s = psa.clone().into_bytes();
        let mid = s.len() / 2;
        s[mid] = if s[mid] == b'A' { b'B' } else { b'A' };
        SessionPickle::from_encrypted(&String::from_utf8(s).unwrap(), &PK)
            .err()
            .map(|e| e.to_string())
    };
    t.check(
        "pickle with wrong key / corrupted body is rejected",
        bad.is_some() && corrupt.is_some(),
        format!("wrong key: {bad:?}; corrupted: {corrupt:?}"),
    );
    drop(p);
    let (_a, _b) = (acct_load(&pa), acct_load(&pb));
    let (mut sa, mut sb) = (sess_load(&psa), sess_load(&psb));
    let w = enc(&mut sa, b"after restart a->b");
    let r1 = dec(&mut sb, &w)
        .map(|x| x == b"after restart a->b")
        .unwrap_or(false);
    let w = enc(&mut sb, b"after restart b->a");
    let r2 = dec(&mut sa, &w)
        .map(|x| x == b"after restart b->a")
        .unwrap_or(false);
    let w = enc(&mut sa, b"second turn");
    let r3 = dec(&mut sb, &w).is_ok();
    t.check(
        "drop everything, unpickle accounts+sessions, conversation continues in both directions",
        r1 && r2 && r3,
        "a->b, b->a, then another ratchet turn",
    );

    // (b) send-side crash: encrypt, do not persist, reload the old pickle, encrypt again
    let mut p = pair();
    let w = enc(&mut p.sa, b"warmup");
    dec(&mut p.sb, &w).unwrap();
    let p0 = sess_pickle(&p.sa); // last persisted state of A
    let common = vec![0x41u8; 32];
    let (m1, m2) = (
        [common.clone(), b"-FIRST".to_vec()].concat(),
        [common.clone(), b"-SECOND".to_vec()].concat(),
    );
    let c1 = enc(&mut p.sa, &m1); // ciphertext released WITHOUT persisting
    let d1 = dec(&mut p.sb, &c1); // peer receives and persists
    let mut sa = sess_load(&p0); // crash + restart from old pickle
    let c2 = enc(&mut sa, &m2);
    let (rk1, i1) = ratchet_and_index(&c1.bytes);
    let (rk2, i2) = ratchet_and_index(&c2.bytes);
    let (ct1, ct2) = (
        match c1.msg() {
            OlmMessage::Normal(m) => Message::ciphertext(&m).to_vec(),
            _ => vec![],
        },
        match c2.msg() {
            OlmMessage::Normal(m) => Message::ciphertext(&m).to_vec(),
            _ => vec![],
        },
    );
    let common_prefix = ct1.iter().zip(&ct2).take_while(|(a, b)| a == b).count();
    t.note(format!(
        "C1: ratchet_key={} chain_index={i1}; C2 (after reload): ratchet_key={} chain_index={i2}",
        hex8(&rk1),
        hex8(&rk2)
    ));
    t.check(
        "send-side rollback is harmless: no ratchet key / chain index / message key reuse",
        !(rk1 == rk2 && i1 == i2),
        format!("same ratchet key={} same index={}; the two ciphertexts share a {common_prefix}-byte identical prefix (plaintexts share a 32-byte prefix) => same AES key and IV were used twice", rk1 == rk2, i1 == i2),
    );
    let r_c2 = dec(&mut p.sb, &c2);
    t.check(
        "send-side rollback: the re-encrypted message C2 is accepted by the peer",
        r_c2.is_ok(),
        format!(
            "B decrypt(C1)={:?}, decrypt(C2)={}",
            d1.map(|x| x.len()),
            match &r_c2 {
                Ok(_) => "OK".into(),
                Err(e) => err_txt(e),
            }
        ),
    );
    let c3 = enc(&mut sa, b"third");
    let r_c3 = dec(&mut p.sb, &c3);
    t.note(format!(
        "next message C3 from the reloaded A (chain_index {}): {}",
        ratchet_and_index(&c3.bytes).1,
        match &r_c3 {
            Ok(_) =>
                "accepted by B: the session is NOT desynchronised, exactly one message was lost"
                    .into(),
            Err(e) => err_txt(e),
        }
    ));
    t.check("send-side rollback: no message is lost (session survives, but C2 was lost and key material was reused)", false, "this is the cost of violating 'persist before release'");
    // reverse arrival order: C2 first -> C1 is the one rejected
    let mut p = pair();
    let w = enc(&mut p.sa, b"warmup");
    dec(&mut p.sb, &w).unwrap();
    let p0 = sess_pickle(&p.sa);
    let c1 = enc(&mut p.sa, &m1);
    let mut sa = sess_load(&p0);
    let c2 = enc(&mut sa, &m2);
    let got2 = dec(&mut p.sb, &c2).map(|x| String::from_utf8_lossy(&x[32..]).to_string());
    let got1 = dec(&mut p.sb, &c1);
    t.note(format!(
        "if C2 arrives first: B accepts {:?}, then C1 -> {}",
        got2,
        match &got1 {
            Ok(_) => "OK".into(),
            Err(e) => err_txt(e),
        }
    ));
    t.note("so which of two authentic messages is delivered depends on arrival order; the sender cannot tell");
    // correct order of operations
    let mut p = pair();
    let w = enc(&mut p.sa, b"warmup");
    dec(&mut p.sb, &w).unwrap();
    let c1 = enc(&mut p.sa, &m1);
    let p1 = sess_pickle(&p.sa); // PERSIST, then release c1
    let _ = c1; // (released; lost in flight in this variant)
    let mut sa = sess_load(&p1); // crash after persist
    let c2 = enc(&mut sa, &m2);
    let r = dec(&mut p.sb, &c2);
    t.check("persist-before-release: crash after persist, next message uses a fresh key and is accepted (C1 undelivered is simply skipped)", r.is_ok(), format!("{:?}", r.map(|x| x.len()).map_err(|e| err_txt(&e))));

    // (c) receive-side
    let mut p = pair();
    let w = enc(&mut p.sa, b"warmup");
    dec(&mut p.sb, &w).unwrap();
    let pb0 = sess_pickle(&p.sb); // persisted state of B before receiving c
    let c = enc(&mut p.sa, b"message that B receives");
    let first = dec(&mut p.sb, &c); // B decrypts, does not persist, crashes
    let mut sb = sess_load(&pb0);
    let again = dec(&mut sb, &c);
    t.check(
        "receive-side rollback: replay of an already-decrypted message is rejected after reloading the old pickle",
        again.is_err(),
        format!("first={:?} again-after-reload={:?}", first.is_ok(), again.as_ref().map(|x| x.len()).map_err(err_txt)),
    );
    let mut p = pair();
    let w = enc(&mut p.sa, b"warmup");
    dec(&mut p.sb, &w).unwrap();
    let c = enc(&mut p.sa, b"message that B receives");
    dec(&mut p.sb, &c).unwrap();
    let pb1 = sess_pickle(&p.sb); // persisted after decrypt
    let mut sb = sess_load(&pb1);
    let again = dec(&mut sb, &c);
    t.check(
        "receive-side with persisted state: the same ciphertext is rejected",
        again.is_err(),
        okerr(&again),
    );
    t.note("converse hazard: if the ratchet state is persisted but the process dies before the plaintext is stored/acked, redelivery of the ciphertext is rejected (the message key is gone) and the message content is lost; ratchet state and the received message must be committed in ONE atomic transaction");
    t.note("RULE (sender): encrypt -> persist session pickle (fsync/atomic rename) -> only then release ciphertext to the transport. RULE (receiver): decrypt -> in one atomic commit persist {new session pickle, plaintext/inbox record, dedupe id} -> only then ack. Violation costs: send side = lost message + AES key/IV reuse; receive side = duplicate delivery (rollback) or permanent message loss (state ahead of data).");
    t
}

// ---------------------------------------------------------------------- T5

fn t5() -> Test {
    let mut t = Test::new(5, "Replay and ordering");
    // (a) replay
    let mut p = pair();
    let c = enc(&mut p.sa, b"once");
    let first = dec(&mut p.sb, &c).is_ok();
    let second = dec(&mut p.sb, &c);
    t.check(
        "same ciphertext twice, no persistence between: second rejected",
        second.is_err(),
        format!("first={first} second={}", okerr(&second)),
    );
    let mut sb2 = sess_load(&sess_pickle(&p.sb));
    let third = dec(&mut sb2, &c);
    t.check(
        "same ciphertext twice, with pickle/unpickle between: second rejected",
        third.is_err(),
        okerr(&third),
    );
    // pre-key replay to the existing session
    let mut p = pair();
    let again = dec(&mut p.sb, &p.first.clone());
    t.check(
        "first pre-key message redelivered to the existing session: rejected",
        again.is_err(),
        okerr(&again),
    );
    let pk = prekey(&p.first);
    let ik = p.a.curve25519_key();
    let again = p.b.create_inbound_session(CFG(), ik, &pk);
    t.check("first pre-key message redelivered as a NEW inbound session (OTK already consumed): rejected", again.is_err(), okerr(&again));

    // (b) out of order within a chain: 5,3,4,1,2
    let mut p = pair();
    let w: Vec<Wire> = (1..=5)
        .map(|i| enc(&mut p.sa, format!("m{i}").as_bytes()))
        .collect();
    let mut res = vec![];
    for i in [5usize, 3, 4, 1, 2] {
        res.push(
            dec(&mut p.sb, &w[i - 1])
                .map(|x| String::from_utf8(x).unwrap())
                .map_err(|e| err_txt(&e)),
        );
    }
    t.check(
        "out-of-order delivery 5,3,4,1,2 within a chain: all decrypt",
        res.iter().all(|r| r.is_ok()),
        format!("{res:?}"),
    );

    // (c) reorder window and the gap limit
    let mut p = pair();
    let w: Vec<Wire> = (0..2500)
        .map(|i| enc(&mut p.sa, format!("{i}").as_bytes()))
        .collect();
    let base = sess_pickle(&p.sb);
    let try_order = |order: &[usize]| -> Vec<String> {
        let mut s = sess_load(&base);
        order
            .iter()
            .map(|&i| match dec(&mut s, &w[i]) {
                Ok(x) => format!("#{i}: OK({})", String::from_utf8_lossy(&x)),
                Err(e) => format!("#{i}: ERR {}", err_txt(&e)),
            })
            .collect()
    };
    let a_in_order_then_first: Vec<usize> = (1..2500).chain(std::iter::once(0)).collect();
    let r = try_order(&a_in_order_then_first);
    t.note(format!(
        "(i) 2499 messages delivered in order, the FIRST one last: last result = {}",
        r.last().unwrap()
    ));
    t.check("2500 sent, #1..#2499 delivered in order then #0 last: #0 still decrypts (its skipped key was kept: only 1 key was ever skipped)", r.last().unwrap().contains("OK"), r.last().unwrap().clone());
    let r = try_order(&[2499, 0]);
    t.note(format!(
        "(ii) last message first: {} ; then first message: {}",
        r[0], r[1]
    ));
    t.check("2500 sent, newest (#2499) delivered first: rejected with exact error; state untouched afterwards (#0 still OK)", r[0].contains("ERR") && r[1].contains("OK"), format!("{} | {}", r[0], r[1]));
    let r = try_order(&[2000, 0, 1999, 1960, 1959]);
    t.note(format!(
        "(iii) #2000 first (gap 2000) then #0, #1999, #1960, #1959: {r:?}"
    ));
    t.check("gap of exactly 2000 accepted; but only the last 40 skipped keys are kept (#0 and #1959 are lost, #1960 and #1999 decrypt)", r[0].contains("OK") && r[1].contains("ERR") && r[2].contains("OK") && r[3].contains("OK") && r[4].contains("ERR"), format!("{r:?}"));
    let r2 = try_order(&[2001]);
    t.note(format!("(iv) #2001 first: {}", r2[0]));
    t.check(
        "gap 2001 rejected",
        r2[0].contains("TooBigMessageGap"),
        r2[0].clone(),
    );
    let r40 = try_order(&[40, 0]);
    let r41 = try_order(&[41, 0, 1]);
    t.check(
        "reorder window: #40 first then #0 works; #41 first evicts #0 (but #1 works)",
        r40[1].contains("OK") && r41[1].contains("ERR") && r41[2].contains("OK"),
        format!("{r40:?} {r41:?}"),
    );
    t.ev("limits", json!({"max_message_gap": 2000, "max_skipped_keys_per_chain": 40, "max_receiving_chains": 5, "source": "vodozemac-0.11.2 src/olm/session/receiver_chain.rs, session/mod.rs"}));

    // (d) chain eviction: delayed message vs number of ping-pong turns
    let mut first_fail = None;
    let mut rows = vec![];
    for k in 0..=9 {
        let mut p = pair();
        let delayed = enc(&mut p.sa, b"delayed");
        for i in 0..k {
            let x = enc(&mut p.sa, format!("x{i}").as_bytes());
            dec(&mut p.sb, &x).unwrap();
            let y = enc(&mut p.sb, format!("y{i}").as_bytes());
            dec(&mut p.sa, &y).unwrap();
        }
        let r = dec(&mut p.sb, &delayed);
        rows.push(format!("{k} round trips later: {}", okerr(&r)));
        if r.is_err() && first_fail.is_none() {
            first_fail = Some(k);
        }
    }
    t.note(format!(
        "delayed message vs ping-pong turns: first failure at k={first_fail:?}"
    ));
    for r in &rows {
        t.note(r.clone());
    }
    t.check(
        "a delayed message survives at most N ratchet turns (receiver keeps 5 receiving chains)",
        first_fail.is_some(),
        format!("first failing k={first_fail:?}"),
    );
    t.ev("delayed_message_rows", json!(rows));
    t
}

// ---------------------------------------------------------------------- T6

fn flip_all(bytes: &[u8]) -> Vec<Vec<u8>> {
    (0..bytes.len() * 8)
        .map(|i| {
            let mut v = bytes.to_vec();
            v[i / 8] ^= 1 << (i % 8);
            v
        })
        .collect()
}

fn bump(m: &mut BTreeMap<String, usize>, k: impl Into<String>) {
    *m.entry(k.into()).or_default() += 1;
}

fn t6() -> Test {
    let mut t = Test::new(
        6,
        "Wrong recipient, tampering, and the libchat failure mode",
    );
    // wrong recipient
    let mut p = pair();
    let mut c = Account::new();
    c.generate_one_time_keys(3);
    c.generate_fallback_key();
    // pre-key message for B, offered to C
    let mut bb = Account::new();
    let bundle = make_bundle(&mut bb, 1, false);
    let v = verify_bundle(&bundle, None).unwrap();
    let a3 = Account::new();
    let mut s3 = a3.create_outbound_session(CFG(), v.cv, v.otks[0]).unwrap();
    let w3 = enc(&mut s3, b"for bb only");
    let rc = c.create_inbound_session(CFG(), a3.curve25519_key(), &prekey(&w3));
    t.check(
        "pre-key message for B offered to C: C cannot create a session",
        rc.is_err(),
        okerr(&rc),
    );
    let mut sc = {
        let mut cacct = Account::new();
        cacct.generate_one_time_keys(1);
        let o = otk_list(&cacct)[0];
        let d = Account::new();
        let mut sd = d
            .create_outbound_session(CFG(), cacct.curve25519_key(), o)
            .unwrap();
        let w = enc(&mut sd, b"c's own peer");
        cacct
            .create_inbound_session(CFG(), d.curve25519_key(), &prekey(&w))
            .unwrap()
            .session
    };
    let wn = enc(&mut p.sa, b"normal message for B");
    let rn = dec(&mut sc, &wn);
    t.check(
        "normal message for B offered to an unrelated session of C: not decryptable",
        rn.is_err(),
        okerr(&rn),
    );

    // tamper: normal message, all single-bit flips, each against a clone (classification)
    let plain = b"genuine message payload 0123456789".to_vec();
    let mut p = pair();
    let genuine = enc(&mut p.sa, &plain);
    let mut classes = BTreeMap::new();
    let (mut malleable, mut accepted_other) = (vec![], 0);
    let flips = flip_all(&genuine.bytes);
    let total = flips.len();
    let mut rejected_flips = vec![];
    for (bit, f) in flips.iter().enumerate() {
        match Message::from_bytes(f) {
            Err(_) => {
                bump(&mut classes, "DecodeError");
                rejected_flips.push(f.clone());
            }
            Ok(m) => {
                let mut s = sess_clone(&p.sb);
                match s.decrypt(&OlmMessage::Normal(m)) {
                    Ok(x) if x == plain => malleable.push(bit),
                    Ok(_) => accepted_other += 1,
                    Err(e) => {
                        bump(&mut classes, variant(&e));
                        rejected_flips.push(f.clone());
                    }
                }
            }
        }
    }
    t.note(format!("normal message ({} bytes): {total} single-bit flips -> rejected {classes:?}; accepted with IDENTICAL plaintext={} (bit indexes {malleable:?}, byte offsets {:?}); accepted with DIFFERENT plaintext={accepted_other}", genuine.bytes.len(), malleable.len(), malleable.iter().map(|b| b / 8).collect::<Vec<_>>()));
    t.check(
        "no single-bit flip of a normal message yields a different plaintext",
        accepted_other == 0,
        format!("{accepted_other} accepted with different plaintext"),
    );
    t.check(
        "wire encoding is non-malleable: every single-bit flip of a normal message is rejected",
        malleable.is_empty(),
        format!("{} flips are accepted and decrypt to the IDENTICAL plaintext (the MAC covers the re-encoded protobuf fields, not the received bytes); dedupe must key on the plaintext message id, never on ciphertext bytes/hash", malleable.len()),
    );
    t.ev("normal_flip_classes", json!(classes));
    t.ev("normal_malleable_bit_indexes", json!(malleable));
    // libchat failure mode: feed every REJECTED tampered copy (and truncations) to the LIVE session, then the genuine one
    for f in &rejected_flips {
        if let Ok(m) = Message::from_bytes(f) {
            let _ = p.sb.decrypt(&OlmMessage::Normal(m));
        }
    }
    let mut trunc_acc = 0;
    for n in 0..genuine.bytes.len() {
        if let Ok(m) = Message::from_bytes(&genuine.bytes[..n]) {
            if p.sb.decrypt(&OlmMessage::Normal(m)).is_ok() {
                trunc_acc += 1;
            }
        }
    }
    let mut ext = genuine.bytes.clone();
    ext.extend_from_slice(&[0u8; 8]);
    let ext_res = Message::from_bytes(&ext)
        .ok()
        .map(|m| p.sb.decrypt(&OlmMessage::Normal(m)).is_ok());
    let g = dec(&mut p.sb, &genuine);
    t.check(
        "after every REJECTED tampered/truncated copy was fed to the live session, the genuine message still decrypts (libchat T3b failure mode)",
        g.is_ok() && trunc_acc == 0,
        format!("{} rejected tampered copies + all truncations fed to the same Session object; truncations accepted={trunc_acc}; +8 trailing bytes: {}; genuine={}", rejected_flips.len(), match ext_res { None => "rejected at decode".to_string(), Some(b) => format!("accepted={b}") }, okerr(&g)),
    );
    // consequence of a malleable variant: delivered first, then the genuine copy
    if let Some(&bit) = malleable.first() {
        let mut p = pair();
        let genuine = enc(&mut p.sa, &plain);
        let mut v = genuine.bytes.clone();
        v[bit / 8] ^= 1 << (bit % 8);
        let first =
            p.sb.decrypt(&OlmMessage::Normal(Message::from_bytes(&v).unwrap()));
        let second = dec(&mut p.sb, &genuine);
        t.note(format!(
            "malleable variant (bit {bit}) delivered first -> {:?}; then the genuine bytes -> {}",
            first.as_ref().map(|x| x == &plain),
            okerr(&second)
        ));
        t.note("effect: the content is delivered exactly once and is correct; the genuine copy is later rejected as a replay. A relay can therefore mint distinct byte strings for one message but cannot change what it decrypts to.");
    }
    // pre-key message tampering
    let mut bb = Account::new();
    let bundle = make_bundle(&mut bb, 2, false);
    let v = verify_bundle(&bundle, None).unwrap();
    let a = Account::new();
    let mut sa = a.create_outbound_session(CFG(), v.cv, v.otks[0]).unwrap();
    let pplain = b"genuine pre-key payload".to_vec();
    let genuine = enc(&mut sa, &pplain);
    let gbytes = prekey(&genuine).to_bytes();
    let mut classes = BTreeMap::new();
    let (mut malleable, mut other) = (vec![], 0);
    let mut rejected = vec![];
    for (bit, f) in flip_all(&gbytes).into_iter().enumerate() {
        match PreKeyMessage::from_bytes(&f) {
            Err(_) => bump(&mut classes, "DecodeError"),
            Ok(pk) => {
                let mut bc = acct_clone(&bb);
                match bc.create_inbound_session(CFG(), pk.identity_key(), &pk) {
                    Ok(r) if r.plaintext == pplain => malleable.push(bit),
                    Ok(_) => other += 1,
                    Err(e) => {
                        bump(&mut classes, variant(&e));
                        rejected.push(pk);
                    }
                }
            }
        }
    }
    t.note(format!("pre-key message ({} bytes): {} single-bit flips -> {classes:?}; accepted with identical plaintext={} (byte offsets {:?}); accepted with different plaintext={other}", gbytes.len(), gbytes.len() * 8, malleable.len(), malleable.iter().map(|b| b / 8).collect::<Vec<_>>()));
    t.check(
        "no single-bit flip of a pre-key message yields a different plaintext",
        other == 0,
        format!("{other}"),
    );
    t.check(
        "wire encoding is non-malleable: every single-bit flip of a pre-key message is rejected",
        malleable.is_empty(),
        format!(
            "{} flips accepted with identical plaintext (same cause as above)",
            malleable.len()
        ),
    );
    let mut live = acct_clone(&bb);
    for pk in &rejected {
        let _ = live.create_inbound_session(CFG(), pk.identity_key(), pk);
    }
    let g = live.create_inbound_session(CFG(), a.curve25519_key(), &prekey(&genuine));
    t.check(
        "after every REJECTED tampered pre-key message hit the live account, the genuine pre-key message still establishes (OTK not burned by failed attempts)",
        g.is_ok(),
        format!("{} rejected tampered pre-key messages fed to one live Account; genuine={}", rejected.len(), okerr(&g)),
    );
    t.note("mechanism: Session::decrypt only commits chain/ratchet state after the MAC verifies; Account::create_inbound_session only removes the OTK after the inner message decrypts (audit Issue G). Caveat: MAC is truncated to 8 bytes (audit Issue J, unresolved; SessionConfig::version_1 is the only non-experimental config in 0.11.2).");
    t
}

// ---------------------------------------------------------------------- T7

fn find(h: &[u8], n: &[u8]) -> Vec<usize> {
    (0..=h.len() - n.len())
        .filter(|&i| &h[i..i + n.len()] == n)
        .collect()
}

fn t7() -> Test {
    let mut t = Test::new(7, "Sender authentication semantics");
    let mut b = Account::new();
    let bundle = make_bundle(&mut b, 4, false);
    let v = verify_bundle(&bundle, None).unwrap();
    let a = Account::new();
    let m = Account::new(); // mallory
    let mut sa = a.create_outbound_session(CFG(), v.cv, v.otks[0]).unwrap();
    let mut sm = m.create_outbound_session(CFG(), v.cv, v.otks[1]).unwrap();
    let wa = enc(&mut sa, b"hi from A");
    let wm = enc(&mut sm, b"hi from M");
    let pka = prekey(&wa);
    t.note(format!(
        "PreKeyMessage exposes: identity_key (Curve25519) = {} ; base_key ; one_time_key. No Ed25519 key, no address, no signature.",
        pka.identity_key().to_base64()
    ));
    t.check("recipient learns the sender's Curve25519 identity key (and nothing else) from a pre-key message", pka.identity_key() == a.curve25519_key(), "pre_key_message.identity_key() == A's identity key; Session::session_keys().identity_key stored in the session");
    let r = b
        .create_inbound_session(CFG(), pka.identity_key(), &pka)
        .unwrap();
    t.check(
        "session's peer key is stored in the session",
        r.session.session_keys().identity_key == a.curve25519_key(),
        "session_keys().identity_key",
    );
    // normal messages carry nothing about the sender
    t.note("A Normal message has only {ratchet key, chain index, ciphertext, MAC}; the receiver identifies the sender by trying its sessions (MAC failure on the wrong ones). Cost measured in T10.");
    // forged claim
    let mut forged_bytes = prekey(&wm).to_bytes();
    let hits = find(&forged_bytes, m.curve25519_key().as_bytes());
    let mut forged_res = "n/a".to_string();
    let mut forged_ok = false;
    if hits.len() == 1 {
        let i = hits[0];
        forged_bytes[i..i + 32].copy_from_slice(a.curve25519_key().as_bytes());
        let forged = PreKeyMessage::from_bytes(&forged_bytes).unwrap();
        let mut bc = acct_clone(&b);
        let res = bc.create_inbound_session(CFG(), a.curve25519_key(), &forged);
        forged_ok = res.is_ok();
        forged_res = res.map(|_| "OK".into()).unwrap_or_else(|e| err_txt(&e));
        // the failed forged attempt must not have burned M's OTK: M's own genuine pre-key still works
        let genuine_m = b
            .create_inbound_session(CFG(), m.curve25519_key(), &prekey(&wm))
            .map(|_| "OK".to_string())
            .unwrap_or_else(|e| err_txt(&e));
        t.note(format!("after the failed forged attempt, the OTK it referenced is intact: M's own genuine pre-key message -> {genuine_m}"));
    }
    t.check(
        "M's pre-key message with the identity-key field rewritten to A's key does not create a session",
        !forged_ok && hits.len() == 1,
        format!("(M's key found {} time(s) in the encoding) result: {forged_res}", hits.len()),
    );
    t.note("why: the 3DH shared secret includes DH(IK_sender_secret, OTK_b); without A's identity secret M derives a different root key and the MAC of the embedded message fails.");
    // app-level binding: first flight carries sender's signed bundle
    let mut sender = Account::new();
    let sb = make_bundle(&mut sender, 0, false);
    let mut so = sender
        .create_outbound_session(CFG(), v.cv, v.otks[2])
        .unwrap();
    let first_plain = serde_json::to_vec(&sb).unwrap();
    let w = enc(&mut so, &first_plain);
    let pk = prekey(&w);
    let mut bc = acct_clone(&b);
    let r = bc
        .create_inbound_session(CFG(), pk.identity_key(), &pk)
        .unwrap();
    let claimed: Bundle = serde_json::from_slice(&r.plaintext).unwrap();
    let vb = verify_bundle(&claimed, None).unwrap();
    t.check(
        "constructive: sender puts its signed bundle in the first flight; recipient binds session identity key == bundle.curve25519 and bundle.ed25519 == address",
        vb.cv == pk.identity_key() && vb.ed == sender.ed25519_key(),
        "this is the application-level step that turns 'holder of Curve25519 key K' into 'holder of address X'",
    );
    // Mallory replays A's genuine bundle inside her own flight
    let mut sm2 = m.create_outbound_session(CFG(), v.cv, v.otks[3]).unwrap();
    let w = enc(&mut sm2, &first_plain);
    let pk = prekey(&w);
    let mut bc = acct_clone(&b);
    let r = bc
        .create_inbound_session(CFG(), pk.identity_key(), &pk)
        .unwrap();
    let claimed: Bundle = serde_json::from_slice(&r.plaintext).unwrap();
    let vb = verify_bundle(&claimed, None).unwrap();
    t.check(
        "M embedding A's genuine bundle in her own flight: session key != bundle key, application check rejects",
        vb.cv != pk.identity_key(),
        "the library alone would accept M's session (it IS a valid session with M); only the app-level comparison catches the mismatch",
    );
    t.sub(
        "key-compromise impersonation (attacker holding B's secrets forges 'A -> B')",
        NE,
        "forging requires computing the 3DH secret from B's secret keys and A's PUBLIC identity key, which the public API does not offer (no Account import of secrets/Session from raw 3DH inputs without the low-level-api feature); by protocol design (3DH with only DH-based authentication, no signatures) it is possible: Olm is deniable and offers no KCI resistance. Not exercised.",
    );
    t.note("Contrast with the current design: HPKE-base + Ed25519 signature gives a transferable, non-repudiable statement 'address X wrote this to Y'; Olm gives deniable, session-bound authentication only.");
    t
}

// ---------------------------------------------------------------------- T8

fn t8() -> Test {
    let mut t = Test::new(8, "Forward secrecy and post-compromise security");
    let mut p = pair();
    let captured: Vec<(Wire, String)> = (1..=3)
        .map(|i| {
            let s = format!("secret-{i}");
            (enc(&mut p.sa, s.as_bytes()), s)
        })
        .collect();
    for (w, s) in &captured {
        assert_eq!(dec(&mut p.sb, w).unwrap(), s.as_bytes());
    }
    let r1 = enc(&mut p.sb, b"reply-1");
    dec(&mut p.sa, &r1).unwrap();
    let m4 = enc(&mut p.sa, b"secret-4");
    dec(&mut p.sb, &m4).unwrap();
    // compromise: snapshot of B's current state AFTER decrypting and ratcheting
    let snap_s = sess_pickle(&p.sb);
    let snap_a = acct_pickle(&p.b);
    let mut att = sess_load(&snap_s);
    let mut res = vec![];
    for (w, s) in &captured {
        res.push(match dec(&mut att, w) {
            Ok(x) => format!("{s}: DECRYPTED {:?}", String::from_utf8_lossy(&x)),
            Err(e) => format!("{s}: {}", err_txt(&e)),
        });
    }
    let r1_try = dec(&mut att, &r1)
        .map(|_| "DECRYPTED".to_string())
        .unwrap_or_else(|e| err_txt(&e));
    t.note(format!(
        "later-state attacker on captured ciphertexts: {res:?}; on B's own reply: {r1_try}"
    ));
    t.check("old ciphertexts (decrypted and ratcheted past) cannot be decrypted from a later stolen state", res.iter().all(|r| !r.contains("DECRYPTED")), format!("{res:?}"));
    t.check(
        "B's own earlier outgoing message cannot be decrypted from the stolen state",
        !r1_try.contains("DECRYPTED"),
        r1_try.clone(),
    );
    let mut acct_later = acct_load(&snap_a);
    let re = acct_later.create_inbound_session(CFG(), p.a.curve25519_key(), &prekey(&p.first));
    t.check("the original pre-key message cannot re-establish the session from the later account state (OTK consumed)", re.is_err(), okerr(&re));
    // skipped keys remain exposed
    let mut p = pair();
    let m5 = enc(&mut p.sa, b"secret-5-never-delivered-yet");
    let m6 = enc(&mut p.sa, b"secret-6");
    dec(&mut p.sb, &m6).unwrap();
    let mut att = sess_load(&sess_pickle(&p.sb));
    let r = dec(&mut att, &m5);
    t.check(
        "messages SKIPPED (not yet delivered) when the state is stolen remain decryptable from it (up to 40 skipped keys per chain, 5 chains)",
        r.is_err(),
        r.map(|x| format!("DECRYPTED {:?}", String::from_utf8_lossy(&x))).unwrap_or_else(|e| err_txt(&e)),
    );
    // PCS
    let mut p = pair();
    let w = enc(&mut p.sa, b"warm");
    dec(&mut p.sb, &w).unwrap();
    let mut att = sess_load(&sess_pickle(&p.sb)); // stolen at time T, attacker then mirrors passively
    let mut rows = vec![];
    for round in 1..=5 {
        let x = enc(&mut p.sa, format!("round-{round}").as_bytes());
        let b_ok = dec(&mut p.sb, &x).is_ok();
        let a_res = dec(&mut att, &x);
        rows.push(format!("round {round}: legit B decrypts={b_ok}; attacker (stolen state at T, passive) decrypts={}", a_res.is_ok()));
        let y = enc(&mut p.sb, format!("ack-{round}").as_bytes());
        dec(&mut p.sa, &y).unwrap();
    }
    for r in &rows {
        t.note(r.clone());
    }
    let healed = rows
        .iter()
        .any(|r| r.ends_with("decrypts=false") && r.contains("attacker"));
    t.check("post-compromise security: a passive attacker with a stolen state is locked out after the peers complete fresh DH ratchet turns", healed, format!("{rows:?}"));
    t.ev("pcs_rounds", json!(rows));
    t.note("Contrast (HPKE base mode as in ADR 0002): ciphertexts are sealed to a long-term recipient KEM key; anyone who later obtains that private key (or a retained previous key) decrypts EVERY recorded frame sealed to it. Olm bounds the exposure to the not-yet-ratcheted window plus stored skipped keys.");
    t
}

// ---------------------------------------------------------------------- T9

fn t9() -> Test {
    let mut t = Test::new(9, "Migration / two live instances of the same state");
    // case X: both instances send from the same sending chain
    let mut p = pair();
    let ps = sess_pickle(&p.sb);
    let mut b1 = sess_load(&ps);
    let mut b2 = sess_load(&ps);
    let r1 = enc(&mut b1, b"from B1");
    let r2 = enc(&mut b2, b"from B2");
    let (rk1, i1) = ratchet_and_index(&r1.bytes);
    let (rk2, i2) = ratchet_and_index(&r2.bytes);
    t.note(format!(
        "B1 sends: ratchet={} idx={i1}; B2 sends: ratchet={} idx={i2}",
        hex8(&rk1),
        hex8(&rk2)
    ));
    let ra = dec(&mut p.sa, &r1);
    let rb = dec(&mut p.sa, &r2);
    t.check(
        "two instances sending from the same chain position are both accepted by the peer",
        ra.is_ok() && rb.is_ok(),
        format!(
            "A decrypt(B1)={}, decrypt(B2)={}",
            ra.as_ref()
                .map(|_| "OK".to_string())
                .unwrap_or_else(err_txt),
            rb.as_ref()
                .map(|_| "OK".to_string())
                .unwrap_or_else(err_txt)
        ),
    );
    t.note("the loser's message is silently lost; both used the same message key for different plaintexts (key reuse)");

    // case Y: both instances receive from A and each performs its own DH ratchet step
    let mut p = pair();
    let ps = sess_pickle(&p.sb);
    let mut b1 = sess_load(&ps);
    let mut b2 = sess_load(&ps);
    let m1 = enc(&mut p.sa, b"A -> both");
    let d1 = dec(&mut b1, &m1).is_ok();
    let d2 = dec(&mut b2, &m1).is_ok();
    t.check(
        "only one instance can decrypt a given message (no duplicate delivery)",
        !(d1 && d2),
        format!("B1={d1} B2={d2}"),
    );
    let y1 = enc(&mut b1, b"B1 reply");
    let y2 = enc(&mut b2, b"B2 reply");
    let (k1, _) = ratchet_and_index(&y1.bytes);
    let (k2, _) = ratchet_and_index(&y2.bytes);
    t.note(format!("after a DH step each instance picked its own fresh ratchet key: B1={} B2={} (different={})", hex8(&k1), hex8(&k2), k1 != k2));
    let ay1 = dec(&mut p.sa, &y1)
        .map(|x| String::from_utf8_lossy(&x).to_string())
        .map_err(|e| err_txt(&e));
    let ay2 = dec(&mut p.sa, &y2)
        .map(|x| String::from_utf8_lossy(&x).to_string())
        .map_err(|e| err_txt(&e));
    t.note(format!("A decrypts B1 reply: {ay1:?}; B2 reply: {ay2:?} (A follows whichever reply arrives first: its root key has already advanced, so the other instance's reply fails the MAC)"));
    let next = enc(&mut p.sa, b"A -> (whoever)");
    let n1 = dec(&mut b1, &next)
        .map(|_| "OK".to_string())
        .map_err(|e| err_txt(&e));
    let n2 = dec(&mut b2, &next)
        .map(|_| "OK".to_string())
        .map_err(|e| err_txt(&e));
    t.check(
        "A's next message is readable by BOTH instances (no split brain)",
        n1.is_ok() && n2.is_ok(),
        format!("B1: {n1:?}; B2: {n2:?}"),
    );
    // does the dead instance ever recover?
    let mut recovered = false;
    let (mut dead, mut live, mut live_is_b1) = if n1.is_ok() {
        (b2, b1, true)
    } else {
        (b1, b2, false)
    };
    let _ = live_is_b1;
    for i in 0..3 {
        let w = enc(&mut live, format!("live reply {i}").as_bytes());
        let _ = dec(&mut p.sa, &w);
        let n = enc(&mut p.sa, format!("A {i}").as_bytes());
        let _ = dec(&mut live, &n);
        if dec(&mut dead, &n).is_ok() {
            recovered = true;
        }
    }
    live_is_b1 = !live_is_b1;
    let _ = live_is_b1;
    t.check("the instance that lost the race recovers on its own", recovered, "it keeps failing for subsequent messages as long as the peer follows the other instance (3 further rounds tried)");
    // account-level: both instances accept the same pre-key message
    let a = Account::new();
    let mut b = Account::new();
    b.generate_one_time_keys(1);
    b.generate_fallback_key();
    let otk = otk_list(&b)[0];
    b.mark_keys_as_published();
    let ap = acct_pickle(&b);
    let (mut bi1, mut bi2) = (acct_load(&ap), acct_load(&ap));
    let mut s = a
        .create_outbound_session(CFG(), b.curve25519_key(), otk)
        .unwrap();
    let w = enc(&mut s, b"establish");
    let r1 = bi1.create_inbound_session(CFG(), a.curve25519_key(), &prekey(&w));
    let r2 = bi2.create_inbound_session(CFG(), a.curve25519_key(), &prekey(&w));
    t.check(
        "two Account copies: the second rejects a pre-key message whose OTK the first already consumed",
        !(r1.is_ok() && r2.is_ok()),
        format!("inst1={} inst2={}", r1.is_ok(), r2.is_ok()),
    );
    t.note("safe migration = quiesce the old instance (final persist), copy the pickles, start the new instance, never run both; the library has no fencing, epoch or lease mechanism, and a pickle contains no 'owner' marker. A restored BACKUP behaves exactly like the rollback cases in T4.");
    t
}

// --------------------------------------------------------------------- T10

fn t10() -> (Test, Value) {
    let mut t = Test::new(10, "Costs");
    let mut rows = vec![];
    for n in [0usize, 1, 16, 100, 1024, 10 * 1024, 100 * 1024] {
        let mut p = pair();
        let a2 = Account::new();
        let mut b2 = Account::new();
        b2.generate_one_time_keys(1);
        let o = otk_list(&b2)[0];
        let mut s = a2
            .create_outbound_session(CFG(), b2.curve25519_key(), o)
            .unwrap();
        let pre = enc(&mut s, &payload(1, n));
        let normal = enc(&mut p.sa, &payload(2, n));
        rows.push(json!({
            "plaintext": n,
            "prekey_bytes": pre.bytes.len(), "prekey_overhead": pre.bytes.len() - n,
            "normal_bytes": normal.bytes.len(), "normal_overhead": normal.bytes.len() - n,
            "prekey_base64": vodozemac::base64_encode(&pre.bytes).len(),
            "normal_base64": vodozemac::base64_encode(&normal.bytes).len(),
        }));
    }
    for r in &rows {
        t.note(format!("{r}"));
    }
    t.ev("message_sizes", json!(rows));

    // pickle sizes
    let fresh = Account::new();
    let mut a2 = Account::new();
    a2.generate_one_time_keys(2);
    a2.generate_fallback_key();
    let mut a50 = Account::new();
    a50.generate_one_time_keys(50);
    a50.generate_fallback_key();
    let p = pair();
    let mut skipped = pair();
    let ws: Vec<Wire> = (0..41)
        .map(|i| enc(&mut skipped.sa, format!("{i}").as_bytes()))
        .collect();
    dec(&mut skipped.sb, &ws[40]).unwrap();
    let pick = json!({
        "account_fresh": acct_pickle(&fresh).len(),
        "account_2otk_fallback": acct_pickle(&a2).len(),
        "account_50otk_fallback": acct_pickle(&a50).len(),
        "session_established_a": sess_pickle(&p.sa).len(),
        "session_established_b": sess_pickle(&p.sb).len(),
        "session_with_40_skipped_keys": sess_pickle(&skipped.sb).len(),
        "unit": "base64 characters of the encrypted pickle string",
    });
    t.note(format!("pickles: {pick}"));
    t.ev("pickle_sizes", pick);

    // timing
    let iters = 10_000;
    let mut tim = Map::new();
    for size in [100usize, 1024] {
        let mut p = pair();
        let pl = payload(3, size);
        let t0 = Instant::now();
        let ws: Vec<Wire> = (0..iters).map(|_| enc(&mut p.sa, &pl)).collect();
        let te = t0.elapsed();
        let t0 = Instant::now();
        for w in &ws {
            dec(&mut p.sb, w).unwrap();
        }
        let td = t0.elapsed();
        // encrypt/decrypt on the wire object includes to_parts/from_parts copies (small)
        tim.insert(format!("encrypt_us_{size}B"), json!(us(te, iters)));
        tim.insert(format!("decrypt_us_{size}B"), json!(us(td, iters)));
        t.note(format!("{size} B payload, {iters} iterations (normal messages, one chain): encrypt {:.2} us, decrypt {:.2} us", us(te, iters), us(td, iters)));
    }
    // ratchet-turn cost: ping-pong
    let mut p = pair();
    let n = 2000;
    let t0 = Instant::now();
    for _ in 0..n {
        let x = enc(&mut p.sa, b"ping");
        dec(&mut p.sb, &x).unwrap();
        let y = enc(&mut p.sb, b"pong");
        dec(&mut p.sa, &y).unwrap();
    }
    let d = t0.elapsed();
    tim.insert(
        "pingpong_turn_us_per_message_100B_every_message_new_chain".into(),
        json!(us(d, n * 2)),
    );
    t.note(format!("ping-pong (every message triggers a DH ratchet step): {:.2} us per message (encrypt+decrypt)", us(d, n * 2)));
    // session creation
    let m = 1000;
    let mut b = Account::new();
    b.generate_one_time_keys(m);
    let otks = otk_list(&b);
    let a = Account::new();
    let t0 = Instant::now();
    let mut sessions: Vec<Session> = otks
        .iter()
        .map(|o| {
            a.create_outbound_session(CFG(), b.curve25519_key(), *o)
                .unwrap()
        })
        .collect();
    let d_out = t0.elapsed();
    let pres: Vec<Wire> = sessions.iter_mut().map(|s| enc(s, b"x")).collect();
    let t0 = Instant::now();
    for w in &pres {
        b.create_inbound_session(CFG(), a.curve25519_key(), &prekey(w))
            .unwrap();
    }
    let d_in = t0.elapsed();
    tim.insert("create_outbound_session_us".into(), json!(us(d_out, m)));
    tim.insert(
        "create_inbound_session_us_incl_first_decrypt".into(),
        json!(us(d_in, m)),
    );
    t.note(format!(
        "session creation ({m} iterations): outbound {:.2} us, inbound {:.2} us",
        us(d_out, m),
        us(d_in, m)
    ));
    // failed trial decrypt on a wrong session (sender lookup cost)
    let mut p = pair();
    let mut q = pair();
    let w = enc(&mut p.sa, b"trial");
    let t0 = Instant::now();
    for _ in 0..iters {
        let _ = dec(&mut q.sb, &w);
    }
    let d = t0.elapsed();
    tim.insert(
        "failed_trial_decrypt_us_wrong_session".into(),
        json!(us(d, iters)),
    );
    t.note(format!("failed trial decrypt on a non-matching session (new ratchet key => DH then MAC fail): {:.2} us", us(d, iters)));
    t.ev("timing_us", Value::Object(tim));
    t.note("timing is wall-clock on the host in a release build, single thread, includes Wire to_parts/from_parts copies; informational only");
    let v = json!({"messages": rows});
    t.sub("costs measured", PASS, "see evidence; dependency count / build time / MSRV recorded by the shell wrapper in results/a1-vodozemac");
    (t, v)
}

fn main() {
    println!("vodozemac-eval: vodozemac =0.11.2, Olm session config version 1 (MAC truncated to 8 bytes)");
    let tests = vec![
        t1(),
        t2(),
        t3(),
        t4(),
        t5(),
        t6(),
        t7(),
        t8(),
        t9(),
        t10().0,
    ];
    println!("\n=== SUMMARY");
    for t in &tests {
        println!("T{:<2} {:<16} {}", t.id, t.overall(), t.title);
        for s in &t.subs {
            if s.verdict != PASS {
                println!("      [{}] {}", s.verdict, s.name);
            }
        }
    }
    let out = json!({
        "tool": "vodozemac-eval", "vodozemac": "0.11.2", "session_config": "version_1 (8-byte truncated MAC)",
        "verdict_convention": {"PASS": "property held / behaviour safe", "FAIL": "property did not hold or hazard confirmed (application must compensate)", "NOT EXPRESSIBLE": "not exercisable through the public API"},
        "tests": tests.iter().map(|t| t.json()).collect::<Vec<_>>(),
    });
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../results/a1-vodozemac");
    std::fs::create_dir_all(dir).expect("create results dir");
    let path = format!("{dir}/results.json");
    std::fs::write(&path, serde_json::to_string_pretty(&out).unwrap()).expect("write results");
    println!("\nwrote {path}");
}
