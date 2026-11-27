//! Implementation Y: rPGP (`pgp`) plus the `rpgpie` semantics layer. Command line driver.
#[path = "../common.rs"]
mod common;

use std::fs::File;
use std::io::Cursor;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use common::*;
use pgp::composed::{Message, MessageBuilder, SubpacketConfig};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Subpacket, SubpacketData};
use pgp::types::{Fingerprint, KeyDetails, KeyVersion, Password, SigningKey, Timestamp};
use rand::thread_rng;
use rpgpie::certificate::{Certificate, Checked};
use rpgpie::message::unpack;
use rpgpie::tsk::Tsk;

fn hexfp(fp: &Fingerprint) -> String {
    hex::encode(fp.as_bytes())
}

fn tsk_fp(t: &Tsk) -> String {
    hexfp(&Certificate::from(t.clone()).fingerprint())
}

fn load_cert(path: &str) -> Result<Certificate> {
    let mut f = File::open(path).with_context(|| format!("open {path}"))?;
    let mut v = Certificate::load(&mut f).map_err(|e| anyhow!("load cert {path}: {e:?}"))?;
    if v.len() != 1 {
        bail!("{path}: expected exactly one certificate, got {}", v.len());
    }
    Ok(v.remove(0))
}

fn load_tsk(path: &str) -> Result<Tsk> {
    let mut f = File::open(path).with_context(|| format!("open {path}"))?;
    let mut v = Tsk::load(&mut f).map_err(|e| anyhow!("load tsk {path}: {e:?}"))?;
    if v.len() != 1 {
        bail!("{path}: expected exactly one key");
    }
    Ok(v.remove(0))
}

pub struct SealOpts {
    pub intended: bool,
    pub anonymous: bool,
    pub unsigned: bool,
}

pub fn seal(from: &Tsk, to: &Certificate, payload: &[u8], o: &SealOpts) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    // OpenPGP semantics (binding signatures, expiry, revocation) are applied by rpgpie `Checked`.
    let checked: Checked = to.clone().into();
    let keys = checked.valid_encryption_capable_component_keys();
    if keys.is_empty() {
        bail!("recipient has no valid encryption subkey (revoked, expired, unbound or missing)");
    }
    let signer = from
        .signing_capable_component_keys()
        .next()
        .ok_or_else(|| anyhow!("sender has no valid signing key"))?;

    let mut b = MessageBuilder::from_bytes("", payload.to_vec()).seipd_v2(
        &mut rng,
        SymmetricKeyAlgorithm::AES256,
        AeadAlgorithm::Ocb,
        ChunkSize::default(),
    );
    for k in &keys {
        if o.anonymous {
            b.encrypt_to_key_anonymous(&mut rng, k)?;
        } else {
            b.encrypt_to_key(&mut rng, k)?;
        }
    }
    if o.unsigned {
        return Ok(b.to_vec(&mut rng)?);
    }
    let mut hashed = vec![
        Subpacket::critical(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
    ];
    if o.intended {
        hashed.push(Subpacket::critical(
            SubpacketData::IntendedRecipientFingerprint(to.fingerprint()),
        )?);
    }
    b.sign_with_subpackets(
        &signer,
        Password::empty(),
        signer.hash_alg(),
        SubpacketConfig::UserDefined {
            hashed,
            unhashed: vec![],
        },
    );
    Ok(b.to_vec(&mut rng)?)
}

#[derive(Debug)]
pub struct Opened {
    pub payload: Vec<u8>,
    pub signer: String,
    pub intended: Vec<String>,
}

pub fn open(me: &Tsk, sender: &Certificate, data: &[u8], require_intended: bool) -> Result<Opened> {
    let msg =
        Message::from_bytes(Cursor::new(data.to_vec())).map_err(|e| anyhow!("parse: {e:?}"))?;
    let certs = vec![sender.clone()];
    let ssk = me.as_signed_secret_key();
    let r = unpack(msg, vec![ssk], vec![], vec![], &[], &certs)
        .map_err(|e| anyhow!("unpack: {e:?}"))?;
    if !matches!(r.encryption_mode, rpgpie::message::EncryptionMode::Seipdv2) {
        bail!("not SEIPDv2");
    }
    if r.validated.len() != 1 {
        bail!(
            "expected exactly one valid signature from the claimed sender, got {}",
            r.validated.len()
        );
    }
    let v = &r.validated[0];
    let signer_cert = v.certs.first().ok_or_else(|| anyhow!("no signer cert"))?;
    if signer_cert.fingerprint() != sender.fingerprint() {
        bail!("signer is not the claimed sender");
    }
    // rpgpie does not evaluate intended recipients: the application does (these few lines are
    // the only "glue" and they are not cryptographic).
    let mut ir = vec![];
    if let Some(cfg) = v.sig.config() {
        for sp in &cfg.hashed_subpackets {
            if let SubpacketData::IntendedRecipientFingerprint(fp) = &sp.data {
                ir.push(hexfp(fp));
            }
        }
    }
    let my_fp = hexfp(&me.as_signed_secret_key().primary_key.fingerprint());
    if require_intended && !ir.iter().any(|f| *f == my_fp) {
        bail!("signature has no intended-recipient subpacket naming me");
    }
    Ok(Opened {
        payload: r.cleartext.to_vec(),
        signer: hexfp(&signer_cert.fingerprint()),
        intended: ir,
    })
}

fn dump(data: &[u8]) -> Result<String> {
    let mut s = String::new();
    let parser = pgp::packet::PacketParser::new(Cursor::new(data.to_vec()));
    for p in parser {
        match p {
            Ok(p) => s += &format!("{:?}\n", p),
            Err(e) => s += &format!("<parse error: {e:?}>\n"),
        }
    }
    Ok(s)
}

fn cert_info(c: &Certificate) -> String {
    let ch: Checked = c.clone().into();
    let now = Timestamp::now();
    let mut s = format!("primary fp={}\n", hexfp(&c.fingerprint()));
    s += &format!(
        "  primary_valid_at(now)={:?} revoked_at(now)={}\n",
        ch.primary_valid_at(now),
        ch.revoked_at(now)
    );
    for k in ch.valid_subkeys_at(now) {
        s += &format!("  valid subkey {:?}\n", k.fingerprint());
    }
    s += &format!(
        "  valid encryption-capable keys: {}\n",
        ch.valid_encryption_capable_component_keys().len()
    );
    s
}

fn safe_open(me: &Tsk, sender: &Certificate, d: &[u8]) -> Result<Opened> {
    // a panic on malformed input would be a robustness finding: count it as an error but report it
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open(me, sender, d, true))) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("PANIC on malformed input (len {})", d.len());
            Err(anyhow!("panic"))
        }
    }
}

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let a = Args::parse(&argv);
    let cmd = a.1.first().map(|s| s.as_str()).unwrap_or("help");
    match cmd {
        "version" => println!("pgp 0.21.1 + rpgpie 0.12.1 (pure Rust)"),
        "gen" => {
            let name = a.get("name")?;
            let dir = a.get("out")?;
            let tsk = Tsk::generate(
                KeyVersion::V6,
                pgp::composed::KeyType::Ed25519,
                Some(pgp::composed::KeyType::X25519),
                None,
                vec![],
                None,
            )
            .map_err(|e| anyhow!("{e:?}"))?;
            tsk.save(true, &mut File::create(format!("{dir}/{name}.sec.asc"))?)
                .map_err(|e| anyhow!("{e:?}"))?;
            let cert = Certificate::from(tsk);
            cert.save(true, &mut File::create(format!("{dir}/{name}.pub.asc"))?)
                .map_err(|e| anyhow!("{e:?}"))?;
            println!("{} {}", name, hexfp(&cert.fingerprint()));
        }
        "fpr" => println!("{}", hexfp(&load_cert(a.get("cert")?)?.fingerprint())),
        "cert-info" => print!("{}", cert_info(&load_cert(a.get("pub")?)?)),
        "seal" => {
            let from = load_tsk(a.get("from")?)?;
            let to = load_cert(a.get("to")?)?;
            let from_fp = tsk_fp(&from);
            let payload = match a.opt("payload") {
                Some(f) => std::fs::read(f)?,
                None => make_payload(
                    &from_fp,
                    &hexfp(&to.fingerprint()),
                    a.num("body", 100) as usize,
                ),
            };
            if a.opt("pad").map(|p| p != "none").unwrap_or(false) {
                bail!("rPGP 0.21.1 MessageBuilder has no API to emit a Padding packet (NOT SUPPORTED for sending)");
            }
            let o = SealOpts {
                intended: !a.flag("no-intended"),
                anonymous: !a.flag("named-recipient"),
                unsigned: a.flag("unsigned"),
            };
            let ct = seal(&from, &to, &payload, &o)?;
            std::fs::write(a.get("out")?, &ct)?;
            println!(
                "sealed {} bytes (payload {} bytes)",
                ct.len(),
                payload.len()
            );
        }
        "open" => {
            let me = load_tsk(a.get("me")?)?;
            let sender = load_cert(a.get("sender")?)?;
            let data = std::fs::read(a.get("in")?)?;
            let o = open(&me, &sender, &data, !a.flag("allow-no-intended"))?;
            let my_fp = tsk_fp(&me);
            if a.flag("crypto-only") {
                println!(
                    "CRYPTO-OK signer={} intended_recipients={:?} (payload checks skipped)",
                    o.signer, o.intended
                );
                return Ok(());
            }
            let pl = check_payload(&o.payload, &o.signer, &my_fp, now_ms())?;
            println!(
                "OK signer={} intended_recipients={:?} message_id={} type={} body_len={}",
                o.signer,
                o.intended,
                pl.message_id,
                pl.kind,
                pl.body.len()
            );
        }
        "scan" => {
            let me = load_tsk(a.get("me")?)?;
            let sender = load_cert(a.get("sender")?)?;
            let data = std::fs::read(a.get("in")?)?;
            let mut accepted = vec![];
            let mut rejected = 0usize;
            for i in 0..data.len() {
                let mut d = data.clone();
                d[i] ^= 0x01;
                match safe_open(&me, &sender, &d) {
                    Ok(_) => accepted.push(i),
                    Err(_) => rejected += 1,
                }
            }
            println!(
                "impl=rpgp flips={} rejected={} accepted={} accepted_offsets={:?}",
                data.len(),
                rejected,
                accepted.len(),
                accepted
            );
            let mut rej_trunc = 0usize;
            let mut acc_trunc = vec![];
            for n in 0..data.len() {
                match safe_open(&me, &sender, &data[..n]) {
                    Ok(_) => acc_trunc.push(n),
                    Err(_) => rej_trunc += 1,
                }
            }
            println!(
                "impl=rpgp truncations={} rejected={} accepted={} accepted_lengths={:?}",
                data.len(),
                rej_trunc,
                acc_trunc.len(),
                acc_trunc
            );
        }
        "sizes" => {
            use pgp::ser::Serialize;
            for f in a.1.iter().skip(1) {
                let c = load_cert(f)?;
                let n = c.clone();
                let spk: pgp::composed::SignedPublicKey = n.into();
                println!("{f}: binary_public={}", spk.to_bytes()?.len());
            }
        }
        "rfc-vectors" => {
            let dir = a.get("dir")?;
            let expect = "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9";
            let cert = load_cert(&format!("{dir}/a3.pub.asc"))?;
            let tsk = load_tsk(&format!("{dir}/a4.sec.asc"))?;
            let fp = hexfp(&cert.fingerprint());
            println!(
                "A.3 cert fingerprint {} expected {} => {}",
                fp,
                expect,
                if fp == expect { "MATCH" } else { "MISMATCH" }
            );
            println!(
                "A.4 secret key fingerprint {} => {}",
                tsk_fp(&tsk),
                if tsk_fp(&tsk) == expect {
                    "MATCH"
                } else {
                    "MISMATCH"
                }
            );
            // A.8.5 via the rpgpie unpack path (no signature expected)
            let data = std::fs::read(format!("{dir}/a85.msg.asc"))?;
            let (msg, _) = Message::from_armor(Cursor::new(data)).map_err(|e| anyhow!("{e:?}"))?;
            let r = unpack(
                msg,
                vec![tsk.as_signed_secret_key()],
                vec![],
                vec![],
                &[],
                &[],
            )
            .map_err(|e| anyhow!("{e:?}"))?;
            println!(
                "A.8.5 decrypted: {:?} => {}",
                String::from_utf8_lossy(&r.cleartext),
                if &r.cleartext[..] == b"Hello, world!" {
                    "MATCH"
                } else {
                    "MISMATCH"
                }
            );
            // A.7 inline-signed
            let data = std::fs::read(format!("{dir}/a7.msg.asc"))?;
            let (msg, _) = Message::from_armor(Cursor::new(data)).map_err(|e| anyhow!("{e:?}"))?;
            let certs = vec![cert.clone()];
            let r =
                unpack(msg, vec![], vec![], vec![], &[], &certs).map_err(|e| anyhow!("{e:?}"))?;
            println!(
                "A.7 inline-signed: {} valid signature(s), content {:?} => {}",
                r.validated.len(),
                String::from_utf8_lossy(&r.cleartext)
                    .lines()
                    .next()
                    .unwrap_or(""),
                if r.validated.len() == 1 {
                    "VERIFIED"
                } else {
                    "NOT VERIFIED (rpgpie policy/time filter)"
                }
            );
        }
        "dump" => print!("{}", dump(&std::fs::read(a.get("in")?)?)?),
        "bench" => {
            let alice = load_tsk(a.get("alice-sec")?)?;
            let bob = load_tsk(a.get("bob-sec")?)?;
            let bob_pub = Certificate::from(bob.clone());
            let alice_pub = Certificate::from(alice.clone());
            let iters = a.num("iters", 20) as usize;
            let afp = tsk_fp(&alice);
            let bfp = tsk_fp(&bob);
            for &len in &[0usize, 100, 1024, 16384, 65536] {
                let payload = make_payload(&afp, &bfp, len);
                let o = SealOpts {
                    intended: true,
                    anonymous: true,
                    unsigned: false,
                };
                let mut sealed = Vec::new();
                let t = Instant::now();
                for _ in 0..iters {
                    sealed = seal(&alice, &bob_pub, &payload, &o)?;
                }
                let seal_ms = t.elapsed().as_secs_f64() * 1000.0 / iters as f64;
                let t = Instant::now();
                for _ in 0..iters {
                    open(&bob, &alice_pub, &sealed, true)?;
                }
                let open_ms = t.elapsed().as_secs_f64() * 1000.0 / iters as f64;
                println!(
                    "impl=rpgp body={len} pad=none json_payload_bytes={} message_bytes={} overhead_vs_payload={} seal_ms={seal_ms:.3} open_ms={open_ms:.3} iters={iters}",
                    payload.len(), sealed.len(), sealed.len() as i64 - payload.len() as i64
                );
            }
        }
        _ => bail!("unknown command {cmd}"),
    }
    Ok(())
}
