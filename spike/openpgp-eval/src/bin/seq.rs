//! Implementation X: Sequoia (`sequoia-openpgp`). Command line driver, see README.md.
#[path = "../common.rs"]
mod common;

use std::cell::RefCell;
use std::io::Write as _;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use common::*;
use sequoia_openpgp as openpgp;

use openpgp::cert::prelude::*;
use openpgp::cert::{CertRevocationBuilder, SubkeyRevocationBuilder};
use openpgp::crypto::SessionKey;
use openpgp::packet::key::{Key6, SecretParts, SubordinateRole};
use openpgp::packet::prelude::*;
use openpgp::parse::stream::*;
use openpgp::parse::{PacketParser, PacketParserResult, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::padding::Padder;
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Recipient, Signer};
use openpgp::serialize::{Marshal, MarshalInto};
use openpgp::types::{
    KeyFlags, ReasonForRevocation, RevocationStatus, SignatureType, SymmetricAlgorithm,
};
use openpgp::{Cert, Fingerprint, Packet, Profile};

fn hexfp(fp: &Fingerprint) -> String {
    fp.to_hex().to_lowercase()
}

// ---------------------------------------------------------------- certificates

fn gen_cert(enc_validity_days: Option<u64>, created_days_ago: u64) -> Result<(Cert, Signature)> {
    let mut b = CertBuilder::new()
        .set_profile(Profile::RFC9580)?
        .set_cipher_suite(CipherSuite::Cv25519) // v6: Ed25519 + X25519
        .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
        .set_validity_period(None); // the identity key does not expire
    if created_days_ago > 0 {
        b = b.set_creation_time(SystemTime::now() - Duration::from_secs(created_days_ago * 86400));
    }
    let b = b.add_subkey(
        KeyFlags::empty().set_transport_encryption(),
        enc_validity_days.map(|d| Duration::from_secs(d * 86400)),
        None,
    );
    b.generate()
}

fn save_cert(cert: &Cert, path: &str, secret: bool) -> Result<()> {
    let bytes = if secret {
        cert.as_tsk().armored().to_vec()?
    } else {
        cert.armored().to_vec()?
    };
    std::fs::write(path, bytes)?;
    Ok(())
}

fn load(path: &str) -> Result<Cert> {
    Cert::from_file(path).with_context(|| format!("reading {path}"))
}

fn primary_signer(cert: &Cert) -> Result<openpgp::crypto::KeyPair> {
    let p = &StandardPolicy::new();
    Ok(cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| anyhow!("no secret primary"))?
        .into_keypair()
        .or_else(|_: anyhow::Error| -> Result<_> {
            let _ = p;
            bail!("primary secret not usable")
        })?)
}

// ---------------------------------------------------------------- seal / open

pub struct SealOpts {
    pub pad: String,
    pub intended: bool,
    pub anonymous: bool,
    pub unsigned: bool,
}

pub fn seal(from: &Cert, to: &Cert, payload: &[u8], o: &SealOpts, armor: bool) -> Result<Vec<u8>> {
    let p = &StandardPolicy::new();
    // Cert-level validity. Key-level `.revoked(false)` below does NOT see a revocation of the
    // primary key (observed in run 1, results/a2-openpgp/g3-summary-run1-4-fails.txt).
    for (what, c) in [("sender", from), ("recipient", to)] {
        let vc = c
            .with_policy(p, None)
            .map_err(|e| anyhow!("{what} certificate not valid: {e}"))?;
        vc.alive()
            .map_err(|e| anyhow!("{what} certificate not alive: {e}"))?;
        if let RevocationStatus::Revoked(_) = vc.revocation_status() {
            bail!("{what} certificate is revoked");
        }
    }
    // Signing key: any valid signing-capable key with secret material (here the primary).
    let signer = from
        .keys()
        .unencrypted_secret()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .ok_or_else(|| anyhow!("sender has no valid signing key"))?
        .key()
        .clone()
        .into_keypair()?;
    // Recipient keys: every valid (bound, alive, not revoked) transport-encryption subkey.
    let kas: Vec<_> = to
        .keys()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .collect();
    if kas.is_empty() {
        bail!("recipient has no valid encryption subkey (revoked, expired, unbound or missing)");
    }
    let recips: Vec<Recipient> = kas
        .iter()
        .map(|ka| {
            if o.anonymous {
                Recipient::new(ka.valid_cert().features(), None, ka.key())
            } else {
                Recipient::from(ka.clone())
            }
        })
        .collect();

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = if armor {
            Armorer::new(message).build()?
        } else {
            message
        };
        let message = Encryptor::for_recipients(message, recips).build()?;
        let message = if o.pad == "none" {
            message
        } else {
            let mode = o.pad.clone();
            Padder::new(message)
                .with_policy(move |n| {
                    let total = padded_total(n, &mode);
                    // total counts the Padding packet header; its body is `amount`
                    let body = padding_body_for_total(total - n);
                    n + body
                })
                .build()?
        };
        let message = if o.unsigned {
            message
        } else {
            let mut sb = Signer::new(message, signer)?;
            if o.intended {
                sb = sb.add_intended_recipient(to);
            }
            sb.build()?
        };
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(payload)?;
        message.finalize()?;
    }
    Ok(sink)
}

#[derive(Debug)]
pub struct Opened {
    pub payload: Vec<u8>,
    pub signer: String,
    pub decrypted_with: String,
    pub intended: Vec<String>,
}

struct Helper<'a> {
    me: &'a Cert,
    sender: &'a Cert,
    p: &'a StandardPolicy<'a>,
    out: Rc<RefCell<(String, Vec<String>, String)>>,
    require_intended: bool,
}

impl VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(vec![self.sender.clone()])
    }
    fn check(&mut self, s: MessageStructure) -> openpgp::Result<()> {
        let mut saw_enc = false;
        let mut saw_sig = false;
        for (i, layer) in s.into_iter().enumerate() {
            match (i, layer) {
                (0, MessageLayer::Encryption { aead_algo, .. }) => {
                    if aead_algo.is_none() {
                        return Err(anyhow!("not SEIPDv2 (no AEAD)"));
                    }
                    saw_enc = true;
                }
                (1, MessageLayer::SignatureGroup { results }) => {
                    if results.len() != 1 {
                        return Err(anyhow!(
                            "expected exactly one signature, got {}",
                            results.len()
                        ));
                    }
                    match &results[0] {
                        Ok(good) => {
                            let sig = good.sig;
                            let signer_fp = good.ka.cert().fingerprint();
                            if signer_fp != self.sender.fingerprint() {
                                return Err(anyhow!("signer is not the claimed sender"));
                            }
                            let ir: Vec<Fingerprint> = sig.intended_recipients().cloned().collect();
                            if self.require_intended
                                && !ir.iter().any(|f| *f == self.me.fingerprint())
                            {
                                return Err(anyhow!(
                                    "signature has no intended-recipient subpacket naming me"
                                ));
                            }
                            self.out.borrow_mut().0 = hexfp(&signer_fp);
                            self.out.borrow_mut().1 = ir.iter().map(hexfp).collect();
                            saw_sig = true;
                        }
                        Err(e) => return Err(anyhow!("signature verification failed: {e}")),
                    }
                }
                (_, other) => return Err(anyhow!("unexpected message structure: {:?}", other)),
            }
        }
        if !(saw_enc && saw_sig) {
            return Err(anyhow!("message is not encrypted-and-signed"));
        }
        Ok(())
    }
}

impl DecryptionHelper for Helper<'_> {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        // Retention policy is the application's: every secret encryption-capable subkey is tried,
        // including expired/rotated ones, because old messages must stay readable.
        for pkesk in pkesks {
            for ka in self.me.keys().subkeys().unencrypted_secret() {
                if !ka.key().pk_algo().for_encryption() {
                    continue;
                }
                let mut pair = ka.key().clone().into_keypair()?;
                if let Some((algo, sk)) = pkesk.decrypt(&mut pair, sym_algo) {
                    if decrypt(algo, &sk) {
                        self.out.borrow_mut().2 = hexfp(&ka.key().fingerprint());
                        // Returning the certificate arms Sequoia's own intended-recipient check.
                        return Ok(Some(self.me.clone()));
                    }
                }
            }
        }
        Err(anyhow!("no secret key decrypts this message"))
    }
}

pub fn open(me: &Cert, sender: &Cert, data: &[u8], require_intended: bool) -> Result<Opened> {
    let p = &StandardPolicy::new();
    let out = Rc::new(RefCell::new((String::new(), vec![], String::new())));
    let h = Helper {
        me,
        sender,
        p,
        out: out.clone(),
        require_intended,
    };
    let _ = h.p;
    let mut d = DecryptorBuilder::from_bytes(data)?.with_policy(p, None, h)?;
    let mut payload = Vec::new();
    std::io::copy(&mut d, &mut payload)?;
    let o = out.borrow();
    Ok(Opened {
        payload,
        signer: o.0.clone(),
        decrypted_with: o.2.clone(),
        intended: o.1.clone(),
    })
}

// ---------------------------------------------------------------- packet dump

fn dump(data: &[u8], me: Option<&Cert>) -> Result<String> {
    let mut s = String::new();
    let mut ppr = PacketParser::from_bytes(data)?;
    let mut session: Option<(Option<SymmetricAlgorithm>, SessionKey)> = None;
    while let PacketParserResult::Some(mut pp) = ppr {
        let depth = pp.recursion_depth();
        let ind = "  ".repeat(depth as usize);
        match &pp.packet {
            Packet::PKESK(k) => {
                s += &format!(
                    "{ind}PKESK v{} recipient={} pk_algo={:?}\n",
                    k.version(),
                    k.recipient()
                        .map(|r| r.to_string())
                        .unwrap_or_else(|| "<none: anonymous/hidden>".into()),
                    k.pk_algo()
                );
                if let (Some(me), None) = (me, &session) {
                    for ka in me.keys().subkeys().unencrypted_secret() {
                        if let Ok(mut pair) = ka.key().clone().into_keypair() {
                            if let Some((a, sk)) = k.decrypt(&mut pair, None) {
                                session = Some((a, sk));
                                break;
                            }
                        }
                    }
                }
            }
            Packet::SEIP(seip) => {
                s += &format!("{ind}SEIPD {:?}\n", seip);
                if let Some((a, sk)) = &session {
                    let algo = a.unwrap_or(SymmetricAlgorithm::AES256);
                    pp.decrypt(Some(algo), sk).ok();
                    s += &format!("{ind}  (decrypted with recipient key; inner packets follow)\n");
                } else {
                    s += &format!("{ind}  (no key: contents opaque)\n");
                }
            }
            Packet::Signature(sig) => {
                s += &format!(
                    "{ind}Signature v{} type={:?} pk_algo={:?} hash={:?}\n",
                    sig.version(),
                    sig.typ(),
                    sig.pk_algo(),
                    sig.hash_algo()
                );
                for sp in sig.hashed_area().iter() {
                    s += &format!(
                        "{ind}    hashed   {:?} critical={}\n",
                        sp.value(),
                        sp.critical()
                    );
                }
                for sp in sig.unhashed_area().iter() {
                    s += &format!("{ind}    unhashed {:?}\n", sp.value());
                }
            }
            Packet::Literal(l) => {
                s += &format!(
                    "{ind}Literal format={:?} filename={:?}\n",
                    l.format(),
                    l.filename()
                )
            }
            Packet::Padding(_) => s += &format!("{ind}Padding header={:?}\n", pp.header().length()),
            other => s += &format!("{ind}{:?}\n", other.tag()),
        }
        ppr = pp.recurse()?.1;
    }
    Ok(s)
}

// ---------------------------------------------------------------- certificate surgery

fn cert_info(c: &Cert) -> String {
    let p = &StandardPolicy::new();
    let mut s = format!(
        "primary v{} fp={} created={:?}\n",
        c.primary_key().key().version(),
        hexfp(&c.fingerprint()),
        c.primary_key().key().creation_time()
    );
    match c.with_policy(p, None) {
        Ok(vc) => {
            s += &format!(
                "  cert valid: alive={:?} revocation={:?}\n",
                vc.alive().is_ok(),
                vc.revocation_status()
            );
            for ka in vc.keys().subkeys() {
                s += &format!(
                    "  subkey {} algo={:?} flags={:?} alive={:?} revoked={:?}\n",
                    hexfp(&ka.key().fingerprint()),
                    ka.key().pk_algo(),
                    ka.key_flags(),
                    ka.alive().is_ok(),
                    ka.revocation_status()
                );
            }
        }
        Err(e) => s += &format!("  cert NOT valid under policy: {e}\n"),
    }
    let n = c.keys().subkeys().count();
    s += &format!("  raw subkeys in cert (bound or not): {n}\n");
    s
}

fn cmd_cert(a: &Args) -> Result<()> {
    let op = a.1.get(1).map(|s| s.as_str()).unwrap_or("");
    let p = &StandardPolicy::new();
    match op {
        // cert revoke-cert --sec S --out O
        "revoke-cert" => {
            let sec = load(a.get("sec")?)?;
            let mut kp = primary_signer(&sec)?;
            let sig = CertRevocationBuilder::new()
                .set_reason_for_revocation(
                    ReasonForRevocation::KeyCompromised,
                    b"spike: key compromised",
                )?
                .build(&mut kp, &sec, None)?;
            let (c, _) = sec.strip_secret_key_material().insert_packets(sig)?;
            save_cert(&c, a.get("out")?, false)?;
        }
        // cert revoke-subkey --sec S --out O   (revokes every encryption subkey)
        "revoke-subkey" => {
            let sec = load(a.get("sec")?)?;
            let mut kp = primary_signer(&sec)?;
            let mut sigs = vec![];
            for ka in sec.keys().subkeys() {
                sigs.push(Packet::from(
                    SubkeyRevocationBuilder::new()
                        .set_reason_for_revocation(
                            ReasonForRevocation::KeyCompromised,
                            b"spike: subkey compromised",
                        )?
                        .build(&mut kp, &sec, ka.key(), None)?,
                ));
            }
            let (c, _) = sec.strip_secret_key_material().insert_packets(sigs)?;
            save_cert(&c, a.get("out")?, false)?;
        }
        // cert rotate --sec S --days N --retire-old-days M --out-sec O1 --out-pub O2
        "rotate" => {
            let sec = load(a.get("sec")?)?;
            let mut kp = primary_signer(&sec)?;
            // 1. retire (expire) the old subkeys M days from now (kept for decryption by the owner)
            let retire =
                SystemTime::now() + Duration::from_secs(a.num("retire-old-days", 7) * 86400);
            let mut packets: Vec<Packet> = vec![];
            for ka in sec.keys().with_policy(p, None).subkeys() {
                for s in ka.set_expiration_time(&mut kp, None, Some(retire))? {
                    packets.push(s.into());
                }
            }
            // 2. new encryption subkey with its own expiry
            let new: Key<SecretParts, SubordinateRole> = Key6::generate_x25519()?.into();
            let flags = KeyFlags::empty().set_transport_encryption();
            let bind = new.bind(
                &mut kp,
                &sec,
                SignatureBuilder::new(SignatureType::SubkeyBinding)
                    .set_key_flags(flags)?
                    .set_key_validity_period(Duration::from_secs(a.num("days", 90) * 86400))?,
            )?;
            packets.push(new.into());
            packets.push(bind.into());
            let (c, _) = sec.insert_packets(packets)?;
            save_cert(&c, a.get("out-sec")?, true)?;
            save_cert(&c.strip_secret_key_material(), a.get("out-pub")?, false)?;
        }
        // cert strip-binding --pub P --out O : drop every subkey binding signature
        "strip-binding" => {
            let c = load(a.get("pub")?)?;
            let mut out: Vec<Packet> = vec![];
            let mut after_subkey = false;
            for pk in c.into_packets() {
                match &pk {
                    Packet::PublicSubkey(_) | Packet::SecretSubkey(_) => {
                        after_subkey = true;
                        out.push(pk);
                    }
                    Packet::Signature(_) if after_subkey => {}
                    _ => {
                        if !matches!(pk, Packet::Signature(_)) {
                            after_subkey = false;
                        }
                        out.push(pk)
                    }
                }
            }
            let c = Cert::from_packets(out.into_iter())?;
            save_cert(&c, a.get("out")?, false)?;
        }
        // cert graft --victim V --attacker X --out O : victim primary + attacker subkey and
        // attacker's own binding signature (attacker tries to get its subkey accepted on victim cert)
        "graft" => {
            let v = load(a.get("victim")?)?;
            let x = load(a.get("attacker")?)?;
            let mut out: Vec<Packet> = vec![];
            for pk in v.into_packets() {
                if matches!(pk, Packet::PublicSubkey(_) | Packet::SecretSubkey(_)) {
                    break;
                }
                out.push(pk);
            }
            // victim's own subkey packets are replaced by attacker's subkey + attacker's binding
            let mut take = false;
            for pk in x.into_packets() {
                if matches!(pk, Packet::PublicSubkey(_) | Packet::SecretSubkey(_)) {
                    take = true;
                }
                if take {
                    out.push(pk);
                }
            }
            let c = Cert::from_packets(out.into_iter())?;
            save_cert(&c, a.get("out")?, false)?;
        }
        // cert merge --a A --b B --out O
        "merge" => {
            let a1 = load(a.get("a")?)?;
            let b1 = load(a.get("b")?)?;
            let m = a1.merge_public(b1)?;
            save_cert(&m, a.get("out")?, false)?;
        }
        "info" => {
            print!("{}", cert_info(&load(a.get("pub")?)?));
        }
        _ => bail!("unknown cert op"),
    }
    Ok(())
}

// ---------------------------------------------------------------- forward (surreptitious forwarding)

/// Bob decrypts a message he received and re-encrypts the *same signed inner packets* to Carol.
fn forward(me: &Cert, to: &Cert, data: &[u8]) -> Result<Vec<u8>> {
    let p = &StandardPolicy::new();
    let mut inner: Vec<u8> = Vec::new();
    let mut ppr = PacketParser::from_bytes(data)?;
    let mut session: Option<(Option<SymmetricAlgorithm>, SessionKey)> = None;
    while let PacketParserResult::Some(mut pp) = ppr {
        match &pp.packet {
            Packet::PKESK(k) => {
                for ka in me.keys().subkeys().unencrypted_secret() {
                    let mut pair = ka.key().clone().into_keypair()?;
                    if let Some((a, sk)) = k.decrypt(&mut pair, None) {
                        session = Some((a, sk));
                        break;
                    }
                }
            }
            Packet::SEIP(_) => {
                let (a, sk) = session.as_ref().ok_or_else(|| anyhow!("cannot decrypt"))?;
                pp.decrypt(Some(a.unwrap_or(SymmetricAlgorithm::AES256)), sk)?;
            }
            Packet::Padding(_) => {}
            Packet::OnePassSig(_) | Packet::Signature(_) | Packet::Literal(_) => {
                if let Packet::Literal(_) = &pp.packet {
                    pp.buffer_unread_content()?;
                }
                let pk = pp.packet.clone();
                pk.serialize(&mut inner)?;
            }
            _ => {}
        }
        ppr = pp.recurse()?.1;
    }
    if inner.is_empty() {
        bail!("nothing recovered");
    }
    let recips: Vec<Recipient> = to
        .keys()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .map(|ka| Recipient::new(ka.valid_cert().features(), None, ka.key()))
        .collect();
    let mut sink = Vec::new();
    {
        let m = Message::new(&mut sink);
        let mut m = Encryptor::for_recipients(m, recips).build()?;
        m.write_all(&inner)?;
        m.finalize()?;
    }
    Ok(sink)
}

// ---------------------------------------------------------------- main

fn safe_open(me: &Cert, sender: &Cert, d: &[u8]) -> Result<Opened> {
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
        "version" => {
            println!("sequoia-openpgp 2.5.0 (backend feature: {})", backend());
        }
        "gen" => {
            let name = a.get("name")?;
            let dir = a.get("out")?;
            let days = a
                .opt("enc-validity-days")
                .map(|d| d.parse::<u64>())
                .transpose()?;
            let (cert, rev) = gen_cert(days, a.num("created-days-ago", 0))?;
            save_cert(&cert, &format!("{dir}/{name}.sec.asc"), true)?;
            save_cert(
                &cert.clone().strip_secret_key_material(),
                &format!("{dir}/{name}.pub.asc"),
                false,
            )?;
            std::fs::write(format!("{dir}/{name}.rev.asc"), {
                let mut w =
                    openpgp::armor::Writer::new(Vec::new(), openpgp::armor::Kind::Signature)?;
                Packet::from(rev).serialize(&mut w)?;
                w.finalize()?
            })?;
            println!("{} {}", name, hexfp(&cert.fingerprint()));
        }
        "fpr" => println!("{}", hexfp(&load(a.get("cert")?)?.fingerprint())),
        "cert" => cmd_cert(&a)?,
        "seal" => {
            let from = load(a.get("from")?)?;
            let to = load(a.get("to")?)?;
            let payload = match a.opt("payload") {
                Some(f) => std::fs::read(f)?,
                None => make_payload(
                    &hexfp(&from.fingerprint()),
                    &hexfp(&to.fingerprint()),
                    a.num("body", 100) as usize,
                ),
            };
            let o = SealOpts {
                pad: a.opt("pad").unwrap_or("none").into(),
                intended: !a.flag("no-intended"),
                anonymous: !a.flag("named-recipient"),
                unsigned: a.flag("unsigned"),
            };
            let ct = seal(&from, &to, &payload, &o, a.flag("armor"))?;
            std::fs::write(a.get("out")?, &ct)?;
            println!(
                "sealed {} bytes (payload {} bytes)",
                ct.len(),
                payload.len()
            );
        }
        "open" => {
            let me = load(a.get("me")?)?;
            let sender = load(a.get("sender")?)?;
            let data = std::fs::read(a.get("in")?)?;
            let o = open(&me, &sender, &data, !a.flag("allow-no-intended"))?;
            if a.flag("crypto-only") {
                println!(
                    "CRYPTO-OK signer={} intended_recipients={:?} (payload checks skipped)",
                    o.signer, o.intended
                );
                return Ok(());
            }
            let pl = check_payload(&o.payload, &o.signer, &hexfp(&me.fingerprint()), now_ms())?;
            println!(
                "OK signer={} decrypted_with_subkey={} intended_recipients={:?} message_id={} type={} body_len={}",
                o.signer, o.decrypted_with, o.intended, pl.message_id, pl.kind, pl.body.len()
            );
        }
        "forward" => {
            let me = load(a.get("me")?)?;
            let to = load(a.get("to")?)?;
            let data = std::fs::read(a.get("in")?)?;
            std::fs::write(a.get("out")?, forward(&me, &to, &data)?)?;
        }
        "dump" => {
            let me = a.opt("me").map(load).transpose()?;
            print!("{}", dump(&std::fs::read(a.get("in")?)?, me.as_ref())?);
        }
        "bench" => bench(&a)?,
        "rfc-vectors" => rfc_vectors(a.get("dir")?)?,
        "scan" => {
            let me = load(a.get("me")?)?;
            let sender = load(a.get("sender")?)?;
            let data = std::fs::read(a.get("in")?)?;
            let mut accepted = vec![];
            let mut rejected = 0usize;
            for i in 0..data.len() {
                let mut d = data.clone();
                d[i] ^= 0x01;
                match safe_open(&me, &sender, &d) {
                    Ok(_) => accepted.push(i),
                    _ => rejected += 1,
                }
            }
            println!(
                "impl=sequoia flips={} rejected={} accepted={} accepted_offsets={:?}",
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
                "impl=sequoia truncations={} rejected={} accepted={} accepted_lengths={:?}",
                data.len(),
                rej_trunc,
                acc_trunc.len(),
                acc_trunc
            );
        }
        "sizes" => {
            for f in a.1.iter().skip(1) {
                let c = load(f)?;
                println!(
                    "{f}: binary_public={} binary_with_secret={}",
                    c.clone().strip_secret_key_material().to_vec()?.len(),
                    c.as_tsk().to_vec()?.len()
                );
            }
        }
        _ => bail!("unknown command {cmd}"),
    }
    Ok(())
}

fn backend() -> &'static str {
    if cfg!(feature = "seq-nettle") {
        "crypto-nettle"
    } else if cfg!(feature = "seq-openssl") {
        "crypto-openssl"
    } else {
        "crypto-rust"
    }
}

fn bench(a: &Args) -> Result<()> {
    let alice = load(a.get("alice-sec")?)?;
    let bob = load(a.get("bob-sec")?)?;
    let bob_pub = bob.clone().strip_secret_key_material();
    let alice_pub = alice.clone().strip_secret_key_material();
    let iters = a.num("iters", 20) as usize;
    let afp = hexfp(&alice.fingerprint());
    let bfp = hexfp(&bob.fingerprint());
    for &len in &[0usize, 100, 1024, 16384, 65536] {
        for pad in ["none", "pow2"] {
            let payload = make_payload(&afp, &bfp, len);
            let o = SealOpts {
                pad: pad.into(),
                intended: true,
                anonymous: true,
                unsigned: false,
            };
            let mut sealed = Vec::new();
            let t = Instant::now();
            for _ in 0..iters {
                sealed = seal(&alice, &bob_pub, &payload, &o, false)?;
            }
            let seal_ms = t.elapsed().as_secs_f64() * 1000.0 / iters as f64;
            let t = Instant::now();
            for _ in 0..iters {
                open(&bob, &alice_pub, &sealed, true)?;
            }
            let open_ms = t.elapsed().as_secs_f64() * 1000.0 / iters as f64;
            println!(
                "impl=sequoia body={len} pad={pad} json_payload_bytes={} message_bytes={} overhead_vs_payload={} seal_ms={seal_ms:.3} open_ms={open_ms:.3} iters={iters}",
                payload.len(), sealed.len(), sealed.len() as i64 - payload.len() as i64
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- RFC 9580 Appendix A vectors

struct RawHelper<'a> {
    sec: &'a Cert,
    certs: Vec<Cert>,
    good: Rc<RefCell<usize>>,
}
impl VerificationHelper for RawHelper<'_> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.certs.clone())
    }
    fn check(&mut self, s: MessageStructure) -> openpgp::Result<()> {
        for layer in s.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for r in results {
                    if r.is_ok() {
                        *self.good.borrow_mut() += 1;
                    } else {
                        return Err(anyhow!("bad signature in vector"));
                    }
                }
            }
        }
        Ok(())
    }
}
impl DecryptionHelper for RawHelper<'_> {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _s: &[SKESK],
        sym: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        for pkesk in pkesks {
            for ka in self.sec.keys().subkeys().unencrypted_secret() {
                let mut pair = ka.key().clone().into_keypair()?;
                if let Some((algo, sk)) = pkesk.decrypt(&mut pair, sym) {
                    if decrypt(algo, &sk) {
                        return Ok(Some(self.sec.clone()));
                    }
                }
            }
        }
        Err(anyhow!("cannot decrypt"))
    }
}

fn rfc_vectors(dir: &str) -> Result<()> {
    let p = &StandardPolicy::new();
    let expect = "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9";
    let cert = Cert::from_file(format!("{dir}/a3.pub.asc"))?;
    let sec = Cert::from_file(format!("{dir}/a4.sec.asc"))?;
    println!(
        "A.3 cert fingerprint {} expected {} => {}",
        hexfp(&cert.fingerprint()),
        expect,
        if hexfp(&cert.fingerprint()) == expect {
            "MATCH"
        } else {
            "MISMATCH"
        }
    );
    println!(
        "A.3 cert valid under StandardPolicy: {}",
        cert.with_policy(p, None).is_ok()
    );
    println!(
        "A.4 secret key fingerprint {} => {}",
        hexfp(&sec.fingerprint()),
        if hexfp(&sec.fingerprint()) == expect {
            "MATCH"
        } else {
            "MISMATCH"
        }
    );
    // A.8.5: decrypt "Hello, world!" (SEIPDv2/AES-128/OCB, v6 PKESK, trailing Padding packet)
    let good = Rc::new(RefCell::new(0));
    let h = RawHelper {
        sec: &sec,
        certs: vec![],
        good: good.clone(),
    };
    let mut d =
        DecryptorBuilder::from_file(format!("{dir}/a85.msg.asc"))?.with_policy(p, None, h)?;
    let mut out = Vec::new();
    std::io::copy(&mut d, &mut out)?;
    println!(
        "A.8.5 decrypted: {:?} => {}",
        String::from_utf8_lossy(&out),
        if out == b"Hello, world!" {
            "MATCH"
        } else {
            "MISMATCH"
        }
    );
    // A.7: inline-signed message, verify with the A.3 certificate
    let good = Rc::new(RefCell::new(0));
    let h = RawHelper {
        sec: &sec,
        certs: vec![cert.clone()],
        good: good.clone(),
    };
    let mut v = VerifierBuilder::from_file(format!("{dir}/a7.msg.asc"))?.with_policy(p, None, h)?;
    let mut out = Vec::new();
    std::io::copy(&mut v, &mut out)?;
    println!(
        "A.7 inline-signed: {} valid signature(s), content {:?} => {}",
        good.borrow(),
        String::from_utf8_lossy(&out).lines().next().unwrap_or(""),
        if *good.borrow() == 1 {
            "VERIFIED"
        } else {
            "NOT VERIFIED"
        }
    );
    Ok(())
}
