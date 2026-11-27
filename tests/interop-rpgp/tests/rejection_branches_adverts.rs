//! The signed (not encrypted) advert path has its own copy of the signature-type and version
//! checks (`SigHelper::check` in crates/core/src/crypto/pgp.rs). Messages signed by rPGP over a
//! genuine advert record: the binary v6 control is accepted, a text-type (0x01) signature and a v4
//! signature by the v6 key are not. (A signing-subkey advert would need a forged record that
//! embeds a certificate with a signing subkey: UNTESTED.)
//! Run: `cd tests/interop-rpgp && cargo test --locked -- --nocapture rejection`.

use agentnet_core::crypto::advert::testing as at;
use agentnet_core::crypto::testing as t;
use agentnet_core::crypto::{AdvertContent, AdvertLimits, Capability, Identity, VerifiedAdvert};
use agentnet_interop_rpgp as rp;

const TOPIC: &str = "agentnet-test";
const LIMITS: AdvertLimits = AdvertLimits {
    max_ttl_ms: 86_400_000,
    clock_skew_ms: 120_000,
    max_capabilities: 16,
};

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn parse(doc: &str) -> Result<(), String> {
    VerifiedAdvert::parse_and_verify(doc, TOPIC, now_ms(), &LIMITS)
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

#[test]
fn rejection_advert_signature_type_and_version() {
    let id = Identity::generate_default(now_ms()).unwrap();
    let now = now_ms();
    let doc = id
        .create_advert(
            &AdvertContent {
                topic: TOPIC,
                capabilities: &[Capability {
                    name: "echo".into(),
                    description: "d".into(),
                }],
                display_name: None,
                issued_at: now,
                expires_at: now + 60_000,
                seq: 1,
            },
            &LIMITS,
        )
        .unwrap()
        .to_document();
    parse(&doc).expect("AgentNet's own advert verifies");
    let record = at::content_of(&doc).expect("record");
    let sk = rp::tsk_from_doc(&t::secret_cert_document(&id)).unwrap();
    let make = |o: rp::SealOpts| {
        at::document_from_bytes(&rp::sign_only(&sk, &record, o).expect("rPGP signs"))
    };

    // control: the same record, binary v6 signature made by rPGP
    let ok = make(rp::SealOpts::default());
    parse(&ok).expect("control (rPGP binary v6 signature) is accepted");
    println!("ACCEPTED  control: advert signed by rPGP, binary v6");

    let text = make(rp::SealOpts {
        text_signature: true,
        ..Default::default()
    });
    let e = parse(&text).expect_err("text-type signature must be rejected");
    println!("REJECTED  advert with a text (0x01) signature -> {e}");

    let v4 = make(rp::SealOpts {
        v4_signature: true,
        ..Default::default()
    });
    let e = parse(&v4).expect_err("v4 signature must be rejected");
    println!("REJECTED  advert with a v4 signature by the v6 key -> {e}");
}
