//! `agentnet relay print-config`: the verified private flag set for a Logos
//! Delivery node and compose snippets. Flags are taken from
//! `spike/relay/docker-compose.yml` and `docs/spike/notes-daemon-rest.md`.

use serde::Serialize;

/// Image pinned by digest (tag v0.39.2, linux/amd64 only).
pub const IMAGE: &str =
    "wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73";

/// Everything the command prints.
#[derive(Serialize)]
pub struct RelayConfig {
    pub image: &'static str,
    pub relay_flags: Vec<String>,
    pub client_flags: Vec<String>,
    pub relay_compose: String,
    pub client_compose: String,
    pub agentnet_toml_peer: String,
    pub tailscale_untested: String,
    pub notes: Vec<String>,
}

fn common_flags() -> Vec<String> {
    [
        "--cluster-id=66",
        "--num-shards-in-network=1",
        "--shard=0",
        "--discv5-discovery=false",
        "--peer-exchange=false",
        "--relay-peer-exchange=false",
        "--rendezvous=false",
        "--enable-kad-discovery=false",
        "--quic-support=false",
        "--mix=false",
        "--rln-relay=false",
        "--dns-addrs-name-server=127.0.0.1",
        "--listen-address=0.0.0.0",
        "--tcp-port=60000",
        "--peer-persistence=false",
        "--metrics-server=false",
        "--max-msg-size=150KiB",
        "--rest=true",
        "--rest-admin=true",
        "--rest-address=127.0.0.1",
        "--rest-port=8645",
        "--local-storage-path=/data",
        "--log-level=INFO",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

pub fn build(ip: &str, peer_id: &str, client_ip: &str) -> RelayConfig {
    let relay_maddr = format!("/ip4/{ip}/tcp/60000/p2p/{peer_id}");

    let mut relay = vec![
        "--nodekey=${RELAY_NODEKEY}".to_owned(),
        format!("--nat=extip:{ip}"),
        "--relay=true".into(),
        "--store=true".into(),
        "--store-message-db-url=sqlite:///data/store.sqlite3".into(),
        "--store-message-retention-policy=time:3600;capacity:5000".into(),
        "--filter=true".into(),
        "--lightpush=true".into(),
    ];
    relay.extend(common_flags());

    let mut client = vec![
        "--nodekey=${CLIENT_NODEKEY}".to_owned(),
        format!("--nat=extip:{client_ip}"),
        "--relay=true".into(),
        "--store=false".into(),
        "--filter=false".into(),
        "--lightpush=false".into(),
        format!("--staticnode={relay_maddr}"),
        format!("--storenode={relay_maddr}"),
        format!("--filternode={relay_maddr}"),
        format!("--lightpushnode={relay_maddr}"),
    ];
    client.extend(common_flags());

    let compose = |name: &str, flags: &[String], ports: &[&str], extra: &str| -> String {
        let mut s = String::new();
        s.push_str("services:\n");
        s.push_str(&format!("  {name}:\n"));
        s.push_str(&format!(
            "    image: {IMAGE}   # v0.39.2, linux/amd64 only (runs under qemu on arm64 hosts)\n"
        ));
        s.push_str("    platform: linux/amd64\n");
        s.push_str("    restart: unless-stopped\n");
        s.push_str("    command:\n");
        for f in flags {
            // The in-container REST server must listen on all interfaces so the
            // published port works; the host side stays on loopback.
            let f = if f == "--rest-address=127.0.0.1" {
                "--rest-address=0.0.0.0"
            } else {
                f
            };
            s.push_str(&format!("      - \"{f}\"\n"));
        }
        let list: Vec<String> = ports.iter().map(|p| format!("\"{p}\"")).collect();
        s.push_str(&format!(
            "    ports: [{}]   # REST stays on the host loopback\n",
            list.join(", ")
        ));
        s.push_str(extra);
        s.push_str(&format!("    volumes: [\"{name}data:/data\"]\n"));
        s.push_str(&format!("volumes:\n  {name}data: {{}}\n"));
        s
    };
    let relay_compose = compose(
        "relay",
        &relay,
        &["60000:60000", "127.0.0.1:18640:8645"],
        "",
    );
    let client_compose = compose("client", &client, &["127.0.0.1:8645:8645"], "");

    let tailscale = String::from(
        "UNTESTED - not run on this project's test hosts; reproduce and verify before relying on it.\n\
         1. On every machine: `tailscale up`; note the relay's tailnet IPv4 with `tailscale ip -4` (100.x.y.z).\n\
         2. Relay node: use the relay flags above but bind and advertise the tailnet address only:\n\
            --listen-address=<relay tailnet IP>  --nat=extip:<relay tailnet IP>\n\
            (with Docker use `network_mode: host`, otherwise the container cannot see the tailnet interface).\n\
         3. Client node: same flags as above with --staticnode/--storenode/--filternode/--lightpushnode =\n\
            /ip4/<relay tailnet IP>/tcp/60000/p2p/<relay peer id>, --nat=extip:<client tailnet IP>.\n\
         4. agentnet.toml: node_url = \"http://127.0.0.1:8645\"; peers = [\"/ip4/<relay tailnet IP>/tcp/60000/p2p/<relay peer id>\"]\n\
            (100.64.0.0/10 passes the private-address check).\n\
         5. Tailnet ACL: allow only your client nodes (by tag) to reach tcp/60000 on the relay and deny everything else, e.g.\n\
            {\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:agentnet-client\"], \"dst\": [\"tag:agentnet-relay:60000\"]}]}\n\
         Tailscale gives encrypted connectivity and machine-level policy only. It is not application identity or message\n\
         encryption (AgentNet does that end to end), and its coordination service sees connection metadata."
    );

    RelayConfig {
        image: IMAGE,
        relay_flags: relay,
        client_flags: client,
        relay_compose,
        client_compose,
        agentnet_toml_peer: relay_maddr,
        tailscale_untested: tailscale,
        notes: vec![
            "Flags are the set verified in spike/relay (docs/spike/notes-daemon-rest.md); retention values other than time:3600;capacity:5000 are UNTESTED.".into(),
            "Generate node keys with `openssl rand -hex 32` (one per node); the relay's peer id is printed in its log and by GET /info on its REST port.".into(),
            "Start the relay first, then the client node, then `agentnet serve`.".into(),
            "--dns-addrs-name-server=127.0.0.1 stops the node's online-monitor from querying 1.1.1.1 every 5 s (the only external contact seen with discovery off). On a no-egress network the node may consider itself offline until its first peer connects.".into(),
            "Cluster ids 1, 2, 3 and 16 select public presets (public bootstrap, RLN) and are rejected by agentnet. Cluster/shard separation is not access control: restrict who can reach tcp/60000 with firewall rules.".into(),
            "Only run the node REST port on loopback: it has no authentication.".into(),
        ],
    }
}

pub fn render_text(c: &RelayConfig) -> String {
    let mut s = String::new();
    s.push_str("# AgentNet private relay configuration (verified flag set)\n\n");
    s.push_str(&format!("Image: {}\n\n", c.image));
    s.push_str("## Relay / store node flags (user-owned service node)\n");
    for f in &c.relay_flags {
        s.push_str(&format!("  {f}\n"));
    }
    s.push_str("\n## Client node flags (the node `agentnet serve` talks to)\n");
    for f in &c.client_flags {
        s.push_str(&format!("  {f}\n"));
    }
    s.push_str("\n## docker-compose: relay / store node (RELAY_NODEKEY from the environment)\n");
    s.push_str(&c.relay_compose);
    s.push_str("\n## docker-compose: client node (CLIENT_NODEKEY from the environment)\n");
    s.push_str(&c.client_compose);
    s.push_str("\n## agentnet.toml\n");
    s.push_str(&format!("peers = [\"{}\"]\n", c.agentnet_toml_peer));
    s.push_str("\n## Tailscale variant (UNTESTED)\n");
    s.push_str(&c.tailscale_untested);
    s.push_str("\n\n## Notes\n");
    for n in &c.notes {
        s.push_str(&format!("- {n}\n"));
    }
    s
}
