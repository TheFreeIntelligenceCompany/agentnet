//! `agentnet relay print-config`: the verified private flag set for a Logos
//! Delivery node and compose snippets. Flags are taken from
//! `spike/relay/docker-compose.yml` and `docs/spike/notes-daemon-rest.md`.

use serde::Serialize;

/// Image pinned by digest (tag v0.39.2, linux/amd64 only).
pub const IMAGE: &str =
    "wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73";

/// Store retention recommended for the service node: 7 days, i.e. the same horizon as the
/// daemon's default `storage.retention_hours = 168` and the maximum message TTL (7 days).
/// `capacity` bounds the number of stored frames (every message and every receipt is one
/// frame); see the sizing note in `notes`. `spike/relay` keeps `time:3600;capacity:5000`
/// as a SHORT test default on purpose (retention tests, small store).
pub const RETENTION_POLICY: &str = "time:604800;capacity:100000";

/// `--rest-relay-cache-capacity` / `--rest-messaging-cache-capacity` for the nodes. The node's
/// REST receive cache is volatile, destructive-on-read and silently drops the oldest entries when
/// full (default 50 slots, shared by all subscribed topics). 1000 absorbs a burst of several hundred
/// frames (messages plus receipts) arriving during a stalled poll; worst-case memory is
/// 1000 x `--max-msg-size` (150 MiB), typically about a megabyte.
pub const REST_CACHE_CAPACITY: u32 = 1000;

/// Everything the command prints.
#[derive(Serialize)]
pub struct RelayConfig {
    pub image: &'static str,
    pub relay_flags: Vec<String>,
    pub client_flags: Vec<String>,
    pub relay_compose: String,
    pub client_compose: String,
    /// Service node with `network_mode: host` (Tailscale variant): REST bound to 127.0.0.1.
    pub relay_compose_host_network: String,
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
    .chain([
        format!("--rest-relay-cache-capacity={REST_CACHE_CAPACITY}"),
        format!("--rest-messaging-cache-capacity={REST_CACHE_CAPACITY}"),
    ])
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
        format!("--store-message-retention-policy={RETENTION_POLICY}"),
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

    // `host_network`: Tailscale-style deployment. The container shares the host network namespace,
    // so the REST server MUST stay on 127.0.0.1 (a `ports:` mapping does not exist there and
    // 0.0.0.0 would expose the unauthenticated REST API on every host interface, tailnet included).
    let compose = |name: &str, flags: &[String], ports: &[&str], host_network: bool| -> String {
        let mut s = String::new();
        s.push_str("services:\n");
        s.push_str(&format!("  {name}:\n"));
        s.push_str(&format!(
            "    image: {IMAGE}   # v0.39.2, linux/amd64 only (runs under qemu on arm64 hosts)\n"
        ));
        s.push_str("    platform: linux/amd64\n");
        s.push_str("    restart: unless-stopped\n");
        if host_network {
            s.push_str("    network_mode: host   # REST stays on 127.0.0.1 below; never use 0.0.0.0 with host networking\n");
        }
        if name == "relay" {
            // A client whose path died silently leaves a half-open tcp connection on the relay; with the kernel default
            // (tcp_retries2=15) it lives 15+ min and the client cannot reconnect meanwhile (results/reconnect, docs/runbook.md 6.3).
            if host_network {
                s.push_str("    # host networking: docker cannot set sysctls here. On the host run `sysctl -w net.ipv4.tcp_retries2=6`\n");
                s.push_str("    # (persist in /etc/sysctl.d/) so half-open client sockets are dropped after ~25 s, not 15+ min.\n");
            } else {
                s.push_str("    sysctls: {net.ipv4.tcp_retries2: \"6\"}   # drop half-open client sockets after ~25 s, not 15+ min\n");
            }
        }
        s.push_str("    command:\n");
        for f in flags {
            let f = if f == "--rest-address=127.0.0.1" && !host_network {
                // Bridge network: inside the container the REST server must listen on all
                // interfaces or the published port cannot reach it. That is safe ONLY because the
                // published port is bound to the host loopback ("127.0.0.1:<host>:8645" below):
                // 0.0.0.0 here is the container's own namespace, not the host's. If you remove the
                // "127.0.0.1:" prefix from the ports mapping, the unauthenticated REST API becomes
                // reachable from your network.
                "--rest-address=0.0.0.0   # container-internal; safe only with the 127.0.0.1: port mapping below"
            } else {
                f.as_str()
            };
            if let Some((flag, comment)) = f.split_once("   #") {
                s.push_str(&format!("      - \"{flag}\"   #{comment}\n"));
            } else {
                s.push_str(&format!("      - \"{f}\"\n"));
            }
        }
        if !host_network {
            let list: Vec<String> = ports.iter().map(|p| format!("\"{p}\"")).collect();
            s.push_str(&format!(
                "    ports: [{}]   # REST: host loopback only (\"127.0.0.1:...\"); tcp/60000 binds all host interfaces, firewall it\n",
                list.join(", ")
            ));
        }
        s.push_str(&format!("    volumes: [\"{name}data:/data\"]\n"));
        s.push_str(&format!("volumes:\n  {name}data: {{}}\n"));
        s
    };
    let relay_compose = compose(
        "relay",
        &relay,
        &["60000:60000", "127.0.0.1:18640:8645"],
        false,
    );
    let client_compose = compose("client", &client, &["127.0.0.1:8645:8645"], false);
    // Host-network variant of the service node: listen/advertise the tailnet address only, REST on loopback.
    let relay_host: Vec<String> = relay
        .iter()
        .map(|f| {
            if f.starts_with("--listen-address=") {
                format!("--listen-address={ip}")
            } else {
                f.clone()
            }
        })
        .collect();
    let relay_compose_host_network = compose("relay", &relay_host, &[], true);

    let tailscale = String::from(
        "UNTESTED - not run on this project's test hosts; reproduce and verify before relying on it.\n\
         1. On every machine: `tailscale up`; note the relay's tailnet IPv4 with `tailscale ip -4` (100.x.y.z).\n\
         2. Relay node: use the relay flags above but bind and advertise the tailnet address only:\n\
            --listen-address=<relay tailnet IP>  --nat=extip:<relay tailnet IP>\n\
            (with Docker use `network_mode: host`, otherwise the container cannot see the tailnet interface; the\n\
            \"docker-compose: relay node, host network\" snippet printed above does this and keeps --rest-address=127.0.0.1:\n\
            with host networking 0.0.0.0 would expose the unauthenticated REST API on every interface, tailnet included).\n\
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
        relay_compose_host_network,
        agentnet_toml_peer: relay_maddr,
        tailscale_untested: tailscale,
        notes: vec![
            "Flags are the set verified in spike/relay (docs/spike/notes-daemon-rest.md). Values that differ from what was run there are UNTESTED as such: the 7-day store retention and --rest-relay-cache-capacity=1000 (spike/relay's own test default is a 1-hour retention, time:3600;capacity:5000).".into(),
            format!("Store retention is set on the service node ({RETENTION_POLICY}: 7 days, 100000 frames; every message and every receipt is one frame, so 100000 frames is about 50000 delivered messages, a few tens of MB for small bodies; a stored frame can be up to --max-msg-size, so add a disk quota if bodies are large). The node applies the policy only at start and every 30 minutes. A daemon's recovery window is the MINIMUM of the relay's retention, the message TTL (default 24 h, max 7 days) and the daemon's own storage.retention_hours (default 168); raising one of them alone changes nothing."),
            "--rest-relay-cache-capacity / --rest-messaging-cache-capacity: the node's REST receive cache is volatile, destructive on read and silently drops the oldest entries when full (default 50 slots, shared by all topics). 1000 keeps a burst of several hundred frames between two polls; worst-case memory is 1000 x --max-msg-size.".into(),
            "ONE Logos Delivery client node PER AGENT (one `agentnet serve` per node): two agents on one node drain each other's frames from the destructive REST cache (each GET returns and deletes), which delays delivery until history sync and is unsupported.".into(),
            "Generate node keys with `openssl rand -hex 32` (one per node); the relay's peer id is printed in its log and by GET /info on its REST port.".into(),
            "Start the relay first, then the client node, then `agentnet serve`.".into(),
            "Half-open connections after a silent path loss: a client whose path died silently (dropped tunnel, lost NAT mapping, laptop sleep) leaves a tcp socket on the relay that the relay's kernel only gives up after 15+ min (tcp_retries2=15); in the simulation the client's node could not reconnect meanwhile. The relay compose above lowers net.ipv4.tcp_retries2 to 6 (~25 s). Alternatively let the client machine's firewall answer stale relay segments with a tcp reset instead of dropping them silently. Measured on a single-host simulation only: results/reconnect/*/SUMMARY.md; the one-connection-per-peer rejection that may explain it is UNTESTED.".into(),
            "--dns-addrs-name-server=127.0.0.1 stops the node's online-monitor from querying 1.1.1.1 every 5 s (the only external contact seen with discovery off). On a no-egress network the node may consider itself offline until its first peer connects.".into(),
            "Cluster ids 1, 2, 3 and 16 select public presets (public bootstrap, RLN) and are rejected by agentnet. Cluster/shard separation is not access control: restrict who can reach tcp/60000 with firewall rules.".into(),
            "REST has no authentication: bind it to loopback only. In a bridge-network compose file the container-internal --rest-address=0.0.0.0 is safe only together with a \"127.0.0.1:<port>:8645\" port mapping; with `network_mode: host` keep --rest-address=127.0.0.1.".into(),
            "The node's REST server answers every request with `Connection: close`, so the agentnet adapter opens one short-lived loopback connection per request (many TIME_WAIT sockets on 127.0.0.1 are expected, not a leak).".into(),
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
    s.push_str("\n## docker-compose: relay node, host network (Tailscale variant, UNTESTED; REST on 127.0.0.1)\n");
    s.push_str(&c.relay_compose_host_network);
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
