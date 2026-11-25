#![allow(dead_code)]
//! Helpers: run the built `agentnet` binary, and an rmcp client over `agentnet mcp`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use rmcp::{
    model::*,
    service::RunningService,
    transport::{ConfigureCommandExt, TokioChildProcess},
    ClientHandler, ClientLifecycleMode, ClientServiceExt, RoleClient,
};
use serde_json::{json, Value};

pub const BIN: &str = env!("CARGO_BIN_EXE_agentnet");
pub const PEER: &str =
    "/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV";

pub fn agentnet(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("--data-dir")
        .arg(dir)
        .args(args)
        .env_remove("AGENTNET_HOME")
        .env_remove("RUST_LOG")
        .output()
        .expect("run agentnet")
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Run and require success; returns stdout.
pub fn ok(dir: &Path, args: &[&str]) -> String {
    let o = agentnet(dir, args);
    assert!(
        o.status.success(),
        "agentnet {args:?} failed: {}\n{}",
        stderr(&o),
        stdout(&o)
    );
    stdout(&o)
}

pub fn json_ok(dir: &Path, args: &[&str]) -> Value {
    let mut a = vec!["--json"];
    a.extend_from_slice(args);
    serde_json::from_str(ok(dir, &a).trim())
        .unwrap_or_else(|e| panic!("not JSON ({e}) for {args:?}"))
}

/// `agentnet init` into `dir/name` with the sample peer; returns (path, address).
pub fn init(root: &Path, name: &str) -> (PathBuf, String) {
    let path = root.join(name);
    let v = json_ok(&path, &["init", "--peer", PEER]);
    (path.clone(), v["address"].as_str().unwrap().to_owned())
}

#[derive(Clone)]
pub struct Collector;
impl ClientHandler for Collector {
    fn get_info(&self) -> ClientConfig {
        let mut c = ClientConfig::default();
        c.client_info = Implementation::new("agentnet-cli-test", "0.0.0");
        c
    }
}

pub type Client = RunningService<RoleClient, Collector>;

/// Spawn `agentnet mcp` for `dir` and complete the 2026-07-28 handshake.
pub async fn mcp_client(dir: &Path, extra: &[&str]) -> anyhow::Result<Client> {
    let dir = dir.to_owned();
    let extra: Vec<String> = extra.iter().map(|s| s.to_string()).collect();
    let cmd = tokio::process::Command::new(BIN).configure(move |c| {
        c.arg("--data-dir").arg(&dir).arg("mcp");
        for e in &extra {
            c.arg(e);
        }
        c.env_remove("RUST_LOG");
    });
    let (transport, _stderr) = TokioChildProcess::builder(cmd)
        .stderr(Stdio::null())
        .spawn()?;
    let client = Collector
        .serve_with_lifecycle(
            transport,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;
    Ok(client)
}

pub async fn call(c: &Client, name: &str, args: Value) -> CallToolResult {
    let mut p = CallToolRequestParams::new(name.to_string());
    if let Some(o) = args.as_object() {
        p = p.with_arguments(o.clone());
    }
    c.peer().call_tool(p).await.expect("protocol error")
}

pub fn structured(r: &CallToolResult) -> Value {
    assert_ne!(r.is_error, Some(true), "tool error: {:?}", r.content);
    r.structured_content.clone().expect("structuredContent")
}

pub fn error_json(r: &CallToolResult) -> Value {
    assert_eq!(r.is_error, Some(true), "expected an error result: {r:?}");
    let block = serde_json::to_value(&r.content[0]).unwrap();
    serde_json::from_str(block["text"].as_str().unwrap()).unwrap()
}

pub fn sub_filter(uris: &[&str]) -> SubscriptionFilter {
    SubscriptionFilter::builder()
        .resource_subscriptions(uris.iter().map(|u| u.to_string()))
        .build()
}

pub async fn wait_until<F: FnMut() -> bool>(what: &str, secs: u64, mut f: F) {
    let end = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < end {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

pub fn contact_record(dir: &Path) -> String {
    let v = json_ok(dir, &["identity", "show"]);
    v["contact_record"].as_str().unwrap().to_owned()
}

pub fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

pub fn kill_term(pid: u32) {
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
}

pub fn _json(v: Value) -> Value {
    json!(v)
}
