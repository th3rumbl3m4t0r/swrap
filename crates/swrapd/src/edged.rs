//! swrap-edged (`swrapd edge`): the public session node (spec 4, 5.2, 5.3, 8.8, 13).
//!
//! Edge holds no database and no private keys. It
//! * serves the local client API (`/run/swrap-edge/api.sock`) for users logged in here,
//! * runs edge-run sessions (ssh signs through a tunnel to core's filtering agent),
//! * relays delegated sessions to core (`core-pty.sock`),
//! * spools recordings and streams them to core, deleting only after core's ack; at the spool
//!   cap all edge-run sessions end with `spool_full` (fail-closed accounting),
//! * verifies and applies core's signed snapshot (accounts, inbound keys, `inet swrap` table),
//! * relays the web GUI (:8443) to core, and ships its own logs.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use swrap_core::api::{EdgePty, EdgeReq, EdgeSession, Req, Resp, WorkerSpec};
use swrap_core::frame::{aio, kind, Frame};
use swrap_core::Paths;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};

use crate::snapshot::Snapshot;

pub struct Edge {
    pub paths: Paths,
    pub uid: u32,
    pub gid: u32,
    snapshot: Mutex<Option<Snapshot>>,
    link_up: AtomicBool,
    down_since: Mutex<jiff::Timestamp>,
}

impl Edge {
    fn down_msg(&self) -> String {
        format!(
            "swrap: core unreachable since {}; sessions unavailable",
            swrap_core::time::fmt_display(*self.down_since.lock().unwrap(), &self.tz(), false)
        )
    }
    fn tz(&self) -> String {
        swrap_core::time::DEFAULT_ZONE.into()
    }
    fn snap_user(&self, name: &str) -> Option<crate::snapshot::SnapUser> {
        self.snapshot.lock().unwrap().as_ref()?.users.iter().find(|u| u.name == name && !u.disabled).cloned()
    }
    fn edge_setting(&self, k: &str) -> Option<toml::Value> {
        self.snapshot.lock().unwrap().as_ref()?.edge.get(k).cloned()
    }
    fn set_link(&self, up: bool) {
        let was = self.link_up.swap(up, Ordering::SeqCst);
        if was && !up {
            *self.down_since.lock().unwrap() = swrap_core::time::now();
        }
    }
}

// ---------------------------------------------------------------- core calls

async fn core_connect(e: &Edge) -> Result<UnixStream> {
    match tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(e.paths.core_api())).await {
        Ok(Ok(s)) => Ok(s),
        _ => {
            e.set_link(false);
            bail!("{}", e.down_msg())
        }
    }
}

/// One request, one final response (STDOUT/STDERR/EVENT/DATA frames are passed to `on_frame`).
async fn core_call(e: &Edge, req: &EdgeReq, mut on_frame: impl FnMut(&Frame)) -> Result<Resp> {
    let mut s = core_connect(e).await?;
    aio::write_frame(&mut s, &Frame::json(kind::REQ, req)).await?;
    loop {
        match aio::read_frame(&mut s).await? {
            Some(f) if f.kind == kind::RESP => {
                e.set_link(true);
                return Ok(f.parse()?);
            }
            Some(f) => on_frame(&f),
            None => {
                e.set_link(false);
                bail!("{}", e.down_msg())
            }
        }
    }
}

// ---------------------------------------------------------------- main

pub fn main() -> Result<()> {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
    let paths = Paths::from_env();
    let pw = swrap_core::sys::user_by_name("swrap-edge").context("user swrap-edge missing (swrap install edge)")?;
    let e = Arc::new(Edge {
        paths,
        uid: pw.uid.as_raw(),
        gid: pw.gid.as_raw(),
        snapshot: Mutex::new(None),
        link_up: AtomicBool::new(false),
        down_since: Mutex::new(swrap_core::time::now()),
    });
    for (d, mode, own) in [(e.paths.run.clone(), 0o755, false), (e.paths.sessions(), 0o711, false), (e.paths.live(), 0o755, true)] {
        std::fs::create_dir_all(&d)?;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode))?;
        if own {
            std::os::unix::fs::chown(&d, Some(e.uid), Some(e.gid))?;
        }
    }
    // Last verified snapshot: edge logins keep working while the link is down.
    if let Ok(t) = std::fs::read_to_string(e.paths.snapshot_dir().join("current.toml")) {
        if let Ok(s) = toml::from_str::<Snapshot>(&t) {
            let _ = apply_nft(&e, &s);
            // Docs link for every current account (also ones created before this existed).
            for u in &s.users {
                if let Some(pw) = swrap_core::sys::user_by_name(&u.name) {
                    swrap_core::paths::ensure_docs_link(&pw.dir, pw.uid.as_raw(), pw.gid.as_raw());
                }
            }
            *e.snapshot.lock().unwrap() = Some(s);
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build()?;
    rt.block_on(async move {
        eprintln!("swrap-edged: started");
        tokio::spawn(hello_loop(e.clone()));
        tokio::spawn(snapshot_loop(e.clone()));
        tokio::spawn(spool_loop(e.clone()));
        tokio::spawn(log_loop(e.clone()));
        tokio::spawn(web_relay(e.clone()));
        tokio::spawn(jobs_loop(e.clone()));
        serve_api(e).await
    })
}

async fn hello_loop(e: Arc<Edge>) {
    loop {
        let r = core_call(&e, &EdgeReq::Hello { node: swrap_core::sys::hostname(), version: env!("CARGO_PKG_VERSION").into(), now: swrap_core::time::fmt_utc(swrap_core::time::now()), addrs: local_addrs() }, |_| {}).await;
        e.set_link(r.is_ok());
        tokio::time::sleep(Duration::from_secs(if r.is_ok() { 30 } else { 5 })).await;
    }
}

/// Edge's own addresses (for `from=` on hosts in edge's networks).
fn local_addrs() -> Vec<String> {
    let mut v = vec![];
    if let Ok(o) = Command::new("ip").args(["-o", "addr", "show", "scope", "global"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            let ifname = l.split_whitespace().nth(1).unwrap_or("");
            if ["podman", "cni", "docker", "virbr", "veth", "br-"].iter().any(|p| ifname.starts_with(p)) {
                continue;
            }
            let mut it = l.split_whitespace();
            while let Some(t) = it.next() {
                if t == "inet" || t == "inet6" {
                    if let Some(a) = it.next().and_then(|a| a.split('/').next()) {
                        v.push(a.to_string());
                    }
                }
            }
        }
    }
    v
}

// ---------------------------------------------------------------- jobs from core

async fn jobs_loop(e: Arc<Edge>) {
    loop {
        match core_call(&e, &EdgeReq::Jobs, |_| {}).await {
            Ok(r) if r.ok && r.data.get("kind").is_some() => {
                let Ok(job) = serde_json::from_value::<swrap_core::api::EdgeJob>(r.data) else { continue };
                let e = e.clone();
                tokio::spawn(async move { run_job(e, job).await });
            }
            Ok(_) => {}
            Err(_) => tokio::time::sleep(Duration::from_secs(5)).await,
        }
    }
}

async fn run_job(e: Arc<Edge>, job: swrap_core::api::EdgeJob) {
    use swrap_core::api::EdgeJob;
    match job {
        EdgeJob::Keyscan { id, addr, port } => {
            let ok_addr = !addr.is_empty() && !addr.starts_with('-') && !addr.contains(char::is_whitespace);
            let out = if ok_addr {
                tokio::process::Command::new("ssh-keyscan").args(["-T", "10", "-p", &port.to_string(), "-t", "ed25519,ecdsa,rsa", &addr]).output().await.map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
            } else {
                String::new()
            };
            let _ = core_call(&e, &EdgeReq::JobResult { id, result: json!({"stdout": out}) }, |_| {}).await;
        }
        EdgeJob::Exec { id, plan, stdin_b64, timeout_secs } => {
            let res = exec_job(&e, &plan, &stdin_b64, timeout_secs).await.unwrap_or_else(|err| json!({"code": 255, "stdout_b64": "", "stderr": format!("edge: {err:#}"), "ssh_log": ""}));
            let _ = std::fs::remove_dir_all(e.paths.session_dir(&plan.id));
            let _ = core_call(&e, &EdgeReq::JobResult { id, result: res }, |_| {}).await;
        }
        EdgeJob::Session { id, user, plan, cols, rows, term } => {
            let Ok(mut s) = core_connect(&e).await else { return };
            if aio::write_frame(&mut s, &Frame::json(kind::REQ, &EdgeReq::Attach { id })).await.is_err() {
                return;
            }
            if let Err(err) = edge_run(&e, &user, plan, cols, rows, term, s).await {
                ship_line(&e, format!("core-origin session failed on edge: {err:#}")).await;
            }
        }
    }
}

/// Non-interactive ssh from edge (enrollment/admin on edge-network hosts), signing through core.
async fn exec_job(e: &Arc<Edge>, plan: &EdgeSession, stdin_b64: &str, timeout_secs: u64) -> Result<Value> {
    use base64::Engine;
    let (sdir, argv, _authed) = prepare_session(e, plan).await?;
    let input = base64::engine::general_purpose::STANDARD.decode(stdin_b64)?;
    let (uid, gid) = (e.uid, e.gid);
    let mut c = tokio::process::Command::new(&argv[0]);
    c.args(&argv[1..])
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .env("HOME", &sdir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    unsafe {
        c.pre_exec(move || {
            libc::setgroups(0, std::ptr::null());
            if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = c.spawn()?;
    let mut sin = child.stdin.take().unwrap();
    tokio::spawn(async move {
        let _ = sin.write_all(&input).await;
    });
    let out = match tokio::time::timeout(Duration::from_secs(timeout_secs.clamp(10, 3600)), child.wait_with_output()).await {
        Ok(r) => r?,
        // kill_on_drop ends ssh; report instead of failing so callers can tell the model.
        Err(_) => return Ok(json!({"code": 124, "stdout_b64": "", "stderr": "timed out", "ssh_log": "", "timed_out": true})),
    };
    let ssh_log = std::fs::read_to_string(sdir.join("ssh.log")).unwrap_or_default();
    let tail: String = ssh_log.lines().rev().take(60).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
    // The result travels in one link frame (MAX_FRAME): keep it well below 1 MiB.
    let mut stdout = out.stdout;
    let dropped = stdout.len().saturating_sub(640 << 10);
    stdout.truncate(640 << 10);
    let stderr = &out.stderr[..out.stderr.len().min(64 << 10)];
    Ok(json!({
        "code": out.status.code().unwrap_or(255),
        "stdout_b64": base64::engine::general_purpose::STANDARD.encode(&stdout),
        "stderr": String::from_utf8_lossy(stderr),
        "ssh_log": tail,
        "dropped": dropped,
    }))
}

// ---------------------------------------------------------------- snapshot

fn verify_snapshot(e: &Edge, text: &str, sig: &str) -> Result<()> {
    let signers = e.paths.trust().join("allowed_signers");
    let tmp = e.paths.snapshot_dir().join(format!(".verify-{}.sig", std::process::id()));
    std::fs::write(&tmp, sig)?;
    let mut c = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&signers)
        .args(["-I", "core", "-n", crate::snapshot::NAMESPACE, "-s"])
        .arg(&tmp)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    c.stdin.take().unwrap().write_all(text.as_bytes())?;
    let o = c.wait_with_output()?;
    let _ = std::fs::remove_file(&tmp);
    if !o.status.success() {
        bail!("snapshot signature invalid: {}", String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(())
}

async fn snapshot_loop(e: Arc<Edge>) {
    loop {
        let have = e.snapshot.lock().unwrap().as_ref().map(|s| s.version).unwrap_or(0);
        match core_call(&e, &EdgeReq::Snapshot { have }, |_| {}).await {
            Ok(r) if r.ok => {
                if let (Some(text), Some(sig)) = (r.data["snapshot"].as_str(), r.data["sig"].as_str()) {
                    let (text, sig) = (text.to_string(), sig.to_string());
                    let e2 = e.clone();
                    let res = tokio::task::spawn_blocking(move || accept_snapshot(&e2, &text, &sig)).await;
                    if let Ok(Err(err)) = res {
                        ship_line(&e, format!("snapshot rejected: {err:#}")).await;
                    }
                }
            }
            _ => tokio::time::sleep(Duration::from_secs(5)).await,
        }
    }
}

fn accept_snapshot(e: &Edge, text: &str, sig: &str) -> Result<()> {
    verify_snapshot(e, text, sig)?;
    let s: Snapshot = toml::from_str(text)?;
    let have = e.snapshot.lock().unwrap().as_ref().map(|s| s.version).unwrap_or(0);
    if s.version <= have {
        bail!("snapshot version {} not newer than {} (rollback refused)", s.version, have);
    }
    apply_accounts(e, &s)?;
    apply_nft(e, &s)?;
    let dir = e.paths.snapshot_dir();
    swrap_core::atomic::write(&dir.join("current.toml"), text.as_bytes(), 0o600, swrap_core::atomic::Owner::NONE)?;
    swrap_core::atomic::write(&dir.join("current.sig"), sig.as_bytes(), 0o600, swrap_core::atomic::Owner::NONE)?;
    eprintln!("swrap-edged: snapshot {} applied", s.version);
    *e.snapshot.lock().unwrap() = Some(s);
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let o = Command::new(cmd).args(args).output()?;
    if !o.status.success() {
        bail!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(())
}

fn apply_accounts(e: &Edge, s: &Snapshot) -> Result<()> {
    let managed_p = e.paths.root.join("managed-users");
    let mut managed: Vec<String> = std::fs::read_to_string(&managed_p).unwrap_or_default().lines().map(String::from).collect();
    let shell = swrap_core::paths::libexec("swrap-shell");
    let akdir = Path::new("/etc/ssh/authorized_keys");
    std::fs::create_dir_all(akdir)?;
    for u in &s.users {
        if !swrap_core::paths::safe_component(&u.name) || u.name.contains('.') || u.name == "root" || u.name.starts_with("swrap") {
            continue;
        }
        let exists = swrap_core::sys::user_by_name(&u.name).is_some();
        if exists && !managed.contains(&u.name) {
            // Never take over an account swrap did not create.
            continue;
        }
        let groups = if u.role == "admin" { "swrap-users,swrap-admin" } else { "swrap-users" };
        if !exists {
            run("useradd", &["-m", "-s", &shell.to_string_lossy(), "-G", groups, "-c", "swrap AAA user", &u.name])?;
            managed.push(u.name.clone());
        } else {
            run("usermod", &["-s", &shell.to_string_lossy(), "-G", groups, &u.name])?;
        }
        run("usermod", &["-p", "*", &u.name])?;
        if let Some(pw) = swrap_core::sys::user_by_name(&u.name) {
            swrap_core::paths::ensure_docs_link(&pw.dir, pw.uid.as_raw(), pw.gid.as_raw());
        }
        let _ = run("usermod", &[if u.disabled { "-L" } else { "-U" }, &u.name]);
        let mut ak = String::from("# managed by swrap (snapshot); edits are overwritten\n");
        if !u.disabled {
            for k in &u.keys {
                if !k.contains('\n') {
                    ak += k.trim();
                    ak.push('\n');
                }
            }
        }
        swrap_core::atomic::write(&akdir.join(&u.name), ak.as_bytes(), 0o644, swrap_core::atomic::Owner::new(0, 0))?;
    }
    // Accounts that left the snapshot: keep home, lock, drop keys.
    for m in managed.clone() {
        if !s.users.iter().any(|u| u.name == m) {
            let _ = run("usermod", &["-L", "-s", "/sbin/nologin", &m]);
            let _ = std::fs::write(akdir.join(&m), "# removed by swrap\n");
        }
    }
    managed.sort();
    managed.dedup();
    swrap_core::atomic::write(&managed_p, (managed.join("\n") + "\n").as_bytes(), 0o600, swrap_core::atomic::Owner::NONE)?;
    let _ = Command::new("restorecon").arg("-R").arg(akdir).output();
    Ok(())
}

/// `N/PT1M`-style rate → packets per minute.
fn per_minute(v: Option<toml::Value>, default: u32) -> u32 {
    let Some(s) = v.and_then(|v| v.as_str().map(String::from)) else { return default };
    let Some((n, d)) = s.split_once('/') else { return default };
    let n: u32 = n.parse().unwrap_or(default);
    let secs = swrap_core::time::IsoDuration::parse(d).ok().and_then(|d| d.exact()).map(|d| d.as_secs().max(1)).unwrap_or(60);
    ((n as u64 * 60) / secs).max(1) as u32
}

fn nft_set(fw: &[swrap_core::config::FwEntry], v6: bool) -> String {
    let t = swrap_core::time::now();
    let mut v = vec![];
    for e in fw {
        let nb = e.not_before.as_deref().and_then(|s| swrap_core::time::parse_datetime(s).ok());
        let na = e.not_after.as_deref().and_then(|s| swrap_core::time::parse_datetime(s).ok());
        if nb.map(|x| t < x).unwrap_or(false) || na.map(|x| t >= x).unwrap_or(false) {
            continue;
        }
        let Ok(n) = e.cidr.parse::<ipnet::IpNet>() else { continue };
        if matches!(n, ipnet::IpNet::V6(_)) != v6 {
            continue;
        }
        let timeout = na.map(|x| format!(" timeout {}s", (x.as_second() - t.as_second()).max(1))).unwrap_or_default();
        v.push(format!("{n}{timeout}"));
    }
    if v.is_empty() { String::new() } else { format!("elements = {{ {} }}", v.join(", ")) }
}

/// Edge table: SSH blocks + per-source rate limit on :22, web allow-list on the relay port,
/// and outbound SSH only for the session user (users cannot bypass recording with their own ssh).
/// Drop-only; swrap never touches other tables (Stalwart, firewalld).
fn apply_nft(e: &Edge, s: &Snapshot) -> Result<()> {
    let rate = per_minute(s.edge.get("ssh_new_per_source").cloned(), 10);
    let web_port = s.edge.get("web_port").and_then(|v| v.as_integer()).unwrap_or(8443);
    let ports: Vec<String> = s.edge.get("managed_ports").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_integer()).map(|x| x.to_string()).collect()).unwrap_or_else(|| vec!["22".into()]);
    let rules = format!(
        r#"table inet swrap {{}}
delete table inet swrap
table inet swrap {{
  set ssh_block4 {{ type ipv4_addr; flags interval, timeout; {b4} }}
  set ssh_block6 {{ type ipv6_addr; flags interval, timeout; {b6} }}
  set web4 {{ type ipv4_addr; flags interval, timeout; {w4} }}
  set web6 {{ type ipv6_addr; flags interval, timeout; {w6} }}
  set ssh_rate4 {{ type ipv4_addr; size 65535; flags dynamic, timeout; timeout 5m; }}
  set ssh_rate6 {{ type ipv6_addr; size 65535; flags dynamic, timeout; timeout 5m; }}
  chain input {{
    type filter hook input priority -5; policy accept;
    iif "lo" accept
    tcp dport 22 ip saddr @ssh_block4 drop
    tcp dport 22 ip6 saddr @ssh_block6 drop
    tcp dport 22 ct state new add @ssh_rate4 {{ ip saddr limit rate over {rate}/minute burst {rate} packets }} drop
    tcp dport 22 ct state new add @ssh_rate6 {{ ip6 saddr limit rate over {rate}/minute burst {rate} packets }} drop
    tcp dport {web_port} ip saddr != @web4 drop
    tcp dport {web_port} ip6 saddr != @web6 drop
  }}
  chain output {{
    type filter hook output priority -5; policy accept;
    oif "lo" accept
    tcp dport {{ {ports} }} ct state new meta skuid != {{ 0, {uid} }} drop
  }}
}}
"#,
        b4 = nft_set(&s.firewall.ssh_block, false),
        b6 = nft_set(&s.firewall.ssh_block, true),
        w4 = nft_set(&s.firewall.web_allow, false),
        w6 = nft_set(&s.firewall.web_allow, true),
        ports = ports.join(", "),
        uid = e.uid,
    );
    let mut c = Command::new("nft").arg("-f").arg("-").stdin(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    c.stdin.take().unwrap().write_all(rules.as_bytes())?;
    let o = c.wait_with_output()?;
    if !o.status.success() {
        bail!("nft: {}", String::from_utf8_lossy(&o.stderr));
    }
    Ok(())
}

// ---------------------------------------------------------------- local API

async fn serve_api(e: Arc<Edge>) -> Result<()> {
    let sock = e.paths.api_sock();
    let _ = std::fs::remove_file(&sock);
    let l = UnixListener::bind(&sock)?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666))?;
    loop {
        let (s, _) = l.accept().await?;
        let e = e.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client(e, s).await {
                eprintln!("swrap-edged: client: {err:#}");
            }
        });
    }
}

async fn reply(s: &mut UnixStream, r: Resp) -> Result<()> {
    aio::write_frame(s, &Frame::json(kind::RESP, &r)).await?;
    Ok(())
}

async fn handle_client(e: Arc<Edge>, mut s: UnixStream) -> Result<()> {
    let cred = swrap_core::sys::peer_cred(&s)?;
    let name = swrap_core::sys::user_name(cred.uid).unwrap_or_default();
    let Some(f) = aio::read_frame(&mut s).await? else { return Ok(()) };
    let req: Req = match f.parse() {
        Ok(r) => r,
        Err(err) => return reply(&mut s, Resp::err(format!("bad request: {err}"))).await,
    };
    // Workers (swrap-edge) and root may only send audit events / status.
    let is_worker = cred.uid == e.uid || cred.uid == 0;
    let known = e.snap_user(&name).is_some();
    if !known && !(is_worker && matches!(req, Req::Audit { .. } | Req::Status | Req::Whoami)) {
        return reply(&mut s, Resp::err(format!("swrap: {name} is not an AAA user on this node"))).await;
    }
    match req {
        Req::Shell { .. } => start_shell(&e, &name, cred.uid, req, s).await,
        Req::Sw { .. } => start_sw(&e, &name, req, s).await,
        // swai runs on core; this node only relays the terminal (like a delegated sw).
        Req::AiStart { ref client_addr, .. } | Req::AiAttach { ref client_addr, .. } => {
            let ca = client_addr.clone();
            delegate(&e, &name, &ca, req, s).await
        }
        Req::AiWorker { .. } => reply(&mut s, Resp::err("not on edge")).await,
        Req::SessionCheck { id } => {
            let live = live_owned(&e.paths, &id, &name);
            reply(&mut s, Resp::ok(json!({"live": live}))).await
        }
        Req::Whoami => {
            reply(&mut s, Resp::ok(json!({"user": name, "node": "edge", "link": e.link_up.load(Ordering::SeqCst)}))).await
        }
        other => {
            let fwd = EdgeReq::Api { user: name, client_addr: String::new(), req: other };
            let mut frames = vec![];
            match core_call(&e, &fwd, |f| frames.push(f.clone())).await {
                Ok(r) => {
                    for f in frames {
                        aio::write_frame(&mut s, &f).await?;
                    }
                    reply(&mut s, r).await
                }
                Err(err) => reply(&mut s, Resp::err(err)).await,
            }
        }
    }
}

/// (edge-run sw sessions on this node, of which `user`'s) from the live markers.
fn edge_run_counts(e: &Edge, user: &str) -> (usize, usize) {
    let mut total = 0;
    let mut mine = 0;
    for m in std::fs::read_dir(e.paths.live()).into_iter().flatten().flatten() {
        let Some(j) = std::fs::read_to_string(m.path()).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()) else { continue };
        let alive = j["pid"].as_i64().map(|p| unsafe { libc::kill(p as i32, 0) } == 0).unwrap_or(false);
        if j["kind"] == "sw" && j["delegated"] != true && alive {
            total += 1;
            if j["user"] == user {
                mine += 1;
            }
        }
    }
    (total, mine)
}

fn live_owned(p: &Paths, id: &str, user: &str) -> bool {
    if !swrap_core::paths::safe_component(id) {
        return false;
    }
    std::fs::read_to_string(p.live().join(id))
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .map(|j| j["user"] == user && j["kind"] == "sw")
        .unwrap_or(false)
}

fn spawn_worker(e: &Edge, spec: &WorkerSpec, client: &std::os::unix::net::UnixStream) -> Result<u32> {
    let exe = std::env::current_exe()?;
    let fd = client.as_raw_fd();
    let (uid, gid) = (e.uid, e.gid);
    let mut cmd = Command::new(exe);
    cmd.arg("worker").env_clear().env("PATH", "/usr/bin:/usr/sbin").env("SWRAP_ROLE", "edge").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::inherit());
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let fl = libc::fcntl(3, libc::F_GETFD);
            libc::fcntl(3, libc::F_SETFD, fl & !libc::FD_CLOEXEC);
            libc::setsid();
            libc::setgroups(0, std::ptr::null());
            if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    child.stdin.take().unwrap().write_all(&serde_json::to_vec(spec)?)?;
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

fn edge_view_url(e: &Edge, id: &str) -> Option<String> {
    let host = e.edge_setting("address")?.as_str()?.to_string();
    let port = e.edge_setting("web_port").and_then(|v| v.as_integer()).unwrap_or(8443);
    Some(format!("https://{host}:{port}/play/{id}"))
}

fn rec_cfg() -> swrap_core::config::RecCfg {
    swrap_core::config::RecCfg::default()
}

async fn start_shell(e: &Arc<Edge>, name: &str, uid: u32, req: Req, s: UnixStream) -> Result<()> {
    let Req::Shell { cols, rows, term, client_addr, conn, nonce, sshd_pid } = req else { unreachable!() };
    let std = s.into_std()?;
    std.set_nonblocking(false)?;
    if nonce.len() < 16 || !nonce.bytes().all(|b| b.is_ascii_alphanumeric()) {
        let mut std = std;
        let _ = swrap_core::frame::write_frame(&mut std, &Frame::json(kind::RESP, &Resp::err("bad nonce")));
        return Ok(());
    }
    let id = swrap_core::new_id();
    let mut header = serde_json::Map::new();
    header.insert("kind".into(), "shell".into());
    for (k, v) in [("origin", json!("edge")), ("exec", json!("edge")), ("delegated", json!(false)), ("aaa_user", json!(name)), ("client_addr", json!(client_addr)), ("conn", json!(conn)), ("cols", json!(cols)), ("rows", json!(rows)), ("term", json!(term)), ("record_input", json!(false))] {
        header.insert(k.into(), v);
    }
    let spec = WorkerSpec {
        mode: "shell".into(),
        id: id.clone(),
        aaa_user: name.into(),
        uid,
        rec_path: e.paths.spool().join(format!("{id}.swrec")).to_string_lossy().into(),
        session_dir: String::new(),
        header,
        argv: vec![],
        cols,
        rows,
        term,
        nonce,
        record_input: false,
        signer: "edge".into(),
        recsign_key: e.paths.recsign().join("ed25519.key").to_string_lossy().into(),
        rec_cfg: rec_cfg(),
        live_marker: e.paths.live().join(&id).to_string_lossy().into(),
        banner: edge_view_url(e, &id).map(|u| format!("swrap: view {u}")).unwrap_or_default(),
        sshd_pid,
        ai: None,
        sftp: None,
    };
    spawn_worker(e, &spec, &std)?;
    Ok(())
}

async fn start_sw(e: &Arc<Edge>, name: &str, req: Req, mut s: UnixStream) -> Result<()> {
    let Req::Sw { target, cmd, cols, rows, term, client_addr, conn, tty } = req.clone() else { unreachable!() };
    let auth = EdgeReq::Authorize { user: name.into(), client_addr: client_addr.clone(), conn: conn.clone(), target, cmd, cols, rows, term: term.clone(), tty };
    let r = match core_call(e, &auth, |_| {}).await {
        Ok(r) => r,
        Err(err) => return reply(&mut s, Resp::err(err)).await,
    };
    if !r.ok {
        return reply(&mut s, r).await;
    }
    let plan: EdgeSession = serde_json::from_value(r.data)?;
    if plan.delegate {
        return delegate(e, name, &client_addr, req, s).await;
    }
    // Limits for sessions running here (delegated ones are counted by core): spec 19.5.
    let (total, mine) = edge_run_counts(e, name);
    let max_total = e.edge_setting("sessions_edge").and_then(|v| v.as_integer()).unwrap_or(20) as usize;
    let max_user = e.edge_setting("sessions_per_user").and_then(|v| v.as_integer()).unwrap_or(10) as usize;
    if total >= max_total || mine >= max_user {
        let why = if total >= max_total { format!("session limit reached on edge ({max_total})") } else { format!("per-user session limit reached ({max_user})") };
        return reply(&mut s, Resp::err(format!("swrap: {why}"))).await;
    }
    edge_run(e, name, plan, cols, rows, term, s).await
}

/// Delegated session: core runs ssh; we relay the stream and keep a local live marker so the
/// recorded edge shell pauses correctly for nested `sw`.
async fn delegate(e: &Arc<Edge>, name: &str, client_addr: &str, req: Req, mut s: UnixStream) -> Result<()> {
    let mut up = match tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(e.paths.core_pty())).await {
        Ok(Ok(u)) => u,
        _ => {
            e.set_link(false);
            return reply(&mut s, Resp::err(e.down_msg())).await;
        }
    };
    aio::write_frame(&mut up, &Frame::json(kind::REQ, &EdgePty { user: name.into(), client_addr: client_addr.into(), req })).await?;
    let Some(first) = aio::read_frame(&mut up).await? else { return reply(&mut s, Resp::err(e.down_msg())).await };
    aio::write_frame(&mut s, &first).await?;
    let marker = if first.kind == kind::RESP {
        let r: Resp = first.parse()?;
        r.data["id"].as_str().filter(|i| swrap_core::paths::safe_component(i)).map(|id| {
            let p = e.paths.live().join(id);
            let _ = std::fs::write(&p, json!({"id": id, "user": name, "kind": "sw", "pid": std::process::id(), "delegated": true}).to_string());
            p
        })
    } else {
        None
    };
    let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
    if let Some(p) = marker {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

/// Session dir + agent tunnel (ssh's agent socket relays to core's filtering proxy for `plan.id`).
/// Returns (session dir, ssh argv, authed flag).
async fn prepare_session(e: &Arc<Edge>, plan: &EdgeSession) -> Result<(PathBuf, Vec<String>, Arc<AtomicBool>)> {
    let id = plan.id.clone();
    if !swrap_core::paths::safe_component(&id) {
        bail!("bad session id from core");
    }
    let sdir = e.paths.session_dir(&id);
    std::fs::create_dir_all(e.paths.sessions())?;
    std::fs::create_dir(&sdir)?;
    std::fs::set_permissions(&sdir, std::fs::Permissions::from_mode(0o700))?;
    std::os::unix::fs::chown(&sdir, Some(e.uid), Some(e.gid))?;
    let own = swrap_core::atomic::Owner::new(e.uid, e.gid);
    swrap_core::atomic::write(&sdir.join("ssh_config"), plan.ssh_config.as_bytes(), 0o600, own)?;
    swrap_core::atomic::write(&sdir.join("known_hosts"), plan.known_hosts.as_bytes(), 0o600, own)?;
    swrap_core::atomic::write(&sdir.join("id.pub"), plan.pub_key.as_bytes(), 0o600, own)?;
    let asock = sdir.join("agent.sock");
    // The session directory is 0700: bind with the normal umask, then 0600 (a umask change
    // would apply to the whole process, every thread and every program started meanwhile).
    let listener = std::os::unix::net::UnixListener::bind(&asock)?;
    std::fs::set_permissions(&asock, std::fs::Permissions::from_mode(0o600))?;
    std::os::unix::fs::chown(&asock, Some(e.uid), Some(e.gid))?;
    listener.set_nonblocking(true)?;
    let l = UnixListener::from_std(listener)?;
    let e2 = e.clone();
    let id2 = id.clone();
    let authed = Arc::new(AtomicBool::new(false));
    let authed2 = authed.clone();
    tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(150);
        while Instant::now() < deadline && !authed2.load(Ordering::SeqCst) {
            let Ok(Ok((c, _))) = tokio::time::timeout(Duration::from_millis(500), l.accept()).await else { continue };
            match swrap_core::sys::peer_cred(&c) {
                Ok(pc) if pc.uid == e2.uid => {}
                _ => continue,
            }
            let (e3, id3) = (e2.clone(), id2.clone());
            tokio::spawn(async move {
                let mut c = c;
                if let Ok(mut up) = core_connect(&e3).await {
                    if aio::write_frame(&mut up, &Frame::json(kind::REQ, &EdgeReq::Agent { id: id3 })).await.is_ok() {
                        let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
                    }
                }
            });
        }
    });
    let log = sdir.join("ssh.log");
    let mut argv: Vec<String> = vec![
        plan.ssh_bin.clone(),
        "-F".into(), sdir.join("ssh_config").to_string_lossy().into(),
        "-E".into(), log.to_string_lossy().into(),
        "-o".into(), "LogLevel=DEBUG1".into(),
        "-o".into(), format!("IdentityAgent={}", asock.display()),
        "-o".into(), "IdentitiesOnly=yes".into(),
        "-i".into(), sdir.join("id.pub").to_string_lossy().into(),
        "-o".into(), format!("UserKnownHostsFile={}", sdir.join("known_hosts").display()),
        "-o".into(), "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(), "StrictHostKeyChecking=yes".into(),
        "-o".into(), "UpdateHostKeys=no".into(),
        "-o".into(), "ForwardAgent=no".into(),
        "-o".into(), "ForwardX11=no".into(),
        "-o".into(), "ClearAllForwardings=yes".into(),
        "-o".into(), "ControlMaster=no".into(),
        "-o".into(), "ControlPath=none".into(),
        "-o".into(), "PasswordAuthentication=no".into(),
        "-o".into(), "KbdInteractiveAuthentication=no".into(),
        "-o".into(), "BatchMode=yes".into(),
    ];
    argv.extend(plan.argv_tail.iter().cloned());
    Ok((sdir, argv, authed))
}

async fn edge_run(e: &Arc<Edge>, name: &str, plan: EdgeSession, cols: u16, rows: u16, term: String, s: UnixStream) -> Result<()> {
    let id = plan.id.clone();
    let (sdir, argv, authed) = prepare_session(e, &plan).await?;
    let log = sdir.join("ssh.log");
    let mut header = plan.header.clone();
    header.insert("exec".into(), json!("edge"));
    let spec = WorkerSpec {
        mode: "sw".into(),
        id: id.clone(),
        aaa_user: name.into(),
        uid: 0,
        rec_path: e.paths.spool().join(format!("{id}.swrec")).to_string_lossy().into(),
        session_dir: sdir.to_string_lossy().into(),
        header,
        argv,
        cols,
        rows,
        term,
        nonce: plan.nonce.clone(),
        record_input: true,
        signer: "edge".into(),
        recsign_key: e.paths.recsign().join("ed25519.key").to_string_lossy().into(),
        rec_cfg: rec_cfg(),
        live_marker: e.paths.live().join(&id).to_string_lossy().into(),
        banner: plan.banner.clone(),
        sshd_pid: 0,
        ai: None,
        sftp: None,
    };
    let std = s.into_std()?;
    std.set_nonblocking(false)?;
    let pid = spawn_worker(e, &spec, &std)?;
    drop(std);
    // Tell core as soon as ssh authenticated so the per-session agent dies immediately.
    let e2 = e.clone();
    tokio::spawn(async move {
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(150) && unsafe { libc::kill(pid as i32, 0) } == 0 {
            if tokio::fs::read_to_string(&log).await.map(|s| s.contains("Authenticated to ")).unwrap_or(false) {
                authed.store(true, Ordering::SeqCst);
                let _ = core_call(&e2, &EdgeReq::Authenticated { id }, |_| {}).await;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    Ok(())
}

// ---------------------------------------------------------------- spool → core (spec 8.8)

struct Shipping {
    conn: UnixStream,
    acked: u64,
}

fn spool_size(p: &Path) -> u64 {
    std::fs::read_dir(p).map(|rd| rd.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum()).unwrap_or(0)
}

async fn spool_loop(e: Arc<Edge>) {
    let mut ship: HashMap<PathBuf, Shipping> = HashMap::new();
    let mut full_since: Option<Instant> = None;
    loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Fail-closed accounting at the cap.
        let cap = e.edge_setting("spool_max_bytes").and_then(|v| v.as_integer()).unwrap_or(512 << 20) as u64;
        if spool_size(&e.paths.spool()) >= cap {
            if full_since.is_none() {
                full_since = Some(Instant::now());
                let _ = std::fs::write(e.paths.run.join("spool_full"), b"1");
                for m in std::fs::read_dir(e.paths.live()).into_iter().flatten().flatten() {
                    if let Some(j) = std::fs::read_to_string(m.path()).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
                        if j["kind"] == "sw" && j["delegated"] != true {
                            if let Some(pid) = j["pid"].as_i64() {
                                unsafe { libc::kill(pid as i32, libc::SIGTERM) };
                            }
                        }
                    }
                }
                ship_line(&e, "spool full: edge-run sessions terminated (spool_full)".into()).await;
            }
        } else if full_since.is_some() {
            full_since = None;
            let _ = std::fs::remove_file(e.paths.run.join("spool_full"));
        }
        let Ok(rd) = std::fs::read_dir(e.paths.spool()) else { continue };
        let mut files: Vec<PathBuf> = rd.flatten().map(|x| x.path()).filter(|p| p.extension().map(|x| x == "swrec").unwrap_or(false)).collect();
        files.sort();
        for p in files {
            if let Err(err) = ship_file(&e, &p, &mut ship).await {
                ship.remove(&p);
                let _ = err;
            }
        }
    }
}

async fn ship_file(e: &Edge, p: &Path, ship: &mut HashMap<PathBuf, Shipping>) -> Result<()> {
    let data = tokio::fs::read(p).await?;
    let Some(nl) = data.iter().position(|&b| b == b'\n') else { return Ok(()) };
    if !ship.contains_key(p) {
        let header = String::from_utf8_lossy(&data[..=nl]).into_owned();
        let mut conn = core_connect(e).await?;
        aio::write_frame(&mut conn, &Frame::json(kind::REQ, &EdgeReq::Ingest { header, offset: 0 })).await?;
        let Some(f) = aio::read_frame(&mut conn).await? else { bail!("link closed") };
        let r: Resp = f.parse()?;
        if !r.ok {
            bail!("ingest refused: {}", r.error.unwrap_or_default());
        }
        let acked = r.data["size"].as_u64().unwrap_or(0);
        ship.insert(p.to_path_buf(), Shipping { conn, acked });
    }
    let st = ship.get_mut(p).unwrap();
    let mut pos = st.acked as usize;
    if pos > data.len() {
        bail!("core has more than the spool ({} > {})", pos, data.len());
    }
    // Whole lines only, in chunks under the frame cap.
    while pos < data.len() {
        let end = data[pos..].iter().rposition(|&b| b == b'\n').map(|i| pos + i + 1).unwrap_or(pos);
        if end == pos {
            break;
        }
        let mut cut = end.min(pos + (512 << 10));
        if cut < end {
            cut = data[pos..cut].iter().rposition(|&b| b == b'\n').map(|i| pos + i + 1).unwrap_or(end);
        }
        aio::write_frame(&mut st.conn, &Frame::new(kind::DATA, data[pos..cut].to_vec())).await?;
        let Some(f) = aio::read_frame(&mut st.conn).await? else { bail!("link closed") };
        let r: Resp = f.parse()?;
        if !r.ok {
            bail!("ingest error: {}", r.error.unwrap_or_default());
        }
        st.acked = r.data["size"].as_u64().unwrap_or(cut as u64);
        pos = st.acked as usize;
    }
    // Delete only after the end record is acknowledged (spec 8.8, "verify before destroying").
    let complete = st.acked as usize == data.len();
    let ended = data.len() > 1 && data[..data.len() - 1].rsplit(|&b| b == b'\n').next().and_then(|l| swrec::format::decode_line(l).ok()).map(|m| m.get("k").and_then(Value::as_str) == Some("e")).unwrap_or(false);
    if complete && ended {
        ship.remove(p);
        tokio::fs::remove_file(p).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------- logs

async fn ship_line(e: &Edge, line: String) {
    let _ = core_call(e, &EdgeReq::Log { lines: vec![line] }, |_| {}).await;
}

async fn log_loop(e: Arc<Edge>) {
    let mut cmd = tokio::process::Command::new("journalctl");
    // Die with the daemon (KillMode=process would otherwise leave it running across restarts).
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut child = match cmd
        .args(["-f", "-n", "0", "-o", "short-iso", "-u", "swrap-edged", "-u", "sshd"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let mut buf: std::collections::VecDeque<String> = Default::default();
    let mut dropped = 0u64;
    let mut last = Instant::now();
    loop {
        match tokio::time::timeout(Duration::from_secs(2), lines.next_line()).await {
            Ok(Ok(Some(l))) => {
                buf.push_back(l);
                // Cap (~64 MiB at ~200 B/line): oldest first, with a drop counter.
                if buf.len() > 300_000 {
                    buf.pop_front();
                    dropped += 1;
                }
            }
            Ok(_) => return,
            Err(_) => {}
        }
        if !buf.is_empty() && (last.elapsed() > Duration::from_secs(2) || buf.len() > 500) {
            let mut batch: Vec<String> = buf.iter().take(1000).cloned().collect();
            if dropped > 0 {
                batch.push(format!("swrap-edged: {dropped} log lines dropped while core was unreachable"));
            }
            if core_call(&e, &EdgeReq::Log { lines: batch.clone() }, |_| {}).await.is_ok() {
                let n = batch.len() - if dropped > 0 { 1 } else { 0 };
                buf.drain(..n);
                dropped = 0;
            }
            last = Instant::now();
        }
    }
}

// ---------------------------------------------------------------- web relay (spec 13.3)

fn web_allowed(e: &Edge, ip: std::net::IpAddr) -> bool {
    let ip = match ip {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(std::net::IpAddr::V6(v6)),
        v4 => v4,
    };
    let g = e.snapshot.lock().unwrap();
    let Some(s) = g.as_ref() else { return false };
    let t = swrap_core::time::now();
    s.firewall.web_allow.iter().any(|x| {
        let nb = x.not_before.as_deref().and_then(|s| swrap_core::time::parse_datetime(s).ok());
        let na = x.not_after.as_deref().and_then(|s| swrap_core::time::parse_datetime(s).ok());
        nb.map(|v| t >= v).unwrap_or(true) && na.map(|v| t < v).unwrap_or(true) && x.cidr.parse::<ipnet::IpNet>().map(|n| n.contains(&ip)).unwrap_or(false)
    })
}

async fn web_relay(e: Arc<Edge>) {
    // Wait for a snapshot (settings + allow-list) before listening.
    while e.snapshot.lock().unwrap().is_none() {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let port = e.edge_setting("web_port").and_then(|v| v.as_integer()).unwrap_or(8443) as u16;
    let l = match TcpListener::bind(("::", port)).await {
        Ok(l) => l,
        Err(err) => {
            ship_line(&e, format!("web relay: cannot bind :{port}: {err}")).await;
            return;
        }
    };
    loop {
        let Ok((mut c, peer)) = l.accept().await else { continue };
        if !web_allowed(&e, peer.ip()) {
            continue;
        }
        let e = e.clone();
        tokio::spawn(async move {
            let Ok(Ok(mut up)) = tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(e.paths.core_web())).await else { return };
            let ip = match peer.ip() {
                std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(std::net::IpAddr::V6(v6)),
                v4 => v4,
            };
            let hdr = format!("SWRAP-RELAY/1 {}\n", json!({"conn": swrap_core::new_id(), "src": ip.to_string(), "sport": peer.port(), "ts": swrap_core::time::fmt_utc(swrap_core::time::now()), "svc": "web"}));
            if up.write_all(hdr.as_bytes()).await.is_err() {
                return;
            }
            let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
        });
    }
}
