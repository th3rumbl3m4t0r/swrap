//! `swai reset <label>` (spec 24.5, MAY): roll an AI test VM back to its named Proxmox snapshot.
//!
//! Needs, per host: `ai_reset = true` and `[proxmox]` (api, node, vmid, snapshot) in the host
//! file (`swai reset-setup`, admin), and an API token in the vault (`swai reset-token`, admin;
//! `vault/keys/proxmox/<label>.enc`) that should hold only `VM.Snapshot.Rollback` and
//! `VM.PowerMgmt` on that VM. Nothing else is needed from the API: the rollback starts the VM
//! (`start=1`), and a token may read the status of its own tasks. The Proxmox CA
//! (`/etc/pve/pve-root-ca.pem`) is pinned with `swai reset-ca` (`config/proxmox/ca.pem`);
//! without it the system roots apply. The caller needs an AI grant on the host. Audited.

use crate::daemon::{Caller, Console, Daemon};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use swrap_core::api::Resp;
use swrap_core::config::{Host, ProxmoxVm, Route};
use swrap_core::rbac;
use swrap_core::time::{fmt_duration_ms, now};

fn token_path(d: &Daemon, label: &str) -> PathBuf {
    d.paths.vault_keys().join("proxmox").join(format!("{label}.enc"))
}

fn ca_path(d: &Daemon) -> PathBuf {
    d.paths.config().join("proxmox").join("ca.pem")
}

/// `user@realm!tokenid=secret`, as Proxmox shows it when the token is created.
pub fn valid_token(t: &str) -> bool {
    let Some((id, secret)) = t.split_once('=') else { return false };
    let Some((user, tok)) = id.split_once('!') else { return false };
    user.contains('@') && !tok.is_empty() && secret.len() >= 16 && !t.chars().any(char::is_whitespace)
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

fn agent(ca_pem: Option<&[u8]>) -> Result<ureq::Agent> {
    let mut b = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(30))).http_status_as_error(false).user_agent(concat!("swrap-swai/", env!("CARGO_PKG_VERSION")));
    if let Some(pem) = ca_pem {
        let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(pem)
            .filter_map(|i| match i {
                Ok(ureq::tls::PemItem::Certificate(c)) => Some(c.to_owned()),
                _ => None,
            })
            .collect();
        if certs.is_empty() {
            bail!("config/proxmox/ca.pem holds no certificate");
        }
        b = b.tls_config(ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::Specific(Arc::new(certs))).build());
    }
    Ok(b.build().into())
}

fn call(a: &ureq::Agent, method: &str, url: &str, token: &str, form: &str) -> Result<(u16, Value)> {
    let auth = format!("PVEAPIToken={token}");
    let r = if method == "POST" {
        a.post(url).header("Authorization", &auth).header("Content-Type", "application/x-www-form-urlencoded").send(form.as_bytes())
    } else {
        a.get(url).header("Authorization", &auth).call()
    };
    let mut r = r.map_err(|e| anyhow!("{url}: {e}"))?;
    let status = r.status().as_u16();
    let body = r.body_mut().read_to_string().unwrap_or_default();
    let v = serde_json::from_str(&body).unwrap_or_else(|_| json!({"message": body.trim()}));
    Ok((status, v))
}

fn why(v: &Value) -> String {
    let mut s = v.get("message").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if let Some(e) = v.get("errors").filter(|e| !e.is_null()) {
        s = format!("{s} {e}");
    }
    s
}

/// Waits for a task this token started; Ok when it ends with exit status OK.
fn wait_task(a: &ureq::Agent, p: &ProxmoxVm, token: &str, upid: &str, limit: Duration, poll: Duration) -> Result<()> {
    let url = format!("{}/api2/json/nodes/{}/tasks/{}/status", p.api.trim_end_matches('/'), enc(&p.node), enc(upid));
    let t0 = Instant::now();
    loop {
        let (st, v) = call(a, "GET", &url, token, "")?;
        if st != 200 {
            bail!("task status: HTTP {st} {}", why(&v));
        }
        if v["data"]["status"] == "stopped" {
            let x = v["data"]["exitstatus"].as_str().unwrap_or("");
            return if x == "OK" { Ok(()) } else { Err(anyhow!("task ended with {x:?}")) };
        }
        if t0.elapsed() > limit {
            bail!("task {upid} still running after {}", fmt_duration_ms(limit));
        }
        std::thread::sleep(poll);
    }
}

/// The rollback itself: snapshot rollback (with start), then start if the VM is not running.
pub fn rollback(a: &ureq::Agent, p: &ProxmoxVm, token: &str, poll: Duration, mut progress: impl FnMut(String)) -> Result<()> {
    let base = format!("{}/api2/json/nodes/{}/qemu/{}", p.api.trim_end_matches('/'), enc(&p.node), p.vmid);
    let url = format!("{base}/snapshot/{}/rollback", enc(&p.snapshot));
    let (mut st, mut v) = call(a, "POST", &url, token, "start=1")?;
    if st == 400 && why(&v).contains("start") {
        // Older Proxmox VE: no `start` on rollback; started below.
        (st, v) = call(a, "POST", &url, token, "")?;
    }
    if st != 200 {
        bail!("rollback to {:?}: HTTP {st} {}", p.snapshot, why(&v));
    }
    let upid = v["data"].as_str().context("rollback: no task id in the answer")?.to_string();
    progress(format!("rolling back VM {} to {:?} ({upid})", p.vmid, p.snapshot));
    wait_task(a, p, token, &upid, Duration::from_secs(600), poll)?;
    let (st, v) = call(a, "POST", &format!("{base}/status/start"), token, "")?;
    match (st, v["data"].as_str()) {
        (200, Some(upid)) => {
            progress("starting the VM".into());
            wait_task(a, p, token, upid, Duration::from_secs(300), poll)?;
        }
        _ if why(&v).contains("already running") => {}
        _ => bail!("start: HTTP {st} {}", why(&v)),
    }
    Ok(())
}

/// `swai reset <label> [--force]`.
pub fn reset(d: &Arc<Daemon>, c: &Caller, label: &str, force: bool, con: &Console) -> Result<Resp> {
    let user = c.aaa()?;
    if user.is_admin() {
        bail!("swai is for normal users; admins are refused (use your non-admin account)");
    }
    let host = Host::load(&d.paths, label).map_err(|_| anyhow!("unknown host {label}"))?;
    if rbac::ai_accounts(user, &host, now()).is_empty() {
        bail!("you have no AI grant on {label}");
    }
    if !host.ai_allowed || !host.ai_reset {
        bail!("{label} cannot be reset (an admin enables it: swai reset-setup {label} …)");
    }
    let p = host.proxmox.clone().ok_or_else(|| anyhow!("{label} has no Proxmox settings (swai reset-setup)"))?;
    if d.is_sealed() {
        bail!("the swrap vault is sealed; an admin login unseals it");
    }
    let tp = token_path(d, label);
    if !tp.exists() {
        bail!("no Proxmox API token for {label} in the vault (admin: swai reset-token {label})");
    }
    let busy: Vec<String> = crate::session::live_sessions(d).into_iter().filter(|j| j["kind"] == "ai" && j["label"] == label).map(|j| format!("{} ({})", j["id"].as_str().unwrap_or(""), j["user"].as_str().unwrap_or(""))).collect();
    if !busy.is_empty() && !force {
        bail!("swai sessions are working on {label}: {}; they would lose the machine under them (--force resets anyway)", busy.join(", "));
    }
    let token = zeroize::Zeroizing::new(String::from_utf8(d.with_dek(|dek| swrap_vault::Vault::new(&d.paths, d.owner()).get(dek, &tp))?.to_vec())?);
    let ca = std::fs::read(ca_path(d)).ok();
    let a = agent(ca.as_deref())?;
    let t0 = Instant::now();
    d.audit_event(&c.name, "ai.reset", label, "", "started", json!({"snapshot": p.snapshot, "vmid": p.vmid, "node": p.node, "force": force, "busy": busy}), "");
    let r = rollback(&a, &p, &token, Duration::from_secs(2), |m| con.out(m));
    if let Err(e) = &r {
        d.audit_event(&c.name, "ai.reset", label, "", "error", json!({"snapshot": p.snapshot, "error": format!("{e:#}")}), "");
        return Err(anyhow!("{e:#}"));
    }
    // Back on the network with the pinned host keys (an older snapshot may hold other keys).
    let mut ssh = "not checked (reachable only through edge)".to_string();
    if host.network != Route::Edge {
        con.out(format!("waiting for ssh on {}:{}", host.address, host.port));
        let addr = format!("{}:{}", host.address, host.port);
        let deadline = Instant::now() + Duration::from_secs(300);
        let up = loop {
            let ok = std::net::ToSocketAddrs::to_socket_addrs(&addr).ok().and_then(|mut it| it.next()).map(|sa| std::net::TcpStream::connect_timeout(&sa, Duration::from_secs(3)).is_ok()).unwrap_or(false);
            if ok || Instant::now() > deadline {
                break ok;
            }
            std::thread::sleep(Duration::from_secs(3));
        };
        ssh = if !up {
            "did not come back within PT5M".into()
        } else {
            match host_check(d, &c.name, &host) {
                Ok(()) => "up, host keys as pinned".into(),
                Err(e) => format!("up, but: {e:#}"),
            }
        };
    }
    let took = fmt_duration_ms(t0.elapsed());
    d.audit_event(&c.name, "ai.reset", label, "", "ok", json!({"snapshot": p.snapshot, "vmid": p.vmid, "duration": took, "ssh": ssh}), "");
    Ok(Resp::text(format!("{label} rolled back to {:?} in {took}; ssh: {ssh}\n", p.snapshot)))
}

/// One command over ssh with the pinned keys (root, else the first account with a key).
fn host_check(d: &Arc<Daemon>, who: &str, h: &Host) -> Result<()> {
    let (ruser, enc) = h.accounts.iter().find_map(|a| crate::session::credential(d, &h.label, &a.name).map(|c| (a.name.clone(), c.0))).ok_or_else(|| anyhow!("no key in the vault"))?;
    let profile = swrap_core::config::Profile::load(&d.paths, &h.profile)?;
    let known = std::fs::read_to_string(d.paths.known_hosts(&h.label))?;
    for _ in 0..10 {
        let r = crate::hosts::remote(d, who, h, &ruser, &enc, &profile, &known, "echo swrap-ok", b"", None)?;
        if r.code == 0 && r.stdout.contains("swrap-ok") {
            return Ok(());
        }
        if r.why().contains("host key") || r.why().contains("HOST IDENTIFICATION") {
            bail!("its host keys differ from the pinned ones (the snapshot predates enrollment?); swrap will not connect");
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    bail!("ssh as {ruser} does not work yet")
}

/// `swai reset-setup <label> --api … --node … --vmid … --snapshot …` / `--off` (admin).
pub fn setup(d: &Arc<Daemon>, c: &Caller, label: &str, p: Option<ProxmoxVm>) -> Result<Resp> {
    c.require_admin()?;
    if let Some(p) = &p {
        if !(p.api.starts_with("https://") || p.api.starts_with("http://127.0.0.1")) || p.api.trim_end_matches('/').ends_with("/api2/json") {
            bail!("--api is the server, e.g. https://pve.lan:8006");
        }
        if p.node.is_empty() || !p.node.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)) || p.snapshot.is_empty() || p.vmid < 100 {
            bail!("--node, --vmid (100 or more) and --snapshot are needed");
        }
    }
    let _g = d.config_lock.lock().unwrap();
    let mut h = Host::load(&d.paths, label).map_err(|_| anyhow!("unknown host {label}"))?;
    if p.is_some() && !h.ai_allowed {
        bail!("{label} is not enabled for AI (swai host {label} on)");
    }
    h.ai_reset = p.is_some();
    h.proxmox = p.clone();
    d.write_config(&format!("hosts/{label}.toml"), &h.to_toml())?;
    d.commit(&format!("swai reset-setup {label} by {}", c.name))?;
    d.audit_event(&c.name, "ai.reset_setup", label, "", "ok", json!({"proxmox": p}), "");
    Ok(Resp::text(match p {
        Some(p) => format!(
            "{label}: swai reset rolls VM {} on {} back to {:?} via {}{}\n",
            p.vmid,
            p.node,
            p.snapshot,
            p.api,
            if token_path(d, label).exists() { "" } else { "; the API token is still missing (swai reset-token)" }
        ),
        None => format!("{label}: swai reset off\n"),
    }))
}

/// `swai reset-token <label>` (admin; stdin): the scoped API token into the vault.
pub fn set_token(d: &Arc<Daemon>, c: &Caller, label: &str, stdin: Option<zeroize::Zeroizing<String>>) -> Result<Resp> {
    c.require_admin()?;
    Host::load(&d.paths, label).map_err(|_| anyhow!("unknown host {label}"))?;
    let t = stdin.ok_or_else(|| anyhow!("the token is read from stdin"))?;
    let t = t.trim();
    if !valid_token(t) {
        bail!("expected user@realm!tokenid=secret (as Proxmox shows it when the token is created)");
    }
    d.with_dek(|dek| swrap_vault::Vault::new(&d.paths, d.owner()).put(dek, &token_path(d, label), &format!("proxmox-{label}"), t.as_bytes()))?;
    d.audit_event(&c.name, "ai.reset_token", label, "", "ok", json!({"token_id": t.split('=').next()}), "");
    Ok(Resp::text(format!("Proxmox token for {label} stored in the vault ({}); give it only VM.Snapshot.Rollback and VM.PowerMgmt on that VM\n", t.split('=').next().unwrap_or(""))))
}

/// `swai reset-ca` (admin; stdin): the Proxmox CA certificate (`/etc/pve/pve-root-ca.pem`).
pub fn set_ca(d: &Arc<Daemon>, c: &Caller, stdin: Option<zeroize::Zeroizing<String>>) -> Result<Resp> {
    c.require_admin()?;
    let pem = stdin.ok_or_else(|| anyhow!("the PEM is read from stdin"))?;
    agent(Some(pem.as_bytes()))?;
    std::fs::create_dir_all(d.paths.config().join("proxmox"))?;
    d.write_config("proxmox/ca.pem", pem.trim())?;
    d.commit(&format!("swai reset-ca by {}", c.name))?;
    d.audit_event(&c.name, "ai.reset_ca", "", "", "ok", json!({}), "");
    Ok(Resp::text("Proxmox CA stored (config/proxmox/ca.pem); the API's certificate must chain to it\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};

    /// A fake Proxmox API: answers each request with the next canned (status, body) and records
    /// the request lines (and form bodies).
    fn fake(answers: Vec<(u16, &'static str)>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            let mut seen = vec![];
            for (st, body) in answers {
                let (s, _) = l.accept().unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                let mut len = 0;
                let mut auth = String::new();
                loop {
                    let mut hl = String::new();
                    r.read_line(&mut hl).unwrap();
                    if hl.trim().is_empty() {
                        break;
                    }
                    let lower = hl.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    if lower.starts_with("authorization:") {
                        auth = hl.trim().to_string();
                    }
                }
                let mut b = vec![0; len];
                r.read_exact(&mut b).unwrap();
                seen.push(format!("{} {} [{}] {}", line.trim(), String::from_utf8_lossy(&b), auth.len(), auth.contains("PVEAPIToken=u@pve!t=")));
                let mut s = s;
                write!(s, "HTTP/1.1 {st} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            seen
        });
        (url, h)
    }

    fn vm(api: &str) -> ProxmoxVm {
        ProxmoxVm { api: api.into(), node: "pve".into(), vmid: 120, snapshot: "clean".into() }
    }

    #[test]
    fn rollback_starts_and_waits_for_tasks() {
        let (url, h) = fake(vec![
            (200, r#"{"data":"UPID:pve:1:rollback"}"#),
            (200, r#"{"data":{"status":"running"}}"#),
            (200, r#"{"data":{"status":"stopped","exitstatus":"OK"}}"#),
            (500, r#"{"data":null,"message":"VM 120 already running\n"}"#),
        ]);
        let a = agent(None).unwrap();
        let mut log = vec![];
        rollback(&a, &vm(&url), "u@pve!t=0123456789abcdef0123", Duration::from_millis(10), |m| log.push(m)).unwrap();
        let seen = h.join().unwrap();
        assert!(seen[0].starts_with("POST /api2/json/nodes/pve/qemu/120/snapshot/clean/rollback HTTP/1.1 start=1"), "{seen:?}");
        assert!(seen[0].ends_with("true"), "token header: {seen:?}");
        assert!(seen[1].starts_with("GET /api2/json/nodes/pve/tasks/UPID%3Apve%3A1%3Arollback/status"), "{seen:?}");
        assert!(seen[3].starts_with("POST /api2/json/nodes/pve/qemu/120/status/start"), "{seen:?}");
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn rollback_reports_a_failed_task_and_old_servers_without_start() {
        let (url, h) = fake(vec![
            (400, r#"{"data":null,"errors":{"start":"property is not defined in schema"}}"#),
            (200, r#"{"data":"UPID:pve:2"}"#),
            (200, r#"{"data":{"status":"stopped","exitstatus":"snapshot 'clean' does not exist"}}"#),
        ]);
        let a = agent(None).unwrap();
        let e = rollback(&a, &vm(&url), "u@pve!t=0123456789abcdef0123", Duration::from_millis(10), |_| {}).unwrap_err();
        assert!(format!("{e:#}").contains("does not exist"), "{e:#}");
        let seen = h.join().unwrap();
        assert!(seen[1].contains("rollback HTTP/1.1  ["), "retried without start: {seen:?}");
    }

    #[test]
    fn token_format() {
        assert!(valid_token("swai@pve!reset-120=3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"));
        for bad in ["", "abc", "root@pam=secretsecretsecret", "root@pam!t=short", "root@pam!t=with space 0123456789"] {
            assert!(!valid_token(bad), "{bad}");
        }
        assert_eq!(enc("UPID:pve:00A:x@pam!"), "UPID%3Apve%3A00A%3Ax%40pam%21");
    }
}
