//! The link (spec 4.5): core dials out to edge with `ssh -N` as `swrap-link` and publishes three
//! reverse unix-socket forwards (edge → core services). Exponential backoff PT1S → PT1M.
//! The link key is deliberately not in the vault (the link must come up while sealed).

use crate::daemon::Daemon;
use serde_json::json;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct LinkCfg {
    pub address: String,
    pub port: u16,
    pub label: String,
}

pub fn config(d: &Daemon) -> Option<LinkCfg> {
    let e = crate::snapshot::edge_toml(d);
    if !e.get("link_enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
        return None;
    }
    Some(LinkCfg {
        address: e.get("link_address").or_else(|| e.get("address")).and_then(|v| v.as_str())?.to_string(),
        port: e.get("link_port").and_then(|v| v.as_integer()).unwrap_or(22) as u16,
        label: e.get("label").and_then(|v| v.as_str()).unwrap_or("edge").to_string(),
    })
}

fn write_state(d: &Daemon, v: serde_json::Value) {
    let p = crate::edge_api::link_state_path(d);
    let mut cur: serde_json::Value = std::fs::read_to_string(&p).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({}));
    if let (Some(c), Some(n)) = (cur.as_object_mut(), v.as_object()) {
        for (k, x) in n {
            c.insert(k.clone(), x.clone());
        }
    }
    let _ = std::fs::write(p, cur.to_string());
}

pub async fn supervise(d: Arc<Daemon>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let Some(cfg) = config(&d) else {
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        };
        let key = d.paths.link().join("id_ed25519");
        let kh = d.paths.link().join("known_hosts");
        if !key.exists() || !kh.exists() {
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        }
        let profile = swrap_core::config::Profile::load(&d.paths, "link").ok();
        let cfgfile = d.paths.link().join("ssh_config");
        if let Some(p) = &profile {
            let _ = swrap_core::atomic::write(&cfgfile, p.ssh_config().as_bytes(), 0o600, d.owner());
        }
        let edge_run = "/run/swrap-edge/link";
        let fwd = |edge: &str, core: std::path::PathBuf| format!("{edge_run}/{edge}:{}", core.display());
        let mut c = Command::new("/usr/bin/ssh");
        c.arg("-N")
            .arg("-F").arg(if profile.is_some() { cfgfile.clone() } else { "/dev/null".into() })
            .arg("-i").arg(&key)
            .args(["-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes"])
            .arg("-o").arg(format!("UserKnownHostsFile={}", kh.display()))
            .args(["-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes"])
            .arg("-o").arg(format!("HostKeyAlias={}", cfg.label))
            .args(["-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=15"])
            .args(["-o", "StreamLocalBindUnlink=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "LogLevel=ERROR"])
            .arg("-R").arg(fwd("core-api.sock", d.paths.edge_api_sock()))
            .arg("-R").arg(fwd("core-pty.sock", d.paths.edge_pty_sock()))
            .arg("-R").arg(fwd("core-web.sock", d.paths.ingress_web_sock()))
            .arg("-p").arg(cfg.port.to_string())
            .arg(format!("swrap-link@{}", cfg.address))
            .env_clear()
            .env("PATH", "/usr/bin")
            .env("HOME", d.paths.link())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let (uid, gid) = (d.swrap_uid, d.swrap_gid);
        unsafe {
            c.pre_exec(move || {
                libc::setgroups(0, std::ptr::null());
                if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let started = Instant::now();
        write_state(&d, json!({"state": "connecting", "since": swrap_core::time::fmt_utc_secs(swrap_core::time::now()), "edge": cfg.address}));
        let r = tokio::process::Command::from(c).kill_on_drop(true).output().await;
        let why = match &r {
            Ok(o) => String::from_utf8_lossy(&o.stderr).trim().lines().last().unwrap_or("").to_string(),
            Err(e) => e.to_string(),
        };
        let lived = started.elapsed();
        write_state(&d, json!({"state": "down", "since": swrap_core::time::fmt_utc_secs(swrap_core::time::now()), "last_error": why, "last_uptime": swrap_core::time::fmt_duration_ms(lived)}));
        d.audit_event("", "link.down", &cfg.label, "", "down", json!({"error": why, "uptime": swrap_core::time::fmt_duration_ms(lived)}), "");
        if lived > Duration::from_secs(60) {
            backoff = Duration::from_secs(1);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}
