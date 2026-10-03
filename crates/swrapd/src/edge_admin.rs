//! `swedge deploy <label>` / `swedge status` (admin, core). Deploys the edge node onto an enrolled
//! host over its root credential, recorded as a run. The link is enabled only after the edge's
//! sshd change has been confirmed by a fresh connection.

use crate::daemon::{Caller, Console, Daemon};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use swrap_core::api::Resp;
use swrap_core::config::{Host, HostState, Profile};

#[derive(Parser, Debug)]
#[command(name = "swedge", about = "Deploy and inspect the edge node")]
struct Swedge {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Install/upgrade swrap-edged on an enrolled host and bring the link up.
    Deploy {
        label: String,
        /// Public name users connect to (informational; the link dials the host address).
        #[arg(long)]
        public_name: Option<String>,
    },
    /// Link state, snapshot version, clock offset.
    Status,
}

pub fn run(d: &Arc<Daemon>, c: &Caller, argv: &[String], con: &Console) -> Result<Resp> {
    let a = Swedge::try_parse_from(argv)?;
    c.require_admin()?;
    match a.cmd {
        Cmd::Deploy { label, public_name } => deploy(d, c, &label, public_name, con),
        Cmd::Status => Ok(Resp::text(status_text(d))),
    }
}

pub fn status_text(d: &Daemon) -> String {
    let link = std::fs::read_to_string(crate::edge_api::link_state_path(d)).unwrap_or_else(|_| "{}".into());
    let snap = std::fs::read_to_string(d.paths.link().join("snapshot/state.json")).unwrap_or_else(|_| "{}".into());
    let cfg = crate::link::config(d).map(|c| format!("{} ({}:{})", c.label, c.address, c.port)).unwrap_or_else(|| "not configured".into());
    format!("edge: {cfg}\nlink: {link}\nsnapshot: {snap}\n")
}

fn deploy(d: &Arc<Daemon>, c: &Caller, label: &str, public_name: Option<String>, con: &Console) -> Result<Resp> {
    let host = Host::load(&d.paths, label)?;
    if host.state != HostState::Active {
        bail!("{label} is not enrolled");
    }
    let (enc, _) = crate::session::credential(d, label, "root").context("no root credential for the edge host")?;
    let profile = Profile::load(&d.paths, &host.profile)?;
    let known = std::fs::read_to_string(d.paths.known_hosts(label))?;
    let own = d.owner();

    // 1. Link key (outside the vault by design) + pinned edge host key.
    let link = d.paths.link();
    swrap_core::atomic::mkdirs(&link, 0o700, own)?;
    let key = link.join("id_ed25519");
    if !key.exists() {
        let o = std::process::Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", "swrap-link", "-f"]).arg(&key).output()?;
        if !o.status.success() {
            bail!("ssh-keygen: {}", String::from_utf8_lossy(&o.stderr));
        }
        std::os::unix::fs::chown(&key, Some(d.swrap_uid), Some(d.swrap_gid))?;
        std::os::unix::fs::chown(link.join("id_ed25519.pub"), Some(d.swrap_uid), Some(d.swrap_gid))?;
    }
    let link_pub = std::fs::read_to_string(link.join("id_ed25519.pub"))?.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    swrap_core::atomic::write(&link.join("known_hosts"), known.as_bytes(), 0o600, own)?;
    let snap_pub = crate::snapshot::public_key(d)?.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    con.out("link key and pinned host key ready");

    // 2. Ship binaries + run the installer (one ssh connection, binary-safe stdin).
    let run = crate::hosts::Run::new(d, "edge-deploy", &c.name, label, json!({"public_name": public_name}))?;
    let mut rec = run.host_writer(d, &host, "root", &c.name, "swedge deploy")?;
    let tar = std::process::Command::new("tar")
        .args(["-C", "/usr/libexec/swrap", "-cf", "-", "swrapd", "swrap", "swrap-shell", "swrap-pam-unlock", "swrec"])
        .output()?;
    if !tar.status.success() {
        bail!("tar: {}", String::from_utf8_lossy(&tar.stderr));
    }
    let token = crate::util::random_hex(8);
    let remote_cmd = format!(
        "set -e; d=$(mktemp -d /var/tmp/swrap-deploy.XXXXXX); trap 'rm -rf \"$d\"' EXIT; tar -xf - -C \"$d\"; \
         \"$d/swrap\" install edge --from \"$d\" --snapshot-pub '{snap_pub}' --link-pub '{link_pub}' --confirm-token {token}"
    );
    con.out(format!("installing on {label} ({} MiB of binaries)…", tar.stdout.len() >> 20));
    let r = crate::hosts::remote(d, &c.name, &host, "root", &enc, &profile, &known, &remote_cmd, &tar.stdout, Some(&mut rec))?;
    for l in r.stdout.lines().filter(|l| l.starts_with("==>") || l.starts_with("    ")) {
        con.out(l.to_string());
    }
    if r.code != 0 {
        rec.end("error", Some(r.code), None)?;
        bail!("edge install failed (exit {}): {}", r.code, r.why());
    }
    let edge_pub = r.stdout.lines().find_map(|l| l.strip_prefix("EDGE-RECSIGN-PUB: ")).context("installer did not report the edge recording key")?;

    // 3. Confirm the sshd change with a brand-new connection (else edge rolls back by itself).
    std::thread::sleep(Duration::from_secs(1));
    let r2 = crate::hosts::remote(d, &c.name, &host, "root", &enc, &profile, &known, &format!("touch /run/swrap-edge/sshd-confirm-{token} && echo confirmed"), b"", Some(&mut rec))?;
    if r2.code != 0 || !r2.stdout.contains("confirmed") {
        rec.end("error", Some(r2.code), None)?;
        bail!("could not confirm sshd on {label} with a new connection; it rolls back within PT120S: {}", r2.why());
    }
    con.out("sshd change confirmed with a fresh connection");

    // 4. Pin the edge recording key, enable the link (config commit → new snapshot).
    swrap_core::atomic::mkdirs(&d.paths.trust(), 0o750, own)?;
    swrap_core::atomic::write(&d.paths.trust().join("edge-recsign.pub"), format!("{edge_pub}\n").as_bytes(), 0o644, own)?;
    {
        let _g = d.config_lock.lock().unwrap();
        let mut e = match crate::snapshot::edge_toml(d) {
            toml::Value::Table(t) => t,
            _ => Default::default(),
        };
        let set = |e: &mut toml::map::Map<String, toml::Value>, k: &str, v: toml::Value, force: bool| {
            if force || !e.contains_key(k) {
                e.insert(k.into(), v);
            }
        };
        set(&mut e, "label", label.into(), true);
        set(&mut e, "address", public_name.clone().unwrap_or_else(|| host.address.clone()).into(), public_name.is_some());
        set(&mut e, "link_address", host.address.clone().into(), true);
        set(&mut e, "link_port", (host.port as i64).into(), true);
        set(&mut e, "link_enabled", true.into(), true);
        set(&mut e, "web_mode", "port".into(), false);
        set(&mut e, "web_port", 8443i64.into(), false);
        set(&mut e, "ssh_new_per_source", "10/PT1M".into(), false);
        set(&mut e, "sessions_edge", 20i64.into(), false);
        set(&mut e, "sessions_per_user", 10i64.into(), false);
        set(&mut e, "spool_max_bytes", 536870912i64.into(), false);
        set(&mut e, "log_spool_max_bytes", 67108864i64.into(), false);
        set(&mut e, "admin_offline_login", false.into(), false);
        set(&mut e, "managed_ports", toml::Value::Array(vec![22i64.into()]), false);
        d.write_config("edge.toml", &toml::to_string_pretty(&e)?)?;
        d.commit(&format!("swedge deploy {label} by {}", c.name))?;
    }
    rec.end("exit", Some(0), None)?;
    d.audit_event(&c.name, "edge.deploy", label, "root", "ok", json!({"run": run.id}), &run.id);

    // 5. Wait for the link and the first Hello.
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(60) {
        let st = std::fs::read_to_string(crate::edge_api::link_state_path(d)).unwrap_or_default();
        if st.contains("up_since") && st.contains("edge_node") {
            let since = serde_json::from_str::<serde_json::Value>(&st).ok().and_then(|v| v["up_since"].as_str().map(String::from)).unwrap_or_default();
            let fresh = since.parse::<jiff::Timestamp>().map(|t| t >= swrap_core::time::now() - jiff::SignedDuration::from_secs(90)).unwrap_or(false);
            if fresh {
                return Ok(Resp::text(format!("edge deployed on {label}; link up\n{}", status_text(d))));
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Ok(Resp { ok: false, exit: 1, text: format!("edge installed on {label}, but the link did not come up within PT60S\n{}", status_text(d)), ..Default::default() })
}
