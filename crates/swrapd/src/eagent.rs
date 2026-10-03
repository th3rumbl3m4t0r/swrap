//! The endpoint agent on enrolled hosts (spec 10.7). The agent needs table forms of its own per
//! host (`asset_read/update_<id>`, `disk_read/update/create_<id>`, `ticket_create_<id>`), which
//! only a table admin can create. swrap does it with the AAA admin login (`swrap table
//! admin-password`, kept in the vault) through the agent's own `--provision-env` on this node,
//! then installs the agent with that env on the host, like `swr`: the env goes on stdin and is
//! redacted from the output, so no form secret lands in a recording. The admin login never
//! leaves the core.

use crate::daemon::{Console, Daemon};
use crate::table::TableCfg;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::json;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use swrap_core::api::SecretEnv;
use swrap_core::config::{Host, Route};

/// table ends an admin's previous session at each login: one provisioning at a time.
static ONE: Mutex<()> = Mutex::new(());

const INSTALL_TIMEOUT: Duration = Duration::from_secs(900);

/// Where `h` reaches table (what goes into its env as TABLE_ENDPOINT).
pub fn host_endpoint(c: &TableCfg, h: &Host) -> Result<String> {
    if h.network == Route::Edge {
        if c.agent_endpoint_edge.is_empty() {
            bail!("{} is on the edge network: set how edge hosts reach table first (`swrap table set agent_endpoint_edge <host:port>`)", h.label);
        }
        return Ok(c.agent_endpoint_edge.clone());
    }
    Ok(if c.agent_endpoint.is_empty() { c.endpoint.clone() } else { c.agent_endpoint.clone() })
}

/// Create (or align) the table forms of asset `aid` for `h` and install the agent there. Forms
/// that exist get new secrets, so this also rotates a host's agent secrets.
pub fn deploy(d: &Arc<Daemon>, who: &str, h: &Host, aid: i64, con: &Console) -> Result<String> {
    let _g = ONE.lock().unwrap_or_else(|p| p.into_inner());
    let c = crate::table::cfg(d);
    let (user, pass) = crate::table::admin_login(d)?.ok_or_else(|| anyhow!("no table admin password in the vault (`swrap table admin-password`)"))?;
    let endpoint = host_endpoint(&c, h)?;
    let ruser = crate::inventory::system_account(d, h).ok_or_else(|| anyhow!("no account with a credential on {}", h.label))?;
    let agent = std::fs::read(&c.agent_script).with_context(|| format!("read {}", c.agent_script))?;

    // 1. The forms and the host's env file, here.
    let dir = d.paths.run.join("eagent");
    swrap_core::atomic::mkdirs(&dir, 0o700, swrap_core::atomic::Owner::new(0, 0))?;
    let out = dir.join(format!("{}.env", h.label));
    let _ = std::fs::remove_file(&out);
    con.err(format!("{}: creating its table forms for asset #{aid} (as {user})", h.label));
    let r = Command::new("/usr/bin/python3")
        .arg(&c.agent_script)
        .args(["--provision-env", &aid.to_string()])
        .arg(&out)
        .arg(&endpoint)
        .env("ASSET_ADMIN_USER", &user)
        .env("ASSET_ADMIN_PASS", pass.as_str())
        .env("TABLE_ENDPOINT", &c.endpoint)
        .env("WAIT_FOR_TABLE_SECS", "20")
        .stdin(Stdio::null())
        .output()
        .context("run the endpoint agent's --provision-env")?;
    let env = zeroize::Zeroizing::new(std::fs::read_to_string(&out).unwrap_or_default());
    let _ = std::fs::remove_file(&out);
    let log = String::from_utf8_lossy(&r.stderr).replace(pass.as_str(), "[REDACTED]");
    if !r.status.success() || env.is_empty() {
        bail!("creating the forms failed: {}", last_lines(&log, 3));
    }
    con.err(format!("{}: {}", h.label, last_lines(&log, 2).replace('\n', &format!("\n{}: ", h.label))));

    // 2. The agent and its env on the host.
    let mut redact = vec![SecretEnv { name: "EA_ENV".into(), value: env.to_string() }];
    for l in env.lines() {
        if let Some((k, v)) = l.split_once('=').filter(|(k, v)| k.ends_with("_SECRET") && v.len() >= 16) {
            redact.push(SecretEnv { name: k.into(), value: v.into() });
        }
    }
    let n = redact.len() - 1;
    let script = install_script(&agent);
    let (run, code, result, detail) = crate::fleet::system_job(d, who, "agent", h, &ruser, "endpoint-agent install", script.as_bytes(), &redact[..1], &redact, INSTALL_TIMEOUT, con)?;
    d.audit_event(who, "table.agent_deployed", &h.label, &ruser, if result == "ok" { "ok" } else { "failed" }, json!({"asset": aid, "forms": n, "run": run, "exit": code, "endpoint": endpoint}), &run);
    if result != "ok" {
        bail!("installing the agent failed ({result}, exit {code}{}); see run {run}", if detail.is_empty() { String::new() } else { format!(": {detail}") });
    }
    Ok(format!("{}: endpoint agent installed with {n} table forms of its own (asset #{aid}); run {run}\n", h.label))
}

fn last_lines(s: &str, n: usize) -> String {
    let v: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    v[v.len().saturating_sub(n)..].join("\n")
}

/// Root on the host: the env from $EA_ENV, the agent (checksummed), then `--install` (systemd
/// units and a first update that proves the form secrets work).
fn install_script(agent: &[u8]) -> String {
    use base64::Engine;
    use sha2::Digest;
    let sha = format!("{:x}", sha2::Sha256::digest(agent));
    let b64 = base64::engine::general_purpose::STANDARD.encode(agent);
    let mut wrapped = String::with_capacity(b64.len() + b64.len() / 76 + 1);
    for chunk in b64.as_bytes().chunks(76) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        wrapped.push('\n');
    }
    format!(
        r#"#!/bin/bash
# endpoint-agent install by swrap (agent {sha16})
set -euo pipefail
F=/usr/local/sbin/endpoint-agent.py
command -v python3 >/dev/null || {{ echo "python3 is missing"; exit 3; }}
umask 077
install -d -m 700 /etc/endpoint-agent
printf '%s\n' "$EA_ENV" > /etc/endpoint-agent/env.new
unset EA_ENV
chmod 600 /etc/endpoint-agent/env.new && mv -f /etc/endpoint-agent/env.new /etc/endpoint-agent/env
restorecon -R /etc/endpoint-agent 2>/dev/null || true
echo "== env: $(grep -c '_SECRET=' /etc/endpoint-agent/env) form secrets for $(grep '^ASSET_NAME=' /etc/endpoint-agent/env)"
umask 022
install -d -m 755 /usr/local/sbin
base64 -d > $F.new <<'B64'
{wrapped}B64
[ "$(sha256sum $F.new | cut -d' ' -f1)" = "{sha}" ] || {{ echo "checksum mismatch"; rm -f $F.new; exit 1; }}
chmod 755 $F.new && chown root:root $F.new && mv -f $F.new $F
restorecon $F 2>/dev/null || true
echo "== agent $($F --version) $(sha256sum $F | cut -c1-16)"
$F --install 2>&1 | cut -c1-200
systemctl list-timers endpoint-agent.timer --no-pager --no-legend 2>/dev/null | head -2 || true
"#,
        sha16 = &sha[..16],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_script_carries_the_agent_intact() {
        use base64::Engine;
        let agent = b"#!/usr/bin/env python3\nprint('x' * 300)\n".repeat(20);
        let s = install_script(&agent);
        let b64: String = s.split("<<'B64'\n").nth(1).unwrap().split("B64\n").next().unwrap().lines().collect();
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(b64).unwrap(), agent);
        assert!(!s.contains("ASSET_ADMIN"));
    }
}
