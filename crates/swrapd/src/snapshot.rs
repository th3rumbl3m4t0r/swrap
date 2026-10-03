//! Edge snapshot (spec 4.3): the public-only data edge needs while the link is down — AAA
//! accounts (names, roles, inbound keys), firewall entries, edge settings. Signed with the
//! vault's `edge-config` key (`ssh-keygen -Y sign`); the version only ever increases so edge can
//! reject rollbacks. While the vault is sealed, changes queue: the last signed snapshot is served.

use crate::daemon::Daemon;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use swrap_core::config::{Firewall, User};

pub const NAMESPACE: &str = "swrap-edge-config";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SnapUser {
    pub name: String,
    pub role: String,
    pub disabled: bool,
    pub keys: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Snapshot {
    pub version: u64,
    pub created: String,
    pub config_rev: String,
    pub users: Vec<SnapUser>,
    pub firewall: Firewall,
    pub edge: toml::Value,
}

#[derive(Serialize, Deserialize, Default)]
struct State {
    version: u64,
    hash: String,
    pending: bool,
}

fn dir(d: &Daemon) -> PathBuf {
    d.paths.link().join("snapshot")
}

pub fn edge_toml(d: &Daemon) -> toml::Value {
    std::fs::read_to_string(d.paths.edge_toml()).ok().and_then(|s| toml::from_str(&s).ok()).unwrap_or(toml::Value::Table(Default::default()))
}

/// Content without version/timestamps (to detect changes).
fn content(d: &Daemon) -> Result<(Vec<SnapUser>, Firewall, toml::Value)> {
    let users = User::all(&d.paths)?
        .into_iter()
        .map(|u| SnapUser { role: format!("{:?}", u.role).to_lowercase(), disabled: u.disabled, keys: u.keys, name: u.name })
        .collect();
    Ok((users, Firewall::load(&d.paths)?, edge_toml(d)))
}

fn sign(d: &Daemon, data: &[u8]) -> Result<String> {
    let enc = d.paths.vault_keys().join("edge-config").join("id_ed25519.enc");
    let private = d.with_dek(|dek| swrap_vault::Vault::new(&d.paths, d.owner()).get(dek, &enc))?;
    let tmp = d.paths.run.join("keygen").join(format!("snap-{}", swrap_core::new_id()));
    std::fs::create_dir_all(&tmp)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))?;
    let key = tmp.join("k");
    let res = (|| -> Result<String> {
        {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&key)?;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            f.write_all(&private)?;
        }
        let mut c = Command::new("ssh-keygen")
            .args(["-q", "-Y", "sign", "-n", NAMESPACE, "-f"])
            .arg(&key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        c.stdin.take().unwrap().write_all(data)?;
        let o = c.wait_with_output()?;
        if !o.status.success() {
            bail!("ssh-keygen -Y sign: {}", String::from_utf8_lossy(&o.stderr));
        }
        Ok(String::from_utf8(o.stdout)?)
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

/// Public key edge pins for snapshot verification.
pub fn public_key(d: &Daemon) -> Result<String> {
    Ok(std::fs::read_to_string(d.paths.vault_keys().join("edge-config").join("id_ed25519.pub"))?.trim().to_string())
}

/// Rebuild if content changed (and the vault can sign). Returns (version, toml, signature).
pub fn current(d: &Daemon) -> Result<Option<(u64, String, String)>> {
    let dir = dir(d);
    swrap_core::atomic::mkdirs(&dir, 0o700, d.owner())?;
    let st_p = dir.join("state.json");
    let mut st: State = std::fs::read_to_string(&st_p).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let (users, fw, edge) = content(d)?;
    let hash = blake3::hash(serde_json::to_string(&(&users, &fw, &edge))?.as_bytes()).to_hex().to_string();
    if hash != st.hash {
        if d.is_sealed() {
            if !st.pending {
                st.pending = true;
                swrap_core::atomic::write(&st_p, serde_json::to_string(&st)?.as_bytes(), 0o600, d.owner())?;
                d.audit_event("", "snapshot.pending", "edge", "", "queued", serde_json::json!({"why": "vault sealed"}), "");
            }
        } else {
            let version = st.version + 1;
            let snap = Snapshot {
                version,
                created: swrap_core::time::fmt_utc_secs(swrap_core::time::now()),
                config_rev: d.config_rev(),
                users,
                firewall: fw,
                edge,
            };
            let text = toml::to_string_pretty(&snap)?;
            let sig = sign(d, text.as_bytes()).context("sign snapshot")?;
            swrap_core::atomic::write(&dir.join("current.toml"), text.as_bytes(), 0o600, d.owner())?;
            swrap_core::atomic::write(&dir.join("current.sig"), sig.as_bytes(), 0o600, d.owner())?;
            st = State { version, hash, pending: false };
            swrap_core::atomic::write(&st_p, serde_json::to_string(&st)?.as_bytes(), 0o600, d.owner())?;
            d.audit_event("", "snapshot.publish", "edge", "", "ok", serde_json::json!({"version": version}), "");
        }
    }
    match (std::fs::read_to_string(dir.join("current.toml")), std::fs::read_to_string(dir.join("current.sig"))) {
        (Ok(t), Ok(s)) => Ok(Some((st.version, t, s))),
        _ => Ok(None),
    }
}
