//! Remote accounts (spec 10.5, `swuser`) and key rotation (10.4, `swrotate`); admin only.
//!
//! * `swuser add|del|lock|unlock|sudo|list|adopt`: accounts on hosts with a vault-held key each,
//!   no password (`usermod -p '!'`, the key is the only authenticator), and swrap-managed
//!   NOPASSWD sudo in `/etc/sudoers.d/swrap-<ruser>`, checked with `visudo -cf` and renamed into
//!   place. The inventory reports a `swrap-*` file that is unexpected, modified or missing.
//! * `swrotate <targets> [--algo …] [--user …]`: per account, add a new key, verify it in a fresh
//!   connection, remove the old one, verify the old one is refused, retire it in the vault
//!   (`vault/keys/retired/`, destroyed after P30D by the daily doctor run). New sessions keep
//!   using the old key until the new one is proven (the new one sorts after it meanwhile).
//!
//! Root work runs as root, or through a swrap-managed sudo account where a host has no root key.
//! Every host is a recorded run; host files change under the config lock and are committed.

use crate::daemon::{Caller, Console, Daemon};
use crate::hosts::{from_addrs, gen_vault_key_with, remote, RemoteOut, Run};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use swrap_core::api::Resp;
use swrap_core::config::{swrap_sudoers, valid_ruser, Account, Host, HostState, Profile};
use swrap_core::rbac;
use swrap_core::time::{fmt_basic, fmt_utc_secs, now};
use swrap_vault::Vault;

#[derive(Parser, Debug)]
#[command(name = "swuser", about = "Accounts on hosts: a vault-held key each, no password, swrap-managed sudo (admin)")]
struct Swuser {
    #[command(subcommand)]
    cmd: UserCmd,
}

#[derive(Subcommand, Debug)]
enum UserCmd {
    /// Create the account with a key of its own (and NOPASSWD sudo with --sudo).
    Add {
        targets: String,
        ruser: String,
        #[arg(long)]
        sudo: bool,
        #[arg(long, default_value = "/bin/bash")]
        shell: String,
        #[arg(long)]
        uid: Option<u32>,
    },
    /// Remove the account (and its home, unless --keep-home); its keys are retired.
    Del {
        targets: String,
        ruser: String,
        #[arg(long)]
        keep_home: bool,
    },
    /// No login at all (the account expires); the key stays.
    Lock { targets: String, ruser: String },
    Unlock { targets: String, ruser: String },
    /// swrap-managed NOPASSWD sudo: on or off.
    Sudo { targets: String, ruser: String, state: String },
    /// The accounts swrap holds keys for, checked on the hosts.
    List { targets: String },
    /// Take over an existing account: a vault-held key, the password locked.
    Adopt { targets: String, ruser: String },
}

#[derive(Parser, Debug)]
#[command(name = "swrotate", about = "Rotate the vault-held keys on hosts (admin)")]
struct Swrotate {
    targets: String,
    /// Key algorithm of the new keys (default: each account's current one).
    #[arg(long)]
    algo: Option<String>,
    /// Only this account (default: every account swrap holds a key for).
    #[arg(long)]
    user: Option<String>,
}

pub fn run(d: &Arc<Daemon>, c: &Caller, cmd: &str, argv: Vec<String>, con: &Console) -> Result<Resp> {
    c.require_admin()?;
    match cmd {
        "swuser" => swuser(d, c, Swuser::try_parse_from(argv)?, con),
        "swrotate" => swrotate(d, c, Swrotate::try_parse_from(argv)?, con),
        _ => bail!("unknown"),
    }
}

// ---------------------------------------------------------------- per host

/// A host and how to work on it: as root, or as a swrap-managed sudo account.
struct Ctx {
    host: Host,
    profile: Profile,
    known: String,
    admin: String,
    admin_enc: PathBuf,
    sudo: bool,
}

fn ctx(d: &Daemon, h: &Host) -> Result<Ctx> {
    let profile = Profile::load(&d.paths, &h.profile)?;
    let known = std::fs::read_to_string(d.paths.known_hosts(&h.label)).context("host keys not pinned")?;
    let cred = |a: &str| crate::session::credential(d, &h.label, a).map(|x| x.0);
    let (admin, admin_enc, sudo) = if let Some(e) = h.accounts.iter().any(|a| a.name == "root").then(|| cred("root")).flatten() {
        ("root".to_string(), e, false)
    } else if let Some((a, e)) = h.accounts.iter().filter(|a| a.sudo == "nopasswd" && a.managed_by_swrap).find_map(|a| cred(&a.name).map(|e| (a.name.clone(), e))) {
        (a, e, true)
    } else {
        bail!("no root key and no swrap-managed sudo account with a key");
    };
    Ok(Ctx { host: h.clone(), profile, known, admin, admin_enc, sudo })
}

impl Ctx {
    /// `script` as root (directly or through swrap-managed sudo). `stdin` is not recorded.
    fn root(&self, d: &Arc<Daemon>, who: &str, script: &str, stdin: &[u8], rec: &mut swrec::Writer) -> Result<RemoteOut> {
        let cmd = format!("{}bash -c {}", if self.sudo { "sudo -n " } else { "" }, crate::ai::q(script));
        remote(d, who, &self.host, &self.admin, &self.admin_enc, &self.profile, &self.known, &cmd, stdin, Some(rec))
    }
    /// `cmd` as `ruser`, with the key in `enc` (a fresh connection).
    fn as_user(&self, d: &Arc<Daemon>, who: &str, ruser: &str, enc: &Path, cmd: &str, stdin: &[u8], rec: Option<&mut swrec::Writer>) -> Result<RemoteOut> {
        remote(d, who, &self.host, ruser, enc, &self.profile, &self.known, cmd, stdin, rec)
    }
}

fn short(algo: &str) -> &'static str {
    match algo {
        "ssh-ed25519" => "ed25519",
        "ecdsa-sha2-nistp256" => "ecdsa",
        _ => "rsa",
    }
}

fn check_algo(a: &str) -> Result<()> {
    if !matches!(a, "ssh-ed25519" | "ecdsa-sha2-nistp256" | "rsa-sha2-512" | "rsa-sha2-256") {
        bail!("--algo is one of ssh-ed25519, ecdsa-sha2-nistp256, rsa-sha2-512, rsa-sha2-256");
    }
    Ok(())
}

/// A new key for (host, ruser) in the vault under `name`; (enc path, .pub line).
fn new_key(d: &Daemon, cx: &Ctx, ruser: &str, algo: &str, name: &str) -> Result<(PathBuf, String)> {
    let enc = d.paths.host_key(&cx.host.label, ruser, name);
    let line = d.with_dek(|dek| gen_vault_key_with(d, dek, &enc, algo, &format!("swrap:{}:{ruser}", cx.host.label), cx.profile.keygen_bin_for("core"), cx.profile.rsa_bits))?;
    Ok((enc, line))
}

fn pub_of(enc: &Path) -> PathBuf {
    PathBuf::from(enc.to_string_lossy().replace(".enc", ".pub"))
}

/// The authorized_keys line for (host, ruser): from= the nodes that connect, no forwarding.
fn key_line(d: &Daemon, h: &Host, ruser: &str, pub_line: &str) -> String {
    let pub_two = pub_line.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let from = from_addrs(d, h);
    let from_opt = if from.is_empty() { String::new() } else { format!("from=\"{}\",", from.join(",")) };
    format!("{from_opt}no-agent-forwarding,no-X11-forwarding {pub_two} swrap:{}:{ruser}:{}", h.label, now().strftime("%Y-%m-%d"))
}

/// As root: the key line on stdin replaces swrap's line for (label, u) in u's authorized_keys
/// (temp file, fsync, rename, restorecon; owner and modes of an ssh directory).
fn install_key_script(label: &str, u: &str) -> String {
    format!(
        r#"h=$(getent passwd '{u}' | cut -d: -f6); g=$(id -gn '{u}')
install -d -m 700 -o '{u}' -g "$g" "$h/.ssh"
f="$h/.ssh/authorized_keys"; t="$h/.ssh/.authorized_keys.swrap.$$"
{{ [ -f "$f" ] && grep -v ' swrap:{label}:{u}:' "$f" || true; cat; }} > "$t"
chown '{u}':"$g" "$t"; chmod 600 "$t"; sync "$t" 2>/dev/null || sync; mv -f "$t" "$f"; restorecon -R "$h/.ssh" 2>/dev/null || true
"#
    )
}

fn sudo_on_script(u: &str) -> String {
    format!(
        r#"command -v visudo >/dev/null || {{ echo "SWUSER: sudo is not installed"; exit 4; }}
t=$(mktemp /etc/sudoers.d/.swrap-{u}.XXXXXX)
printf '%s' '{content}' > "$t"; chmod 0440 "$t"
if ! visudo -cf "$t" >/dev/null 2>&1; then rm -f "$t"; echo "SWUSER: visudo refused the file"; exit 4; fi
mv -f "$t" /etc/sudoers.d/swrap-{u}; restorecon /etc/sudoers.d/swrap-{u} 2>/dev/null || true
"#,
        content = swrap_sudoers(u)
    )
}

fn sudo_off_script(u: &str) -> String {
    format!("rm -f /etc/sudoers.d/swrap-{u}\n")
}

/// Change one account in the host file (under the config lock) and commit.
fn update_host(d: &Daemon, label: &str, msg: &str, f: impl FnOnce(&mut Vec<Account>)) -> Result<()> {
    let _g = d.config_lock.lock().unwrap();
    let mut h = Host::load(&d.paths, label)?;
    f(&mut h.accounts);
    d.write_config(&format!("hosts/{label}.toml"), &h.to_toml())?;
    d.commit(msg)?;
    Ok(())
}

/// Moves `files` (a key and its .pub) to `vault/keys/retired/<label>_<ruser>_<ts>/`,
/// re-encrypted under the new path; the daily doctor run destroys it after P30D.
fn retire(d: &Daemon, label: &str, ruser: &str, files: &[PathBuf]) -> Result<PathBuf> {
    let dst = d.paths.vault_keys().join("retired").join(format!("{label}_{ruser}_{}", fmt_basic(now())));
    std::fs::create_dir_all(&dst)?;
    d.with_dek(|dek| {
        let v = Vault::new(&d.paths, d.owner());
        for f in files.iter().filter(|f| f.exists()) {
            let to = dst.join(f.file_name().context("file name")?);
            if f.to_string_lossy().ends_with(".enc") {
                let pt = v.get(dek, f)?;
                v.put(dek, &to, "retired", &pt)?;
            } else {
                std::fs::copy(f, &to)?;
            }
        }
        Ok(())
    })?;
    for f in files {
        let _ = std::fs::remove_file(f);
    }
    Vault::new(&d.paths, d.owner()).manifest_update()?;
    Ok(dst)
}

/// Retired keys older than P30D are destroyed (spec 10.4); run daily by the doctor loop.
pub fn purge_retired(d: &Daemon) -> Vec<String> {
    let dir = d.paths.vault_keys().join("retired");
    let cutoff = now() - jiff::SignedDuration::from_hours(30 * 24);
    let mut gone = vec![];
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(ts) = name.rsplit('_').next().and_then(|t| jiff::civil::DateTime::strptime("%Y%m%dT%H%M%SZ", t).ok()).and_then(|t| t.to_zoned(jiff::tz::TimeZone::UTC).ok()).map(|z| z.timestamp()) else {
            continue;
        };
        if ts < cutoff && std::fs::remove_dir_all(e.path()).is_ok() {
            gone.push(name);
        }
    }
    if !gone.is_empty() {
        let _ = Vault::new(&d.paths, d.owner()).manifest_update();
        d.audit_event("swrap", "vault.retired_destroyed", "", "", "ok", json!({"entries": gone}), "");
    }
    gone
}

fn targets(d: &Daemon, expr: &str) -> Result<Vec<Host>> {
    let all = Host::all(&d.paths)?;
    let hosts = rbac::expand(expr, &all, |h| h.state == HostState::Active)?;
    if hosts.is_empty() {
        bail!("no enrolled host in {expr:?}");
    }
    Ok(hosts.into_iter().cloned().collect())
}

/// Runs `f` on every host in parallel (each a recorded run of `kind`); the text has a line per host.
fn per_host(
    d: &Arc<Daemon>,
    c: &Caller,
    kind: &'static str,
    expr: &str,
    con: &Console,
    f: impl Fn(&Arc<Daemon>, &str, &Ctx, &mut swrec::Writer) -> Result<String> + Send + Sync + 'static,
) -> Result<Resp> {
    let hosts = targets(d, expr)?;
    let run = Arc::new(Run::new(d, kind, &c.name, expr, json!({"hosts": hosts.iter().map(|h| h.label.clone()).collect::<Vec<_>>()}))?);
    let (d2, who, run2, con2) = (d.clone(), c.name.clone(), run.clone(), con.clone());
    let f = Arc::new(f);
    let mut out = crate::fleet::parallel(
        d,
        hosts,
        move |h: &Host| -> Result<(String, bool, String)> {
            let cx = match ctx(&d2, h) {
                Ok(cx) => cx,
                Err(e) => return Ok((h.label.clone(), false, format!("{e:#}"))),
            };
            let mut rec = run2.host_writer(&d2, h, &cx.admin, &who, kind)?;
            let r = f(&d2, &who, &cx, &mut rec);
            let _ = rec.end(if r.is_ok() { "exit" } else { "error" }, Some(if r.is_ok() { 0 } else { 1 }), None);
            let (ok, text) = match r {
                Ok(t) => (true, t),
                Err(e) => (false, format!("{e:#}")),
            };
            con2.out(format!("{}: {}{text}", h.label, if ok { "" } else { "FAILED: " }));
            Ok((h.label.clone(), ok, text))
        },
        |h: &Host, why: String| (h.label.clone(), false, why),
    );
    out.sort();
    let failed = out.iter().filter(|o| !o.1).count();
    let mut text = String::new();
    for (l, ok, t) in &out {
        text += &format!("{l}: {}{t}\n", if *ok { "" } else { "FAILED: " });
    }
    text += &format!("run {} · {} ok, {failed} failed\n", run.id, out.len() - failed);
    let mut r = Resp::text(text);
    r.exit = if failed == 0 { 0 } else { 1 };
    Ok(r)
}

// ---------------------------------------------------------------- swuser

fn swuser(d: &Arc<Daemon>, c: &Caller, a: Swuser, con: &Console) -> Result<Resp> {
    if d.is_sealed() {
        bail!("the swrap vault is sealed; an admin login unseals it");
    }
    let need = |u: &str| -> Result<String> {
        if !valid_ruser(u) {
            bail!("{u:?} is not an account name swuser manages (lower case letters, digits, _ and -; not root)");
        }
        Ok(u.to_string())
    };
    match a.cmd {
        UserCmd::Add { targets, ruser, sudo, shell, uid } => {
            let u = need(&ruser)?;
            if !shell.starts_with('/') || !shell.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)) {
                bail!("--shell takes an absolute path");
            }
            per_host(d, c, "swuser", &targets, con, move |d, who, cx, rec| add(d, who, cx, rec, &u, sudo, &shell, uid))
        }
        UserCmd::Adopt { targets, ruser } => {
            let u = need(&ruser)?;
            per_host(d, c, "swuser", &targets, con, move |d, who, cx, rec| adopt(d, who, cx, rec, &u))
        }
        UserCmd::Del { targets, ruser, keep_home } => {
            let u = need(&ruser)?;
            per_host(d, c, "swuser", &targets, con, move |d, who, cx, rec| del(d, who, cx, rec, &u, keep_home))
        }
        UserCmd::Lock { targets, ruser } => {
            let u = need(&ruser)?;
            per_host(d, c, "swuser", &targets, con, move |d, who, cx, rec| lock(d, who, cx, rec, &u, true))
        }
        UserCmd::Unlock { targets, ruser } => {
            let u = need(&ruser)?;
            per_host(d, c, "swuser", &targets, con, move |d, who, cx, rec| lock(d, who, cx, rec, &u, false))
        }
        UserCmd::Sudo { targets, ruser, state } => {
            let u = need(&ruser)?;
            let on = match state.as_str() {
                "on" => true,
                "off" => false,
                _ => bail!("swuser sudo <targets> <ruser> on|off"),
            };
            per_host(d, c, "swuser", &targets, con, move |d, who, cx, rec| sudo(d, who, cx, rec, &u, on))
        }
        UserCmd::List { targets } => per_host(d, c, "swuser-list", &targets, con, list),
    }
}

fn known_account<'a>(cx: &'a Ctx, u: &str) -> Option<&'a Account> {
    cx.host.accounts.iter().find(|a| a.name == u)
}

fn default_algo(cx: &Ctx) -> String {
    known_account(cx, "root").map(|a| a.key_algo.clone()).filter(|a| !a.is_empty()).unwrap_or_else(|| cx.profile.key_preference.first().cloned().unwrap_or_else(|| "ssh-ed25519".into()))
}

fn ok_or(r: &RemoteOut, what: &str) -> Result<()> {
    if r.code == 0 {
        return Ok(());
    }
    let msg = r.stdout.lines().chain(r.stderr.lines()).find_map(|l| l.strip_prefix("SWUSER: ")).map(String::from).unwrap_or_else(|| r.why());
    bail!("{what}: {msg}")
}

/// Log in as `u` with its key in a fresh connection (and use sudo when it should have it).
fn verify_login(d: &Arc<Daemon>, who: &str, cx: &Ctx, u: &str, enc: &Path, sudo: bool, rec: &mut swrec::Writer) -> Result<()> {
    let cmd = if sudo { "echo swrap-ok; sudo -n true && echo sudo-ok" } else { "echo swrap-ok" };
    let r = cx.as_user(d, who, u, enc, cmd, b"", Some(rec))?;
    if r.code != 0 || !r.stdout.contains("swrap-ok") {
        bail!("logging in as {u} with the new key failed: {}", r.why());
    }
    if sudo && !r.stdout.contains("sudo-ok") {
        bail!("{u} logs in, but sudo -n does not work");
    }
    Ok(())
}

fn add(d: &Arc<Daemon>, who: &str, cx: &Ctx, rec: &mut swrec::Writer, u: &str, sudo: bool, shell: &str, uid: Option<u32>) -> Result<String> {
    if known_account(cx, u).is_some() {
        bail!("{u} is managed already (swuser list)");
    }
    let label = cx.host.label.clone();
    let algo = default_algo(cx);
    let name = format!("id_{}", short(&algo));
    let enc = d.paths.host_key(&label, u, &name);
    let pub_line = if enc.exists() { std::fs::read_to_string(pub_of(&enc))?.trim().to_string() } else { new_key(d, cx, u, &algo, &name)?.1 };
    let line = key_line(d, &cx.host, u, &pub_line);
    // An account of an earlier, interrupted add (it has our key line) is completed, not refused.
    let script = format!(
        r#"set -euo pipefail
if id '{u}' >/dev/null 2>&1; then
  h=$(getent passwd '{u}' | cut -d: -f6)
  grep -qs ' swrap:{label}:{u}:' "$h/.ssh/authorized_keys" || {{ echo "SWUSER: {u} exists already on this host (swuser adopt takes it over)"; exit 3; }}
else
  useradd -m {uid} -s '{shell}' '{u}'
fi
usermod -p '!' '{u}'
{install}{sudo}echo SWUSER-OK"#,
        uid = uid.map(|n| format!("-u {n}")).unwrap_or_default(),
        install = install_key_script(&label, u),
        sudo = if sudo { sudo_on_script(u) } else { sudo_off_script(u) },
    );
    ok_or(&cx.root(d, who, &script, format!("{line}\n").as_bytes(), rec)?, "creating the account")?;
    verify_login(d, who, cx, u, &enc, sudo, rec)?;
    let fp = crate::agent::fingerprint_of_pub_line(&pub_line).unwrap_or_default();
    update_host(d, &label, &format!("swuser add {u} on {label} by {who}"), |accts| {
        accts.retain(|a| a.name != u);
        accts.push(Account { name: u.into(), key_algo: algo.clone(), key_fingerprint: fp.clone(), created: fmt_utc_secs(now()), sudo: if sudo { "nopasswd".into() } else { "none".into() }, managed_by_swrap: true, integration: true, locked: false });
    })?;
    d.audit_event(who, "host.user_add", &label, u, "ok", json!({"sudo": sudo, "key": fp}), "");
    Ok(format!("{u} created ({}), key {fp} verified", if sudo { "NOPASSWD sudo" } else { "no sudo" }))
}

fn adopt(d: &Arc<Daemon>, who: &str, cx: &Ctx, rec: &mut swrec::Writer, u: &str) -> Result<String> {
    if known_account(cx, u).is_some() {
        bail!("{u} is managed already");
    }
    let label = cx.host.label.clone();
    let algo = default_algo(cx);
    let name = format!("id_{}", short(&algo));
    let enc = d.paths.host_key(&label, u, &name);
    let pub_line = if enc.exists() { std::fs::read_to_string(pub_of(&enc))?.trim().to_string() } else { new_key(d, cx, u, &algo, &name)?.1 };
    let line = key_line(d, &cx.host, u, &pub_line);
    let want = {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(swrap_sudoers(u).as_bytes()))
    };
    let script = format!(
        r#"set -euo pipefail
id '{u}' >/dev/null 2>&1 || {{ echo "SWUSER: there is no account {u} on this host (swuser add creates one)"; exit 3; }}
usermod -p '!' '{u}'
{install}if [ -f /etc/sudoers.d/swrap-{u} ] && [ "$(sha256sum /etc/sudoers.d/swrap-{u} | cut -d' ' -f1)" = '{want}' ]; then echo SUDO=nopasswd; else echo SUDO=none; fi
echo SWUSER-OK"#,
        install = install_key_script(&label, u)
    );
    let r = cx.root(d, who, &script, format!("{line}\n").as_bytes(), rec)?;
    ok_or(&r, "adopting the account")?;
    let sudo = r.stdout.contains("SUDO=nopasswd");
    verify_login(d, who, cx, u, &enc, sudo, rec)?;
    let fp = crate::agent::fingerprint_of_pub_line(&pub_line).unwrap_or_default();
    update_host(d, &label, &format!("swuser adopt {u} on {label} by {who}"), |accts| {
        accts.push(Account { name: u.into(), key_algo: algo.clone(), key_fingerprint: fp.clone(), created: fmt_utc_secs(now()), sudo: if sudo { "nopasswd".into() } else { "none".into() }, managed_by_swrap: true, integration: true, locked: false });
    })?;
    d.audit_event(who, "host.user_adopt", &label, u, "ok", json!({"sudo": sudo, "key": fp}), "");
    Ok(format!("{u} adopted: key {fp} verified, password locked{}", if sudo { ", swrap sudo kept" } else { "" }))
}

fn del(d: &Arc<Daemon>, who: &str, cx: &Ctx, rec: &mut swrec::Writer, u: &str, keep_home: bool) -> Result<String> {
    if known_account(cx, u).is_none() {
        bail!("{u} is not an account swrap manages here (swuser list)");
    }
    if cx.sudo && cx.admin == u {
        bail!("{u} is the account swrap uses for root work on this host; it cannot remove itself");
    }
    let label = cx.host.label.clone();
    let script = format!(
        r#"set -uo pipefail
rm -f /etc/sudoers.d/swrap-{u}
if id '{u}' >/dev/null 2>&1; then
  pkill -KILL -u '{u}' 2>/dev/null; sleep 1
  userdel {r} '{u}'; rc=$?
  [ $rc -eq 0 ] || [ $rc -eq 12 ] || {{ echo "SWUSER: userdel exited $rc"; exit 1; }}
fi
echo SWUSER-OK"#,
        r = if keep_home { "" } else { "-r" }
    );
    ok_or(&cx.root(d, who, &script, b"", rec)?, "removing the account")?;
    let dir = d.paths.vault_keys().join("hosts").join(&label).join(u);
    let files: Vec<PathBuf> = std::fs::read_dir(&dir).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default();
    let retired = retire(d, &label, u, &files)?;
    let _ = std::fs::remove_dir(&dir);
    update_host(d, &label, &format!("swuser del {u} on {label} by {who}"), |accts| accts.retain(|a| a.name != u))?;
    d.audit_event(who, "host.user_del", &label, u, "ok", json!({"keep_home": keep_home, "retired": retired.file_name().map(|n| n.to_string_lossy().to_string())}), "");
    Ok(format!("{u} removed{}; its key retired (destroyed after P30D)", if keep_home { " (home kept)" } else { "" }))
}

fn lock(d: &Arc<Daemon>, who: &str, cx: &Ctx, rec: &mut swrec::Writer, u: &str, on: bool) -> Result<String> {
    if known_account(cx, u).is_none() {
        bail!("{u} is not an account swrap manages here");
    }
    if on && cx.sudo && cx.admin == u {
        bail!("{u} is the account swrap uses for root work on this host; locking it would lock swrap out");
    }
    let label = cx.host.label.clone();
    // An expired account cannot log in at all, also not with a key (PAM account check).
    let script = format!("set -euo pipefail\nusermod -e {} '{u}'\necho SWUSER-OK", if on { "1" } else { "''" });
    ok_or(&cx.root(d, who, &script, b"", rec)?, if on { "locking" } else { "unlocking" })?;
    let (enc, _) = crate::session::credential(d, &label, u).ok_or_else(|| anyhow!("no key for {u}@{label} in the vault"))?;
    let r = cx.as_user(d, who, u, &enc, "echo swrap-ok", b"", None)?;
    let works = r.code == 0 && r.stdout.contains("swrap-ok");
    if on && works {
        bail!("{u} still logs in after locking");
    }
    if !on && !works {
        bail!("{u} does not log in after unlocking: {}", r.why());
    }
    update_host(d, &label, &format!("swuser {} {u} on {label} by {who}", if on { "lock" } else { "unlock" }), |accts| {
        if let Some(a) = accts.iter_mut().find(|a| a.name == u) {
            a.locked = on;
        }
    })?;
    d.audit_event(who, if on { "host.user_lock" } else { "host.user_unlock" }, &label, u, "ok", json!({}), "");
    Ok(format!("{u} {} (verified)", if on { "locked: no login" } else { "unlocked" }))
}

fn sudo(d: &Arc<Daemon>, who: &str, cx: &Ctx, rec: &mut swrec::Writer, u: &str, on: bool) -> Result<String> {
    if known_account(cx, u).is_none() {
        bail!("{u} is not an account swrap manages here");
    }
    if !on && cx.sudo && cx.admin == u {
        bail!("{u} is the account swrap uses for root work on this host; it keeps its sudo");
    }
    let label = cx.host.label.clone();
    let script = format!("set -euo pipefail\n{}echo SWUSER-OK", if on { sudo_on_script(u) } else { sudo_off_script(u) });
    ok_or(&cx.root(d, who, &script, b"", rec)?, "changing sudo")?;
    if on {
        let (enc, _) = crate::session::credential(d, &label, u).ok_or_else(|| anyhow!("no key for {u}@{label} in the vault"))?;
        verify_login(d, who, cx, u, &enc, true, rec)?;
    }
    update_host(d, &label, &format!("swuser sudo {u} {} on {label} by {who}", if on { "on" } else { "off" }), |accts| {
        if let Some(a) = accts.iter_mut().find(|a| a.name == u) {
            a.sudo = if on { "nopasswd".into() } else { "none".into() };
            a.managed_by_swrap = true;
        }
    })?;
    d.audit_event(who, "host.user_sudo", &label, u, "ok", json!({"sudo": on}), "");
    Ok(format!("{u}: NOPASSWD sudo {}", if on { "on (verified)" } else { "off" }))
}

/// Accounts swrap holds keys for, checked on the host: exists, locked (expired), sudo file.
fn list(d: &Arc<Daemon>, who: &str, cx: &Ctx, rec: &mut swrec::Writer) -> Result<String> {
    let names: Vec<String> = cx.host.accounts.iter().map(|a| a.name.clone()).collect();
    let mut script = String::from("set -u\nnow=$(( $(date +%s) / 86400 ))\n");
    for n in &names {
        script += &format!(
            "if id '{n}' >/dev/null 2>&1; then e=$(getent shadow '{n}' | cut -d: -f8); s=$( [ -f /etc/sudoers.d/swrap-{n} ] && sha256sum /etc/sudoers.d/swrap-{n} | cut -d' ' -f1 || echo -); printf '%s\\t%s\\t%s\\n' '{n}' \"$( [ -n \"$e\" ] && [ \"$e\" -le \"$now\" ] && echo expired || echo active)\" \"$s\"; else printf '%s\\tmissing\\t-\\n' '{n}'; fi\n"
        );
    }
    let r = cx.root(d, who, &script, b"", rec)?;
    ok_or(&r, "listing")?;
    let mut lines = vec![];
    for a in &cx.host.accounts {
        let row = r.stdout.lines().find(|l| l.split('\t').next() == Some(a.name.as_str())).unwrap_or("");
        let f: Vec<&str> = row.split('\t').collect();
        let state = f.get(1).copied().unwrap_or("?");
        let sudo_file = f.get(2).copied().unwrap_or("-");
        let want = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(swrap_sudoers(&a.name).as_bytes()))
        };
        let sudo_state = match (a.sudo.as_str(), sudo_file) {
            ("nopasswd", "-") if a.managed_by_swrap => "sudo MISSING".to_string(),
            ("nopasswd", h) if a.managed_by_swrap && h != want => "sudo MODIFIED".to_string(),
            ("nopasswd", _) => "sudo".to_string(),
            (_, "-") => "no sudo".to_string(),
            _ => "no sudo, but a swrap-* sudoers file (drift)".to_string(),
        };
        let key = crate::session::credential(d, &cx.host.label, &a.name).map(|_| a.key_algo.as_str()).unwrap_or("NO KEY");
        lines.push(format!(
            "{} ({key}{}, {state}{}, {sudo_state})",
            a.name,
            if a.managed_by_swrap { ", managed" } else { "" },
            if a.locked && state != "expired" { ", should be locked" } else { "" }
        ));
    }
    Ok(lines.join("; "))
}

// ---------------------------------------------------------------- swrotate

fn swrotate(d: &Arc<Daemon>, c: &Caller, a: Swrotate, con: &Console) -> Result<Resp> {
    if d.is_sealed() {
        bail!("the swrap vault is sealed; an admin login unseals it");
    }
    if let Some(al) = &a.algo {
        check_algo(al)?;
    }
    let (algo, user) = (a.algo.clone(), a.user.clone());
    per_host(d, c, "swrotate", &a.targets, con, move |d, who, cx, rec| {
        let accts: Vec<Account> = cx.host.accounts.iter().filter(|x| user.as_deref().is_none_or(|u| u == x.name)).cloned().collect();
        if accts.is_empty() {
            bail!("no such account here");
        }
        // The account swrap works through last, so the others use a proven key path.
        let mut order = accts.clone();
        order.sort_by_key(|x| x.name == cx.admin);
        let mut done = vec![];
        for x in &order {
            match rotate_one(d, who, cx, rec, x, algo.as_deref()) {
                Ok(fp) => done.push(format!("{} → {fp}", x.name)),
                Err(e) => {
                    let ok = if done.is_empty() { String::new() } else { format!(" (rotated: {})", done.join(", ")) };
                    return Err(e.context(format!("{}{ok}", x.name)));
                }
            }
        }
        Ok(format!("rotated {}", done.join(", ")))
    })
}

fn rotate_one(d: &Arc<Daemon>, who: &str, cx: &Ctx, rec: &mut swrec::Writer, acct: &Account, algo: Option<&str>) -> Result<String> {
    let label = cx.host.label.clone();
    let u = acct.name.clone();
    let (old_enc, old_pubp) = crate::session::credential(d, &label, &u).ok_or_else(|| anyhow!("no key in the vault"))?;
    let old_pub = std::fs::read_to_string(&old_pubp)?;
    let blob = old_pub.split_whitespace().nth(1).context("old public key")?.to_string();
    let algo = algo.map(String::from).unwrap_or_else(|| if acct.key_algo.is_empty() { default_algo(cx) } else { acct.key_algo.clone() });
    check_algo(&algo)?;
    // 1. The new key, under a name that sorts after the old one: new sessions keep using the
    //    old key until the new one works.
    let staging = format!("zz-rotating-id_{}", short(&algo));
    let staged = d.paths.host_key(&label, &u, &staging);
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_file(pub_of(&staged));
    let (new_enc, new_pub) = new_key(d, cx, &u, &algo, &staging)?;
    let line = key_line(d, &cx.host, &u, &new_pub);
    // 2. Add it next to the old one (as the account, with the old key).
    let add = r#"set -eu; umask 077; mkdir -p "$HOME/.ssh"; f="$HOME/.ssh/authorized_keys"; t="$HOME/.ssh/.authorized_keys.swrap.$$"
line=$(cat)
{ cat "$f" 2>/dev/null || true; grep -qxF "$line" "$f" 2>/dev/null || printf '%s\n' "$line"; } > "$t"
sync "$t" 2>/dev/null || sync; mv -f "$t" "$f"; restorecon "$f" 2>/dev/null || true; echo added"#;
    let r = cx.as_user(d, who, &u, &old_enc, add, format!("{line}\n").as_bytes(), Some(rec))?;
    if r.code != 0 || !r.stdout.contains("added") {
        let _ = retire(d, &label, &u, &[new_enc.clone(), pub_of(&new_enc)]);
        bail!("adding the new key failed: {}", r.why());
    }
    // 3. The new key works in a fresh connection.
    let r = cx.as_user(d, who, &u, &new_enc, "echo swrap-ok", b"", Some(rec))?;
    if r.code != 0 || !r.stdout.contains("swrap-ok") {
        bail!("the new key does not log in ({}); the old one stays in use", r.why());
    }
    // 4. Remove the old one (with the new key) and 5. check it is refused.
    let rm = format!(
        r#"set -eu; f="$HOME/.ssh/authorized_keys"; t="$HOME/.ssh/.authorized_keys.swrap.$$"
grep -vF ' {blob} ' "$f" > "$t" || true; sync "$t" 2>/dev/null || sync; mv -f "$t" "$f"; restorecon "$f" 2>/dev/null || true; echo removed"#
    );
    let r = cx.as_user(d, who, &u, &new_enc, &rm, b"", Some(rec))?;
    if r.code != 0 || !r.stdout.contains("removed") {
        bail!("removing the old key failed: {}", r.why());
    }
    let r = cx.as_user(d, who, &u, &old_enc, "echo swrap-old-key-works", b"", None)?;
    if r.code == 0 && r.stdout.contains("swrap-old-key-works") {
        bail!("the old key still logs in after its removal (another AuthorizedKeysFile?); both keys are kept");
    }
    // 6. Retire the old key, give the new one the usual name.
    retire(d, &label, &u, &[old_enc.clone(), old_pubp.clone()])?;
    let canonical = d.paths.host_key(&label, &u, &format!("id_{}", short(&algo)));
    d.with_dek(|dek| {
        let v = Vault::new(&d.paths, d.owner());
        let pt = v.get(dek, &new_enc)?;
        v.put(dek, &canonical, &crate::agent::fingerprint_of_pub_line(&new_pub).unwrap_or_default(), &pt)?;
        Ok(())
    })?;
    swrap_core::atomic::write(&pub_of(&canonical), format!("{new_pub}\n").as_bytes(), 0o640, d.owner())?;
    let _ = std::fs::remove_file(&new_enc);
    let _ = std::fs::remove_file(pub_of(&new_enc));
    Vault::new(&d.paths, d.owner()).manifest_update()?;
    let fp = crate::agent::fingerprint_of_pub_line(&new_pub).unwrap_or_default();
    update_host(d, &label, &format!("swrotate {u}@{label} by {who}"), |accts| {
        if let Some(a) = accts.iter_mut().find(|a| a.name == u) {
            a.key_algo = algo.clone();
            a.key_fingerprint = fp.clone();
            a.created = fmt_utc_secs(now());
        }
    })?;
    d.audit_event(who, "host.rotate", &label, &u, "ok", json!({"old": blob.chars().take(16).collect::<String>(), "new": fp, "algo": algo}), "");
    Ok(fp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudoers_text_and_names() {
        assert_eq!(swrap_sudoers("deploy"), "# managed by swrap (swuser): edits are reported as drift\ndeploy ALL=(ALL) NOPASSWD: ALL\n");
        for ok in ["deploy", "_svc", "a-b_9"] {
            assert!(valid_ruser(ok), "{ok}");
        }
        for bad in ["root", "", "Deploy", "9x", "a b", "a;b", "a/b", "x".repeat(33).as_str()] {
            assert!(!valid_ruser(bad), "{bad}");
        }
        assert!(install_key_script("test1", "deploy").contains(" swrap:test1:deploy:"));
        assert!(sudo_on_script("deploy").contains("visudo -cf"));
        assert_eq!(short("ecdsa-sha2-nistp256"), "ecdsa");
        assert!(check_algo("ssh-dss").is_err());
    }
}
