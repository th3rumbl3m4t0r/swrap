//! Admin commands executed on core (spec 14.4, 17). The client forwards argv; parsing happens
//! here so the daemon is the single source of truth. All writes are git-committed.

use crate::daemon::{Caller, Console, Daemon};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::sync::Arc;
use swrap_core::api::Resp;
use swrap_core::config::{Grant, Profile, Role, User};
use swrap_core::paths::safe_component;
use swrap_core::time::{fmt_utc_secs, now, IsoDuration};
use swrap_vault::Vault;
use zeroize::Zeroizing;

pub fn run(d: &Arc<Daemon>, c: &Caller, cmd: &str, args: Vec<String>, stdin: Option<String>, con: &Console) -> Result<Resp> {
    let stdin = stdin.map(Zeroizing::new);
    let mut argv = vec![cmd.to_string()];
    argv.extend(args);
    // Help/usage never needs privileges.
    let r = match cmd {
        "swadm" => parse::<Swadm>(&argv).and_then(|a| { c.require_admin()?; swadm(d, c, a, stdin, con) }),
        "swunlock" => swunlock(d, c, stdin),
        "swcrypto" => parse::<Swcrypto>(&argv).and_then(|a| { c.require_admin()?; swcrypto(d, a) }),
        "swfw" => crate::fw::run(d, c, &argv),
        "swedge" => crate::edge_admin::run(d, c, &argv, con),
        "swai" => crate::ai::admin(d, c, &argv, stdin.clone(), con),
        "doctor" => crate::doctor::run(d, c, &argv[1..], con),
        "table" => crate::table::admin(d, c, &argv, stdin.clone(), con),
        "swadd" | "swenroll" | "swdel" => { c.require_admin().and_then(|_| crate::hosts::run(d, c, cmd, argv, con)) }
        _ => bail!("unknown admin command {cmd}"),
    };
    match r {
        Err(e) => match e.downcast::<clap::Error>() {
            Ok(ce) => {
                let code = if ce.use_stderr() { 2 } else { 0 };
                Ok(Resp { ok: code == 0, text: ce.render().to_string(), exit: code, ..Default::default() })
            }
            Err(e) => Err(e),
        },
        ok => ok,
    }
}

fn parse<T: Parser>(argv: &[String]) -> Result<T> {
    // Accept single-dash long options (`-host`) as the spec allows for swadd.
    let fixed: Vec<String> = argv
        .iter()
        .map(|a| if a.len() > 2 && a.starts_with('-') && !a.starts_with("--") && a[1..].chars().all(|c| c.is_ascii_lowercase() || c == '-') { format!("-{a}") } else { a.clone() })
        .collect();
    T::try_parse_from(fixed).map_err(anyhow::Error::from)
}

// ---------------------------------------------------------------- swadm

#[derive(Parser, Debug)]
#[command(name = "swadm", about = "swrap administration (executed on core)")]
struct Swadm {
    #[command(subcommand)]
    cmd: AdmCmd,
}

#[derive(Subcommand, Debug)]
enum AdmCmd {
    /// AAA users.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Inbound SSH keys of AAA users.
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Grant hosts/remote users: swadm grant <aaa_user> <hosts> <remote_users> [--via core,edge] [--until ISO]
    Grant {
        user: String,
        hosts: String,
        remote_users: String,
        #[arg(long, default_value = "core,edge")]
        via: String,
        #[arg(long)]
        until: Option<String>,
        #[arg(long = "for")]
        for_: Option<String>,
    },
    /// Revoke a grant by id.
    Revoke { user: String, grant_id: String },
    /// Show an AAA user.
    Show { user: String },
    /// Vault: status | seal | passwd | add-admin <user> | recover
    Vault {
        #[command(subcommand)]
        cmd: VaultCmd,
    },
}

#[derive(Subcommand, Debug)]
enum UserCmd {
    Add {
        name: String,
        #[arg(long)]
        admin: bool,
        #[arg(long)]
        key: Vec<String>,
    },
    Del { name: String },
    List,
    Disable { name: String },
    Enable { name: String },
}

#[derive(Subcommand, Debug)]
enum KeyCmd {
    Add { name: String, key: Vec<String> },
    Del { name: String, fingerprint_or_index: String },
    List { name: String },
}

#[derive(Subcommand, Debug)]
enum VaultCmd {
    Status,
    Seal,
    /// Change your vault (= admin SSH) password. Old and new password on stdin.
    Passwd,
    /// Add a vault wrap for an admin (their password on stdin). Vault must be unsealed.
    AddAdmin { user: String },
    /// Unseal with the recovery key (on stdin).
    Recover,
    /// Initialise the vault (installer): first admin password on stdin.
    Init { admin: String },
}

fn swadm(d: &Arc<Daemon>, c: &Caller, a: Swadm, stdin: Option<Zeroizing<String>>, con: &Console) -> Result<Resp> {
    match a.cmd {
        AdmCmd::User { cmd } => user_cmd(d, c, cmd, con),
        AdmCmd::Key { cmd } => key_cmd(d, c, cmd),
        AdmCmd::Grant { user, hosts, remote_users, via, until, for_ } => {
            let _g = d.config_lock.lock().unwrap();
            let mut u = User::load(&d.paths, &user)?;
            swrap_core::rbac::Targets::parse(&hosts)?;
            let via: Vec<String> = via.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            if via.is_empty() || via.iter().any(|v| v != "core" && v != "edge") {
                bail!("--via takes core, edge or core,edge");
            }
            let until = match (until, for_) {
                (Some(_), Some(_)) => bail!("use either --until or --for"),
                (Some(u), None) => Some(fmt_utc_secs(swrap_core::time::parse_datetime(&u)?)),
                (None, Some(f)) => Some(fmt_utc_secs(IsoDuration::parse(&f)?.after(now()))),
                _ => None,
            };
            let g = Grant {
                id: swrap_core::new_id(),
                hosts: hosts.clone(),
                remote_users: remote_users.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
                via,
                until,
                created: fmt_utc_secs(now()),
            };
            let id = g.id.clone();
            u.grants.push(g);
            d.write_config(&format!("users/{user}.toml"), &u.to_toml())?;
            d.commit(&format!("grant {user} {hosts} {remote_users} ({id}) by {}", c.name))?;
            d.audit_event(&c.name, "grant.add", &hosts, &remote_users, "ok", json!({"user": user, "id": id}), "");
            Ok(Resp::text(format!("grant {id} added\n")))
        }
        AdmCmd::Revoke { user, grant_id } => {
            let _g = d.config_lock.lock().unwrap();
            let mut u = User::load(&d.paths, &user)?;
            let n = u.grants.len();
            u.grants.retain(|g| g.id != grant_id);
            if u.grants.len() == n {
                bail!("no grant {grant_id} for {user}");
            }
            d.write_config(&format!("users/{user}.toml"), &u.to_toml())?;
            d.commit(&format!("revoke {user} {grant_id} by {}", c.name))?;
            d.audit_event(&c.name, "grant.revoke", "", "", "ok", json!({"user": user, "id": grant_id}), "");
            Ok(Resp::text(format!("grant {grant_id} revoked\n")))
        }
        AdmCmd::Show { user } => {
            let u = User::load(&d.paths, &user)?;
            let tz = d.tz();
            let mut t = format!("{} role={:?} disabled={} created={}\nkeys:\n", u.name, u.role, u.disabled, u.created);
            for (i, k) in u.keys.iter().enumerate() {
                t += &format!("  [{i}] {}\n", crate::agent::fingerprint_of_pub_line(k).unwrap_or_else(|| "?".into()) + " " + k.split_whitespace().nth(2).unwrap_or(""));
            }
            t += "grants:\n";
            for g in &u.grants {
                let until = g.until.as_deref().and_then(|s| swrap_core::time::parse_datetime(s).ok()).map(|t| swrap_core::time::fmt_display(t, &tz, false)).unwrap_or_else(|| "-".into());
                t += &format!("  {} hosts={} remote_users={} via={} until={}\n", g.id, g.hosts, g.remote_users.join(","), g.via.join(","), until);
            }
            Ok(Resp { ok: true, text: t, data: serde_json::to_value(&u)?, ..Default::default() })
        }
        AdmCmd::Vault { cmd } => vault_cmd(d, c, cmd, stdin),
    }
}

fn linux_user_exists(name: &str) -> bool {
    swrap_core::sys::user_by_name(name).is_some()
}

pub fn render_authorized_keys(d: &Daemon, u: &User) -> Result<()> {
    let dir = std::path::Path::new("/etc/ssh/authorized_keys");
    swrap_core::atomic::mkdirs(dir, 0o755, swrap_core::atomic::Owner::new(0, 0))?;
    let mut s = format!("# managed by swrap (swadm key); edits are overwritten\n");
    if !u.disabled {
        for k in &u.keys {
            s += k.trim();
            s.push('\n');
        }
    }
    swrap_core::atomic::write(&dir.join(&u.name), s.as_bytes(), 0o644, swrap_core::atomic::Owner::new(0, 0))?;
    let _ = d;
    let _ = std::process::Command::new("restorecon").arg(dir.join(&u.name)).output();
    Ok(())
}

fn validate_key(k: &str) -> Result<String> {
    let k = k.trim();
    let mut it = k.split_whitespace();
    let (Some(t), Some(b)) = (it.next(), it.next()) else { bail!("not an OpenSSH public key") };
    let allowed = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"];
    if !allowed.contains(&t) {
        bail!("key type {t} not accepted");
    }
    if crate::agent::pub_blob(&format!("{t} {b}")).is_none() || k.contains('\n') {
        bail!("bad key data");
    }
    Ok(k.to_string())
}

/// Create/update the Linux account for an AAA user on core.
pub fn ensure_linux_account(d: &Daemon, u: &User) -> Result<()> {
    let shell = swrap_core::paths::libexec("swrap-shell");
    let groups = if u.role == Role::Admin { "swrap-users,swrap-admin" } else { "swrap-users" };
    if !linux_user_exists(&u.name) {
        crate::util::run("useradd", &["-m", "-s", &shell.to_string_lossy(), "-G", groups, "-c", "swrap AAA user", &u.name])?;
    } else {
        crate::util::run("usermod", &["-s", &shell.to_string_lossy(), "-G", groups, &u.name])?;
    }
    // No password: key-only (admins authenticate the second factor against the vault via PAM).
    crate::util::run("usermod", &["-p", "*", &u.name])?;
    let pw = swrap_core::sys::user_by_name(&u.name).context("account")?;
    let home = pw.dir;
    let link = |target: &std::path::Path, name: &str| {
        let l = home.join(name);
        if std::fs::symlink_metadata(&l).is_err() {
            let _ = std::os::unix::fs::symlink(target, &l);
            let _ = std::os::unix::fs::lchown(&l, Some(pw.uid.as_raw()), Some(pw.gid.as_raw()));
        }
    };
    link(&d.paths.state(), "swrap");
    swrap_core::paths::ensure_docs_link(&home, pw.uid.as_raw(), pw.gid.as_raw());
    let recdir = crate::session::ensure_rec_dir(d, &u.name)?;
    link(&recdir, "recordings");
    // Traverse-only ACLs so the user can reach rec/<user>/ and state/.
    for p in [d.paths.root.clone(), d.paths.rec()] {
        let _ = crate::util::setfacl(&["-m", &format!("u:{}:x", u.name)], &p);
    }
    render_authorized_keys(d, u)
}

fn user_cmd(d: &Arc<Daemon>, c: &Caller, cmd: UserCmd, con: &Console) -> Result<Resp> {
    let _g = d.config_lock.lock().unwrap();
    match cmd {
        UserCmd::Add { name, admin, key } => {
            if !safe_component(&name) || name.contains('.') || name == "root" || name.starts_with("swrap") {
                bail!("bad user name {name:?}");
            }
            if d.paths.user(&name).exists() {
                bail!("{name} already exists");
            }
            if linux_user_exists(&name) && swrap_core::sys::uid_of(&name).unwrap_or(0) < 1000 {
                bail!("{name} is a system account");
            }
            let keys = key.iter().map(|k| validate_key(k)).collect::<Result<Vec<_>>>()?;
            let u = User { name: name.clone(), role: if admin { Role::Admin } else { Role::User }, disabled: false, keys, created: fmt_utc_secs(now()), grants: vec![], ai_grants: vec![] };
            d.write_config(&format!("users/{name}.toml"), &u.to_toml())?;
            ensure_linux_account(d, &u)?;
            d.commit(&format!("user add {name} ({:?}) by {}", u.role, c.name))?;
            d.audit_event(&c.name, "user.add", &name, "", "ok", json!({"admin": admin}), "");
            if admin {
                con.out(format!("{name} is an admin: set their vault password with `swadm vault add-admin {name}` (vault must be unsealed)"));
            }
            Ok(Resp::text(format!("user {name} added\n")))
        }
        UserCmd::Del { name } => {
            let u = User::load(&d.paths, &name)?;
            if u.role == Role::Admin && User::all(&d.paths)?.iter().filter(|x| x.is_admin()).count() <= 1 {
                bail!("refusing to delete the last admin");
            }
            std::fs::remove_file(d.paths.user(&name))?;
            let _ = std::fs::remove_file(format!("/etc/ssh/authorized_keys/{name}"));
            if linux_user_exists(&name) {
                // Keep the home dir; lock the account (records are never deleted).
                let _ = crate::util::run("usermod", &["-L", "-e", "1", "-s", "/sbin/nologin", &name]);
            }
            d.commit(&format!("user del {name} by {}", c.name))?;
            d.audit_event(&c.name, "user.del", &name, "", "ok", json!({}), "");
            Ok(Resp::text(format!("user {name} deleted (Linux account locked, records kept)\n")))
        }
        UserCmd::List => {
            let mut t = String::new();
            for u in User::all(&d.paths)? {
                t += &format!("{}\t{:?}\t{}\tkeys={}\tgrants={}\n", u.name, u.role, if u.disabled { "disabled" } else { "active" }, u.keys.len(), u.grants.len());
            }
            Ok(Resp::text(t))
        }
        UserCmd::Disable { name } => set_disabled(d, c, &name, true),
        UserCmd::Enable { name } => set_disabled(d, c, &name, false),
    }
}

fn set_disabled(d: &Daemon, c: &Caller, name: &str, dis: bool) -> Result<Resp> {
    let mut u = User::load(&d.paths, name)?;
    u.disabled = dis;
    d.write_config(&format!("users/{name}.toml"), &u.to_toml())?;
    render_authorized_keys(d, &u)?;
    let _ = crate::util::run("usermod", &[if dis { "-L" } else { "-U" }, name]);
    if !dis {
        let _ = crate::util::run("usermod", &["-p", "*", name]);
    }
    d.commit(&format!("user {} {name} by {}", if dis { "disable" } else { "enable" }, c.name))?;
    d.audit_event(&c.name, if dis { "user.disable" } else { "user.enable" }, name, "", "ok", json!({}), "");
    Ok(Resp::text(format!("user {name} {}\n", if dis { "disabled" } else { "enabled" })))
}

fn key_cmd(d: &Arc<Daemon>, c: &Caller, cmd: KeyCmd) -> Result<Resp> {
    let _g = d.config_lock.lock().unwrap();
    match cmd {
        KeyCmd::Add { name, key } => {
            let mut u = User::load(&d.paths, &name)?;
            let k = validate_key(&key.join(" "))?;
            let fp = crate::agent::fingerprint_of_pub_line(&k).unwrap_or_default();
            if u.keys.iter().any(|x| crate::agent::fingerprint_of_pub_line(x).as_deref() == Some(fp.as_str())) {
                bail!("key {fp} already present");
            }
            u.keys.push(k);
            d.write_config(&format!("users/{name}.toml"), &u.to_toml())?;
            render_authorized_keys(d, &u)?;
            d.commit(&format!("key add {name} {fp} by {}", c.name))?;
            d.audit_event(&c.name, "key.add", &name, "", "ok", json!({"fp": fp}), "");
            Ok(Resp::text(format!("key {fp} added for {name}\n")))
        }
        KeyCmd::Del { name, fingerprint_or_index } => {
            let mut u = User::load(&d.paths, &name)?;
            let before = u.keys.len();
            if let Ok(i) = fingerprint_or_index.parse::<usize>() {
                if i < u.keys.len() {
                    u.keys.remove(i);
                }
            } else {
                u.keys.retain(|k| crate::agent::fingerprint_of_pub_line(k).as_deref() != Some(fingerprint_or_index.as_str()));
            }
            if u.keys.len() == before {
                bail!("no such key");
            }
            d.write_config(&format!("users/{name}.toml"), &u.to_toml())?;
            render_authorized_keys(d, &u)?;
            d.commit(&format!("key del {name} {fingerprint_or_index} by {}", c.name))?;
            d.audit_event(&c.name, "key.del", &name, "", "ok", json!({"key": fingerprint_or_index}), "");
            Ok(Resp::text("key removed\n"))
        }
        KeyCmd::List { name } => {
            let u = User::load(&d.paths, &name)?;
            let mut t = String::new();
            for (i, k) in u.keys.iter().enumerate() {
                t += &format!("[{i}] {} {}\n", crate::agent::fingerprint_of_pub_line(k).unwrap_or_default(), k.split_whitespace().nth(2).unwrap_or(""));
            }
            Ok(Resp::text(t))
        }
    }
}

fn vault_cmd(d: &Arc<Daemon>, c: &Caller, cmd: VaultCmd, stdin: Option<Zeroizing<String>>) -> Result<Resp> {
    let v = Vault::new(&d.paths, d.owner());
    let cfg = d.cfg();
    match cmd {
        VaultCmd::Status => {
            let sealed = d.is_sealed();
            let when = if sealed { *d.sealed_since.lock().unwrap() } else { d.unsealed_at.lock().unwrap().unwrap_or_else(now) };
            let mut t = format!(
                "vault: {} since {}\nadmin wraps: {}\ninitialized: {}\n",
                if sealed { "SEALED" } else { "unsealed" },
                d.disp(when),
                v.admins().join(", "),
                v.initialized()
            );
            let f = v.manifest_verify()?;
            t += &format!("manifest: {}\n", if f.is_empty() { "ok".to_string() } else { f.join("; ") });
            Ok(Resp { ok: true, text: t, data: json!({"sealed": sealed}), ..Default::default() })
        }
        VaultCmd::Seal => {
            d.seal(&c.name);
            Ok(Resp::text("vault sealed\n"))
        }
        VaultCmd::Passwd => {
            let s = stdin.context("old and new password expected")?;
            let mut it = s.splitn(2, '\n');
            let (old, new) = (it.next().unwrap_or(""), it.next().unwrap_or("").trim_end_matches('\n'));
            let dek = v.unwrap_password(&c.name, old.as_bytes()).map_err(|_| anyhow::anyhow!("old password wrong"))?;
            v.add_admin(&dek, &c.name, new.as_bytes(), &cfg.vault)?;
            d.audit_event(&c.name, "vault.passwd", &c.name, "", "ok", json!({}), "");
            Ok(Resp::text("vault password changed (this is also your SSH password)\n"))
        }
        VaultCmd::AddAdmin { user } => {
            let u = User::load(&d.paths, &user)?;
            if u.role != Role::Admin {
                bail!("{user} is not an admin (swadm user add {user} --admin)");
            }
            let pw = stdin.context("password expected on stdin")?;
            d.with_dek(|dek| v.add_admin(dek, &user, pw.trim_end_matches('\n').as_bytes(), &cfg.vault))?;
            d.audit_event(&c.name, "vault.add-admin", &user, "", "ok", json!({}), "");
            Ok(Resp::text(format!("vault wrap for {user} written; their SSH password is now this vault password\n")))
        }
        VaultCmd::Recover => {
            let rk = stdin.context("recovery key expected on stdin")?;
            let dek = v.unwrap_recovery(&rk).map_err(|e| {
                d.audit_event(&c.name, "vault.recover", "", "", "fail", json!({"error": e.to_string()}), "");
                e
            })?;
            let fresh = d.unseal(dek, &c.name, "recovery")?;
            Ok(Resp::text(if fresh { "vault unsealed with the recovery key\n" } else { "recovery key ok (vault was already unsealed)\n" }))
        }
        VaultCmd::Init { admin } => {
            if c.uid != 0 {
                bail!("vault init is done by the installer (root)");
            }
            let pw = stdin.context("password expected on stdin")?;
            let (dek, rec) = v.init(&admin, pw.trim_end_matches('\n').as_bytes(), &cfg.vault)?;
            // edge-config signing key lives in the vault (spec 4.3).
            crate::hosts::gen_vault_key(d, &dek, &d.paths.vault_keys().join("edge-config").join("id_ed25519.enc"), "ssh-ed25519", "edge-config")?;
            d.unseal(dek, &admin, "init")?;
            d.audit_event(&c.name, "vault.init", &admin, "", "ok", json!({}), "");
            Ok(Resp { ok: true, text: format!("RECOVERY KEY (store offline, shown once):\n\n    {}\n\n", rec.as_str()), ..Default::default() })
        }
    }
}

/// `swunlock`: manual unseal with an admin's vault password (stdin).
fn swunlock(d: &Arc<Daemon>, c: &Caller, stdin: Option<Zeroizing<String>>) -> Result<Resp> {
    c.require_admin()?;
    let pw = stdin.context("password expected")?;
    let name = if c.uid == 0 { bail!("run swunlock as your admin user") } else { c.name.clone() };
    let v = Vault::new(&d.paths, d.owner());
    match v.unwrap_password(&name, pw.trim_end_matches('\n').as_bytes()) {
        Ok(dek) => {
            let fresh = d.unseal(dek, &name, "swunlock")?;
            Ok(Resp::text(if fresh { "vault unsealed\n" } else { "vault already unsealed\n" }))
        }
        Err(e) => {
            d.audit_event(&name, "vault.unlock", "", "", "fail", json!({"error": e.to_string()}), "");
            bail!("unlock failed: {e}")
        }
    }
}

pub fn web_passwd(d: &Daemon, c: &Caller, password: &str) -> Result<Resp> {
    c.aaa()?;
    if password.len() < 12 {
        bail!("web password must be at least 12 characters");
    }
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let cfg = d.cfg();
    let params = argon2::Params::new(cfg.vault.argon2_m_kib.min(65536), cfg.vault.argon2_t, 1, None).map_err(|e| anyhow::anyhow!("{e}"))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let h = a.hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng)).map_err(|e| anyhow::anyhow!("{e}"))?.to_string();
    let p = d.paths.webpw(&c.name);
    swrap_core::atomic::mkdirs(p.parent().unwrap(), 0o700, d.owner())?;
    swrap_core::atomic::write(&p, format!("{h}\n").as_bytes(), 0o600, d.owner())?;
    d.audit_event(&c.name, "web.passwd", &c.name, "", "ok", json!({}), "");
    Ok(Resp::text("web password set\n"))
}

// ---------------------------------------------------------------- swcrypto

#[derive(Parser, Debug)]
#[command(name = "swcrypto", about = "crypto profiles")]
struct Swcrypto {
    #[command(subcommand)]
    cmd: CryptoCmd,
}

#[derive(Subcommand, Debug)]
enum CryptoCmd {
    /// Validate profiles against this node's OpenSSH binaries.
    Test {
        profile: Option<String>,
        #[arg(long, default_value = "core")]
        node: String,
    },
}

fn swcrypto(d: &Arc<Daemon>, a: Swcrypto) -> Result<Resp> {
    match a.cmd {
        CryptoCmd::Test { profile, node } => {
            if node != "core" {
                bail!("edge validation arrives with the edge node");
            }
            let profiles = match profile {
                Some(p) => vec![Profile::load(&d.paths, &p)?],
                None => swrap_core::config::load_all_profiles(&d.paths)?,
            };
            let mut t = String::new();
            let mut all_ok = true;
            for p in profiles {
                let c = crate::crypto::caps(&d.paths.run.join("caps"), p.ssh_bin_for(&node))?;
                let m = crate::crypto::missing(&p, &c);
                all_ok &= m.is_empty();
                t += &format!("{:<8} {:<5} {}  {}\n", p.name, node, if m.is_empty() { "valid" } else { "INVALID" }, if m.is_empty() { c.version.clone() } else { format!("missing: {}", m.join(", ")) });
            }
            Ok(Resp { ok: true, text: t, exit: if all_ok { 0 } else { 1 }, ..Default::default() })
        }
    }
}
