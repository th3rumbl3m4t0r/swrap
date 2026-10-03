//! swrapd core: shared state, API listener, request dispatch.

use crate::audit::AuditLog;
use anyhow::{anyhow, bail, Context, Result};
use jiff::Timestamp;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use swrap_core::api::{Req, Resp};
use swrap_core::atomic::Owner;
use swrap_core::config::{SwrapConfig, User};
use swrap_core::frame::{aio, kind, Frame};
use swrap_core::rbac::Node;
use swrap_core::sys;
use swrap_core::time::{fmt_display, now};
use swrap_core::Paths;
use swrap_vault::Dek;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

pub struct Daemon {
    pub paths: Paths,
    pub node: Node,
    pub vault: Mutex<Option<Dek>>,
    pub sealed_since: Mutex<Timestamp>,
    pub unsealed_at: Mutex<Option<Timestamp>>,
    pub audit: Mutex<AuditLog>,
    pub swrap_uid: u32,
    pub swrap_gid: u32,
    pub admin_gid: u32,
    /// Serialises writes to the config repo.
    pub config_lock: Mutex<()>,
}

/// Who is calling, from SO_PEERCRED.
#[derive(Clone, Debug)]
pub struct Caller {
    pub uid: u32,
    pub pid: i32,
    pub name: String,
    pub user: Option<User>,
    pub admin: bool,
    /// Node the user is logged into (edge requests arrive over the link).
    pub origin: Node,
}

impl Caller {
    pub fn aaa(&self) -> Result<&User> {
        match &self.user {
            Some(u) if !u.disabled => Ok(u),
            Some(_) => bail!("AAA user {} is disabled", self.name),
            None => bail!("{} is not an AAA user", self.name),
        }
    }
    pub fn require_admin(&self) -> Result<()> {
        if !self.admin {
            bail!("permission denied: admin only");
        }
        Ok(())
    }
}

/// Output channel for streaming human-readable lines back to the client.
#[derive(Clone)]
pub struct Console {
    pub tx: mpsc::UnboundedSender<Frame>,
}

impl Console {
    pub fn out(&self, s: impl Into<String>) {
        let _ = self.tx.send(Frame::new(kind::STDOUT, s.into().into_bytes()));
    }
    pub fn err(&self, s: impl Into<String>) {
        let _ = self.tx.send(Frame::new(kind::STDERR, s.into().into_bytes()));
    }
    pub fn frame(&self, f: Frame) {
        let _ = self.tx.send(f);
    }
    pub fn null() -> Self {
        let (tx, _rx) = mpsc::unbounded_channel();
        Console { tx }
    }
}

impl Daemon {
    pub fn new(paths: Paths) -> Result<Arc<Self>> {
        let (swrap_uid, swrap_gid) = sys::swrap_ids().context("user 'swrap' does not exist (run swrap-install core)")?;
        let admin_gid = sys::gid_of_group("swrap-admin").context("group 'swrap-admin' does not exist")?;
        let signer = swrec::RecSigner::load(&paths.recsign().join("ed25519.key"), "core").context("load recording signing key")?;
        let audit = AuditLog::new(paths.clone(), signer, Owner::new(swrap_uid, admin_gid));
        let d = Daemon {
            paths,
            node: Node::Core,
            vault: Mutex::new(None),
            sealed_since: Mutex::new(boot_time()),
            unsealed_at: Mutex::new(None),
            audit: Mutex::new(audit),
            swrap_uid,
            swrap_gid,
            admin_gid,
            config_lock: Mutex::new(()),
        };
        // Restarting swrapd must not reseal: pick up the DEK from the kernel keyring.
        if let Some(dek) = swrap_vault::keyring::load() {
            let v = swrap_vault::Vault::new(&d.paths, d.owner());
            if v.initialized() && std::fs::read_to_string(d.paths.wraps().join("recovery.wrap")).ok().and_then(|s| toml::from_str::<swrap_vault::Wrap>(&s).ok()).map(|w| w.commitment == hex(&dek.commitment())).unwrap_or(false) {
                *d.vault.lock().unwrap() = Some(dek);
                *d.unsealed_at.lock().unwrap() = Some(now());
            }
        }
        Ok(Arc::new(d))
    }

    pub fn owner(&self) -> Owner {
        Owner::new(self.swrap_uid, self.swrap_gid)
    }

    pub fn cfg(&self) -> SwrapConfig {
        SwrapConfig::load(&self.paths).unwrap_or_default()
    }

    pub fn tz(&self) -> String {
        self.cfg().general.display_timezone
    }

    pub fn disp(&self, ts: Timestamp) -> String {
        fmt_display(ts, &self.tz(), false)
    }

    pub fn is_sealed(&self) -> bool {
        self.vault.lock().unwrap().is_none()
    }

    /// Run `f` with the DEK, or fail with the spec's sealed message.
    pub fn with_dek<T>(&self, f: impl FnOnce(&Dek) -> Result<T>) -> Result<T> {
        let g = self.vault.lock().unwrap();
        match g.as_ref() {
            Some(d) => f(d),
            None => bail!("swrap: vault sealed since {} — an admin must log in with password", self.disp(*self.sealed_since.lock().unwrap())),
        }
    }

    pub fn unseal(&self, dek: Dek, by: &str, via: &str) -> Result<bool> {
        let mut g = self.vault.lock().unwrap();
        if g.is_some() {
            return Ok(false);
        }
        if let Err(e) = swrap_vault::keyring::store(dek.bytes()) {
            self.audit_event("", "vault.keyring", "", "", "error", json!({"error": e.to_string()}), "");
        }
        *g = Some(dek);
        *self.unsealed_at.lock().unwrap() = Some(now());
        drop(g);
        self.audit_event(by, "vault.unseal", "", "", "ok", json!({"via": via}), "");
        crate::motd::update(self);
        Ok(true)
    }

    pub fn seal(&self, by: &str) {
        swrap_vault::keyring::clear();
        *self.vault.lock().unwrap() = None;
        *self.sealed_since.lock().unwrap() = now();
        *self.unsealed_at.lock().unwrap() = None;
        self.audit_event(by, "vault.seal", "", "", "ok", json!({}), "");
        crate::motd::update(self);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn audit_event(&self, user: &str, action: &str, target: &str, ruser: &str, result: &str, detail: serde_json::Value, reference: &str) {
        let mut a = self.audit.lock().unwrap();
        if let Err(e) = a.log(user, action, target, ruser, result, detail, reference) {
            eprintln!("swrapd: audit write failed: {e:#}");
        }
    }

    /// Commit the config repo (single writer).
    pub fn commit(&self, msg: &str) -> Result<Option<String>> {
        let repo = swrap_core::git::Repo::new(self.paths.config()).run_as(self.swrap_uid, self.swrap_gid);
        let m = format!("{} {}", swrap_core::time::fmt_utc_secs(now()), msg);
        repo.commit_all(&m)
    }

    pub fn config_rev(&self) -> String {
        swrap_core::git::Repo::new(self.paths.config()).run_as(self.swrap_uid, self.swrap_gid).short_head()
    }

    pub fn write_config(&self, rel: &str, data: &str) -> Result<()> {
        let p = self.paths.config().join(rel);
        if let Some(parent) = p.parent() {
            swrap_core::atomic::mkdirs(parent, 0o750, self.owner())?;
        }
        swrap_core::atomic::write(&p, data.as_bytes(), 0o640, self.owner())
    }

    pub fn caller(&self, cred: sys::PeerCred) -> Caller {
        let name = sys::user_name(cred.uid).unwrap_or_else(|| format!("uid{}", cred.uid));
        let user = User::load(&self.paths, &name).ok();
        let admin = cred.uid == 0 || user.as_ref().map(|u| u.is_admin()).unwrap_or(false);
        Caller { uid: cred.uid, pid: cred.pid, name, user, admin, origin: Node::Core }
    }

    /// A user edge says is logged in there. Edge is trusted for identity only (spec 4.7).
    pub fn edge_caller(&self, name: &str) -> Result<Caller> {
        if !swrap_core::paths::safe_component(name) {
            bail!("bad user name");
        }
        let user = User::load(&self.paths, name).ok();
        let admin = user.as_ref().map(|u| u.is_admin()).unwrap_or(false);
        Ok(Caller { uid: u32::MAX, pid: 0, name: name.to_string(), user, admin, origin: Node::Edge })
    }
}

fn self_swrap_uid(d: &Daemon) -> u32 {
    d.swrap_uid
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn boot_time() -> Timestamp {
    // btime from /proc/stat
    std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("btime ")).and_then(|l| l[6..].trim().parse::<i64>().ok()))
        .and_then(|t| Timestamp::from_second(t).ok())
        .unwrap_or_else(now)
}

pub async fn serve_api(d: Arc<Daemon>) -> Result<()> {
    let sock = d.paths.api_sock();
    let _ = std::fs::remove_file(&sock);
    let l = UnixListener::bind(&sock).with_context(|| format!("bind {}", sock.display()))?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666))?;
    loop {
        let (s, _) = l.accept().await?;
        let d = d.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(d, s).await {
                eprintln!("swrapd: connection error: {e:#}");
            }
        });
    }
}

async fn handle(d: Arc<Daemon>, mut s: UnixStream) -> Result<()> {
    let cred = sys::peer_cred(&s)?;
    let caller = d.caller(cred);
    let Some(f) = aio::read_frame(&mut s).await? else { return Ok(()) };
    if f.kind != kind::REQ {
        bail!("expected request");
    }
    let req: Req = match f.parse() {
        Ok(r) => r,
        Err(e) => {
            aio::write_frame(&mut s, &Frame::json(kind::RESP, &Resp::err(format!("bad request: {e}")))).await?;
            return Ok(());
        }
    };
    match req {
        Req::Sw { .. } | Req::Shell { .. } => {
            // Session requests hand the connection to a worker process.
            let std = s.into_std()?;
            std.set_nonblocking(false)?;
            let d2 = d.clone();
            tokio::task::spawn_blocking(move || crate::session::start(d2, caller, req, std)).await??;
            Ok(())
        }
        Req::Sftp { .. } => {
            let std = s.into_std()?;
            std.set_nonblocking(false)?;
            let d2 = d.clone();
            tokio::task::spawn_blocking(move || crate::sftp::start(d2, caller, req, std)).await??;
            Ok(())
        }
        Req::AiStart { .. } | Req::AiAttach { .. } => {
            let std = s.into_std()?;
            std.set_nonblocking(false)?;
            let d2 = d.clone();
            if matches!(req, Req::AiAttach { .. }) {
                tokio::task::spawn_blocking(move || crate::ai::attach(d2, caller, req, std, Node::Core)).await??;
            } else {
                tokio::task::spawn_blocking(move || crate::ai::start(d2, caller, req, std, Node::Core, false)).await??;
            }
            Ok(())
        }
        other => {
            let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();
            let console = Console { tx };
            let d2 = d.clone();
            let task = tokio::task::spawn_blocking(move || {
                let r = dispatch(&d2, &caller, other, &console);
                let resp = match r {
                    Ok(r) => r,
                    Err(e) => Resp::err(format!("{e:#}")),
                };
                console.frame(Frame::json(kind::RESP, &resp));
            });
            while let Some(f) = rx.recv().await {
                if aio::write_frame(&mut s, &f).await.is_err() {
                    break;
                }
            }
            task.await?;
            Ok(())
        }
    }
}

pub fn dispatch(d: &Arc<Daemon>, c: &Caller, req: Req, con: &Console) -> Result<Resp> {
    match req {
        Req::Whoami => Ok(Resp::ok(json!({
            "user": c.name, "uid": c.uid, "aaa": c.user.is_some(), "admin": c.admin,
            "node": d.node.as_str(), "sealed": d.is_sealed(),
        }))),
        Req::Status => Ok(Resp::text(crate::motd::status_text(d))),
        Req::Ls => crate::records::ls(d, c),
        Req::Log { window, kind, all } => crate::records::log(d, c, &window, kind.as_deref(), all),
        Req::Find { id } => crate::records::find(d, c, &id),
        Req::Fetch { id } => crate::records::fetch(d, c, &id, con),
        Req::Search { query } => crate::records::search(d, c, &query, con),
        Req::Update { targets, app } => crate::fleet::update(d, c, &targets, app.as_deref(), con),
        Req::Inventory { targets } => crate::inventory::inventory(d, c, &targets, con),
        Req::Run { targets, ruser, script_name, script_b64, args, secrets } => crate::fleet::run(d, c, &targets, ruser.as_deref(), &script_name, &script_b64, &args, &secrets, con),
        Req::SftpBackend { session, token, entry } => crate::sftp::backend(d, c, &session, &token, &entry),
        Req::Audit { action, target, result, detail } => {
            let allowed = action.starts_with("shell.") || action.starts_with("session.") || action.starts_with("sftp.") || (c.uid == 0 && action.starts_with("replica.")) || (c.uid == self_swrap_uid(d) && (action.starts_with("web.") || action.starts_with("ai.")));
            if !allowed {
                bail!("audit action not allowed");
            }
            d.audit_event(&c.name, &action, &target, "", &result, detail, "");
            Ok(Resp::ok(json!({})))
        }
        Req::SessionCheck { id } => crate::session::check_live(d, c, &id),
        Req::Passwd { password } => crate::admin::web_passwd(d, c, &password),
        Req::Admin { cmd, args, stdin } => crate::admin::run(d, c, &cmd, args, stdin, con),
        Req::AiOptions => crate::ai::options(d, c),
        Req::AiModels { backend } => crate::ai::models(d, c, &backend),
        Req::AiAddBackend { addr } => crate::ai::add_backend(d, c, &addr, con),
        Req::AiWorker { session, token, call, args } => crate::ai::worker_call(d, c, &session, &token, &call, &args, con),
        Req::AiList => crate::ai::list(d, c),
        Req::Sw { .. } | Req::Shell { .. } | Req::AiStart { .. } | Req::AiAttach { .. } | Req::Sftp { .. } => Err(anyhow!("unreachable")),
    }
}
