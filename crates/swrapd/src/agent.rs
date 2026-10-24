//! Per-session ssh-agent behind a filtering proxy (spec 4.4, 9.2).
//!
//! A real `ssh-agent` holding exactly one key (decrypted in memory from the vault, loaded with
//! `ssh-add -` over a pipe) listens on a root-only socket. The proxy socket in the session dir is
//! the only thing `ssh` can reach. It allows only:
//! * `REQUEST_IDENTITIES` → just this session's public key;
//! * `session-bind@openssh.com` whose host key is pinned for the label (binds the session);
//! * `SIGN_REQUEST` for that key where the data is a userauth request for the expected remote
//!   user, at most N times within the window.
//!
//! Everything else is refused. Every decision is audited.
//!
//! A host reached through another (`via`, a jump) adds a second hop: the jump host's key, user and
//! pinned host keys. Each agent connection binds to one hop (its session-bind picks the hop by
//! host key), sees only that hop's key, and each hop binds once.

use crate::daemon::Daemon;
use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::json;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

pub struct Policy {
    pub session_id: String,
    pub aaa_user: String,
    pub label: String,
    pub ruser: String,
    pub key_blob: Vec<u8>,
    pub pinned: Vec<Vec<u8>>,
    pub max_sigs: u32,
    pub window: Duration,
    pub require_hostbound: bool,
    /// The jump host's leg, for hosts reached `via` another one.
    pub jump: Option<Hop>,
}

/// One leg of a connection: whose key, for which account, against which pinned host keys.
#[derive(Clone, Debug)]
pub struct Hop {
    pub label: String,
    pub ruser: String,
    pub key_blob: Vec<u8>,
    pub pinned: Vec<Vec<u8>>,
}

impl Policy {
    /// Hop 0 is the target, hop 1 the jump (if any).
    fn hop(&self, i: usize) -> Option<(&str, &str, &[u8], &[Vec<u8>])> {
        match (i, &self.jump) {
            (0, _) => Some((&self.label, &self.ruser, &self.key_blob, &self.pinned)),
            (1, Some(j)) => Some((&j.label, &j.ruser, &j.key_blob, &j.pinned)),
            _ => None,
        }
    }
    fn hops(&self) -> usize {
        1 + self.jump.is_some() as usize
    }
}

pub struct SessionAgent {
    agent: Mutex<Option<Child>>,
    real_dir: PathBuf,
    pub proxy_path: PathBuf,
    pub hostbound: AtomicBool,
    pub signatures: AtomicU32,
    stop: Arc<tokio::sync::Notify>,
    stopped: AtomicBool,
}

// ---------------------------------------------------------------- wire helpers

struct Rd<'a> {
    b: &'a [u8],
}

impl<'a> Rd<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (x, r) = self.b.split_first()?;
        self.b = r;
        Some(*x)
    }
    fn u32(&mut self) -> Option<u32> {
        if self.b.len() < 4 {
            return None;
        }
        let v = u32::from_be_bytes(self.b[..4].try_into().ok()?);
        self.b = &self.b[4..];
        Some(v)
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        if self.b.len() < n {
            return None;
        }
        let (s, r) = self.b.split_at(n);
        self.b = r;
        Some(s)
    }
}

fn put_string(v: &mut Vec<u8>, s: &[u8]) {
    v.extend_from_slice(&(s.len() as u32).to_be_bytes());
    v.extend_from_slice(s);
}

fn msg(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut v = ((body.len() + 1) as u32).to_be_bytes().to_vec();
    v.push(ty);
    v.extend_from_slice(body);
    v
}

async fn read_msg(s: &mut UnixStream) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match s.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > 256 * 1024 {
        bail!("bad agent message length {n}");
    }
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await?;
    Ok(Some(b))
}

/// Blob of a public key from an OpenSSH `.pub` / known_hosts line.
pub fn pub_blob(line: &str) -> Option<Vec<u8>> {
    let mut it = line.split_whitespace();
    let a = it.next()?;
    // known_hosts: "host type b64"; .pub: "type b64 comment"
    let b64 = if a.starts_with("ssh-") || a.starts_with("ecdsa-") || a.starts_with("sk-") || a.starts_with("rsa-") {
        it.next()?
    } else {
        it.next()?;
        it.next()?
    };
    B64.decode(b64).ok()
}

pub fn pinned_blobs(known_hosts: &str) -> Vec<Vec<u8>> {
    known_hosts.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).filter_map(pub_blob).collect()
}

fn blob_fp(b: &[u8]) -> String {
    use sha2::Digest;
    format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha2::Sha256::digest(b)))
}

pub fn fingerprint_of_pub_line(line: &str) -> Option<String> {
    pub_blob(line).map(|b| blob_fp(&b))
}

// ---------------------------------------------------------------- policy checks

enum Verdict {
    Allow,
    Deny(String),
}

struct State {
    started: Instant,
    /// The session id each hop is bound to.
    bound: [Option<Vec<u8>>; 2],
}

/// session-bind: the host key picks the hop (and binds this connection to it); once per hop.
fn check_bind(p: &Policy, body: &[u8], st: &mut State, conn: &mut Option<usize>) -> Verdict {
    let mut r = Rd { b: body };
    let (Some(_name), Some(hostkey), Some(sid), Some(_sig), Some(fwd)) = (r.string(), r.string(), r.string(), r.string(), r.u8()) else {
        return Verdict::Deny("malformed session-bind".into());
    };
    if fwd != 0 {
        return Verdict::Deny("session-bind for forwarding refused".into());
    }
    let Some(i) = (0..p.hops()).find(|&i| p.hop(i).map(|h| h.3.iter().any(|k| k.as_slice() == hostkey)).unwrap_or(false)) else {
        return Verdict::Deny(format!("session-bind host key {} is not pinned for {}", blob_fp(hostkey), p.label));
    };
    if st.bound[i].is_some() || conn.is_some() {
        return Verdict::Deny("session already bound".into());
    }
    st.bound[i] = Some(sid.to_vec());
    *conn = Some(i);
    Verdict::Allow
}

/// The hop a sign request is for: the connection's bound hop, else the one holding that key.
fn sign_hop(p: &Policy, body: &[u8], conn: Option<usize>) -> usize {
    if let Some(i) = conn {
        return i;
    }
    let mut r = Rd { b: body };
    let key = r.string().unwrap_or_default();
    (0..p.hops()).find(|&i| p.hop(i).map(|h| h.2 == key).unwrap_or(false)).unwrap_or(0)
}

fn check_sign(p: &Policy, body: &[u8], st: &State, count: u32, conn: Option<usize>) -> Verdict {
    let i = sign_hop(p, body, conn);
    let Some((_, ruser, key_blob, pinned)) = p.hop(i) else { return Verdict::Deny("no such hop".into()) };
    if count >= p.max_sigs {
        return Verdict::Deny(format!("signature limit {} reached", p.max_sigs));
    }
    if st.started.elapsed() > p.window {
        return Verdict::Deny("outside the signing window".into());
    }
    let mut r = Rd { b: body };
    let (Some(key), Some(data)) = (r.string(), r.string()) else { return Verdict::Deny("malformed sign request".into()) };
    if key != key_blob {
        return Verdict::Deny("sign request for a foreign key".into());
    }
    let mut d = Rd { b: data };
    let Some(sid) = d.string() else { return Verdict::Deny("data is not a userauth request".into()) };
    if d.u8() != Some(SSH_MSG_USERAUTH_REQUEST) {
        return Verdict::Deny("data is not a userauth request".into());
    }
    let (Some(user), Some(service), Some(method)) = (d.string(), d.string(), d.string()) else {
        return Verdict::Deny("malformed userauth request".into());
    };
    if user != ruser.as_bytes() {
        return Verdict::Deny(format!("userauth for {:?}, expected {:?}", String::from_utf8_lossy(user), ruser));
    }
    if service != b"ssh-connection" {
        return Verdict::Deny("unexpected service".into());
    }
    let hostbound_method = method == b"publickey-hostbound-v00@openssh.com";
    if method != b"publickey" && !hostbound_method {
        return Verdict::Deny("unexpected auth method".into());
    }
    if d.u8() != Some(1) {
        return Verdict::Deny("not a signature request".into());
    }
    let (Some(_alg), Some(kb)) = (d.string(), d.string()) else { return Verdict::Deny("malformed userauth request".into()) };
    if kb != key_blob {
        return Verdict::Deny("userauth key mismatch".into());
    }
    if hostbound_method {
        let Some(hk) = d.string() else { return Verdict::Deny("hostbound request without host key".into()) };
        if !pinned.iter().any(|k| k.as_slice() == hk) {
            return Verdict::Deny("hostbound request for an unpinned host key".into());
        }
    }
    if !d.b.is_empty() {
        return Verdict::Deny("trailing data in userauth request".into());
    }
    match &st.bound[i] {
        Some(b) if b.as_slice() != sid => return Verdict::Deny("session id differs from the bound session".into()),
        None if p.require_hostbound => return Verdict::Deny("session not host-bound (require_hostbound)".into()),
        _ => {}
    }
    Verdict::Allow
}

// ---------------------------------------------------------------- lifecycle

impl SessionAgent {
    /// Start the real agent (root-only socket), load the key, and serve the proxy socket.
    pub fn start(d: Arc<Daemon>, policy: Policy, private_key: Zeroizing<Vec<u8>>, session_dir: &Path) -> Result<Arc<Self>> {
        Self::start_with_jump(d, policy, private_key, None, session_dir)
    }

    /// `start` for a host reached through a jump: the agent also holds the jump leg's key
    /// (`policy.jump` says what it may sign).
    pub fn start_with_jump(d: Arc<Daemon>, policy: Policy, private_key: Zeroizing<Vec<u8>>, jump_key: Option<Zeroizing<Vec<u8>>>, session_dir: &Path) -> Result<Arc<Self>> {
        let real_dir = d.paths.run.join("agents").join(&policy.session_id);
        std::fs::create_dir_all(&real_dir)?;
        std::fs::set_permissions(&real_dir, std::fs::Permissions::from_mode(0o700))?;
        let real_sock = real_dir.join("agent.sock");
        let child = Command::new("/usr/bin/ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&real_sock)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn ssh-agent")?;
        let t0 = Instant::now();
        while !real_sock.exists() {
            if t0.elapsed() > Duration::from_secs(5) {
                bail!("ssh-agent did not start");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        for key in std::iter::once(private_key).chain(jump_key) {
            let mut add = Command::new("/usr/bin/ssh-add")
                .arg("-q")
                .arg("-")
                .env("SSH_AUTH_SOCK", &real_sock)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .context("spawn ssh-add")?;
            add.stdin.take().unwrap().write_all(&key)?;
            drop(key);
            let out = add.wait_with_output()?;
            if !out.status.success() {
                bail!("ssh-add failed: {}", String::from_utf8_lossy(&out.stderr).trim());
            }
        }
        let proxy_path = session_dir.join("agent.sock");
        let _ = std::fs::remove_file(&proxy_path);
        // Bound with the normal umask, then 0600: the session directory is 0700, so nobody else
        // reaches the socket in between. (Narrowing the umask instead would narrow it for the
        // whole process, every thread, and so for any program started meanwhile, e.g. git.)
        let listener = std::os::unix::net::UnixListener::bind(&proxy_path)?;
        std::fs::set_permissions(&proxy_path, std::fs::Permissions::from_mode(0o600))?;
        std::os::unix::fs::chown(&proxy_path, Some(d.swrap_uid), Some(d.swrap_gid))?;
        listener.set_nonblocking(true)?;
        let sa = Arc::new(SessionAgent {
            agent: Mutex::new(Some(child)),
            real_dir,
            proxy_path,
            hostbound: AtomicBool::new(false),
            signatures: AtomicU32::new(0),
            stop: Arc::new(tokio::sync::Notify::new()),
            stopped: AtomicBool::new(false),
        });
        let rt = tokio::runtime::Handle::current();
        let sa2 = sa.clone();
        let policy = Arc::new(policy);
        rt.spawn(async move {
            let l = match UnixListener::from_std(listener) {
                Ok(l) => l,
                Err(_) => return,
            };
            let st = Arc::new(tokio::sync::Mutex::new(State { started: Instant::now(), bound: [None, None] }));
            let deadline = tokio::time::sleep(policy.window);
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    _ = &mut deadline => break,
                    _ = sa2.stop.notified() => break,
                    acc = l.accept() => {
                        let Ok((c, _)) = acc else { break };
                        // Only the swrap user (ssh) may talk to the proxy.
                        match swrap_core::sys::peer_cred(&c) {
                            Ok(pc) if pc.uid == d.swrap_uid || pc.uid == 0 => {}
                            _ => continue,
                        }
                        let (d, p, st, sa) = (d.clone(), policy.clone(), st.clone(), sa2.clone());
                        let real = real_sock.clone();
                        tokio::spawn(async move {
                            if let Err(e) = proxy_conn(d.clone(), p.clone(), st, sa, c, &real).await {
                                d.audit_event(&p.aaa_user, "agent.error", &p.label, &p.ruser, "error", json!({"error": e.to_string()}), &p.session_id);
                            }
                        });
                    }
                }
            }
            sa2.shutdown();
        });
        Ok(sa)
    }

    /// Kill the agent (zeroizes the key with the process) and remove sockets.
    pub fn shutdown(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        self.stop.notify_waiters();
        if let Some(mut c) = self.agent.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.real_dir);
        let _ = std::fs::remove_file(&self.proxy_path);
    }
}

impl Drop for SessionAgent {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn proxy_conn(d: Arc<Daemon>, p: Arc<Policy>, st: Arc<tokio::sync::Mutex<State>>, sa: Arc<SessionAgent>, mut c: UnixStream, real: &Path) -> Result<()> {
    let mut upstream: Option<UnixStream> = None;
    // The hop this connection is bound to (session-bind); its key is the only one it sees.
    let mut conn: Option<usize> = None;
    while let Some(m) = read_msg(&mut c).await? {
        let ty = m[0];
        let body = &m[1..];
        let verdict = match ty {
            SSH_AGENTC_REQUEST_IDENTITIES => {
                // Bound: that hop's key. Unbound (no session-bind): the target's key first.
                let hops: Vec<usize> = match conn {
                    Some(i) => vec![i],
                    None => (0..p.hops()).collect(),
                };
                let mut b = (hops.len() as u32).to_be_bytes().to_vec();
                for i in hops {
                    let (label, ruser, key, _) = p.hop(i).expect("hop");
                    put_string(&mut b, key);
                    put_string(&mut b, format!("swrap:{label}:{ruser}").as_bytes());
                }
                c.write_all(&msg(SSH_AGENT_IDENTITIES_ANSWER, &b)).await?;
                continue;
            }
            SSH_AGENTC_EXTENSION => {
                let mut r = Rd { b: body };
                match r.string() {
                    Some(b"session-bind@openssh.com") => {
                        let v = check_bind(&p, body, &mut *st.lock().await, &mut conn);
                        if matches!(v, Verdict::Allow) {
                            sa.hostbound.store(true, Ordering::SeqCst);
                        }
                        ("session-bind", v)
                    }
                    Some(n) => ("extension", Verdict::Deny(format!("extension {} refused", String::from_utf8_lossy(n)))),
                    None => ("extension", Verdict::Deny("malformed extension".into())),
                }
            }
            SSH_AGENTC_SIGN_REQUEST => {
                let n = sa.signatures.load(Ordering::SeqCst);
                let v = check_sign(&p, body, &*st.lock().await, n, conn);
                if matches!(v, Verdict::Allow) {
                    sa.signatures.fetch_add(1, Ordering::SeqCst);
                }
                ("sign", v)
            }
            other => ("request", Verdict::Deny(format!("agent message type {other} refused"))),
        };
        match verdict.1 {
            Verdict::Deny(why) => {
                let what = match ty {
                    SSH_AGENTC_SIGN_REQUEST => "agent.sign",
                    SSH_AGENTC_EXTENSION => "agent.extension",
                    _ => "agent.request",
                };
                let (label, ruser, _, _) = p.hop(conn.unwrap_or(0)).expect("hop");
                d.audit_event(&p.aaa_user, what, label, ruser, "refused", json!({"why": why}), &p.session_id);
                c.write_all(&msg(SSH_AGENT_FAILURE, &[])).await?;
            }
            Verdict::Allow => {
                if upstream.is_none() {
                    upstream = Some(UnixStream::connect(real).await?);
                }
                let up = upstream.as_mut().unwrap();
                up.write_all(&((m.len()) as u32).to_be_bytes()).await?;
                up.write_all(&m).await?;
                let resp = read_msg(up).await?.context("agent closed")?;
                c.write_all(&(resp.len() as u32).to_be_bytes()).await?;
                c.write_all(&resp).await?;
                let i = if ty == SSH_AGENTC_SIGN_REQUEST { sign_hop(&p, body, conn) } else { conn.unwrap_or(0) };
                let (label, ruser, _, pinned) = p.hop(i).expect("hop");
                let jump = if i == 1 { json!(true) } else { json!(null) };
                if ty == SSH_AGENTC_SIGN_REQUEST {
                    let bound = st.lock().await.bound[i].is_some();
                    d.audit_event(&p.aaa_user, "agent.sign", label, ruser, if resp.first() == Some(&14) { "ok" } else { "agent-failed" },
                        json!({"hostbound": bound, "n": sa.signatures.load(Ordering::SeqCst), "hostkeys": pinned.iter().map(|b| blob_fp(b)).collect::<Vec<_>>(), "jump": jump, "for": p.label}), &p.session_id);
                } else {
                    d.audit_event(&p.aaa_user, "agent.session-bind", label, ruser, "ok", json!({"jump": jump, "for": p.label}), &p.session_id);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            session_id: "S".into(),
            aaa_user: "u".into(),
            label: "m".into(),
            ruser: "root".into(),
            key_blob: b"KEY".to_vec(),
            pinned: vec![b"HOSTKEY".to_vec()],
            max_sigs: 2,
            window: Duration::from_secs(60),
            require_hostbound: false,
            jump: None,
        }
    }

    fn userauth(user: &str, method: &str, key: &[u8], hostkey: Option<&[u8]>) -> Vec<u8> {
        let mut d = vec![];
        put_string(&mut d, b"SESSIONID");
        d.push(50);
        put_string(&mut d, user.as_bytes());
        put_string(&mut d, b"ssh-connection");
        put_string(&mut d, method.as_bytes());
        d.push(1);
        put_string(&mut d, b"ssh-ed25519");
        put_string(&mut d, key);
        if let Some(h) = hostkey {
            put_string(&mut d, h);
        }
        let mut b = vec![];
        put_string(&mut b, key);
        put_string(&mut b, &d);
        b.extend_from_slice(&0u32.to_be_bytes());
        b
    }

    #[test]
    fn sign_filtering() {
        let p = policy();
        let st = State { started: Instant::now(), bound: [None, None] };
        assert!(matches!(check_sign(&p, &userauth("root", "publickey", b"KEY", None), &st, 0, None), Verdict::Allow));
        assert!(matches!(check_sign(&p, &userauth("admin", "publickey", b"KEY", None), &st, 0, None), Verdict::Deny(_)));
        assert!(matches!(check_sign(&p, &userauth("root", "publickey", b"OTHER", None), &st, 0, None), Verdict::Deny(_)));
        assert!(matches!(check_sign(&p, &userauth("root", "publickey", b"KEY", None), &st, 2, None), Verdict::Deny(_)));
        assert!(matches!(check_sign(&p, &userauth("root", "publickey-hostbound-v00@openssh.com", b"KEY", Some(b"HOSTKEY")), &st, 0, None), Verdict::Allow));
        assert!(matches!(check_sign(&p, &userauth("root", "publickey-hostbound-v00@openssh.com", b"KEY", Some(b"EVIL")), &st, 0, None), Verdict::Deny(_)));
        let old = State { started: Instant::now() - Duration::from_secs(120), bound: [None, None] };
        assert!(matches!(check_sign(&p, &userauth("root", "publickey", b"KEY", None), &old, 0, None), Verdict::Deny(_)));
        // Arbitrary data (not a userauth request) is refused.
        let mut b = vec![];
        put_string(&mut b, b"KEY");
        put_string(&mut b, b"git commit to sign");
        b.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(check_sign(&p, &b, &st, 0, None), Verdict::Deny(_)));
    }

    #[test]
    fn bind_filtering() {
        let p = policy();
        let mk = |hk: &[u8], fwd: u8| {
            let mut b = vec![];
            put_string(&mut b, b"session-bind@openssh.com");
            put_string(&mut b, hk);
            put_string(&mut b, b"SESSIONID");
            put_string(&mut b, b"SIG");
            b.push(fwd);
            b
        };
        let mut st = State { started: Instant::now(), bound: [None, None] };
        let mut conn = None;
        assert!(matches!(check_bind(&p, &mk(b"EVIL", 0), &mut st, &mut conn), Verdict::Deny(_)));
        assert!(matches!(check_bind(&p, &mk(b"HOSTKEY", 1), &mut st, &mut conn), Verdict::Deny(_)));
        assert!(matches!(check_bind(&p, &mk(b"HOSTKEY", 0), &mut st, &mut conn), Verdict::Allow));
        // Now a sign request with a different session id is refused.
        let mut d = vec![];
        put_string(&mut d, b"OTHERSESSION");
        d.push(50);
        put_string(&mut d, b"root");
        put_string(&mut d, b"ssh-connection");
        put_string(&mut d, b"publickey");
        d.push(1);
        put_string(&mut d, b"ssh-ed25519");
        put_string(&mut d, b"KEY");
        let mut b = vec![];
        put_string(&mut b, b"KEY");
        put_string(&mut b, &d);
        b.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(check_sign(&p, &b, &st, 0, None), Verdict::Deny(_)));
    }

}
