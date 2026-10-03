//! Session worker (runs as `swrap`, in its own session, survives swrapd restarts).
//!
//! * `sw` mode: owns the PTY, the `ssh` child and the recording (o, i, r, x, n, e).
//! * `shell` mode: records an AAA login shell streamed by `swrap-shell` (o, r, x, l, n, e;
//!   never keystrokes), including the nested-`sw` pause protocol.

use anyhow::{Context, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::pty::{openpty, Winsize};
use nix::sys::signal::{self, SigHandler, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use serde_json::{json, Value};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use swrap_core::api::{Resp, WorkerSpec};
use swrap_core::frame::{kind, Frame};
use swrec::osc::{OscEvent, OscFilter, Piece};
use swrec::render::LineEditor;
use swrec::{RecSigner, Writer, WriterOpts};

static TERM: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_: libc::c_int) {
    TERM.store(true, Ordering::SeqCst);
}

pub fn terminated() -> bool {
    TERM.load(Ordering::SeqCst)
}

/// Buffered frame reader over a blocking socket that we only read when poll says readable.
pub struct FrameBuf {
    pub buf: Vec<u8>,
}

impl FrameBuf {
    pub fn fill(&mut self, s: &mut UnixStream) -> std::io::Result<usize> {
        let mut tmp = [0u8; 65536];
        let n = s.read(&mut tmp)?;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }
    pub fn next(&mut self) -> Result<Option<Frame>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes(self.buf[..4].try_into().unwrap()) as usize;
        if !(5..=swrap_core::frame::MAX_FRAME + 5).contains(&len) {
            anyhow::bail!("bad frame length");
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let f = Frame {
            stream: u32::from_be_bytes(self.buf[4..8].try_into().unwrap()),
            kind: self.buf[8],
            payload: self.buf[9..4 + len].to_vec(),
        };
        self.buf.drain(..4 + len);
        Ok(Some(f))
    }
}

pub fn send(s: &mut UnixStream, f: &Frame) -> bool {
    swrap_core::frame::write_frame(s, f).is_ok()
}

pub fn audit(action: &str, target: &str, result: &str, detail: Value) {
    // Best-effort: tell swrapd (it may be restarting; the recording is authoritative anyway).
    let p = swrap_core::Paths::from_env().api_sock();
    if let Ok(mut s) = UnixStream::connect(p) {
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        let req = swrap_core::api::Req::Audit { action: action.into(), target: target.into(), result: result.into(), detail };
        let _ = swrap_core::frame::write_frame(&mut s, &Frame::json(kind::REQ, &req));
        let _ = swrap_core::frame::read_frame(&mut s);
    }
}

pub fn main() -> Result<()> {
    unsafe {
        let _ = signal::signal(Signal::SIGTERM, SigHandler::Handler(on_term));
        let _ = signal::signal(Signal::SIGHUP, SigHandler::SigIgn);
        let _ = signal::signal(Signal::SIGPIPE, SigHandler::SigIgn);
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let spec: WorkerSpec = serde_json::from_str(&input).context("worker spec")?;
    // The client connection must not leak into children (ssh, the swai sandbox).
    unsafe {
        let fl = libc::fcntl(3, libc::F_GETFD);
        libc::fcntl(3, libc::F_SETFD, fl | libc::FD_CLOEXEC);
    }
    let client = unsafe { UnixStream::from_raw_fd(3) };
    if spec.mode == "ai" {
        // Starts as root: sets up the sandbox, then drops to swrap before touching the client.
        return crate::ai_worker::run(spec, client);
    }
    if unsafe { libc::getuid() } == 0 {
        anyhow::bail!("session workers must not run as root");
    }
    let signer = RecSigner::load(Path::new(&spec.recsign_key), &spec.signer)?;
    let opts = WriterOpts::from_cfg(&spec.rec_cfg);
    let rec_path = Path::new(&spec.rec_path);
    let mut w = Writer::create(rec_path, &spec.id, spec.header.clone(), opts)?;
    // Keystroke relay must never wait for a disk flush (p99 target < 1 ms).
    w.enable_background_sync()?;
    std::fs::write(
        &spec.live_marker,
        json!({"id": spec.id, "user": spec.aaa_user, "kind": spec.mode, "pid": std::process::id(), "rec": spec.rec_path}).to_string(),
    )?;
    let res = match spec.mode.as_str() {
        "sw" => run_sw(&spec, client, &mut w, &signer),
        "sftp" => crate::sftp::run_worker(&spec, client, &mut w, &signer),
        _ => run_shell(&spec, client, &mut w, &signer),
    };
    let _ = std::fs::remove_file(&spec.live_marker);
    if !spec.session_dir.is_empty() {
        let _ = std::fs::remove_dir_all(&spec.session_dir);
    }
    if let Err(e) = &res {
        let _ = w.note(&format!("worker error: {e:#}"));
        let _ = w.end("error", None, Some(&signer));
    }
    res
}

// ---------------------------------------------------------------- sw

struct SshLog {
    pos: u64,
    kex: Option<String>,
    hostkey_alg: Option<String>,
    c2s: Option<String>,
    s2c: Option<String>,
    server_key: Option<String>,
    authed: bool,
    noted: bool,
}

impl SshLog {
    fn poll(&mut self, path: &Path) {
        let Ok(mut f) = File::open(path) else { return };
        use std::io::{Seek, SeekFrom};
        if f.seek(SeekFrom::Start(self.pos)).is_err() {
            return;
        }
        let mut s = String::new();
        let _ = f.read_to_string(&mut s);
        let consumed = s.rfind('\n').map(|i| i + 1).unwrap_or(0);
        self.pos += consumed as u64;
        for l in s[..consumed].lines() {
            let l = l.trim_start_matches("debug1: ");
            if let Some(v) = l.strip_prefix("kex: algorithm: ") {
                self.kex = Some(v.trim().into());
            } else if let Some(v) = l.strip_prefix("kex: host key algorithm: ") {
                self.hostkey_alg = Some(v.trim().into());
            } else if let Some(v) = l.strip_prefix("kex: client->server cipher: ") {
                self.c2s = Some(v.trim().into());
            } else if let Some(v) = l.strip_prefix("kex: server->client cipher: ") {
                self.s2c = Some(v.trim().into());
            } else if let Some(v) = l.strip_prefix("Server host key: ") {
                self.server_key = Some(v.trim().into());
            } else if l.starts_with("Authenticated to ") {
                self.authed = true;
            }
        }
    }
    fn tail(&self, path: &Path) -> String {
        let s = std::fs::read_to_string(path).unwrap_or_default();
        s.lines().filter(|l| !l.starts_with("debug1:")).rev().take(3).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("; ")
    }
}

pub fn set_winsize(fd: &impl AsRawFd, cols: u16, rows: u16) {
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
}

fn run_sw(spec: &WorkerSpec, mut client: UnixStream, w: &mut Writer, signer: &RecSigner) -> Result<()> {
    let ws = Winsize { ws_row: spec.rows.max(1), ws_col: spec.cols.max(1), ws_xpixel: 0, ws_ypixel: 0 };
    let pty = openpty(Some(&ws), None)?;
    crate::ai_worker::cloexec(&pty.master);
    crate::ai_worker::cloexec(&pty.slave);
    let master: OwnedFd = pty.master;
    let slave: OwnedFd = pty.slave;
    let sfd = slave.as_raw_fd();
    let mut cmd = Command::new(&spec.argv[0]);
    cmd.args(&spec.argv[1..])
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .env("TERM", &spec.term)
        .env("HOME", &spec.session_dir)
        .env("LANG", "C.UTF-8")
        .stdin(unsafe { Stdio::from_raw_fd(libc::dup(sfd)) })
        .stdout(unsafe { Stdio::from_raw_fd(libc::dup(sfd)) })
        .stderr(unsafe { Stdio::from_raw_fd(libc::dup(sfd)) });
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            // The worker ignores SIGHUP/SIGPIPE and ignored dispositions survive exec: restore them.
            libc::signal(libc::SIGHUP, libc::SIG_DFL);
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            // If the worker is killed (even SIGKILL), ssh must not outlive its recorder.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().context("spawn ssh")?;
    // Command owns the slave dups until dropped; the master only sees EIO once all are closed.
    drop(cmd);
    drop(slave);
    let pid = Pid::from_raw(child.id() as i32);
    std::mem::forget(child); // reaped with waitpid below

    let mut resp = Resp::ok(json!({"id": spec.id, "banner": spec.banner}));
    resp.text = spec.banner.clone();
    send(&mut client, &Frame::json(kind::RESP, &resp));

    let mut master_f = File::from(master);
    let mut osc = OscFilter::new(&spec.nonce);
    let mut editor = LineEditor::default();
    let mut integration_seen = false;
    let sdir = Path::new(&spec.session_dir);
    let ssh_log_path = sdir.join("ssh.log");
    let mut sshlog = SshLog { pos: 0, kex: None, hostkey_alg: None, c2s: None, s2c: None, server_key: None, authed: false, noted: false };
    let mut fb = FrameBuf { buf: vec![] };
    let mut exit_status: Option<i32> = None;
    let mut reason = "exit";
    let mut client_open = true;
    let mut buf = vec![0u8; 65536];
    let mut next_tick = Duration::from_millis(5);
    let mut last_log_poll = Instant::now();
    let started = Instant::now();

    loop {
        if TERM.load(Ordering::SeqCst) {
            // On edge, the daemon terminates sessions when the spool is full (fail-closed).
            reason = if swrap_core::Paths::from_env().run.join("spool_full").exists() { "spool_full" } else { "killed" };
            let _ = signal::kill(pid, Signal::SIGHUP);
            break;
        }
        let timeout = PollTimeout::try_from(next_tick.min(Duration::from_millis(200)).as_millis() as i32).unwrap_or(PollTimeout::NONE);
        let (mr, cr) = {
            let mut fds = vec![PollFd::new(master_f.as_fd(), PollFlags::POLLIN)];
            if client_open {
                fds.push(PollFd::new(client.as_fd(), PollFlags::POLLIN));
            }
            match poll(&mut fds, timeout) {
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
            }
            let m = fds[0].revents().unwrap_or(PollFlags::empty());
            let c = if client_open { fds[1].revents().unwrap_or(PollFlags::empty()) } else { PollFlags::empty() };
            (m, c)
        };
        if mr.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            match master_f.read(&mut buf) {
                Ok(0) | Err(_) => {
                    // EIO: slave closed (ssh exited). Collect status below.
                    if let Ok(st) = waitpid(pid, None) {
                        exit_status = Some(match st {
                            WaitStatus::Exited(_, c) => c,
                            WaitStatus::Signaled(_, s, _) => 128 + s as i32,
                            _ => 255,
                        });
                    }
                    break;
                }
                Ok(n) => {
                    let data = &buf[..n];
                    // The user sees exactly what the host sent (OSC 7719 is invisible to terminals).
                    if client_open && !send(&mut client, &Frame::new(kind::DATA, data.to_vec())) {
                        client_open = false;
                    }
                    for p in osc.push(data) {
                        match p {
                            Piece::Bytes(b) => w.output(&b)?,
                            Piece::Event(OscEvent::Cmd { cmd, cwd, exit }) => {
                                integration_seen = true;
                                let mut m = serde_json::Map::new();
                                m.insert("cmd".into(), cmd.into());
                                m.insert("src".into(), "integration".into());
                                if let Some(c) = cwd {
                                    m.insert("cwd".into(), c.into());
                                }
                                if let Some(e) = exit {
                                    m.insert("exit".into(), e.into());
                                }
                                w.record("x", m)?;
                            }
                            Piece::Event(OscEvent::WrongNonce) => w.note("OSC 7719 sequence with wrong nonce left in output (spoofed marker?)")?,
                            Piece::Event(OscEvent::Malformed(e)) => w.note(&format!("malformed integration sequence: {e}"))?,
                            Piece::Event(OscEvent::Marker { .. }) => w.note("sw marker inside sw session ignored")?,
                        }
                    }
                }
            }
        }
        if cr.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            match fb.fill(&mut client) {
                Ok(0) | Err(_) => {
                    client_open = false;
                    reason = "client_disconnect";
                    let _ = signal::kill(pid, Signal::SIGHUP);
                    // Give ssh a moment to exit; EIO on the master ends the loop.
                }
                Ok(_) => {
                    while let Some(f) = fb.next()? {
                        match f.kind {
                            kind::DATA => {
                                master_f.write_all(&f.payload)?;
                                w.input(&f.payload)?;
                                if !integration_seen {
                                    for line in editor.push(&f.payload) {
                                        w.record_json("x", json!({"cmd": line, "src": "heuristic"}))?;
                                    }
                                }
                            }
                            kind::RESIZE => {
                                if let Ok(v) = serde_json::from_slice::<Value>(&f.payload) {
                                    let c = v["cols"].as_u64().unwrap_or(80) as u16;
                                    let r = v["rows"].as_u64().unwrap_or(24) as u16;
                                    set_winsize(&master_f, c, r);
                                    w.record_json("r", json!({"cols": c, "rows": r}))?;
                                }
                            }
                            kind::SIGNAL => {
                                if let Some(&s) = f.payload.first() {
                                    if let Ok(sig) = Signal::try_from(s as i32) {
                                        if matches!(sig, Signal::SIGINT | Signal::SIGTERM | Signal::SIGHUP) {
                                            let _ = signal::kill(pid, sig);
                                        }
                                    }
                                }
                            }
                            kind::EOF => {
                                // stdin closed on a non-tty client; a PTY session has no EOF to forward.
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        if !client_open && reason == "client_disconnect" {
            // ssh ignores SIGHUP sometimes before auth; escalate after a grace period.
            if let Ok(WaitStatus::StillAlive) = waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                std::thread::sleep(Duration::from_millis(50));
                let _ = signal::kill(pid, Signal::SIGKILL);
            }
        }
        if last_log_poll.elapsed() > Duration::from_millis(100) && !sshlog.noted {
            last_log_poll = Instant::now();
            sshlog.poll(&ssh_log_path);
            if sshlog.authed {
                // Wait briefly for swrapd's agent summary (host binding, signature count).
                let agent = std::fs::read_to_string(sdir.join("agent.json")).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok());
                if agent.is_some() || started.elapsed() > Duration::from_secs(5) {
                    let a = agent.unwrap_or(json!({}));
                    let msg = format!(
                        "crypto: kex={} hostkey={} c2s={} s2c={} server_key={} hostbound={} signatures={}",
                        sshlog.kex.as_deref().unwrap_or("?"),
                        sshlog.hostkey_alg.as_deref().unwrap_or("?"),
                        sshlog.c2s.as_deref().unwrap_or("?"),
                        sshlog.s2c.as_deref().unwrap_or("?"),
                        sshlog.server_key.as_deref().unwrap_or("?"),
                        a["hostbound"],
                        a["signatures"]
                    );
                    w.record_json("n", json!({"msg": msg, "kex": sshlog.kex, "hostkey_alg": sshlog.hostkey_alg, "cipher_c2s": sshlog.c2s, "cipher_s2c": sshlog.s2c, "server_key": sshlog.server_key, "hostbound": a["hostbound"]}))?;
                    audit("session.crypto", &spec.header.get("label").and_then(Value::as_str).unwrap_or(""), "ok", json!({"id": spec.id, "kex": sshlog.kex, "hostkey_alg": sshlog.hostkey_alg, "c2s": sshlog.c2s, "s2c": sshlog.s2c, "hostbound": a["hostbound"]}));
                    sshlog.noted = true;
                }
            }
        }
        next_tick = w.tick()?;
    }
    // Drain remaining output after exit.
    if exit_status.is_none() {
        if let Ok(st) = waitpid(pid, None) {
            exit_status = Some(match st {
                WaitStatus::Exited(_, c) => c,
                WaitStatus::Signaled(_, s, _) => 128 + s as i32,
                _ => 255,
            });
        }
    }
    let rest = osc.finish();
    w.output(&rest)?;
    if !sshlog.authed {
        sshlog.poll(&ssh_log_path);
        if !sshlog.authed {
            let t = sshlog.tail(&ssh_log_path);
            if !t.is_empty() {
                w.note(&format!("ssh: {t}"))?;
                if client_open {
                    send(&mut client, &Frame::new(kind::STDERR, format!("swrap: ssh: {t}").into_bytes()));
                }
            }
        }
    }
    let code = exit_status.unwrap_or(255);
    w.end(reason, Some(code), Some(signer))?;
    if client_open {
        send(&mut client, &Frame::exit(code, reason));
    }
    audit("session.end", spec.header.get("label").and_then(Value::as_str).unwrap_or(""), reason,
        json!({"id": spec.id, "exit_code": code, "bytes_out": w.bytes_out, "bytes_in": w.bytes_in, "duration": swrap_core::time::fmt_duration_ms(started.elapsed())}));
    Ok(())
}

// ---------------------------------------------------------------- shell

fn live_owned_by(id: &str, user: &str) -> bool {
    if !swrap_core::paths::safe_component(id) {
        return false;
    }
    let p = swrap_core::Paths::from_env().live().join(id);
    std::fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .map(|j| j["user"] == user && (j["kind"] == "sw" || j["kind"] == "ai") && crate::util::process_alive(j["pid"].as_i64().unwrap_or(0) as i32))
        .unwrap_or(false)
}

fn run_shell(spec: &WorkerSpec, mut client: UnixStream, w: &mut Writer, signer: &RecSigner) -> Result<()> {
    send(&mut client, &Frame::json(kind::RESP, &Resp::ok(json!({"id": spec.id, "banner": spec.banner}))));
    let mut osc = OscFilter::new(&spec.nonce);
    let mut fb = FrameBuf { buf: vec![] };
    let mut paused: Option<String> = None;
    let mut exit_code: Option<i32> = None;
    let mut reason = "client_disconnect";
    let mut next_tick = Duration::from_millis(5);
    let mut last_pause_check = Instant::now();
    loop {
        if TERM.load(Ordering::SeqCst) {
            reason = "killed";
            break;
        }
        let timeout = PollTimeout::try_from(next_tick.min(Duration::from_millis(200)).as_millis() as i32).unwrap_or(PollTimeout::NONE);
        let mut fds = [PollFd::new(client.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, timeout) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
        let ev = fds[0].revents().unwrap_or(PollFlags::empty());
        if ev.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            match fb.fill(&mut client) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    while let Some(f) = fb.next()? {
                        match f.kind {
                            kind::DATA => {
                                for p in osc.push(&f.payload) {
                                    match p {
                                        Piece::Bytes(b) => {
                                            if paused.is_none() {
                                                w.output(&b)?;
                                            }
                                        }
                                        Piece::Event(OscEvent::Cmd { cmd, cwd, exit }) => {
                                            if paused.is_none() {
                                                let mut m = serde_json::Map::new();
                                                m.insert("cmd".into(), cmd.into());
                                                m.insert("src".into(), "integration".into());
                                                if let Some(c) = cwd {
                                                    m.insert("cwd".into(), c.into());
                                                }
                                                if let Some(e) = exit {
                                                    m.insert("exit".into(), e.into());
                                                }
                                                w.record("x", m)?;
                                            }
                                        }
                                        Piece::Event(OscEvent::Marker { start: true, id }) => {
                                            if paused.is_none() && live_owned_by(&id, &spec.aaa_user) {
                                                w.record_json("l", json!({"sw": id, "phase": "start"}))?;
                                                paused = Some(id);
                                            } else {
                                                w.note(&format!("forged or stale sw-start marker for {id:?} ignored"))?;
                                            }
                                        }
                                        Piece::Event(OscEvent::Marker { start: false, id }) => {
                                            if paused.as_deref() == Some(id.as_str()) {
                                                w.record_json("l", json!({"sw": id, "phase": "end"}))?;
                                                paused = None;
                                            } else {
                                                w.note(&format!("unexpected sw-end marker for {id:?} ignored"))?;
                                            }
                                        }
                                        Piece::Event(OscEvent::WrongNonce) => {
                                            if paused.is_none() {
                                                w.note("OSC 7719 sequence with wrong nonce left in output (spoofed marker?)")?;
                                            }
                                        }
                                        Piece::Event(OscEvent::Malformed(e)) => w.note(&format!("malformed integration sequence: {e}"))?,
                                    }
                                }
                            }
                            kind::RESIZE => {
                                if let Ok(v) = serde_json::from_slice::<Value>(&f.payload) {
                                    w.record_json("r", json!({"cols": v["cols"], "rows": v["rows"]}))?;
                                }
                            }
                            kind::EXIT => {
                                let (c, _) = f.exit_code();
                                exit_code = Some(c);
                                reason = "exit";
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        // A pause must not outlive the sw session it covers.
        if let Some(id) = &paused {
            if last_pause_check.elapsed() > Duration::from_secs(1) {
                last_pause_check = Instant::now();
                if !live_owned_by(id, &spec.aaa_user) {
                    // Give the sw client a moment to print its final bytes + sw-end.
                    std::thread::sleep(Duration::from_millis(300));
                    if paused.is_some() && !live_owned_by(id, &spec.aaa_user) {
                        w.record_json("l", json!({"sw": id, "phase": "end"}))?;
                        w.note("pause ended because the sw session is gone")?;
                        paused = None;
                    }
                }
            }
        }
        next_tick = w.tick()?;
    }
    if paused.is_none() {
        w.output(&osc.finish())?;
    }
    if reason == "client_disconnect" && spec.sshd_pid > 0 && crate::util::process_alive(spec.sshd_pid) {
        w.note("recorder stream ended before the sshd session")?;
        audit("shell.recorder_lost", "core", "alert", json!({"id": spec.id, "sshd_pid": spec.sshd_pid}));
    }
    w.end(reason, exit_code, Some(signer))?;
    audit("shell.end", "core", reason, json!({"id": spec.id, "exit_code": exit_code, "bytes_out": w.bytes_out}));
    Ok(())
}
