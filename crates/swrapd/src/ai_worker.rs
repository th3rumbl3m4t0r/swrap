//! swai session worker (spec 24, terminal edition).
//!
//! Starts as root only to (1) bind the two sockets the sandbox may reach and (2) start opencode
//! in bubblewrap as the unprivileged `swai` user with no network, no shell and no view of the
//! host's files. It then drops to `swrap` for everything else:
//! * the TUI relay and its recording (o, i, r — like `sw`);
//! * the inference proxy on `infer.sock`: adds the API key (fetched from swrapd per request, so
//!   sealing the vault stops it), applies the chosen effort, and records m/q/a (messages are
//!   stored once per session and referenced by hash, spec 24.8);
//! * the MCP server on `mcp.sock`: tool calls run in swrapd under AI grants; the worker records
//!   `t` and the full output as `o` records carrying `call`.

use crate::worker::{self, FrameBuf};
use anyhow::{anyhow, bail, Context, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::pty::{openpty, Winsize};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use swrap_core::api::{AiSpec, Req, Resp, WorkerSpec};
use swrap_core::frame::{kind, read_frame, write_frame, Frame};
use swrap_core::time::{fmt_duration_ms, fmt_utc};
use swrec::format::B64;
use swrec::{RecSigner, Writer, WriterOpts};
use base64::Engine;

/// Loopback port of the in-sandbox bridge to `infer.sock` (the sandbox has its own netns).
const INNER_PORT: u16 = 4141;

#[derive(Default, serde::Serialize)]
struct Stats {
    requests: u64,
    errors: u64,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    tool_calls: u64,
    tool_errors: u64,
}

struct Shared {
    spec: WorkerSpec,
    /// Session start (UTC), for `swai ls`.
    started: String,
    ai: AiSpec,
    w: Mutex<Writer>,
    seen: Mutex<HashSet<String>>,
    req_no: AtomicU64,
    tool_no: AtomicU64,
    effort_off: AtomicBool,
    models: Mutex<HashSet<String>>,
    stats: Mutex<Stats>,
    agent: ureq::Agent,
}

impl Shared {
    fn record(&self, k: &str, v: Value) {
        if let Value::Object(m) = v {
            let _ = self.w.lock().unwrap().record(k, m);
        }
    }
    fn note(&self, msg: &str) {
        let _ = self.w.lock().unwrap().note(msg);
    }
}

pub fn run(spec: WorkerSpec, client: UnixStream) -> Result<()> {
    let ai = spec.ai.clone().context("swai worker without ai spec")?;
    if unsafe { libc::getuid() } != 0 {
        bail!("swai workers start as root");
    }
    // ------------------------------------------------ privileged part (trusted input only)
    let run_dir = PathBuf::from(&ai.run_dir);
    let sock_dir = run_dir.join("sock");
    let infer_l = bind_sock(&sock_dir.join("infer.sock"), &ai)?;
    let mcp_l = bind_sock(&sock_dir.join("mcp.sock"), &ai)?;
    // Lifeline: the in-sandbox helper holds a connection and kills opencode when it drops.
    // (PDEATHSIG can't do this: the kernel checks the dying parent's credentials, and once this
    // worker is `swrap` it may not signal the `swai` sandbox.)
    let life_l = bind_sock(&sock_dir.join("life.sock"), &ai)?;
    // Claude Code's sign-in/account hosts only (CONNECT, TLS end to end, logged).
    let tunnel_l = bind_sock(&sock_dir.join("tunnel.sock"), &ai)?;
    // Control socket for `swai attach` (swrapd hands over the new client): swrap only, and
    // outside the directory the sandbox sees.
    let ctl_dir = run_dir.join("ctl");
    let _ = std::fs::create_dir(&ctl_dir);
    std::os::unix::fs::chown(&ctl_dir, Some(ai.swrap_uid), Some(ai.swrap_gid))?;
    std::fs::set_permissions(&ctl_dir, std::fs::Permissions::from_mode(0o700))?;
    let _ = std::fs::remove_file(ctl_dir.join("ctl.sock"));
    let ctl_l = UnixListener::bind(ctl_dir.join("ctl.sock"))?;
    std::os::unix::fs::chown(ctl_dir.join("ctl.sock"), Some(ai.swrap_uid), Some(ai.swrap_gid))?;
    std::fs::set_permissions(ctl_dir.join("ctl.sock"), std::fs::Permissions::from_mode(0o600))?;
    for (name, body) in [
        ("passwd", format!("root:x:0:0:root:/root:/sbin/nologin\nswai:x:{}:{}:swai:/home/swai:/sbin/nologin\n", ai.swai_uid, ai.swai_gid)),
        ("group", format!("root:x:0:\nswai:x:{}:\n", ai.swai_gid)),
        ("hosts", "127.0.0.1 localhost swai\n::1 localhost\n".to_string()),
    ] {
        swrap_core::atomic::write(&run_dir.join(name), body.as_bytes(), 0o644, swrap_core::atomic::Owner::new(0, 0))?;
    }
    let ws = Winsize { ws_row: spec.rows.max(1), ws_col: spec.cols.max(1), ws_xpixel: 0, ws_ypixel: 0 };
    let pty = openpty(Some(&ws), None)?;
    // openpty() fds are inheritable: a master leaking into the sandbox would keep the terminal
    // from ever hanging up.
    cloexec(&pty.master);
    cloexec(&pty.slave);
    let master: OwnedFd = pty.master;
    let lifelines: Arc<Mutex<Vec<UnixStream>>> = Arc::new(Mutex::new(vec![]));
    {
        let keep = lifelines.clone();
        std::thread::spawn(move || {
            for c in life_l.incoming().flatten() {
                keep.lock().unwrap().push(c);
            }
        });
    }
    let pid = spawn_sandbox(&spec, &ai, &pty.slave)?;
    drop(pty.slave);
    drop_privileges(&ai)?;

    // ------------------------------------------------ unprivileged from here on
    let signer = RecSigner::load(Path::new(&spec.recsign_key), &spec.signer)?;
    let mut w = Writer::create(Path::new(&spec.rec_path), &spec.id, spec.header.clone(), WriterOpts::from_cfg(&spec.rec_cfg))?;
    w.enable_background_sync()?;
    let harness = spec.header.get("harness").and_then(Value::as_str).unwrap_or("").to_string();
    let ctx = if ai.context > 0 { format!(" · context {}", ai.context) } else { String::new() };
    let _ = w.record_json("n", json!({"msg": format!("swai: {} · {} {} · effort {}{ctx} · {harness}", if ai.mode == "aaa" { "aaa".to_string() } else { format!("{}@{}", ai.ruser, ai.label) }, ai.backend, ai.model, if ai.effort.is_empty() { "default" } else { &ai.effort }), "system_prompt": ai.system_prompt}));
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(ai.timeout_secs.max(60))))
        .http_status_as_error(false)
        .proxy(None)
        .user_agent(concat!("swrap-swai/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let sh = Arc::new(Shared {
        spec: spec.clone(),
        started: fmt_utc(swrap_core::time::now()),
        ai: ai.clone(),
        w: Mutex::new(w),
        seen: Mutex::new(HashSet::new()),
        req_no: AtomicU64::new(0),
        tool_no: AtomicU64::new(0),
        effort_off: AtomicBool::new(false),
        models: Mutex::new(HashSet::new()),
        stats: Mutex::new(Stats::default()),
        agent,
    });
    for (l, which) in [(infer_l, 0), (mcp_l, 1), (tunnel_l, 2)] {
        let sh = sh.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let sh = sh.clone();
                std::thread::spawn(move || match which {
                    0 => serve_infer(sh, c),
                    1 => serve_mcp(sh, c),
                    _ => serve_tunnel(sh, c),
                });
            }
        });
    }
    let started = Instant::now();
    let res = relay(&sh, client, master, pid, ctl_l);
    // Session over (for whatever reason): cut the lifeline so the sandbox goes away with us.
    lifelines.lock().unwrap().clear();
    let (reason, code) = match &res {
        Ok((r, c)) => (r.clone(), *c),
        Err(e) => {
            sh.note(&format!("worker error: {e:#}"));
            ("error".to_string(), 255)
        }
    };
    let stats = serde_json::to_value(&*sh.stats.lock().unwrap()).unwrap_or_default();
    sh.record("n", json!({"msg": "swai session totals", "stats": stats}));
    {
        let mut w = sh.w.lock().unwrap();
        w.end(&reason, Some(code), Some(&signer))?;
    }
    let _ = std::fs::remove_file(&spec.live_marker);
    let _ = daemon_call(&ai, &spec.id, "end", json!({"reason": reason, "exit_code": code, "stats": stats, "duration": fmt_duration_ms(started.elapsed())}));
    res.map(|_| ())
}

pub fn cloexec(fd: &impl AsRawFd) {
    unsafe {
        let fl = libc::fcntl(fd.as_raw_fd(), libc::F_GETFD);
        libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, fl | libc::FD_CLOEXEC);
    }
}

fn bind_sock(p: &Path, ai: &AiSpec) -> Result<UnixListener> {
    let _ = std::fs::remove_file(p);
    let l = UnixListener::bind(p).with_context(|| format!("bind {}", p.display()))?;
    std::os::unix::fs::chown(p, Some(ai.swrap_uid), Some(ai.swai_gid))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o660))?;
    Ok(l)
}

fn drop_privileges(ai: &AiSpec) -> Result<()> {
    let groups = [ai.swrap_gid, ai.admin_gid];
    unsafe {
        if libc::setgroups(2, groups.as_ptr()) != 0 || libc::setgid(ai.swrap_gid) != 0 || libc::setuid(ai.swrap_uid) != 0 {
            bail!("dropping privileges failed: {}", std::io::Error::last_os_error());
        }
        if libc::geteuid() == 0 || libc::getuid() == 0 || libc::setuid(0) == 0 {
            bail!("still privileged after setuid");
        }
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
    std::env::set_current_dir("/")?;
    Ok(())
}

/// Loopback port of the in-sandbox bridge to the CONNECT tunnel (Claude Code's sign-in hosts).
const TUNNEL_PORT: u16 = 4142;

/// The sandbox: read-only libc/harness/helper, a persistent home, no network (own netns with
/// loopback only), no shell, new pid/ipc/uts namespaces, dies with this worker.
fn spawn_sandbox(spec: &WorkerSpec, ai: &AiSpec, slave: &OwnedFd) -> Result<Pid> {
    let run_dir = Path::new(&ai.run_dir);
    let claude = ai.harness == "claude";
    let mut a: Vec<String> = vec![];
    let mut push = |xs: &[&str]| a.extend(xs.iter().map(|x| x.to_string()));
    push(&["--unshare-all", "--die-with-parent", "--hostname", "swai"]);
    push(&["--ro-bind", "/usr/lib64", "/usr/lib64", "--symlink", "usr/lib64", "/lib64"]);
    if Path::new("/usr/share/zoneinfo").is_dir() {
        push(&["--ro-bind", "/usr/share/zoneinfo", "/usr/share/zoneinfo"]);
    }
    push(&["--ro-bind", &ai.helper, "/opt/swai/swrap"]);
    for f in ["passwd", "group", "hosts"] {
        push(&["--ro-bind", &run_dir.join(f).to_string_lossy(), &format!("/etc/{f}")]);
    }
    push(&["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]);
    push(&["--bind", &ai.home, "/home/swai", "--bind", &run_dir.join("sock").to_string_lossy(), "/swai"]);
    let mut env: Vec<(&str, String)> = vec![
        ("HOME", "/home/swai".into()),
        ("USER", "swai".into()),
        ("LOGNAME", "swai".into()),
        ("PATH", "/opt/swai".into()),
        ("TERM", spec.term.clone()),
        ("COLORTERM", "truecolor".into()),
        ("LANG", "C.UTF-8".into()),
        ("TZ", ai.tz.clone()),
        ("SWAI_MCP_SOCK", "/swai/mcp.sock".into()),
        ("SWAI_LIFE_SOCK", "/swai/life.sock".into()),
    ];
    let mut tail: Vec<String> = vec!["--".into(), "/opt/swai/swrap".into(), "swai-sandbox".into()];
    if claude {
        // Claude Code, signed in with the user's plan. Model traffic goes to the recording proxy
        // (ANTHROPIC_BASE_URL); only its sign-in/account hosts get a (logged) tunnel.
        let cc_dir = Path::new(&ai.claude).parent().context("claude path")?.to_string_lossy().to_string();
        push(&["--ro-bind", &cc_dir, "/opt/swai/claude", "--dir", &ai.workdir, "--chdir", &ai.workdir]);
        env.extend([
            ("ANTHROPIC_BASE_URL", format!("http://127.0.0.1:{INNER_PORT}")),
            ("HTTPS_PROXY", format!("http://127.0.0.1:{TUNNEL_PORT}")),
            ("HTTP_PROXY", format!("http://127.0.0.1:{TUNNEL_PORT}")),
            ("NO_PROXY", "127.0.0.1,localhost".into()),
            ("SWAI_BRIDGES", format!("{INNER_PORT}=/swai/infer.sock,{TUNNEL_PORT}=/swai/tunnel.sock")),
            ("DISABLE_AUTOUPDATER", "1".into()),
            ("DISABLE_INSTALLATION_CHECKS", "1".into()),
            ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1".into()),
            ("DISABLE_TELEMETRY", "1".into()),
            ("DISABLE_ERROR_REPORTING", "1".into()),
            ("CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY", "1".into()),
            ("CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL", "1".into()),
            ("CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1".into()),
            ("MCP_TIMEOUT", "30000".into()),
            ("API_TIMEOUT_MS", (ai.timeout_secs.max(60) * 1000).to_string()),
            ("MCP_TOOL_TIMEOUT", "3700000".into()),
        ]);
        let tools: Vec<String> = ai.tools.as_array().into_iter().flatten().filter_map(|t| t["name"].as_str().map(String::from)).collect();
        let allow_all = ai.approval == "allow";
        let allowed: Vec<String> = tools.iter().filter(|t| allow_all || !matches!(t.as_str(), "exec" | "write_file" | "edit_file")).map(|t| format!("mcp__swrap__{t}")).collect();
        let mcp = json!({"mcpServers": {"swrap": {"type": "stdio", "command": "/opt/swai/swrap", "args": ["swai-mcp"]}}}).to_string();
        let what = if ai.mode == "aaa" { "aaa".to_string() } else { format!("{}@{}", ai.ruser, ai.label) };
        let what = if ai.loose { format!("{what} · loose") } else { what };
        tail.extend([
            "/opt/swai/claude/claude".into(),
            // No built-in tools (no shell, files or web): only swrap's.
            "--tools".into(), "".into(),
            "--strict-mcp-config".into(), "--mcp-config".into(), mcp,
            "--append-system-prompt".into(), ai.system_prompt.clone(),
            "--model".into(), ai.model.clone(),
            "--name".into(), format!("swai · {what}"),
        ]);
        if !allowed.is_empty() {
            tail.push("--allowedTools".into());
            tail.push(allowed.join(","));
        }
        if !ai.effort.is_empty() {
            tail.extend(["--effort".into(), ai.effort.clone()]);
        }
        if ai.loose && ai.mode == "host" {
            // Chosen per session for one host: no prompts and no auto-mode classifier. The
            // sandbox still has no built-in tools; swrap's act on that host under its AI grant.
            tail.push("--dangerously-skip-permissions".into());
        }
        match ai.resume.as_str() {
            "" => {}
            "last" => tail.push("--continue".into()),
            id => tail.extend(["--resume".into(), id.to_string()]),
        }
    } else {
        let oc_dir = Path::new(&ai.opencode).parent().context("opencode path")?.to_string_lossy().to_string();
        let oc_name = Path::new(&ai.opencode).file_name().context("opencode path")?.to_string_lossy().to_string();
        // Working directory "/": opencode tells the model its cwd, and a sandbox path (which does
        // not exist on the targets) invites the model to pass it as `cwd` to exec.
        push(&["--ro-bind", &oc_dir, "/opt/swai/opencode", "--chdir", "/"]);
        env.extend([
            ("OPENCODE_CONFIG_CONTENT", opencode_config(spec, ai).to_string()),
            ("OPENCODE_DISABLE_AUTOUPDATE", "1".into()),
            ("OPENCODE_DISABLE_MODELS_FETCH", "1".into()),
            ("OPENCODE_DISABLE_SHARE", "1".into()),
            ("OPENCODE_DISABLE_CLAUDE_CODE", "1".into()),
            ("OPENCODE_DISABLE_DEFAULT_PLUGINS", "1".into()),
            ("OPENCODE_DISABLE_LSP_DOWNLOAD", "1".into()),
            ("OPENCODE_DISABLE_EXTERNAL_SKILLS", "1".into()),
            ("OPENCODE_DISABLE_EMBEDDED_WEB_UI", "1".into()),
            // opencode caps max_tokens at 32000 by default; agentic work wants 64K (128K at xhigh/max).
            ("OPENCODE_EXPERIMENTAL_OUTPUT_TOKEN_MAX", output_limit(ai).to_string()),
            ("SWAI_INFER_SOCK", "/swai/infer.sock".into()),
            ("SWAI_PORT", INNER_PORT.to_string()),
        ]);
        tail.push(format!("/opt/swai/opencode/{oc_name}"));
        match ai.resume.as_str() {
            "" => {}
            "last" => tail.push("--continue".into()),
            id => tail.extend(["--session".into(), id.to_string()]),
        }
    }
    for (k, v) in &env {
        a.push("--setenv".into());
        a.push(k.to_string());
        a.push(v.clone());
    }
    a.extend(tail);

    let sfd = slave.as_raw_fd();
    let mut cmd = Command::new("/usr/bin/bwrap");
    cmd.args(&a)
        .env_clear()
        .stdin(unsafe { Stdio::from_raw_fd(libc::dup(sfd)) })
        .stdout(unsafe { Stdio::from_raw_fd(libc::dup(sfd)) })
        .stderr(unsafe { Stdio::from_raw_fd(libc::dup(sfd)) });
    let (uid, gid) = (ai.swai_uid, ai.swai_gid);
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let groups = [gid];
            if libc::setgroups(1, groups.as_ptr()) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // After setuid (a credential change clears it): die with this worker.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            libc::signal(libc::SIGHUP, libc::SIG_DFL);
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
            Ok(())
        });
    }
    let child = cmd.spawn().context("start the sandbox (bwrap)")?;
    drop(cmd);
    let pid = Pid::from_raw(child.id() as i32);
    std::mem::forget(child);
    Ok(pid)
}

/// opencode configuration: one provider (this session's proxy), one agent with swrap's prompt,
/// only the swrap MCP tools (host mode also drops the todo tool to keep the context small).
fn output_limit(ai: &AiSpec) -> u64 {
    let big = matches!(ai.effort.as_str(), "xhigh" | "max");
    if ai.api == "anthropic" { ai.max_output.min(if big { 128_000 } else { 64_000 }) } else { ai.max_output }
}

fn opencode_config(spec: &WorkerSpec, ai: &AiSpec) -> Value {
    let anthropic = ai.api == "anthropic";
    let output = output_limit(ai);
    let aaa = ai.mode == "aaa";
    let approval = if ai.approval.is_empty() { "ask" } else { ai.approval.as_str() };
    let mut perm = Map::new();
    for t in ai.tools.as_array().into_iter().flatten().filter_map(|t| t["name"].as_str()) {
        let v = if matches!(t, "exec" | "write_file" | "edit_file") { approval } else { "allow" };
        perm.insert(format!("swrap_{t}"), json!(v));
    }
    let mut tools = Map::new();
    for t in ["bash", "edit", "write", "read", "grep", "glob", "list", "patch", "webfetch", "websearch", "codesearch", "task", "skill", "lsp", "question", "multiedit", "apply_patch"] {
        tools.insert(t.into(), json!(false));
    }
    tools.insert("todowrite".into(), json!(aaa));
    tools.insert("todoread".into(), json!(aaa));
    let what = if aaa { "the AAA (all AI-enabled hosts and swrap records)".to_string() } else { format!("{}@{}", ai.ruser, ai.label) };
    json!({
        "$schema": "https://opencode.ai/config.json",
        "autoupdate": false,
        "share": "disabled",
        "snapshot": false,
        "enabled_providers": ["swrap"],
        "model": format!("swrap/{}", ai.model),
        "small_model": format!("swrap/{}", ai.model),
        "default_agent": "swai",
        "username": spec.aaa_user,
        "lsp": false,
        "formatter": false,
        "instructions": [],
        "provider": {"swrap": {
            "npm": if anthropic { "@ai-sdk/anthropic" } else { "@ai-sdk/openai-compatible" },
            "name": format!("swrap · {}", ai.backend),
            // opencode aborts a request after PT5M without a chunk by default; local models at high
            // effort can think (or build a large tool call) silently for longer. swrap's proxy
            // bounds the silence instead (the backend's timeout), so opencode waits as long.
            "options": {"baseURL": format!("http://127.0.0.1:{INNER_PORT}/v1"), "apiKey": "swai-session", "timeout": false, "chunkTimeout": ai.timeout_secs.max(60) * 1000 + 30_000, "headerTimeout": ai.timeout_secs.max(60) * 1000 + 30_000},
            "models": {ai.model.clone(): {"name": ai.model, "limit": {"context": ai.context, "output": output}, "tool_call": true}},
        }},
        "agent": {
            "swai": {"mode": "primary", "description": format!("swrap: {what}"), "prompt": ai.system_prompt, "permission": perm},
            "build": {"disable": true},
            "plan": {"disable": true},
        },
        "tools": tools,
        "permission": Value::Object(perm.clone()),
        "mcp": {"swrap": {"type": "local", "command": ["/opt/swai/swrap", "swai-mcp"], "enabled": true, "timeout": 3_700_000}},
    })
}

// ---------------------------------------------------------------- swrapd calls

fn daemon_call(ai: &AiSpec, id: &str, op: &str, args: Value) -> Result<(Resp, Vec<u8>, Vec<u8>)> {
    let mut s = UnixStream::connect(swrap_core::Paths::from_env().api_sock()).context("swrapd unreachable")?;
    let req = Req::AiWorker { session: id.into(), token: ai.token.clone(), call: op.into(), args };
    write_frame(&mut s, &Frame::json(kind::REQ, &req))?;
    let (mut out, mut err) = (vec![], vec![]);
    loop {
        let Some(f) = read_frame(&mut s)? else { bail!("swrapd closed the connection") };
        match f.kind {
            kind::STDOUT => out.extend_from_slice(&f.payload),
            kind::STDERR => err.extend_from_slice(&f.payload),
            kind::RESP => return Ok((f.parse()?, out, err)),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------- TUI relay

/// Terminal modes opencode switched on, so a client attaching later starts from the same
/// terminal state (alternate screen, mouse, paste, focus, kitty keyboard) before the redraw.
#[derive(Default)]
struct Modes {
    dec: std::collections::BTreeMap<u32, bool>,
    kitty: Vec<u32>,
    carry: Vec<u8>,
}

impl Modes {
    fn feed(&mut self, data: &[u8]) {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(data);
        let mut i = 0;
        while i < buf.len() {
            if buf[i] != 0x1b {
                i += 1;
                continue;
            }
            if i + 1 >= buf.len() {
                self.carry = buf[i..].to_vec();
                return;
            }
            if buf[i + 1] != b'[' {
                i += 1;
                continue;
            }
            let mut j = i + 2;
            while j < buf.len() && (0x20..=0x3f).contains(&buf[j]) {
                j += 1;
            }
            if j >= buf.len() {
                if buf.len() - i < 64 {
                    self.carry = buf[i..].to_vec();
                }
                return;
            }
            let p = String::from_utf8_lossy(&buf[i + 2..j]).to_string();
            self.csi(&p, buf[j]);
            i = j + 1;
        }
    }

    fn csi(&mut self, p: &str, fin: u8) {
        let rest = p.get(1..).unwrap_or("");
        match (p.chars().next(), fin) {
            (Some('?'), b'h' | b'l') => {
                for n in rest.split(';').filter_map(|x| x.parse::<u32>().ok()) {
                    self.dec.insert(n, fin == b'h');
                }
            }
            (Some('>'), b'u') => {
                self.kitty.push(rest.parse().unwrap_or(0));
                if self.kitty.len() > 16 {
                    self.kitty.remove(0);
                }
            }
            (Some('<'), b'u') => {
                for _ in 0..rest.parse::<usize>().unwrap_or(1).max(1) {
                    self.kitty.pop();
                }
            }
            (Some('='), b'u') => {
                let f = rest.split(';').next().and_then(|x| x.parse().ok()).unwrap_or(0);
                match self.kitty.last_mut() {
                    Some(top) => *top = f,
                    None => self.kitty.push(f),
                }
            }
            _ => {}
        }
    }

    fn replay(&self) -> Vec<u8> {
        let alt = [1049u32, 1047, 47];
        let mut s = String::new();
        if let Some(a) = alt.iter().find(|a| self.dec.get(a) == Some(&true)) {
            s += &format!("\x1b[?{a}h");
        }
        for (n, on) in &self.dec {
            if *on && !alt.contains(n) {
                s += &format!("\x1b[?{n}h");
            }
        }
        if self.dec.get(&25) == Some(&false) {
            s += "\x1b[?25l";
        }
        for f in &self.kitty {
            s += &format!("\x1b[>{f}u");
        }
        s.into_bytes()
    }
}

/// Live marker: what `swai ls` shows and what attach checks (owner, kind, pid).
fn write_marker(sh: &Shared, attached: bool, client_addr: &str, since: jiff::Timestamp) {
    let spec = &sh.spec;
    let ai = &sh.ai;
    let v = json!({
        "id": spec.id, "user": spec.aaa_user, "kind": "ai", "pid": std::process::id(), "rec": spec.rec_path,
        "target": if ai.mode == "aaa" { "aaa".to_string() } else { format!("{}@{}", ai.ruser, ai.label) },
        "backend": ai.backend, "model": ai.model, "effort": ai.effort,
        "started": sh.started,
        "attached": attached, "client_addr": client_addr, "since": fmt_utc(since),
    });
    let p = Path::new(&spec.live_marker);
    let tmp = p.with_extension("tmp");
    if std::fs::write(&tmp, v.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, p);
    }
}

/// Take a client handed over by swrapd on the control socket (SCM_RIGHTS + JSON header).
fn take_client(conn: &UnixStream) -> Result<(UnixStream, Value)> {
    use nix::sys::socket::{getsockopt, recvmsg, sockopt::PeerCredentials, ControlMessageOwned, MsgFlags};
    let cred = getsockopt(conn, PeerCredentials)?;
    if cred.uid() != 0 {
        bail!("attach from uid {} refused", cred.uid());
    }
    let mut buf = vec![0u8; 16 << 10];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let mut space = nix::cmsg_space!([std::os::fd::RawFd; 1]);
    let msg = recvmsg::<()>(conn.as_raw_fd(), &mut iov, Some(&mut space), MsgFlags::MSG_CMSG_CLOEXEC)?;
    let mut fd = None;
    for c in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = c {
            fd = fds.first().copied();
        }
    }
    let n = msg.bytes;
    let fd = fd.context("no client descriptor")?;
    let hdr: Value = serde_json::from_slice(&buf[..n]).unwrap_or(Value::Null);
    Ok((unsafe { UnixStream::from_raw_fd(fd) }, hdr))
}

fn greet(sh: &Shared, client: &mut UnixStream, attached: bool) -> bool {
    let spec = &sh.spec;
    let text = if attached { format!("swai: attached to {}", spec.banner.trim_start_matches("swai: recording ")) } else { spec.banner.clone() };
    let mut resp = Resp::ok(json!({"id": spec.id, "banner": text, "attached": attached}));
    resp.text = text;
    worker::send(client, &Frame::json(kind::RESP, &resp))
}

/// Like tmux: the session lives on when the client goes away (detached) and takes a new client
/// through swrapd (`swai attach`). It ends when opencode exits, on `swai kill`, on SIGTERM, or
/// after `detached_timeout` without a client.
fn relay(sh: &Arc<Shared>, client: UnixStream, master: OwnedFd, pid: Pid, ctl: UnixListener) -> Result<(String, i32)> {
    let spec = &sh.spec;
    let mut client = Some(client);
    greet(sh, client.as_mut().unwrap(), false);
    let mut client_addr = spec.header.get("client_addr").and_then(Value::as_str).unwrap_or("").to_string();
    write_marker(sh, true, &client_addr, swrap_core::time::now());
    let mut master_f = File::from(master);
    let mut fb = FrameBuf { buf: vec![] };
    let mut buf = vec![0u8; 65536];
    let mut reason = "exit".to_string();
    let mut exit_status: Option<i32> = None;
    let mut modes = Modes::default();
    let mut size = (spec.cols.max(1), spec.rows.max(1));
    // What the terminal shows right now (like tmux), repainted for a client that attaches.
    let mut vt = vt100::Parser::new(size.1, size.0, 0);
    let mut detached_at: Option<Instant> = None;
    let detached_max = Duration::from_secs(sh.ai.detached_secs.max(60));
    let mut next_tick = Duration::from_millis(5);
    let detach = |client: &mut Option<UnixStream>, why: &str, detached_at: &mut Option<Instant>, fb: &mut FrameBuf| {
        if client.take().is_some() {
            fb.buf.clear();
            *detached_at = Some(Instant::now());
            sh.record("n", json!({"msg": format!("detached ({why}); the session keeps running"), "detached": true}));
            write_marker(sh, false, "", swrap_core::time::now());
            worker::audit("ai.detach", &sh.ai.label, why, json!({"id": sh.spec.id}));
        }
    };
    loop {
        if worker::terminated() {
            reason = "killed".into();
            break;
        }
        if detached_at.map(|t| t.elapsed() > detached_max).unwrap_or(false) {
            reason = "detached_timeout".into();
            break;
        }
        let timeout = PollTimeout::try_from(next_tick.min(Duration::from_millis(200)).as_millis() as i32).unwrap_or(PollTimeout::NONE);
        let (mr, cr, lr) = {
            let mut fds = vec![PollFd::new(master_f.as_fd(), PollFlags::POLLIN), PollFd::new(ctl.as_fd(), PollFlags::POLLIN)];
            if let Some(c) = &client {
                fds.push(PollFd::new(c.as_fd(), PollFlags::POLLIN));
            }
            match poll(&mut fds, timeout) {
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
            }
            let ev = |i: usize| fds.get(i).and_then(|f| f.revents()).unwrap_or(PollFlags::empty());
            (ev(0), ev(2), ev(1))
        };
        if mr.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            match master_f.read(&mut buf) {
                Ok(0) | Err(_) => {
                    if let Ok(st) = waitpid(pid, None) {
                        exit_status = Some(status_code(st));
                    }
                    break;
                }
                Ok(n) => {
                    modes.feed(&buf[..n]);
                    vt.process(&buf[..n]);
                    let lost = match client.as_mut() {
                        Some(c) => !worker::send(c, &Frame::new(kind::DATA, buf[..n].to_vec())),
                        None => false,
                    };
                    if lost {
                        detach(&mut client, "client gone", &mut detached_at, &mut fb);
                    }
                    sh.w.lock().unwrap().output(&buf[..n])?;
                }
            }
        }
        if cr.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            let got = match client.as_mut() {
                Some(c) => fb.fill(c),
                None => Ok(0),
            };
            match got {
                Ok(0) | Err(_) => detach(&mut client, "client disconnected", &mut detached_at, &mut fb),
                Ok(_) => {
                    let mut hung_up = false;
                    while let Some(f) = fb.next()? {
                        match f.kind {
                            kind::DATA => {
                                master_f.write_all(&f.payload)?;
                                sh.w.lock().unwrap().input(&f.payload)?;
                            }
                            kind::RESIZE => {
                                if let Ok(v) = serde_json::from_slice::<Value>(&f.payload) {
                                    let c = v["cols"].as_u64().unwrap_or(80) as u16;
                                    let r = v["rows"].as_u64().unwrap_or(24) as u16;
                                    size = (c.max(1), r.max(1));
                                    worker::set_winsize(&master_f, size.0, size.1);
                                    vt.screen_mut().set_size(size.1, size.0);
                                    sh.w.lock().unwrap().record_json("r", json!({"cols": size.0, "rows": size.1}))?;
                                }
                            }
                            // The client's terminal hung up: detach (the session goes on).
                            kind::SIGNAL if matches!(f.payload.first().map(|&b| b as i32), Some(libc::SIGHUP) | Some(libc::SIGTERM)) => hung_up = true,
                            _ => {}
                        }
                    }
                    if hung_up {
                        detach(&mut client, "client hung up", &mut detached_at, &mut fb);
                    }
                }
            }
        }
        if lr.contains(PollFlags::POLLIN) {
            if let Ok((conn, _)) = ctl.accept() {
                match take_client(&conn) {
                    Ok((mut nc, hdr)) => {
                        let mut conn = conn;
                        let _ = conn.write_all(b"1");
                        if let Some(mut old) = client.take() {
                            let _ = worker::send(&mut old, &Frame::new(kind::STDERR, b"swai: attached from another terminal".to_vec()));
                            let _ = worker::send(&mut old, &Frame::exit(0, "detached"));
                        }
                        fb.buf.clear();
                        if greet(sh, &mut nc, true) {
                            client_addr = hdr["client_addr"].as_str().unwrap_or("").to_string();
                            // Same terminal modes and the exact current screen; a different
                            // size then makes the program repaint for the new terminal.
                            let mut replay = modes.replay();
                            replay.extend_from_slice(&vt.screen().contents_formatted());
                            replay.extend_from_slice(&vt.screen().input_mode_formatted());
                            worker::send(&mut nc, &Frame::new(kind::DATA, replay));
                            let c = hdr["cols"].as_u64().unwrap_or(size.0 as u64).max(1) as u16;
                            let r = hdr["rows"].as_u64().unwrap_or(size.1 as u64).max(1) as u16;
                            if (c, r) != size {
                                size = (c, r);
                                worker::set_winsize(&master_f, c, r);
                                vt.screen_mut().set_size(r, c);
                            }
                            sh.record("n", json!({"msg": format!("attached from {}", if client_addr.is_empty() { "?" } else { &client_addr }), "attached": true, "origin": hdr["origin"]}));
                            sh.w.lock().unwrap().record_json("r", json!({"cols": c, "rows": r}))?;
                            write_marker(sh, true, &client_addr, swrap_core::time::now());
                            detached_at = None;
                            client = Some(nc);
                        }
                    }
                    Err(e) => sh.note(&format!("attach refused: {e:#}")),
                }
            }
        }
        next_tick = sh.w.lock().unwrap().tick()?;
    }
    if exit_status.is_none() {
        // End the sandbox: the lifeline (cut by our caller) and the terminal hangup below.
        drop(master_f);
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(5) {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => std::thread::sleep(Duration::from_millis(50)),
                Ok(st) => {
                    exit_status = Some(status_code(st));
                    break;
                }
                Err(_) => break,
            }
        }
    }
    let code = exit_status.unwrap_or(255);
    if let Some(mut c) = client {
        worker::send(&mut c, &Frame::exit(code, &reason));
    }
    Ok((reason, code))
}

fn status_code(st: WaitStatus) -> i32 {
    match st {
        WaitStatus::Exited(_, c) => c,
        WaitStatus::Signaled(_, s, _) => 128 + s as i32,
        _ => 255,
    }
}

// ---------------------------------------------------------------- message store (dedup)

fn canonical(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys.iter().map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(&m[*k]))).collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(canonical).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

/// opencode moves `cache_control` markers along the conversation; they are not content.
fn strip_cache(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.remove("cache_control");
            m.values_mut().for_each(strip_cache);
        }
        Value::Array(a) => a.iter_mut().for_each(strip_cache),
        _ => {}
    }
}

impl Shared {
    /// Store a message body once per session; returns its hash. `aux`: first seen in one of
    /// opencode's helper requests (title, compaction), not the conversation itself.
    fn put_msg(&self, role: &str, content: &Value, aux: bool) -> String {
        let mut c = content.clone();
        strip_cache(&mut c);
        let body = json!({"role": role, "content": c});
        let h = blake3::hash(canonical(&body).as_bytes()).to_hex()[..32].to_string();
        if self.seen.lock().unwrap().insert(h.clone()) {
            let mut m = json!({"h": h, "role": role, "content": body["content"]});
            if aux {
                m["aux"] = json!(true);
            }
            self.record("m", m);
        }
        h
    }
}

// ---------------------------------------------------------------- inference proxy

#[derive(Clone, Copy, PartialEq)]
enum Api {
    Anthropic,
    Openai,
}

struct HttpReq {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpReq {
    fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
}

const MAX_BODY: usize = 64 << 20;

fn read_request(c: &mut UnixStream) -> Result<Option<HttpReq>> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 65536];
    let (head_len, method, path, headers) = loop {
        let n = c.read(&mut tmp)?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            bail!("connection closed mid-request");
        }
        buf.extend_from_slice(&tmp[..n]);
        let mut hs = [httparse::EMPTY_HEADER; 96];
        let mut r = httparse::Request::new(&mut hs);
        match r.parse(&buf)? {
            httparse::Status::Complete(len) => {
                let headers = r.headers.iter().map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).to_string())).collect::<Vec<_>>();
                break (len, r.method.unwrap_or("").to_string(), r.path.unwrap_or("").to_string(), headers);
            }
            httparse::Status::Partial if buf.len() > 256 << 10 => bail!("request head too large"),
            httparse::Status::Partial => {}
        }
    };
    let mut req = HttpReq { method, path, headers, body: buf[head_len..].to_vec() };
    let chunked = req.header("transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false);
    if chunked {
        let mut raw = std::mem::take(&mut req.body);
        let mut out = vec![];
        let mut pos = 0;
        loop {
            // Need a full size line.
            let Some(nl) = raw[pos..].windows(2).position(|w| w == b"\r\n") else {
                let n = c.read(&mut tmp)?;
                if n == 0 {
                    bail!("truncated chunked body");
                }
                raw.extend_from_slice(&tmp[..n]);
                continue;
            };
            let line = String::from_utf8_lossy(&raw[pos..pos + nl]).to_string();
            let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).context("bad chunk size")?;
            let need = pos + nl + 2 + size + 2;
            while raw.len() < need {
                let n = c.read(&mut tmp)?;
                if n == 0 {
                    bail!("truncated chunked body");
                }
                raw.extend_from_slice(&tmp[..n]);
            }
            if size == 0 {
                break;
            }
            out.extend_from_slice(&raw[pos + nl + 2..pos + nl + 2 + size]);
            if out.len() > MAX_BODY {
                bail!("request body too large");
            }
            pos = need;
        }
        req.body = out;
    } else {
        let len: usize = req.header("content-length").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        if len > MAX_BODY {
            bail!("request body too large");
        }
        while req.body.len() < len {
            let n = c.read(&mut tmp)?;
            if n == 0 {
                bail!("truncated body");
            }
            req.body.extend_from_slice(&tmp[..n]);
        }
        req.body.truncate(len);
    }
    Ok(Some(req))
}

fn reason_phrase(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        529 => "Overloaded",
        _ => "Status",
    }
}

fn write_head(c: &mut UnixStream, code: u16, content_type: &str, extra: &[(String, String)]) -> std::io::Result<()> {
    let mut h = format!("HTTP/1.1 {code} {}\r\ncontent-type: {content_type}\r\ncache-control: no-cache\r\nconnection: close\r\n", reason_phrase(code));
    for (k, v) in extra {
        h += &format!("{k}: {v}\r\n");
    }
    h += "\r\n";
    c.write_all(h.as_bytes())
}

fn error_body(api: Api, msg: &str) -> Value {
    match api {
        Api::Anthropic => json!({"type": "error", "error": {"type": "api_error", "message": format!("swai: {msg}")}}),
        Api::Openai => json!({"error": {"message": format!("swai: {msg}"), "type": "swai_proxy_error"}}),
    }
}

fn respond_json(c: &mut UnixStream, code: u16, v: &Value) {
    let body = v.to_string();
    let _ = write_head(c, code, "application/json", &[("content-length".into(), body.len().to_string())]);
    let _ = c.write_all(body.as_bytes());
}

fn serve_infer(sh: Arc<Shared>, mut c: UnixStream) {
    let _ = c.set_read_timeout(Some(Duration::from_secs(120)));
    let api = if sh.ai.api == "openai" { Api::Openai } else { Api::Anthropic };
    let req = match read_request(&mut c) {
        Ok(Some(r)) => r,
        Ok(None) => return,
        Err(e) => {
            respond_json(&mut c, 400, &error_body(api, &format!("bad request: {e:#}")));
            return;
        }
    };
    if sh.ai.harness == "claude" {
        if let Err(e) = passthrough(&sh, &mut c, &req) {
            sh.note(&format!("inference proxy: {e:#}"));
            respond_json(&mut c, 502, &error_body(Api::Anthropic, &format!("{e:#}")));
        }
        return;
    }
    let path = req.path.split('?').next().unwrap_or("").to_string();
    let r = match (req.method.as_str(), path.as_str(), api) {
        ("POST", "/v1/messages", Api::Anthropic) | ("POST", "/v1/chat/completions", Api::Openai) => infer(&sh, &mut c, &req, api),
        ("GET", "/v1/models", _) => models(&sh, &mut c, api),
        _ => {
            respond_json(&mut c, 404, &error_body(api, &format!("{} {path} is not available through swai", req.method)));
            Ok(())
        }
    };
    if let Err(e) = r {
        sh.note(&format!("inference proxy: {e:#}"));
        respond_json(&mut c, 502, &error_body(api, &format!("{e:#}")));
    }
}

/// Claude Code with the user's plan: forward every request to Anthropic as is (its own sign-in
/// token included; nothing added or changed) and record the conversation (`/v1/messages`).
fn passthrough(sh: &Arc<Shared>, c: &mut UnixStream, req: &HttpReq) -> Result<()> {
    let path = req.path.split('?').next().unwrap_or("").to_string();
    let record = req.method == "POST" && path == "/v1/messages";
    let n = if record { sh.req_no.fetch_add(1, Ordering::SeqCst) + 1 } else { 0 };
    let body_json: Option<Value> = if record { serde_json::from_slice(&req.body).ok() } else { None };
    if let Some(b) = &body_json {
        let model = b["model"].as_str().unwrap_or("").to_string();
        if !model.is_empty() && sh.models.lock().unwrap().insert(model.clone()) {
            let _ = daemon_call(&sh.ai, &sh.spec.id, "usage", json!({"model": model}));
        }
        record_request(sh, n, Api::Anthropic, b, &None);
        sh.stats.lock().unwrap().requests += 1;
    }
    let url = format!("{}{}", sh.ai.base_url, req.path);
    let mut rb = ureq::http::Request::builder().method(req.method.as_str()).uri(&url);
    for (k, v) in &req.headers {
        let lk = k.to_ascii_lowercase();
        // Hop-by-hop, framing, and compression (we want to read what we record).
        if matches!(lk.as_str(), "host" | "connection" | "content-length" | "transfer-encoding" | "accept-encoding" | "keep-alive" | "proxy-connection" | "te" | "upgrade") {
            continue;
        }
        rb = rb.header(k.as_str(), v.as_str());
    }
    let t0 = Instant::now();
    let resp = sh.agent.run(rb.body(req.body.clone())?).map_err(|e| anyhow!("Anthropic unreachable: {e}"))?;
    let status = resp.status().as_u16();
    let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("application/json").to_string();
    let mut extra = vec![];
    for (k, v) in resp.headers() {
        let k = k.as_str().to_ascii_lowercase();
        if matches!(k.as_str(), "content-type" | "connection" | "transfer-encoding" | "content-length" | "keep-alive" | "content-encoding" | "cache-control") {
            continue;
        }
        if let Ok(v) = v.to_str() {
            extra.push((k, v.to_string()));
        }
    }
    write_head(c, status, &ct, &extra)?;
    let mut asm = Asm::new(Api::Anthropic, ct.contains("event-stream"));
    let mut reader = resp.into_body().into_reader();
    let mut buf = vec![0u8; 32 << 10];
    let mut cancelled = false;
    loop {
        let k = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => k,
            Err(e) => {
                asm.error = Some(json!(format!("upstream read: {e}")));
                break;
            }
        };
        if record {
            asm.feed(&buf[..k], t0);
        }
        if c.write_all(&buf[..k]).is_err() {
            cancelled = true;
            break;
        }
    }
    if let Some(body) = &body_json {
        let done = asm.finish();
        let h = done.message.as_ref().map(|m| sh.put_msg("assistant", m, !has_tools(body)));
        let mut a = json!({"n": n, "status": status, "h": h, "stop": done.stop, "usage": done.usage, "latency": fmt_duration_ms(t0.elapsed())});
        if let Some(t) = done.ttft {
            a["ttft"] = json!(fmt_duration_ms(t));
        }
        if let Some(m) = &done.model {
            a["model"] = json!(m);
        }
        if let Some(e) = &done.error {
            a["error"] = e.clone();
        }
        if cancelled {
            a["cancelled"] = json!(true);
        }
        sh.record("a", a);
        let mut st = sh.stats.lock().unwrap();
        if status >= 400 || done.error.is_some() {
            st.errors += 1;
        }
        let u = &done.usage;
        st.input_tokens += u["input_tokens"].as_u64().unwrap_or(0);
        st.output_tokens += u["output_tokens"].as_u64().unwrap_or(0);
        st.cache_read_tokens += u["cache_read_input_tokens"].as_u64().unwrap_or(0);
        st.cache_write_tokens += u["cache_creation_input_tokens"].as_u64().unwrap_or(0);
    }
    Ok(())
}

/// Hosts Claude Code signs in and manages the account with. Model traffic never needs these:
/// it goes through `ANTHROPIC_BASE_URL` (the recording proxy).
const TUNNEL_HOSTS: [&str; 4] = ["api.anthropic.com", "platform.claude.com", "claude.ai", "claude.com"];

fn serve_tunnel(sh: Arc<Shared>, mut c: UnixStream) {
    let _ = c.set_read_timeout(Some(Duration::from_secs(30)));
    let mut head = vec![];
    let mut b = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut b) {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&b[..n]),
        }
        if head.len() > 16 << 10 {
            return;
        }
    }
    let end = head.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let line = String::from_utf8_lossy(&head[..head.iter().position(|&x| x == b'\r').unwrap_or(0)]).to_string();
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let (host, port) = target.rsplit_once(':').unwrap_or((target, ""));
    if method != "CONNECT" || port != "443" || !TUNNEL_HOSTS.contains(&host) {
        let _ = c.write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        sh.record("n", json!({"msg": format!("tunnel refused: {method} {target}"), "tunnel": target, "allowed": false}));
        return;
    }
    let up = (|| -> Result<std::net::TcpStream> {
        use std::net::ToSocketAddrs;
        let mut last = anyhow!("no address for {host}");
        for addr in (host, 443u16).to_socket_addrs()? {
            match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
                Ok(t) => return Ok(t),
                Err(e) => last = anyhow!("{addr}: {e}"),
            }
        }
        Err(last)
    })();
    let mut up = match up {
        Ok(u) => u,
        Err(e) => {
            let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            sh.note(&format!("tunnel to {host}: {e:#}"));
            return;
        }
    };
    let _ = c.set_read_timeout(None);
    if c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
        return;
    }
    let t0 = Instant::now();
    if end < head.len() && up.write_all(&head[end..]).is_err() {
        return;
    }
    let (Ok(mut c2), Ok(mut up2)) = (c.try_clone(), up.try_clone()) else { return };
    let upload = std::thread::spawn(move || {
        let n = std::io::copy(&mut c2, &mut up2).unwrap_or(0);
        let _ = up2.shutdown(std::net::Shutdown::Write);
        n
    });
    let down = std::io::copy(&mut up, &mut c).unwrap_or(0);
    let _ = c.shutdown(std::net::Shutdown::Write);
    let upl = upload.join().unwrap_or(0) + (head.len() - end) as u64;
    sh.record("n", json!({"msg": format!("tunnel {host}:443 (TLS, not inspected)"), "tunnel": host, "allowed": true, "bytes_up": upl, "bytes_down": down, "duration": fmt_duration_ms(t0.elapsed())}));
}

fn fetch_key(sh: &Shared) -> Result<Option<zeroize::Zeroizing<String>>> {
    if !sh.ai.needs_key {
        return Ok(None);
    }
    let (r, _, _) = daemon_call(&sh.ai, &sh.spec.id, "key", json!({}))?;
    if !r.ok {
        bail!("{}", r.error.unwrap_or_else(|| "no API key".into()));
    }
    Ok(Some(zeroize::Zeroizing::new(r.data["key"].as_str().unwrap_or("").to_string())))
}

/// The client (opencode, via the sandbox bridge) hung up while we waited for the model.
#[derive(Debug)]
struct ClientGone;
impl std::fmt::Display for ClientGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the client abandoned the request")
    }
}
impl std::error::Error for ClientGone {}

/// Did the client close its side? (It never sends more after the request, so any EOF means
/// it gave up; with Connection: close that is how an abort looks.)
fn client_gone(c: &UnixStream) -> bool {
    let mut fds = [libc::pollfd { fd: c.as_raw_fd(), events: libc::POLLRDHUP, revents: 0 }];
    unsafe { libc::poll(fds.as_mut_ptr(), 1, 0) > 0 && fds[0].revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) != 0 }
}

/// Transfer-Encoding: chunked, decoded incrementally.
enum Chunked {
    Size(Vec<u8>),
    Data(u64),
    DataEnd,
    Done,
}

impl Chunked {
    fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        while !input.is_empty() {
            match self {
                Chunked::Size(line) => {
                    let Some(nl) = input.iter().position(|&b| b == b'\n') else {
                        line.extend_from_slice(input);
                        return Ok(());
                    };
                    line.extend_from_slice(&input[..nl]);
                    input = &input[nl + 1..];
                    let txt = String::from_utf8_lossy(line).to_string();
                    let size = u64::from_str_radix(txt.split(';').next().unwrap_or("").trim(), 16).map_err(|_| anyhow!("bad chunk size {txt:?}"))?;
                    *self = if size == 0 { Chunked::Done } else { Chunked::Data(size) };
                }
                Chunked::Data(n) => {
                    let take = (*n).min(input.len() as u64) as usize;
                    out.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    *n -= take as u64;
                    if *n == 0 {
                        *self = Chunked::DataEnd;
                    }
                }
                Chunked::DataEnd => {
                    // The CRLF after the data; tolerate a bare LF.
                    match input.iter().position(|&b| b == b'\n') {
                        Some(nl) => {
                            input = &input[nl + 1..];
                            *self = Chunked::Size(vec![]);
                        }
                        None => return Ok(()),
                    }
                }
                Chunked::Done => return Ok(()),
            }
        }
        Ok(())
    }
}

enum Framing {
    Chunked(Chunked),
    Length(u64),
    UntilClose,
}

/// Plain-HTTP upstream (local inference servers) on our own socket, so that silence is bounded
/// per read (not the whole response, which can take a long time at high effort) and an
/// abandoned request is cut at once, which makes the server stop generating.
struct RawUp {
    sock: std::net::TcpStream,
    status: u16,
    headers: Vec<(String, String)>,
    framing: Framing,
    out: Vec<u8>,
    eof: bool,
    idle: Duration,
}

impl RawUp {
    fn send(base: &str, path: &str, headers: &[(String, String)], body: &[u8], idle: Duration, client: &UnixStream) -> Result<RawUp> {
        use std::net::ToSocketAddrs;
        let hostport = base.strip_prefix("http://").context("not an http:// backend")?.split('/').next().unwrap_or("").to_string();
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (h.trim_matches(['[', ']']).to_string(), p.parse::<u16>().unwrap_or(80)),
            _ => (hostport.trim_matches(['[', ']']).to_string(), 80),
        };
        let mut last = anyhow!("no address for {host}");
        let mut sock = None;
        for addr in (host.as_str(), port).to_socket_addrs()? {
            match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
                Ok(t) => {
                    sock = Some(t);
                    break;
                }
                Err(e) => last = anyhow!("{addr}: {e}"),
            }
        }
        let mut sock = sock.ok_or(last)?;
        sock.set_nodelay(true)?;
        sock.set_write_timeout(Some(Duration::from_secs(60)))?;
        let mut head = format!("POST {path} HTTP/1.1\r\nhost: {hostport}\r\nconnection: close\r\ncontent-length: {}\r\n", body.len());
        for (k, v) in headers {
            head += &format!("{k}: {v}\r\n");
        }
        head += "\r\n";
        sock.write_all(head.as_bytes())?;
        sock.write_all(body)?;
        sock.set_read_timeout(Some(Duration::from_millis(500)))?;
        // Response head: the server may think for a while first (prompt processing).
        let t0 = Instant::now();
        let mut buf = vec![];
        let mut tmp = [0u8; 16 << 10];
        loop {
            match sock.read(&mut tmp) {
                Ok(0) => bail!("the server closed the connection without answering"),
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                    if client_gone(client) {
                        return Err(ClientGone.into());
                    }
                    if t0.elapsed() > idle {
                        bail!("no answer within {}", fmt_duration_ms(idle));
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
            let mut hs = [httparse::EMPTY_HEADER; 96];
            let mut r = httparse::Response::new(&mut hs);
            if let httparse::Status::Complete(n) = r.parse(&buf)? {
                let status = r.code.unwrap_or(502);
                let headers: Vec<(String, String)> = r.headers.iter().map(|h| (h.name.to_ascii_lowercase(), String::from_utf8_lossy(h.value).to_string())).collect();
                let get = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
                let framing = if get("transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false) {
                    Framing::Chunked(Chunked::Size(vec![]))
                } else if let Some(len) = get("content-length").and_then(|v| v.trim().parse::<u64>().ok()) {
                    Framing::Length(len)
                } else {
                    Framing::UntilClose
                };
                let mut up = RawUp { sock, status, headers, framing, out: vec![], eof: false, idle };
                let rest = buf[n..].to_vec();
                up.decode(&rest)?;
                return Ok(up);
            }
            if buf.len() > 256 << 10 {
                bail!("response head too large");
            }
        }
    }

    fn decode(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.framing {
            Framing::Chunked(c) => {
                c.feed(data, &mut self.out)?;
                if matches!(c, Chunked::Done) {
                    self.eof = true;
                }
            }
            Framing::Length(left) => {
                let take = (*left).min(data.len() as u64) as usize;
                self.out.extend_from_slice(&data[..take]);
                *left -= take as u64;
                if *left == 0 {
                    self.eof = true;
                }
            }
            Framing::UntilClose => self.out.extend_from_slice(data),
        }
        Ok(())
    }

    /// Next piece of the body; Ok(None) at the end. Checks the client twice a second.
    fn next(&mut self, client: &UnixStream) -> Result<Option<Vec<u8>>> {
        let mut last = Instant::now();
        let mut tmp = [0u8; 32 << 10];
        loop {
            if !self.out.is_empty() {
                return Ok(Some(std::mem::take(&mut self.out)));
            }
            if self.eof {
                return Ok(None);
            }
            match self.sock.read(&mut tmp) {
                Ok(0) => {
                    self.eof = true;
                    if let Framing::Length(left) = self.framing {
                        if left > 0 {
                            bail!("the server closed the connection {left} bytes early");
                        }
                    }
                }
                Ok(n) => {
                    last = Instant::now();
                    self.decode(&tmp[..n])?;
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                    if client_gone(client) {
                        return Err(ClientGone.into());
                    }
                    if last.elapsed() > self.idle {
                        bail!("the server sent nothing for {}", fmt_duration_ms(self.idle));
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

/// A response being read: TLS backends through ureq (Anthropic streams pings, and a client that
/// left is noticed at the next write), plain HTTP through `RawUp`.
enum Up {
    Tls { status: u16, headers: Vec<(String, String)>, reader: Box<dyn Read + Send> },
    Raw(RawUp),
}

impl Up {
    fn status(&self) -> u16 {
        match self {
            Up::Tls { status, .. } => *status,
            Up::Raw(r) => r.status,
        }
    }
    fn headers(&self) -> &[(String, String)] {
        match self {
            Up::Tls { headers, .. } => headers,
            Up::Raw(r) => &r.headers,
        }
    }
    fn header(&self, k: &str) -> Option<&str> {
        self.headers().iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
    fn next(&mut self, client: &UnixStream) -> Result<Option<Vec<u8>>> {
        match self {
            Up::Tls { reader, .. } => {
                let mut buf = vec![0u8; 32 << 10];
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    return Ok(None);
                }
                buf.truncate(n);
                Ok(Some(buf))
            }
            Up::Raw(r) => r.next(client),
        }
    }
    fn read_all(&mut self, limit: usize, client: &UnixStream) -> String {
        let mut v = vec![];
        while let Ok(Some(b)) = self.next(client) {
            v.extend_from_slice(&b);
            if v.len() > limit {
                break;
            }
        }
        String::from_utf8_lossy(&v).to_string()
    }
}

fn upstream(sh: &Shared, api: Api, req: &HttpReq, path: &str, body: &[u8], key: Option<&str>, client: &UnixStream) -> Result<Up> {
    let mut hs: Vec<(String, String)> = vec![
        ("content-type".into(), "application/json".into()),
        ("accept".into(), req.header("accept").unwrap_or("application/json, text/event-stream").into()),
    ];
    match api {
        Api::Anthropic => {
            hs.push(("anthropic-version".into(), req.header("anthropic-version").unwrap_or("2023-06-01").into()));
            if let Some(b) = req.header("anthropic-beta") {
                hs.push(("anthropic-beta".into(), b.into()));
            }
            if let Some(k) = key {
                hs.push(("x-api-key".into(), k.into()));
            }
        }
        Api::Openai => {
            if let Some(k) = key {
                hs.push(("authorization".into(), format!("Bearer {k}")));
            }
        }
    }
    if sh.ai.base_url.starts_with("http://") {
        let idle = Duration::from_secs(sh.ai.timeout_secs.max(60));
        return RawUp::send(&sh.ai.base_url, path, &hs, body, idle, client).map(Up::Raw).map_err(|e| if e.is::<ClientGone>() { e } else { anyhow!("{} unreachable: {e:#}", sh.ai.backend) });
    }
    let url = format!("{}{path}", sh.ai.base_url);
    let mut r = sh.agent.post(&url);
    for (k, v) in &hs {
        r = r.header(k.as_str(), v.as_str());
    }
    let resp = r.send(body).map_err(|e| anyhow!("{} unreachable: {e}", sh.ai.backend))?;
    let status = resp.status().as_u16();
    let headers = resp.headers().iter().filter_map(|(k, v)| Some((k.as_str().to_ascii_lowercase(), v.to_str().ok()?.to_string()))).collect();
    Ok(Up::Tls { status, headers, reader: Box::new(resp.into_body().into_reader()) })
}

fn models(sh: &Shared, c: &mut UnixStream, api: Api) -> Result<()> {
    // opencode knows its model from the config; answer locally with just that.
    let v = match api {
        Api::Anthropic => json!({"data": [{"type": "model", "id": sh.ai.model, "display_name": sh.ai.model}], "has_more": false}),
        Api::Openai => json!({"object": "list", "data": [{"id": sh.ai.model, "object": "model", "owned_by": sh.ai.backend}]}),
    };
    respond_json(c, 200, &v);
    Ok(())
}

const EFFORT_ORDER: [&str; 5] = ["low", "medium", "high", "xhigh", "max"];

/// The chosen level if the model accepts it, else the nearest lower one it does accept.
fn pick_level(want: &str, levels: &[String]) -> Option<String> {
    if levels.iter().any(|l| l == want) {
        return Some(want.to_string());
    }
    let wi = EFFORT_ORDER.iter().position(|x| *x == want)?;
    EFFORT_ORDER[..wi].iter().rev().find(|l| levels.iter().any(|x| x == *l)).map(|l| l.to_string()).or_else(|| levels.first().cloned())
}

/// Apply the session's effort to agent turns (requests with tools). Titles and summaries keep
/// opencode's own settings. Returns the level applied.
fn apply_effort(sh: &Shared, api: Api, body: &mut Value) -> Option<String> {
    let e = sh.ai.effort.as_str();
    if e.is_empty() || sh.effort_off.load(Ordering::SeqCst) {
        return None;
    }
    if !has_tools(body) {
        return None;
    }
    match api {
        Api::Anthropic => {
            let lvl = pick_level(e, &sh.ai.effort_levels)?;
            if !body["output_config"].is_object() {
                body["output_config"] = json!({});
            }
            body["output_config"]["effort"] = json!(lvl);
            if sh.ai.adaptive {
                if body["thinking"]["type"] != "adaptive" {
                    body["thinking"] = json!({"type": "adaptive", "display": "summarized"});
                } else if body["thinking"].get("display").is_none() {
                    body["thinking"]["display"] = json!("summarized");
                }
            }
            if matches!(lvl.as_str(), "xhigh" | "max") {
                let want = sh.ai.max_output.min(64_000);
                if body["max_tokens"].as_u64().unwrap_or(0) < want {
                    body["max_tokens"] = json!(want);
                }
            }
            Some(lvl)
        }
        Api::Openai => {
            let lvl = match e {
                "low" => "low",
                "medium" => "medium",
                _ => "high",
            };
            body["reasoning_effort"] = json!(lvl);
            Some(lvl.to_string())
        }
    }
}

fn has_tools(body: &Value) -> bool {
    body["tools"].as_array().map(|t| !t.is_empty()).unwrap_or(false)
}

fn record_request(sh: &Shared, n: u64, api: Api, body: &Value, effort: &Option<String>) {
    let aux = !has_tools(body);
    let mut hashes = vec![];
    match api {
        Api::Anthropic => {
            if let Some(s) = body.get("system") {
                hashes.push(sh.put_msg("system", s, aux));
            }
            for m in body["messages"].as_array().into_iter().flatten() {
                hashes.push(sh.put_msg(m["role"].as_str().unwrap_or("?"), &m["content"], aux));
            }
        }
        Api::Openai => {
            for m in body["messages"].as_array().into_iter().flatten() {
                let mut c = m.clone();
                let role = c["role"].as_str().unwrap_or("?").to_string();
                if let Some(o) = c.as_object_mut() {
                    o.remove("role");
                }
                hashes.push(sh.put_msg(&role, &c, aux));
            }
        }
    }
    let tools = body.get("tools").filter(|t| t.as_array().map(|a| !a.is_empty()).unwrap_or(false)).map(|t| sh.put_msg("tools", t, false));
    let mut params = Map::new();
    for k in ["max_tokens", "max_completion_tokens", "temperature", "top_p", "stream", "tool_choice", "thinking", "output_config", "reasoning_effort"] {
        if let Some(v) = body.get(k) {
            params.insert(k.into(), v.clone());
        }
    }
    sh.record("q", json!({"n": n, "backend": sh.ai.backend, "model": body["model"], "msgs": hashes, "tools": tools, "params": params, "effort": effort}));
}

fn looks_like_effort_rejection(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    ["effort", "output_config", "thinking", "reasoning"].iter().any(|k| b.contains(k))
}

fn infer(sh: &Arc<Shared>, c: &mut UnixStream, req: &HttpReq, api: Api) -> Result<()> {
    let path = req.path.split('?').next().unwrap_or("").to_string();
    let n = sh.req_no.fetch_add(1, Ordering::SeqCst) + 1;
    let orig: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(e) => {
            respond_json(c, 400, &error_body(api, &format!("request body is not JSON: {e}")));
            return Ok(());
        }
    };
    let model = orig["model"].as_str().unwrap_or("").to_string();
    if sh.models.lock().unwrap().insert(model.clone()) && model != sh.ai.model {
        let _ = daemon_call(&sh.ai, &sh.spec.id, "usage", json!({"model": model}));
    }
    let mut body = orig.clone();
    let mut effort = apply_effort(sh, api, &mut body);
    record_request(sh, n, api, &body, &effort);
    sh.stats.lock().unwrap().requests += 1;
    let key = match fetch_key(sh) {
        Ok(k) => k,
        Err(e) => {
            let msg = format!("{e:#}");
            sh.record("a", json!({"n": n, "status": 503, "error": msg}));
            respond_json(c, 503, &error_body(api, &msg));
            return Ok(());
        }
    };
    let t0 = Instant::now();
    let abandoned = |sh: &Shared| {
        sh.record("a", json!({"n": n, "status": 0, "cancelled": true, "latency": fmt_duration_ms(t0.elapsed()), "error": "the client abandoned the request before the model answered"}));
    };
    let mut resp = match upstream(sh, api, req, &path, &serde_json::to_vec(&body)?, key.as_deref().map(|k| k.as_str()), c) {
        Ok(r) => r,
        Err(e) if e.is::<ClientGone>() => {
            abandoned(sh);
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let status = resp.status();
    if (status == 400 || status == 422) && effort.is_some() {
        let text = resp.read_all(1 << 20, c);
        if looks_like_effort_rejection(&text) {
            // "can always be chosen and ignored if unsupported": retry without, and stop trying.
            sh.effort_off.store(true, Ordering::SeqCst);
            sh.record("n", json!({"msg": format!("{} rejected effort {}; continuing without it", sh.ai.model, effort.as_deref().unwrap_or("")), "detail": text.chars().take(2000).collect::<String>()}));
            effort = None;
            resp = match upstream(sh, api, req, &path, &serde_json::to_vec(&orig)?, key.as_deref().map(|k| k.as_str()), c) {
                Ok(r) => r,
                Err(e) if e.is::<ClientGone>() => {
                    abandoned(sh);
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
        } else {
            sh.record("a", json!({"n": n, "status": status, "error": text.chars().take(8000).collect::<String>(), "latency": fmt_duration_ms(t0.elapsed())}));
            sh.stats.lock().unwrap().errors += 1;
            let ct = resp.header("content-type").unwrap_or("application/json").to_string();
            let _ = write_head(c, status, &ct, &[("content-length".into(), text.len().to_string())]);
            let _ = c.write_all(text.as_bytes());
            return Ok(());
        }
    }
    drop(key);
    let _ = effort;
    let status = resp.status();
    let ct = resp.header("content-type").unwrap_or("application/json").to_string();
    let mut extra = vec![];
    for (k, v) in resp.headers() {
        if k == "request-id" || k == "x-request-id" || k == "retry-after" || k == "x-should-retry" || k.starts_with("anthropic-ratelimit") || k.starts_with("x-ratelimit") {
            extra.push((k.clone(), v.clone()));
        }
    }
    write_head(c, status, &ct, &extra)?;
    let sse = ct.contains("event-stream");
    let mut asm = Asm::new(api, sse);
    let mut cancelled = false;
    loop {
        let chunk = match resp.next(c) {
            Ok(Some(b)) => b,
            Ok(None) => break,
            Err(e) if e.is::<ClientGone>() => {
                // opencode gave up (Esc, or its own timeout): closing our side makes the server
                // stop generating an answer nobody will read.
                cancelled = true;
                break;
            }
            Err(e) => {
                asm.error = Some(json!(format!("upstream: {e:#}")));
                break;
            }
        };
        asm.feed(&chunk, t0);
        if c.write_all(&chunk).is_err() {
            cancelled = true;
            break;
        }
    }
    drop(resp);
    let done = asm.finish();
    let h = done.message.as_ref().map(|m| sh.put_msg("assistant", m, !has_tools(&body)));
    let mut a = json!({"n": n, "status": status, "h": h, "stop": done.stop, "usage": done.usage, "latency": fmt_duration_ms(t0.elapsed())});
    if let Some(t) = done.ttft {
        a["ttft"] = json!(fmt_duration_ms(t));
    }
    if let Some(m) = &done.model {
        a["model"] = json!(m);
    }
    if let Some(e) = &done.error {
        a["error"] = e.clone();
    }
    if cancelled {
        a["cancelled"] = json!(true);
    }
    sh.record("a", a);
    let mut st = sh.stats.lock().unwrap();
    if status >= 400 || done.error.is_some() {
        st.errors += 1;
    }
    let u = &done.usage;
    st.input_tokens += u["input_tokens"].as_u64().or(u["prompt_tokens"].as_u64()).unwrap_or(0);
    st.output_tokens += u["output_tokens"].as_u64().or(u["completion_tokens"].as_u64()).unwrap_or(0);
    st.cache_read_tokens += u["cache_read_input_tokens"].as_u64().unwrap_or(0);
    st.cache_write_tokens += u["cache_creation_input_tokens"].as_u64().unwrap_or(0);
    Ok(())
}

// ---------------------------------------------------------------- response assembly

struct Done {
    message: Option<Value>,
    stop: Value,
    usage: Value,
    ttft: Option<Duration>,
    model: Option<String>,
    error: Option<Value>,
}

struct Asm {
    api: Api,
    sse: bool,
    line: Vec<u8>,
    event: String,
    data: String,
    raw: Vec<u8>,
    // Anthropic
    blocks: Vec<Value>,
    partial: Vec<String>,
    // OpenAI
    text: String,
    reasoning: String,
    calls: Vec<Value>,
    stop: Value,
    usage: Value,
    ttft: Option<Duration>,
    model: Option<String>,
    error: Option<Value>,
}

impl Asm {
    fn new(api: Api, sse: bool) -> Self {
        Asm { api, sse, line: vec![], event: String::new(), data: String::new(), raw: vec![], blocks: vec![], partial: vec![], text: String::new(), reasoning: String::new(), calls: vec![], stop: Value::Null, usage: json!({}), ttft: None, model: None, error: None }
    }

    fn feed(&mut self, b: &[u8], t0: Instant) {
        if !self.sse {
            if self.raw.len() < 16 << 20 {
                self.raw.extend_from_slice(b);
            }
            return;
        }
        for &byte in b {
            if byte != b'\n' {
                self.line.push(byte);
                continue;
            }
            let line = String::from_utf8_lossy(&self.line).trim_end_matches('\r').to_string();
            self.line.clear();
            if line.is_empty() {
                if !self.data.is_empty() {
                    let (ev, data) = (std::mem::take(&mut self.event), std::mem::take(&mut self.data));
                    self.dispatch(&ev, &data, t0);
                }
                self.event.clear();
            } else if let Some(v) = line.strip_prefix("event:") {
                self.event = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("data:") {
                if !self.data.is_empty() {
                    self.data.push('\n');
                }
                self.data.push_str(v.strip_prefix(' ').unwrap_or(v));
            }
        }
    }

    fn first(&mut self, t0: Instant) {
        if self.ttft.is_none() {
            self.ttft = Some(t0.elapsed());
        }
    }

    fn merge_usage(&mut self, u: &Value) {
        if let (Some(dst), Some(src)) = (self.usage.as_object_mut(), u.as_object()) {
            for (k, v) in src {
                if !v.is_null() {
                    dst.insert(k.clone(), v.clone());
                }
            }
        }
    }

    fn dispatch(&mut self, event: &str, data: &str, t0: Instant) {
        if data == "[DONE]" {
            return;
        }
        let Ok(v) = serde_json::from_str::<Value>(data) else { return };
        match self.api {
            Api::Anthropic => {
                let ty = v["type"].as_str().unwrap_or(event).to_string();
                let idx = v["index"].as_u64().unwrap_or(0) as usize;
                match ty.as_str() {
                    "message_start" => {
                        self.model = v["message"]["model"].as_str().map(String::from);
                        let u = v["message"]["usage"].clone();
                        self.merge_usage(&u);
                    }
                    "content_block_start" => {
                        while self.blocks.len() <= idx {
                            self.blocks.push(Value::Null);
                            self.partial.push(String::new());
                        }
                        self.blocks[idx] = v["content_block"].clone();
                    }
                    "content_block_delta" => {
                        self.first(t0);
                        if idx >= self.blocks.len() {
                            return;
                        }
                        let d = &v["delta"];
                        let blk = &mut self.blocks[idx];
                        match d["type"].as_str().unwrap_or("") {
                            "text_delta" => blk["text"] = json!(format!("{}{}", blk["text"].as_str().unwrap_or(""), d["text"].as_str().unwrap_or(""))),
                            "thinking_delta" => blk["thinking"] = json!(format!("{}{}", blk["thinking"].as_str().unwrap_or(""), d["thinking"].as_str().unwrap_or(""))),
                            "signature_delta" => blk["signature"] = d["signature"].clone(),
                            "input_json_delta" => self.partial[idx].push_str(d["partial_json"].as_str().unwrap_or("")),
                            _ => {}
                        }
                    }
                    "content_block_stop" => {
                        if idx < self.blocks.len() && !self.partial[idx].is_empty() {
                            let p = std::mem::take(&mut self.partial[idx]);
                            self.blocks[idx]["input"] = serde_json::from_str(&p).unwrap_or(Value::String(p));
                        }
                    }
                    "message_delta" => {
                        self.stop = v["delta"]["stop_reason"].clone();
                        let u = v["usage"].clone();
                        self.merge_usage(&u);
                    }
                    "error" => self.error = Some(v["error"].clone()),
                    _ => {}
                }
            }
            Api::Openai => {
                if let Some(m) = v["model"].as_str() {
                    self.model = Some(m.to_string());
                }
                if v.get("error").is_some() {
                    self.error = Some(v["error"].clone());
                }
                if v["usage"].is_object() {
                    let u = v["usage"].clone();
                    self.merge_usage(&u);
                }
                let ch = &v["choices"][0];
                let d = &ch["delta"];
                if let Some(t) = d["content"].as_str() {
                    self.first(t0);
                    self.text.push_str(t);
                }
                if let Some(t) = d["reasoning_content"].as_str().or(d["reasoning"].as_str()) {
                    self.first(t0);
                    self.reasoning.push_str(t);
                }
                for tc in d["tool_calls"].as_array().into_iter().flatten() {
                    self.first(t0);
                    let i = tc["index"].as_u64().unwrap_or(self.calls.len() as u64) as usize;
                    while self.calls.len() <= i {
                        self.calls.push(json!({"id": "", "type": "function", "function": {"name": "", "arguments": ""}}));
                    }
                    let c = &mut self.calls[i];
                    if let Some(id) = tc["id"].as_str() {
                        c["id"] = json!(id);
                    }
                    if let Some(nm) = tc["function"]["name"].as_str() {
                        c["function"]["name"] = json!(format!("{}{}", c["function"]["name"].as_str().unwrap_or(""), nm));
                    }
                    if let Some(a) = tc["function"]["arguments"].as_str() {
                        c["function"]["arguments"] = json!(format!("{}{}", c["function"]["arguments"].as_str().unwrap_or(""), a));
                    }
                }
                if !ch["finish_reason"].is_null() {
                    self.stop = ch["finish_reason"].clone();
                }
            }
        }
    }

    fn finish(mut self) -> Done {
        if !self.sse {
            let v: Value = serde_json::from_slice(&self.raw).unwrap_or(Value::Null);
            return match self.api {
                Api::Anthropic => Done {
                    message: v.get("content").map(|c| c.clone()),
                    stop: v["stop_reason"].clone(),
                    usage: v["usage"].clone(),
                    ttft: None,
                    model: v["model"].as_str().map(String::from),
                    error: v.get("error").cloned().or(self.error),
                },
                Api::Openai => Done {
                    message: v["choices"][0].get("message").cloned(),
                    stop: v["choices"][0]["finish_reason"].clone(),
                    usage: v["usage"].clone(),
                    ttft: None,
                    model: v["model"].as_str().map(String::from),
                    error: v.get("error").cloned().or(self.error),
                },
            };
        }
        if !self.data.is_empty() {
            let (ev, data) = (std::mem::take(&mut self.event), std::mem::take(&mut self.data));
            self.dispatch(&ev, &data, Instant::now());
        }
        let message = match self.api {
            Api::Anthropic => (!self.blocks.is_empty()).then(|| json!(self.blocks.iter().filter(|b| !b.is_null()).cloned().collect::<Vec<_>>())),
            Api::Openai => {
                let mut m = json!({"content": self.text});
                if !self.reasoning.is_empty() {
                    m["reasoning_content"] = json!(self.reasoning);
                }
                if !self.calls.is_empty() {
                    m["tool_calls"] = json!(self.calls);
                }
                Some(m)
            }
        };
        Done { message, stop: self.stop, usage: self.usage, ttft: self.ttft, model: self.model, error: self.error }
    }
}

// ---------------------------------------------------------------- MCP server

fn serve_mcp(sh: Arc<Shared>, c: UnixStream) {
    let Ok(wc) = c.try_clone() else { return };
    let writer = Arc::new(Mutex::new(wc));
    let reply = |w: &Arc<Mutex<UnixStream>>, v: Value| {
        let mut s = serde_json::to_vec(&v).unwrap_or_default();
        s.push(b'\n');
        let _ = w.lock().unwrap().write_all(&s);
    };
    for line in BufReader::new(c).split(b'\n') {
        let Ok(line) = line else { break };
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let Ok(m) = serde_json::from_slice::<Value>(&line) else {
            reply(&writer, json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}}));
            continue;
        };
        let Some(id) = m.get("id").cloned() else { continue }; // notification
        let method = m["method"].as_str().unwrap_or("").to_string();
        match method.as_str() {
            "initialize" => reply(&writer, json!({"jsonrpc": "2.0", "id": id, "result": {
                "protocolVersion": m["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "swrap", "version": env!("CARGO_PKG_VERSION")},
            }})),
            "ping" => reply(&writer, json!({"jsonrpc": "2.0", "id": id, "result": {}})),
            "tools/list" => reply(&writer, json!({"jsonrpc": "2.0", "id": id, "result": {"tools": sh.ai.tools}})),
            "tools/call" => {
                // Calls may overlap (parallel tool use); each gets its own thread.
                let (sh, w) = (sh.clone(), writer.clone());
                std::thread::spawn(move || {
                    let name = m["params"]["name"].as_str().unwrap_or("").to_string();
                    let args = m["params"]["arguments"].clone();
                    let result = call_tool(&sh, &name, &args);
                    reply(&w, json!({"jsonrpc": "2.0", "id": id, "result": result}));
                });
            }
            _ => reply(&writer, json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("method not found: {method}")}})),
        }
    }
}

fn tool_text(text: &str, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

/// Arguments as recorded in `t`: big file contents are recorded once, in the `o` records.
fn args_for_record(name: &str, args: &Value) -> Value {
    let mut a = args.clone();
    if name == "write_file" {
        if let Some(c) = a["content"].as_str().map(String::from) {
            if c.len() > 4096 {
                a["content"] = json!({"bytes": c.len(), "b3": blake3::hash(c.as_bytes()).to_hex().to_string(), "in": "o records (fd 1)"});
            }
        }
    }
    a
}

fn record_output(sh: &Shared, call: &str, fd: u8, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let mut w = sh.w.lock().unwrap();
    match std::str::from_utf8(data) {
        Ok(s) => {
            let mut start = 0;
            while start < s.len() {
                let mut end = (start + (256 << 10)).min(s.len());
                while !s.is_char_boundary(end) {
                    end -= 1;
                }
                let _ = w.record_json("o", json!({"call": call, "fd": fd, "d": &s[start..end]}));
                start = end;
            }
        }
        Err(_) => {
            for chunk in data.chunks(192 << 10) {
                let _ = w.record_json("o", json!({"call": call, "fd": fd, "b": B64.encode(chunk)}));
            }
        }
    }
}

fn call_tool(sh: &Shared, name: &str, args: &Value) -> Value {
    let n = sh.tool_no.fetch_add(1, Ordering::SeqCst) + 1;
    let call = format!("t{n}");
    if n as usize > sh.ai.max_tool_calls {
        let msg = format!("tool budget of this session is exhausted ({} calls)", sh.ai.max_tool_calls);
        sh.record("t", json!({"call": call, "tool": name, "args": args_for_record(name, args), "error": true, "result": msg}));
        sh.note(&msg);
        return tool_text(&msg, true);
    }
    let started = fmt_utc(swrap_core::time::now());
    let t0 = Instant::now();
    let r = daemon_call(&sh.ai, &sh.spec.id, "tool", json!({"name": name, "arguments": args}));
    let (text, is_err, meta, out, err) = match r {
        Ok((resp, out, err)) if resp.ok => {
            let d = resp.data;
            (d["text"].as_str().unwrap_or("").to_string(), d["is_error"].as_bool().unwrap_or(false), d, out, err)
        }
        Ok((resp, _, _)) => (format!("error: {}", resp.error.unwrap_or_default()), true, Value::Null, vec![], vec![]),
        Err(e) => (format!("error: swrapd: {e:#}"), true, Value::Null, vec![], vec![]),
    };
    sh.record("t", json!({
        "call": call, "tool": name, "target": meta["target"], "ruser": meta["ruser"], "args": args_for_record(name, args),
        "exit": meta["exit"], "error": is_err, "result_bytes": text.len(), "out_bytes": out.len(), "err_bytes": err.len(),
        "dropped": meta["dropped"], "started": started, "duration": fmt_duration_ms(t0.elapsed()),
        "result": text.chars().take(2000).collect::<String>(),
    }));
    record_output(sh, &call, 1, &out);
    record_output(sh, &call, 2, &err);
    {
        let mut st = sh.stats.lock().unwrap();
        st.tool_calls += 1;
        if is_err {
            st.tool_errors += 1;
        }
    }
    tool_text(&text, is_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effort_falls_back_to_nearest_lower() {
        let all: Vec<String> = ["low", "medium", "high", "xhigh", "max"].iter().map(|s| s.to_string()).collect();
        assert_eq!(pick_level("xhigh", &all).as_deref(), Some("xhigh"));
        let three: Vec<String> = ["low", "medium", "high"].iter().map(|s| s.to_string()).collect();
        assert_eq!(pick_level("max", &three).as_deref(), Some("high"));
        assert_eq!(pick_level("low", &["medium".to_string()]).as_deref(), Some("medium"));
        assert_eq!(pick_level("high", &[]), None, "no effort support: ignored");
    }

    #[test]
    fn modes_replay_across_split_sequences() {
        let mut m = Modes::default();
        m.feed(b"\x1b[?1049h\x1b[?10");
        m.feed(b"06h\x1b[?2004h\x1b[?25l\x1b[>3u");
        m.feed(b"\x1b[?2004l");
        let r = String::from_utf8(m.replay()).unwrap();
        assert!(r.starts_with("\x1b[?1049h"), "{r:?}");
        assert!(r.contains("\x1b[?1006h") && !r.contains("2004h"), "{r:?}");
        assert!(r.contains("\x1b[?25l") && r.ends_with("\x1b[>3u"), "{r:?}");
        m.feed(b"\x1b[<u");
        assert!(!String::from_utf8(m.replay()).unwrap().contains(">3u"));
    }

    #[test]
    fn message_hash_ignores_key_order_and_cache_markers() {
        let a = json!({"role": "user", "content": [{"type": "text", "text": "hi", "cache_control": {"type": "ephemeral"}}]});
        let mut b = json!({"content": [{"text": "hi", "type": "text"}], "role": "user"});
        strip_cache(&mut b);
        let mut a2 = a.clone();
        strip_cache(&mut a2);
        assert_eq!(canonical(&a2), canonical(&b));
    }
}
