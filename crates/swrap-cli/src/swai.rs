//! `swai`: AI harness on swrap. Without arguments it asks five small "choose an option" questions
//! (target, host, inference, model, effort; for one host also permissions) and opens opencode or
//! Claude Code — sandboxed on core, recorded, acting on hosts only through swrap's tools under AI
//! grants.
//!
//! * `swai --target aaa|<label> --backend <b> --model <m> [--effort <e>] [--loose]` skips the
//!   questions. `--loose` (one host only): no permission prompts — Claude Code runs with
//!   --dangerously-skip-permissions, opencode allows every tool.
//! * `swai targets|backend|grant|revoke-grant|host|status …` run on the daemon.
//! * `swai-sandbox` / `swai-mcp` are helpers that run *inside* the sandbox.

use crate::client;
use crate::term::{self, RawGuard};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use swrap_core::api::{Req, Resp};
use swrap_core::frame::{kind, read_frame, write_frame, Frame};

const EFFORT_HELP: &str = "ignored when the model does not support it";

pub fn main(args: Vec<String>) -> Result<i32> {
    if matches!(args.first().map(String::as_str), Some("-h" | "--help" | "help")) {
        println!(
            "usage: swai                      choose target, host, inference, model, effort; then open the AI\n       \
             swai --target aaa|<host> --backend <name> --model <id> [--effort low|medium|high|xhigh|max] [--loose]\n       \
             --loose: one host only; no permission prompts (Claude Code --dangerously-skip-permissions)\n       \
             swai -c                     continue the last conversation (same choices)\n       \
             swai ls                     running sessions (they survive disconnects, like tmux)\n       \
             swai attach [id]            reconnect (default: the latest detached session); ctrl-\\ detaches\n       \
             swai kill <id>              end a session\n       \
             swai targets                hosts and accounts the AI may use for you\n       \
             swai backend list|test <n>  inference backends\n\
             admin: swai backend add <name> <url> [--api openai|anthropic] [--key] | del <name> | key <name>\n       \
             swai grant <user> <hosts> <accounts> [--until ISO] | revoke-grant <user> <id>\n       \
             swai host <label> on|off    | swai status\n\n\
             Everything is recorded: the terminal (with keystrokes), every model request and reply, every tool call."
        );
        return Ok(0);
    }
    match args.first().map(String::as_str) {
        Some("ls" | "list" | "sessions") => {
            let r = client::call(&Req::AiList)?;
            return Ok(client::finish(&r));
        }
        Some("attach" | "a") => {
            if !(term::isatty(0) && term::isatty(1)) {
                bail!("swai needs a terminal");
            }
            return attach(args.get(1).cloned().unwrap_or_default());
        }
        _ => {}
    }
    if let Some(first) = args.first() {
        if !first.starts_with('-') {
            let stdin = if args.len() >= 3 && args[0] == "backend" && args[1] == "key" {
                Some(term::prompt_secret(&format!("API key for {}: ", args[2]))?.to_string())
            } else {
                None
            };
            let r = client::call(&Req::Admin { cmd: "swai".into(), args, stdin })?;
            return Ok(client::finish(&r));
        }
    }
    let mut pick = Choice::default();
    let mut resume = String::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().cloned().with_context(|| format!("{name} needs a value"));
        match a.as_str() {
            "--target" => pick.target = Some(val("--target")?),
            "--backend" => pick.backend = Some(val("--backend")?),
            "--model" => pick.model = Some(val("--model")?),
            "--effort" => pick.effort = Some(val("--effort")?),
            "--loose" | "--dangerously-skip-permissions" => pick.loose = Some(true),
            "-c" | "--continue" => resume = "last".into(),
            "-s" | "--session" => resume = val("--session")?,
            o => bail!("unknown option {o} (see swai --help)"),
        }
    }
    if !(term::isatty(0) && term::isatty(1)) {
        bail!("swai needs a terminal");
    }
    // Continuing: same target/inference/model/effort as last time unless given.
    if !resume.is_empty() {
        let l = last();
        pick.target = pick.target.or(l.target);
        pick.backend = pick.backend.or(l.backend);
        pick.model = pick.model.or(l.model);
        pick.effort = pick.effort.or(l.effort);
        pick.loose = pick.loose.or(l.loose);
    }
    // Loose is for one host: carried over from last time it never applies to the whole AAA.
    if pick.target.as_deref() == Some("aaa") && !args.iter().any(|a| a == "--loose" || a == "--dangerously-skip-permissions") {
        pick.loose = Some(false);
    }
    let choice = if pick.complete() { Some(pick) } else { wizard(pick)? };
    if let Some(id) = choice.as_ref().and_then(|c| c.target.as_deref()).and_then(|t| t.strip_prefix("\u{3}attach:")) {
        return attach(id.to_string());
    }
    let Some(choice) = choice.filter(|c| c.complete()) else { return Ok(1) };
    remember(&choice);
    start(choice, resume)
}

#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
struct Choice {
    target: Option<String>,
    backend: Option<String>,
    model: Option<String>,
    effort: Option<String>,
    /// One host, no permission prompts (`--loose`).
    loose: Option<bool>,
}

impl Choice {
    fn complete(&self) -> bool {
        self.target.is_some() && self.backend.is_some() && self.model.is_some()
    }
}

fn last_path() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config/swai/last.json"))
}

fn last() -> Choice {
    last_path().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn remember(c: &Choice) {
    if let Some(p) = last_path() {
        let _ = std::fs::create_dir_all(p.parent().unwrap());
        let _ = std::fs::write(p, serde_json::to_string(c).unwrap_or_default());
    }
}

// ---------------------------------------------------------------- session

fn start(c: Choice, resume: String) -> Result<i32> {
    let (cols, rows) = term::winsize();
    let ssh_conn = std::env::var("SSH_CONNECTION").unwrap_or_default();
    let req = Req::AiStart {
        target: c.target.clone().unwrap_or_default(),
        backend: c.backend.clone().unwrap_or_default(),
        model: c.model.clone().unwrap_or_default(),
        effort: c.effort.clone().unwrap_or_default(),
        cols,
        rows,
        term: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
        client_addr: ssh_conn.split_whitespace().next().unwrap_or("local").to_string(),
        conn: ssh_conn,
        resume,
        loose: c.loose.unwrap_or(false),
    };
    let mut s = client::connect()?;
    write_frame(&mut s, &Frame::json(kind::REQ, &req))?;
    let resp: Resp = loop {
        let Some(f) = read_frame(&mut s)? else { bail!("swrap: daemon closed the connection") };
        match f.kind {
            kind::RESP => break f.parse()?,
            kind::STDERR => eprintln!("{}", String::from_utf8_lossy(&f.payload)),
            _ => {}
        }
    };
    if !resp.ok {
        return Ok(client::finish(&resp));
    }
    let id = resp.data["id"].as_str().unwrap_or("").to_string();
    eprintln!("{}", resp.text);
    // Inside the recorded AAA shell: pause its recording while this (separately recorded) runs.
    let shell_nonce = std::env::var("SWRAP_SHELL_NONCE").ok().filter(|n| !n.is_empty());
    let mut out = std::io::stdout();
    if let Some(n) = &shell_nonce {
        let _ = write!(out, "\x1b]7719;{n};sw-start:{id}\x07");
        let _ = out.flush();
    }
    let code = relay(&mut s, &id)?;
    if let Some(n) = &shell_nonce {
        let _ = write!(out, "\x1b]7719;{n};sw-end:{id}\x07");
        let _ = out.flush();
    }
    Ok(code)
}

fn attach(id: String) -> Result<i32> {
    let (cols, rows) = term::winsize();
    let ssh_conn = std::env::var("SSH_CONNECTION").unwrap_or_default();
    let req = Req::AiAttach {
        id,
        cols,
        rows,
        term: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
        client_addr: ssh_conn.split_whitespace().next().unwrap_or("local").to_string(),
    };
    let mut s = client::connect()?;
    write_frame(&mut s, &Frame::json(kind::REQ, &req))?;
    let resp: Resp = loop {
        let Some(f) = read_frame(&mut s)? else { bail!("swrap: daemon closed the connection") };
        match f.kind {
            kind::RESP => break f.parse()?,
            kind::STDERR => eprintln!("{}", String::from_utf8_lossy(&f.payload)),
            _ => {}
        }
    };
    if !resp.ok {
        return Ok(client::finish(&resp));
    }
    let id = resp.data["id"].as_str().unwrap_or("").to_string();
    eprintln!("{}", resp.text);
    let shell_nonce = std::env::var("SWRAP_SHELL_NONCE").ok().filter(|n| !n.is_empty());
    let mut out = std::io::stdout();
    if let Some(n) = &shell_nonce {
        let _ = write!(out, "\x1b]7719;{n};sw-start:{id}\x07");
        let _ = out.flush();
    }
    let code = relay(&mut s, &id)?;
    if let Some(n) = &shell_nonce {
        let _ = write!(out, "\x1b]7719;{n};sw-end:{id}\x07");
        let _ = out.flush();
    }
    Ok(code)
}

/// Undo what the TUI switched on, for when we leave it running (detach, lost connection).
const TERM_RESTORE: &str = "\x1b[<u\x1b[<u\x1b[<u\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l\x1b[?1004l\x1b[?2004l\x1b[?1049l\x1b[?25h\x1b[0m\r\n";

/// Ctrl-\ (0x1c) detaches: the session keeps running on core.
const DETACH_KEY: u8 = 0x1c;

fn relay(s: &mut UnixStream, id: &str) -> Result<i32> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use std::os::fd::{AsFd, BorrowedFd};
    let raw = RawGuard::new();
    let sigr = term::signal_pipe();
    let mut buf = vec![0u8; 65536];
    let mut rbuf: Vec<u8> = vec![];
    let mut out = std::io::stdout();
    let detached = |raw: Option<RawGuard>, msg: &str| -> Result<i32> {
        let mut o = std::io::stdout();
        let _ = o.write_all(TERM_RESTORE.as_bytes());
        let _ = o.flush();
        drop(raw);
        eprintln!("{msg}");
        Ok(0)
    };
    loop {
        let stdin_fd = unsafe { BorrowedFd::borrow_raw(0) };
        let sig_fd = unsafe { BorrowedFd::borrow_raw(sigr) };
        let mut fds = [PollFd::new(s.as_fd(), PollFlags::POLLIN), PollFd::new(sig_fd, PollFlags::POLLIN), PollFd::new(stdin_fd, PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::NONE) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
        let ev: Vec<PollFlags> = fds.iter().map(|f| f.revents().unwrap_or(PollFlags::empty())).collect();
        if ev[1].contains(PollFlags::POLLIN) {
            let mut b = [0u8; 16];
            let n = unsafe { libc::read(sigr, b.as_mut_ptr() as *mut _, 16) };
            for &sig in &b[..n.max(0) as usize] {
                if sig as i32 == libc::SIGWINCH {
                    let (c, r) = term::winsize();
                    write_frame(s, &Frame::json(kind::RESIZE, &serde_json::json!({"cols": c, "rows": r})))?;
                } else {
                    // Our terminal is going away: the session detaches and keeps running.
                    let _ = write_frame(s, &Frame::new(kind::SIGNAL, vec![libc::SIGHUP as u8]));
                    return Ok(129);
                }
            }
        }
        if ev[2].intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            let n = unsafe { libc::read(0, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n <= 0 {
                let _ = write_frame(s, &Frame::new(kind::SIGNAL, vec![libc::SIGHUP as u8]));
                return Ok(129);
            }
            let data = &buf[..n as usize];
            if let Some(p) = data.iter().position(|&b| b == DETACH_KEY) {
                if p > 0 {
                    write_frame(s, &Frame::new(kind::DATA, data[..p].to_vec()))?;
                }
                return detached(raw, &format!("swai: detached; {id} keeps running · reattach: swai attach {} · list: swai ls", &id[id.len().saturating_sub(6)..]));
            }
            write_frame(s, &Frame::new(kind::DATA, data.to_vec()))?;
        }
        if ev[0].intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            let n = s.read(&mut buf)?;
            if n == 0 {
                return detached(raw, &format!("swai: connection to the session lost; it may still be running · swai ls / swai attach {id}"));
            }
            rbuf.extend_from_slice(&buf[..n]);
            while rbuf.len() >= 4 {
                let len = u32::from_be_bytes(rbuf[..4].try_into().unwrap()) as usize;
                if rbuf.len() < 4 + len {
                    break;
                }
                let f = Frame { stream: 0, kind: rbuf[8], payload: rbuf[9..4 + len].to_vec() };
                rbuf.drain(..4 + len);
                match f.kind {
                    kind::DATA => {
                        out.write_all(&f.payload)?;
                        out.flush()?;
                    }
                    kind::STDERR => eprint!("{}\r\n", String::from_utf8_lossy(&f.payload)),
                    kind::EXIT => {
                        let (code, reason) = f.exit_code();
                        if reason == "detached" {
                            return detached(raw, &format!("swai: {id} was attached from another terminal"));
                        }
                        drop(raw);
                        let why = if reason == "exit" { String::new() } else { format!(" ({reason})") };
                        eprintln!("swai: session {id} ended{why} · replay: swplay {id} · continue the conversation: swai -c");
                        return Ok(code);
                    }
                    _ => {}
                }
            }
        }
    }
}

// ---------------------------------------------------------------- wizard

struct Item {
    label: String,
    detail: String,
    value: String,
    enabled: bool,
}

impl Item {
    fn new(label: impl Into<String>, detail: impl Into<String>, value: impl Into<String>) -> Self {
        Item { label: label.into(), detail: detail.into(), value: value.into(), enabled: true }
    }
    fn off(mut self) -> Self {
        self.enabled = false;
        self
    }
}

enum Pick {
    Value(String),
    Text(String),
    Back,
    Quit,
}

enum Key {
    Up,
    Down,
    PgUp,
    PgDn,
    Home,
    End,
    Enter,
    Esc,
    Backspace,
    Quit,
    Char(char),
    Other,
}

/// One byte from fd 0, unbuffered (std's Stdin buffers, which would hide escape sequences from
/// the poll below). `wait_ms`: None blocks; Some(ms) returns None on timeout.
fn byte(wait_ms: Option<i32>) -> Result<Option<u8>> {
    if let Some(ms) = wait_ms {
        let mut fds = [libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 }];
        if unsafe { libc::poll(fds.as_mut_ptr(), 1, ms) } <= 0 {
            return Ok(None);
        }
    }
    let mut b = [0u8; 1];
    loop {
        let n = unsafe { libc::read(0, b.as_mut_ptr() as *mut _, 1) };
        if n == 1 {
            return Ok(Some(b[0]));
        }
        if n == 0 {
            return Ok(None);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e.into());
        }
    }
}

fn read_key() -> Result<Key> {
    let Some(b0) = byte(None)? else { return Ok(Key::Quit) };
    Ok(match b0 {
        b'\r' | b'\n' => Key::Enter,
        0x03 | 0x04 => Key::Quit,
        0x7f | 0x08 => Key::Backspace,
        0x10 => Key::Up,
        0x0e => Key::Down,
        0x1b => {
            // A lone Esc, or the start of a CSI/SS3 sequence.
            let Some(s) = byte(Some(40))? else { return Ok(Key::Esc) };
            if s != b'[' && s != b'O' {
                return Ok(Key::Esc);
            }
            let mut seq = vec![];
            while let Some(c) = byte(Some(40))? {
                seq.push(c);
                if (0x40..=0x7e).contains(&c) || seq.len() > 8 {
                    break;
                }
            }
            match seq.as_slice() {
                b"A" => Key::Up,
                b"B" => Key::Down,
                b"D" => Key::Esc,
                b"C" => Key::Enter,
                b"H" | b"1~" => Key::Home,
                b"F" | b"4~" => Key::End,
                b"5~" => Key::PgUp,
                b"6~" => Key::PgDn,
                _ => Key::Other,
            }
        }
        c if c >= 0x20 => {
            // UTF-8 continuation bytes of a typed character.
            let need = if c >= 0xf0 { 3 } else if c >= 0xe0 { 2 } else if c >= 0xc0 { 1 } else { 0 };
            let mut v = vec![c];
            for _ in 0..need {
                if let Some(x) = byte(Some(100))? {
                    v.push(x);
                }
            }
            String::from_utf8(v).ok().and_then(|s| s.chars().next()).map(Key::Char).unwrap_or(Key::Other)
        }
        _ => Key::Other,
    })
}

/// Terminal width in columns of a string (good enough for our ASCII/box-drawing text).
fn width(s: &str) -> usize {
    s.chars().count()
}

fn fit(s: &str, w: usize) -> String {
    if width(s) <= w {
        format!("{s}{}", " ".repeat(w - width(s)))
    } else {
        let mut t: String = s.chars().take(w.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

struct Screen {
    drawn: usize,
}

impl Screen {
    fn clear(&mut self, out: &mut impl Write) {
        if self.drawn > 0 {
            let _ = write!(out, "\r\x1b[{}A\x1b[J", self.drawn);
            self.drawn = 0;
        }
        let _ = out.flush();
    }

    fn draw(&mut self, out: &mut impl Write, lines: &[String]) {
        let mut buf = String::new();
        if self.drawn > 0 {
            buf += &format!("\r\x1b[{}A", self.drawn);
        }
        buf += "\r\x1b[J";
        for l in lines {
            buf += l;
            buf += "\r\n";
        }
        self.drawn = lines.len();
        let _ = out.write_all(buf.as_bytes());
        let _ = out.flush();
    }
}

const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const INV: &str = "\x1b[7m";
const RST: &str = "\x1b[0m";
const ACC: &str = "\x1b[36m";

/// One "choose an option" screen. `text_prompt`: the items include a free-text entry whose
/// value is this marker; choosing it switches to a one-line input.
fn menu(scr: &mut Screen, step: &str, title: &str, items: &[Item], preselect: Option<&str>, note: &str) -> Result<Pick> {
    let mut out = std::io::stdout();
    let (cols, rows) = term::winsize();
    let inner = (cols as usize).saturating_sub(4).clamp(30, 78);
    let visible = (rows as usize).saturating_sub(10).clamp(3, 12);
    let mut filter = String::new();
    let mut sel = items.iter().position(|i| i.enabled && Some(i.value.as_str()) == preselect).or_else(|| items.iter().position(|i| i.enabled)).unwrap_or(0);
    let mut top = 0usize;
    let mut input: Option<(String, String)> = None; // (value marker, typed text)
    loop {
        let shown: Vec<usize> = (0..items.len())
            .filter(|&i| filter.is_empty() || items[i].label.to_lowercase().contains(&filter.to_lowercase()) || items[i].detail.to_lowercase().contains(&filter.to_lowercase()))
            .collect();
        if !shown.contains(&sel) {
            sel = shown.iter().copied().find(|&i| items[i].enabled).unwrap_or(usize::MAX);
        }
        let pos = shown.iter().position(|&i| i == sel).unwrap_or(0);
        if pos < top {
            top = pos;
        }
        if pos >= top + visible {
            top = pos + 1 - visible;
        }
        // ---- draw
        let mut lines = vec![];
        let head = format!("─ swai · {step} · {title} ");
        lines.push(format!("{ACC}┌{}{}┐{RST}", head, "─".repeat((inner + 2).saturating_sub(width(&head)))));
        let row = |s: String, raw_len: usize| format!("{ACC}│{RST} {s}{} {ACC}│{RST}", " ".repeat(inner.saturating_sub(raw_len)));
        if let Some((_, text)) = &input {
            let p = format!("{} › {text}", items.iter().find(|i| Some(&i.value) == input.as_ref().map(|x| &x.0)).map(|i| i.label.as_str()).unwrap_or(""));
            lines.push(row(format!("{BOLD}{}{RST}\x1b[5m▏\x1b[25m", fit(&p, inner.saturating_sub(1)).trim_end()), width(fit(&p, inner.saturating_sub(1)).trim_end()) + 1));
            lines.push(row(format!("{DIM}{}{RST}", fit("enter confirm · esc back", inner)), inner));
        } else {
            lines.push(row(format!("{BOLD}choose an option{RST}{}", if filter.is_empty() { String::new() } else { format!("  {DIM}filter: {filter}{RST}") }), width("choose an option") + if filter.is_empty() { 0 } else { width(&filter) + 10 }));
            if top > 0 {
                lines.push(row(format!("{DIM}  ↑ {} more{RST}", top), width(&format!("  ↑ {} more", top))));
            }
            for (n, &i) in shown.iter().enumerate().skip(top).take(visible) {
                let it = &items[i];
                let num = if n < 9 && filter.is_empty() && shown.len() <= 9 { format!("{}", n + 1) } else { " ".into() };
                let lab_w = (inner / 2).max(18).min(inner.saturating_sub(6));
                let text = format!("{} {num}  {}  {}", if i == sel { "▸" } else { " " }, fit(&it.label, lab_w.saturating_sub(5)), it.detail);
                let text = fit(&text, inner);
                let styled = if i == sel {
                    format!("{INV}{text}{RST}")
                } else if !it.enabled {
                    format!("{DIM}{text}{RST}")
                } else {
                    text.clone()
                };
                lines.push(row(styled, width(&text)));
            }
            if shown.is_empty() {
                lines.push(row(format!("{DIM}(nothing matches){RST}"), width("(nothing matches)")));
            }
            if top + visible < shown.len() {
                lines.push(row(format!("{DIM}  ↓ {} more{RST}", shown.len() - top - visible), width(&format!("  ↓ {} more", shown.len() - top - visible))));
            }
            if !note.is_empty() {
                lines.push(row(format!("{DIM}{}{RST}", fit(note, inner)), inner));
            }
            let keys = if items.len() > 9 { "↑↓ move · type to filter · enter ok · esc back · ctrl-c quit" } else { "↑↓/1-9 · enter ok · esc back · ctrl-c quit" };
            lines.push(row(format!("{DIM}{}{RST}", fit(keys, inner)), inner));
        }
        lines.push(format!("{ACC}└{}┘{RST}", "─".repeat(inner + 2)));
        scr.draw(&mut out, &lines);
        // ---- keys
        let key = read_key()?;
        if let Some((marker, text)) = &mut input {
            match key {
                Key::Enter if !text.trim().is_empty() => return Ok(Pick::Text(format!("{marker}\u{0}{}", text.trim()))),
                Key::Esc | Key::Quit => input = None,
                Key::Backspace => {
                    text.pop();
                }
                Key::Char(c) if !c.is_control() && text.len() < 200 => text.push(c),
                _ => {}
            }
            continue;
        }
        let enabled_shown: Vec<usize> = shown.iter().copied().filter(|&i| items[i].enabled).collect();
        let cur = enabled_shown.iter().position(|&i| i == sel);
        match key {
            Key::Quit => return Ok(Pick::Quit),
            Key::Esc => {
                if filter.is_empty() {
                    return Ok(Pick::Back);
                }
                filter.clear();
            }
            Key::Backspace => {
                if filter.is_empty() {
                    return Ok(Pick::Back);
                }
                filter.pop();
            }
            Key::Up => {
                if let Some(c) = cur {
                    sel = enabled_shown[c.saturating_sub(1)];
                }
            }
            Key::Down => {
                if let Some(c) = cur {
                    sel = enabled_shown[(c + 1).min(enabled_shown.len() - 1)];
                }
            }
            Key::PgUp => {
                if let Some(c) = cur {
                    sel = enabled_shown[c.saturating_sub(visible)];
                }
            }
            Key::PgDn => {
                if let Some(c) = cur {
                    sel = enabled_shown[(c + visible).min(enabled_shown.len() - 1)];
                }
            }
            Key::Home => {
                if let Some(&f) = enabled_shown.first() {
                    sel = f;
                }
            }
            Key::End => {
                if let Some(&l) = enabled_shown.last() {
                    sel = l;
                }
            }
            Key::Enter => {
                if sel < items.len() && items[sel].enabled {
                    let v = items[sel].value.clone();
                    if v.starts_with("\u{1}input:") {
                        input = Some((v, String::new()));
                        continue;
                    }
                    return Ok(Pick::Value(v));
                }
            }
            Key::Char(c) if c.is_ascii_digit() && c != '0' && filter.is_empty() && shown.len() <= 9 => {
                let i = shown[(c as usize - '1' as usize).min(shown.len() - 1)];
                if (c as usize - '1' as usize) < shown.len() && items[i].enabled {
                    let v = items[i].value.clone();
                    if v.starts_with("\u{1}input:") {
                        sel = i;
                        input = Some((v, String::new()));
                        continue;
                    }
                    return Ok(Pick::Value(v));
                }
            }
            Key::Char(c) if !c.is_control() => filter.push(c),
            _ => {}
        }
    }
}

fn status_line(scr: &mut Screen, msg: &str) {
    let mut out = std::io::stdout();
    scr.draw(&mut out, &[format!("{DIM}swai: {msg}{RST}")]);
}

fn opts() -> Result<Value> {
    let r = client::call(&Req::AiOptions)?;
    if !r.ok {
        bail!("{}", r.error.unwrap_or_default());
    }
    Ok(r.data)
}

/// "Mock Opus 5 · 1000k context", "loaded · 262k context", …
fn model_detail(m: &Value) -> String {
    match (m["name"].as_str().filter(|s| !s.is_empty()), m["context"].as_u64()) {
        (Some(n), Some(ctx)) => format!("{n} · {}k context", ctx / 1000),
        (Some(n), None) => n.to_string(),
        (None, Some(ctx)) => format!("{}k context", ctx / 1000),
        _ => String::new(),
    }
}

fn short_date(iso: &str) -> String {
    iso.get(..10).unwrap_or(iso).to_string()
}

fn wizard(mut c: Choice) -> Result<Option<Choice>> {
    let mut o = opts()?;
    let prev = last();
    let _raw = RawGuard::new().context("raw mode")?;
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b[?25l");
    let mut scr = Screen { drawn: 0 };
    let res = (|| -> Result<Option<Choice>> {
        // Steps: 1 target, 2 host, 3 inference, 4 model, 5 effort, 6 permissions (one host only).
        // Esc goes back one step.
        let of = |n: u8, c: &Choice| format!("{n}/{}", if c.target.as_deref() == Some("aaa") { 5 } else { 6 });
        let mut step = if c.target.is_some() { 3 } else { 1 };
        loop {
            match step {
                1 => {
                    let hosts = o["hosts"].as_array().cloned().unwrap_or_default();
                    let mut items = vec![];
                    // Running sessions come first: reattach like tmux.
                    let running = client::call_with_quiet(&Req::AiList).ok().filter(|r| r.ok).map(|r| r.data.as_array().cloned().unwrap_or_default()).unwrap_or_default();
                    for j in &running {
                        let id = j["id"].as_str().unwrap_or("");
                        let state = if j["attached"] == true { "attached elsewhere" } else { "detached" };
                        items.push(Item::new(format!("↺ {}", j["target"].as_str().unwrap_or("")), format!("{} {} · {state} · {}", j["backend"].as_str().unwrap_or(""), j["model"].as_str().unwrap_or(""), &id[id.len().saturating_sub(6)..]), format!("\u{3}attach:{id}")));
                    }
                    let mut one = Item::new("one host", "lean: one target, fewer tools, smaller context", "host");
                    if hosts.is_empty() {
                        one = Item::new("one host", "no hosts are enabled for AI for you yet", "host").off();
                    }
                    items.push(one);
                    items.push(Item::new("aaa", "all your AI hosts + swrap records (more context)", "aaa"));
                    // A detached session is the likely intent (like `tmux attach`); else last time's.
                    let first_detached = running.iter().find(|j| j["attached"] != true).and_then(|j| j["id"].as_str()).map(|id| format!("\u{3}attach:{id}"));
                    let pre_owned = first_detached.or_else(|| prev.target.as_deref().map(|t| if t == "aaa" { "aaa".to_string() } else { "host".to_string() }));
                    let pre = pre_owned.as_deref();
                    let note = if hosts.is_empty() { "admin: swai host <label> on · swai grant <you> <hosts> <accounts>" } else { "" };
                    match menu(&mut scr, &of(1, &c), "target", &items, pre, note)? {
                        Pick::Value(v) if v.starts_with("\u{3}attach:") => {
                            c.target = Some(v);
                            return Ok(Some(c.clone()));
                        }
                        Pick::Value(v) if v == "aaa" => {
                            c.target = Some("aaa".into());
                            step = 3;
                        }
                        Pick::Value(_) => step = 2,
                        Pick::Back | Pick::Quit => return Ok(None),
                        Pick::Text(_) => {}
                    }
                }
                2 => {
                    let mut items = vec![];
                    for h in o["hosts"].as_array().cloned().unwrap_or_default() {
                        let label = h["label"].as_str().unwrap_or("");
                        let accts: Vec<String> = h["accounts"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(String::from)).collect();
                        let tags: Vec<String> = h["tags"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(String::from)).collect();
                        let extra = format!("{}{}", h["address"].as_str().unwrap_or(""), if tags.is_empty() { String::new() } else { format!(" · {}", tags.join(",")) });
                        for (i, a) in accts.iter().enumerate() {
                            let val = if i == 0 { label.to_string() } else { format!("{a}@{label}") };
                            items.push(Item::new(format!("{label} · {a}"), extra.clone(), val));
                        }
                    }
                    for h in o["others"].as_array().cloned().unwrap_or_default() {
                        items.push(Item::new(h["label"].as_str().unwrap_or(""), h["why"].as_str().unwrap_or(""), "").off());
                    }
                    match menu(&mut scr, &of(2, &c), "host", &items, prev.target.as_deref(), "")? {
                        Pick::Value(v) => {
                            c.target = Some(v);
                            step = 3;
                        }
                        Pick::Back => {
                            c.target = None;
                            step = 1;
                        }
                        Pick::Quit => return Ok(None),
                        Pick::Text(_) => {}
                    }
                }
                3 => {
                    let mut items = vec![];
                    // Claude Code with your plan first, then API-key and local backends.
                    let mut backends = o["backends"].as_array().cloned().unwrap_or_default();
                    backends.sort_by_key(|b| b["api"] != "claude-code");
                    for b in backends {
                        let name = b["name"].as_str().unwrap_or("").to_string();
                        let desc = match b["api"].as_str().unwrap_or("") {
                            "claude-code" => "Claude Code · your Claude plan (Pro/Max)".to_string(),
                            "anthropic" => "Claude API (key) · opencode".to_string(),
                            _ => format!("local · {} · opencode", b["base_url"].as_str().unwrap_or("")),
                        };
                        let it = if b["ready"].as_bool() == Some(true) { Item::new(&name, desc, &name) } else { Item::new(&name, b["why"].as_str().unwrap_or(""), &name).off() };
                        items.push(it);
                    }
                    if o["can_add"].as_bool() == Some(true) {
                        items.push(Item::new("add new IP…", "an OpenAI-compatible server (llama.cpp, vLLM, Ollama…)", "\u{1}input:ip"));
                    }
                    match menu(&mut scr, &of(3, &c), "inference", &items, prev.backend.as_deref(), "")? {
                        Pick::Value(v) => {
                            c.backend = Some(v);
                            step = 4;
                        }
                        Pick::Text(t) => {
                            let addr = t.split('\u{0}').nth(1).unwrap_or("").to_string();
                            status_line(&mut scr, &format!("probing {addr} …"));
                            let r = client::call_with_quiet(&Req::AiAddBackend { addr: addr.clone() })?;
                            if !r.ok {
                                status_line(&mut scr, &format!("{} (any key)", r.error.unwrap_or_default()));
                                let _ = read_key();
                                continue;
                            }
                            o = opts()?;
                            c.backend = r.data["name"].as_str().map(String::from);
                            step = 4;
                        }
                        Pick::Back => {
                            step = if c.target.as_deref() == Some("aaa") { 1 } else { 2 };
                            c.target = if step == 1 { None } else { c.target.take() };
                        }
                        Pick::Quit => return Ok(None),
                    }
                }
                4 => {
                    let be = c.backend.clone().unwrap_or_default();
                    let b = o["backends"].as_array().and_then(|a| a.iter().find(|b| b["name"] == be.as_str())).cloned().unwrap_or_default();
                    let recent: Vec<Value> = b["recent"].as_array().cloned().unwrap_or_default();
                    let mut items: Vec<Item> = recent
                        .iter()
                        .map(|m| {
                            let id = m["model"].as_str().unwrap_or("");
                            Item::new(id, format!("last used {}", short_date(m["last"].as_str().unwrap_or(""))), id)
                        })
                        .collect();
                    let mut note = String::new();
                    if items.is_empty() {
                        // Nothing used in the last P30D: list what the backend serves right now.
                        status_line(&mut scr, &format!("asking {be} for its models …"));
                        match client::call_with_quiet(&Req::AiModels { backend: be.clone() }) {
                            Ok(r) if r.ok => {
                                for m in r.data["models"].as_array().cloned().unwrap_or_default() {
                                    let id = m["id"].as_str().unwrap_or("");
                                    items.push(Item::new(id, model_detail(&m), id));
                                }
                                note = "no model used with this backend in the last P30D; all it serves:".into();
                            }
                            Ok(r) => note = r.error.unwrap_or_default(),
                            Err(e) => note = format!("{e:#}"),
                        }
                    } else {
                        items.push(Item::new("all models…", "everything this backend serves", "\u{2}all"));
                    }
                    items.push(Item::new("type a model id…", "", "\u{1}input:model"));
                    match menu(&mut scr, &of(4, &c), &format!("model · {be}"), &items, prev.model.as_deref(), &note)? {
                        Pick::Value(v) if v == "\u{2}all" => {
                            status_line(&mut scr, &format!("asking {be} for its models …"));
                            let r = client::call_with_quiet(&Req::AiModels { backend: be.clone() })?;
                            if !r.ok {
                                status_line(&mut scr, &format!("{} (any key)", r.error.unwrap_or_default()));
                                let _ = read_key();
                                continue;
                            }
                            let all: Vec<Item> = r.data["models"].as_array().cloned().unwrap_or_default().iter().map(|m| {
                                let id = m["id"].as_str().unwrap_or("");
                                Item::new(id, model_detail(m), id)
                            }).collect();
                            match menu(&mut scr, &of(4, &c), &format!("all models · {be}"), &all, prev.model.as_deref(), "")? {
                                Pick::Value(v) => {
                                    c.model = Some(v);
                                    step = 5;
                                }
                                Pick::Quit => return Ok(None),
                                _ => {}
                            }
                        }
                        Pick::Value(v) => {
                            c.model = Some(v);
                            step = 5;
                        }
                        Pick::Text(t) => {
                            c.model = t.split('\u{0}').nth(1).map(String::from);
                            step = 5;
                        }
                        Pick::Back => {
                            c.backend = None;
                            step = 3;
                        }
                        Pick::Quit => return Ok(None),
                    }
                }
                5 => {
                    let mut items = vec![Item::new("default", "let the model decide", "")];
                    for (e, d) in [("low", "fastest, cheapest"), ("medium", "balanced"), ("high", "more thinking"), ("xhigh", "coding / agentic work"), ("max", "hardest problems, slowest")] {
                        items.push(Item::new(e, d, e));
                    }
                    match menu(&mut scr, &of(5, &c), "effort", &items, prev.effort.as_deref(), EFFORT_HELP)? {
                        Pick::Value(v) => {
                            c.effort = Some(v);
                            if c.target.as_deref() == Some("aaa") {
                                c.loose = Some(false);
                                return Ok(Some(c.clone()));
                            }
                            step = 6;
                        }
                        Pick::Back => {
                            c.model = None;
                            step = 4;
                        }
                        Pick::Quit => return Ok(None),
                        Pick::Text(_) => {}
                    }
                }
                6 => {
                    // Asking stays the default; loose is preselected only where it was chosen
                    // last time for this same host.
                    let items = vec![
                        Item::new("ask", "prompts before exec / write / edit (the auto-mode classifier may also step in)", "ask"),
                        Item::new("let it loose", "no prompts at all (Claude Code --dangerously-skip-permissions); still only this host, under its AI grant, recorded", "loose"),
                    ];
                    let pre = if prev.loose == Some(true) && prev.target == c.target { "loose" } else { "ask" };
                    match menu(&mut scr, &of(6, &c), "permissions", &items, Some(pre), "")? {
                        Pick::Value(v) => {
                            c.loose = Some(v == "loose");
                            return Ok(Some(c.clone()));
                        }
                        Pick::Back => {
                            c.effort = None;
                            step = 5;
                        }
                        Pick::Quit => return Ok(None),
                        Pick::Text(_) => {}
                    }
                }
                _ => unreachable!(),
            }
        }
    })();
    scr.clear(&mut out);
    let _ = write!(out, "\x1b[?25h");
    let _ = out.flush();
    drop(_raw);
    if let Ok(Some(ch)) = res.as_ref().map(|r| r.as_ref().filter(|c| !c.target.as_deref().unwrap_or("").starts_with('\u{3}'))) {
        let what = match ch.target.as_deref() {
            Some("aaa") => "aaa".to_string(),
            Some(t) => t.to_string(),
            None => String::new(),
        };
        println!(
            "swai: {what} · {} · {} · effort {}{}",
            ch.backend.as_deref().unwrap_or(""),
            ch.model.as_deref().unwrap_or(""),
            ch.effort.as_deref().filter(|e| !e.is_empty()).unwrap_or("default"),
            if ch.loose == Some(true) { " · LOOSE (no permission prompts)" } else { "" }
        );
    }
    res
}

// ---------------------------------------------------------------- inside the sandbox

/// `swai-sandbox <opencode> [args]`: bridge 127.0.0.1:$SWAI_PORT (this netns only) to the proxy
/// socket, then run opencode on the terminal.
pub fn sandbox(args: Vec<String>) -> Result<i32> {
    let Some(prog) = args.first() else { bail!("usage: swai-sandbox <program> [args]") };
    // Bridges from loopback ports (this netns only) to the worker's sockets:
    // SWAI_BRIDGES="4141=/swai/infer.sock,4142=/swai/connect.sock"; SWAI_PORT/SWAI_INFER_SOCK
    // is the older single-bridge form.
    let mut bridges: Vec<(u16, String)> = vec![];
    if let Ok(b) = std::env::var("SWAI_BRIDGES") {
        for part in b.split(',').filter(|p| !p.is_empty()) {
            let (port, sock) = part.split_once('=').context("SWAI_BRIDGES: port=socket")?;
            bridges.push((port.parse().context("SWAI_BRIDGES port")?, sock.to_string()));
        }
    } else {
        let sock = std::env::var("SWAI_INFER_SOCK").context("SWAI_INFER_SOCK")?;
        let port: u16 = std::env::var("SWAI_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(4141);
        bridges.push((port, sock));
    }
    // Fail closed: without the lifeline to the session worker, don't start at all.
    let life = UnixStream::connect(std::env::var("SWAI_LIFE_SOCK").context("SWAI_LIFE_SOCK")?).context("connect the lifeline")?;
    for (port, sock) in bridges {
        let l = std::net::TcpListener::bind(("127.0.0.1", port)).with_context(|| format!("bind the bridge on port {port}"))?;
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let sock = sock.clone();
                std::thread::spawn(move || {
                    let _ = c.set_nodelay(true);
                    if let Ok(u) = UnixStream::connect(&sock) {
                        pump_pair(c, u);
                    }
                });
            }
        });
    }
    let mut child = std::process::Command::new(prog).args(&args[1..]).spawn().with_context(|| format!("run {prog}"))?;
    let pid = child.id() as i32;
    std::thread::spawn(move || {
        // Blocks until the worker goes away (it never writes); then take the sandbox down.
        let mut life = life;
        let mut b = [0u8; 64];
        while matches!(life.read(&mut b), Ok(n) if n > 0) {}
        unsafe { libc::kill(pid, libc::SIGKILL) };
        std::process::exit(137);
    });
    let st = child.wait()?;
    Ok(st.code().unwrap_or(1))
}

fn pump_pair(t: std::net::TcpStream, u: UnixStream) {
    let (Ok(t2), Ok(u2)) = (t.try_clone(), u.try_clone()) else { return };
    let a = std::thread::spawn(move || copy_close(t, u, |u| u.shutdown(std::net::Shutdown::Write)));
    copy_close(u2, t2, |t| t.shutdown(std::net::Shutdown::Write));
    let _ = a.join();
}

fn copy_close<R: Read, W: Write>(mut r: R, mut w: W, close: impl FnOnce(&W) -> std::io::Result<()>) {
    let mut buf = vec![0u8; 64 << 10];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if w.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = close(&w);
}

/// `swai-mcp`: opencode's stdio MCP server = a relay to the worker's MCP socket.
pub fn mcp() -> Result<i32> {
    let sock = std::env::var("SWAI_MCP_SOCK").context("SWAI_MCP_SOCK")?;
    let s = UnixStream::connect(&sock).context("connect to the swrap MCP socket")?;
    let s2 = s.try_clone()?;
    std::thread::spawn(move || copy_close(std::io::stdin(), s2, |s| s.shutdown(std::net::Shutdown::Write)));
    let mut out = std::io::stdout();
    let mut s = s;
    let mut buf = vec![0u8; 64 << 10];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.write_all(&buf[..n]).and_then(|_| out.flush()).is_err() {
                    break;
                }
            }
        }
    }
    Ok(0)
}
