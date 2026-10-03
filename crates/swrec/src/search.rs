//! Search (spec 16.1): streaming zgrep-like scan over `.swrec`/`.swrec.gz`, parallel with rayon.
//!
//! Query language (identical in `swsearch` and the web UI):
//! `window:P7D/now host:web* cmd:/dnf .*install/ out:"permission denied" -ruser:deploy free text`
//! Values are literal (case-insensitive) by default, `/regex/` for a regex, `"…"` for a phrase,
//! `-` negates. Header fields (`host`, `ruser`, `user`) take globs.

use crate::reader::{for_each_raw_line, header_and_last_ts, is_gz};
use crate::format::decode_line;
use crate::render::{rec_bytes, AnsiStripper, KeyRenderer};
use anyhow::{bail, Result};
use globset::{Glob, GlobMatcher};
use jiff::Timestamp;
use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use swrap_core::time::Interval;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Host,
    Ruser,
    User,
    Kind,
    Node,
    Cmd,
    Keys,
    Out,
    File,
    /// swai: what the user typed / what the model answered / tool calls.
    Prompt,
    Reply,
    Tool,
    Free,
}

impl Field {
    fn parse(s: &str) -> Option<Field> {
        Some(match s {
            "host" => Field::Host,
            "ruser" => Field::Ruser,
            "user" => Field::User,
            "kind" => Field::Kind,
            "node" => Field::Node,
            "cmd" => Field::Cmd,
            "keys" => Field::Keys,
            "out" => Field::Out,
            "file" => Field::File,
            "prompt" => Field::Prompt,
            "reply" => Field::Reply,
            "tool" => Field::Tool,
            _ => return None,
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Field::Host => "host",
            Field::Ruser => "ruser",
            Field::User => "user",
            Field::Kind => "kind",
            Field::Node => "node",
            Field::Cmd => "cmd",
            Field::Keys => "keys",
            Field::Out => "out",
            Field::File => "file",
            Field::Prompt => "prompt",
            Field::Reply => "reply",
            Field::Tool => "tool",
            Field::Free => "text",
        }
    }
    fn is_header(&self) -> bool {
        matches!(self, Field::Host | Field::Ruser | Field::User | Field::Kind | Field::Node)
    }
}

#[derive(Debug, Clone)]
pub enum Matcher {
    Re(Regex),
    Glob(GlobMatcher),
}

impl Matcher {
    fn is_match(&self, s: &str) -> bool {
        match self {
            Matcher::Re(r) => r.is_match(s),
            Matcher::Glob(g) => g.is_match(s),
        }
    }
    fn find(&self, s: &str) -> Option<(usize, usize)> {
        match self {
            Matcher::Re(r) => r.find(s).map(|m| (m.start(), m.end())),
            Matcher::Glob(g) => g.is_match(s).then_some((0, s.len())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Term {
    pub field: Field,
    pub neg: bool,
    pub m: Matcher,
    pub raw: String,
}

#[derive(Debug, Clone)]
pub struct Query {
    pub window: Option<Interval>,
    pub terms: Vec<Term>,
}

fn tokenize(q: &str) -> Result<Vec<String>> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut chars = q.chars().peekable();
    let mut in_quote = false;
    let mut in_re = false;
    while let Some(c) = chars.next() {
        if in_quote {
            if c == '\\' {
                if let Some(n) = chars.next() {
                    cur.push('\\');
                    cur.push(n);
                }
                continue;
            }
            cur.push(c);
            if c == '"' {
                in_quote = false;
            }
            continue;
        }
        if in_re {
            cur.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            } else if c == '/' {
                in_re = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_quote = true;
                cur.push(c);
            }
            '/' if cur.is_empty() || cur.ends_with(':') || cur == "-" => {
                in_re = true;
                cur.push(c);
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if in_quote || in_re {
        bail!("unterminated {} in query", if in_quote { "quote" } else { "regex" });
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

fn value_matcher(v: &str, glob: bool) -> Result<Matcher> {
    if v.len() >= 2 && v.starts_with('/') && v.ends_with('/') {
        return Ok(Matcher::Re(Regex::new(&v[1..v.len() - 1])?));
    }
    let lit = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        v[1..v.len() - 1].replace("\\\"", "\"").replace("\\\\", "\\")
    } else {
        v.to_string()
    };
    if glob {
        return Ok(Matcher::Glob(Glob::new(&lit)?.compile_matcher()));
    }
    Ok(Matcher::Re(Regex::new(&format!("(?i){}", regex::escape(&lit)))?))
}

impl Query {
    pub fn parse(q: &str) -> Result<Query> {
        Self::parse_at(q, swrap_core::time::now())
    }

    pub fn parse_at(q: &str, now: Timestamp) -> Result<Query> {
        let mut window = None;
        let mut terms = vec![];
        for tok in tokenize(q)? {
            let (neg, t) = match tok.strip_prefix('-') {
                Some(r) if !r.is_empty() => (true, r),
                _ => (false, tok.as_str()),
            };
            let (field, value) = match t.split_once(':') {
                Some((f, v)) if f == "window" => {
                    window = Some(Interval::parse_at(v, now)?);
                    continue;
                }
                Some((f, v)) if Field::parse(f).is_some() && !t.starts_with('"') && !t.starts_with('/') => (Field::parse(f).unwrap(), v),
                _ => (Field::Free, t),
            };
            if value.is_empty() {
                bail!("empty value for {}", field.name());
            }
            let glob = matches!(field, Field::Host | Field::Ruser | Field::User);
            let m = if matches!(field, Field::Kind | Field::Node) {
                Matcher::Re(Regex::new(&format!("^{}$", regex::escape(value)))?)
            } else {
                value_matcher(value, glob)?
            };
            terms.push(Term { field, neg, m, raw: value.to_string() });
        }
        Ok(Query { window, terms })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub id: String,
    pub path: String,
    pub kind: String,
    pub user: String,
    pub label: String,
    pub ruser: String,
    pub origin: String,
    pub exec: String,
    pub start: String,
    pub field: &'static str,
    pub ts: String,
    pub snippet: String,
    /// Size of the record file on disk (compressed size for `.swrec.gz`).
    pub bytes: u64,
    pub gz: bool,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct Progress {
    pub files_total: u64,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub hits: u64,
}

pub struct SearchOpts<'a> {
    pub root: PathBuf,
    /// None = admin (all users); Some(list) = only these users' records.
    pub users: Option<Vec<String>>,
    pub max_results: usize,
    pub cancel: &'a AtomicBool,
    pub kinds: Vec<String>,
}

/// Candidate file with the date from its directory.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub path: PathBuf,
    pub user: String,
    pub kind: String,
}

fn date_of_dir(y: &str, m: &str, d: &str) -> Option<jiff::civil::Date> {
    jiff::civil::Date::new(y.parse().ok()?, m.parse().ok()?, d.parse().ok()?).ok()
}

/// Enumerate record files, pruned by `YYYY/MM/DD` path (with mtime rescue for sessions that
/// started earlier but ran into the window).
pub fn candidates(root: &Path, users: Option<&[String]>, kinds: &[String], window: &Interval) -> Vec<Candidate> {
    let mut out = vec![];
    let start_date = window.start.to_zoned(jiff::tz::TimeZone::UTC).date();
    let end_date = window.end.to_zoned(jiff::tz::TimeZone::UTC).date();
    let rec = root.join("rec");
    let Ok(ud) = std::fs::read_dir(&rec) else { return out };
    for u in ud.flatten() {
        let user = u.file_name().to_string_lossy().to_string();
        if let Some(us) = users {
            if !us.iter().any(|x| x == &user) {
                continue;
            }
        }
        for kind in ["sw", "shell", "sftp", "ai"] {
            if !kinds.is_empty() && !kinds.iter().any(|k| k == kind) {
                continue;
            }
            walk_dated(&u.path().join(kind), start_date, end_date, window, &mut |p| {
                out.push(Candidate { path: p, user: user.clone(), kind: kind.into() })
            });
        }
    }
    if users.is_none() && (kinds.is_empty() || kinds.iter().any(|k| k == "run")) {
        walk_dated(&root.join("runs"), start_date, end_date, window, &mut |p| {
            out.push(Candidate { path: p, user: String::new(), kind: "run".into() })
        });
    }
    out
}

fn walk_dated(base: &Path, sd: jiff::civil::Date, ed: jiff::civil::Date, window: &Interval, f: &mut dyn FnMut(PathBuf)) {
    let Ok(ys) = std::fs::read_dir(base) else { return };
    for y in ys.flatten() {
        let yn = y.file_name().to_string_lossy().to_string();
        if yn.len() != 4 || yn.as_str() > ed.year().to_string().as_str() {
            continue;
        }
        let Ok(ms) = std::fs::read_dir(y.path()) else { continue };
        for m in ms.flatten() {
            let mn = m.file_name().to_string_lossy().to_string();
            let Ok(ds) = std::fs::read_dir(m.path()) else { continue };
            for d in ds.flatten() {
                let dn = d.file_name().to_string_lossy().to_string();
                let Some(date) = date_of_dir(&yn, &mn, &dn) else { continue };
                if date > ed {
                    continue;
                }
                let early = date < sd;
                collect_files(&d.path(), early, window, f);
            }
        }
    }
}

fn collect_files(dir: &Path, early: bool, window: &Interval, f: &mut dyn FnMut(PathBuf)) {
    let Ok(fs) = std::fs::read_dir(dir) else { return };
    for e in fs.flatten() {
        let p = e.path();
        if p.is_dir() {
            // runs/<date>/<run dir>/<host>.swrec
            collect_files(&p, early, window, f);
            continue;
        }
        let n = p.to_string_lossy();
        if !(n.ends_with(".swrec") || n.ends_with(".swrec.gz")) {
            continue;
        }
        if early {
            // Started before the window: only if it was still being written inside it.
            let mt = e.metadata().ok().and_then(|m| m.modified().ok());
            let Some(mt) = mt else { continue };
            let Ok(mts) = Timestamp::try_from(mt) else { continue };
            if mts < window.start {
                continue;
            }
        }
        f(p);
    }
}

fn hstr(h: &Map<String, Value>, k: &str) -> String {
    h.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

fn header_matches(t: &Term, h: &Map<String, Value>, user: &str, kind: &str) -> bool {
    match t.field {
        Field::Host => t.m.is_match(&hstr(h, "label")) || t.m.is_match(&hstr(h, "addr")),
        Field::Ruser => t.m.is_match(&hstr(h, "ruser")),
        Field::User => t.m.is_match(&hstr(h, "aaa_user")) || t.m.is_match(user),
        Field::Kind => t.m.is_match(&hstr(h, "kind")) || t.m.is_match(kind),
        Field::Node => t.m.is_match(&hstr(h, "origin")) || t.m.is_match(&hstr(h, "exec")),
        _ => false,
    }
}

fn header_text(h: &Map<String, Value>) -> String {
    let mut s = String::new();
    for (k, v) in h {
        if let Some(x) = v.as_str() {
            s.push_str(k);
            s.push('=');
            s.push_str(x);
            s.push(' ');
        }
    }
    s
}

fn snippet(text: &str, a: usize, b: usize) -> String {
    let mut s = a.saturating_sub(60);
    while !text.is_char_boundary(s) {
        s -= 1;
    }
    let mut e = (b + 60).min(text.len());
    while !text.is_char_boundary(e) {
        e += 1;
    }
    let mut out = String::new();
    if s > 0 {
        out.push('…');
    }
    out.push_str(&text[s..e].replace(['\r'], "").replace('\n', "⏎"));
    if e < text.len() {
        out.push('…');
    }
    out
}

/// Text stream of one field with ts mapping: (offset in text, ts).
struct Stream {
    text: String,
    map: Vec<(usize, String)>,
}

impl Stream {
    fn new() -> Self {
        Stream { text: String::new(), map: vec![] }
    }
    fn mark(&mut self, ts: &str) {
        if self.map.last().map(|(o, _)| *o != self.text.len()).unwrap_or(true) {
            self.map.push((self.text.len(), ts.to_string()));
        }
    }
    fn ts_at(&self, off: usize) -> String {
        match self.map.binary_search_by(|(o, _)| o.cmp(&off)) {
            Ok(i) => self.map[i].1.clone(),
            Err(0) => self.map.first().map(|x| x.1.clone()).unwrap_or_default(),
            Err(i) => self.map[i - 1].1.clone(),
        }
    }
}

/// Scan one file. Returns hits (empty if the file doesn't qualify) and bytes read.
pub fn scan_file(c: &Candidate, q: &Query, window: &Interval, per_file_max: usize) -> (Vec<Hit>, u64) {
    let (h, last_ts, _) = header_and_last_ts(&c.path);
    let Some(h) = h else { return (vec![], 0) };
    // Prune by header start and last ts.
    let start = hstr(&h, "start");
    if let Ok(st) = start.parse::<Timestamp>() {
        let end = last_ts.as_deref().and_then(|t| t.parse::<Timestamp>().ok()).unwrap_or(st);
        if !window.overlaps(st, end) {
            return (vec![], 0);
        }
    }
    let kind = { let k = hstr(&h, "kind"); if k.is_empty() { c.kind.clone() } else { k } };
    for t in q.terms.iter().filter(|t| t.field.is_header()) {
        if header_matches(t, &h, &c.user, &kind) == t.neg {
            return (vec![], 0);
        }
    }
    let content: Vec<&Term> = q.terms.iter().filter(|t| !t.field.is_header()).collect();
    let file_bytes = std::fs::metadata(&c.path).map(|m| m.len()).unwrap_or(0);
    let file_gz = is_gz(&c.path);
    let mk_hit = |field: &'static str, ts: String, snip: String| Hit {
        id: hstr(&h, "id"),
        path: c.path.to_string_lossy().into(),
        kind: kind.clone(),
        user: { let u = hstr(&h, "aaa_user"); if u.is_empty() { c.user.clone() } else { u } },
        label: hstr(&h, "label"),
        ruser: hstr(&h, "ruser"),
        origin: hstr(&h, "origin"),
        exec: hstr(&h, "exec"),
        start: start.clone(),
        field,
        ts,
        snippet: snip,
        bytes: file_bytes,
        gz: file_gz,
    };
    if content.is_empty() {
        return (vec![mk_hit("header", start.clone(), header_text(&h))], 0);
    }
    let need = |f: Field| content.iter().any(|t| t.field == f || t.field == Field::Free);
    let (mut out, mut keys, mut cmd, mut file) = (Stream::new(), Stream::new(), Stream::new(), Stream::new());
    let (mut prompt, mut reply, mut tool) = (Stream::new(), Stream::new(), Stream::new());
    let mut strip = AnsiStripper::default();
    let mut strip_tool = AnsiStripper::default();
    let mut kr = KeyRenderer::default();
    let (n_out, n_keys, n_cmd, n_file) = (need(Field::Out), need(Field::Keys), need(Field::Cmd), need(Field::File));
    let (n_prompt, n_reply, n_tool) = (need(Field::Prompt), need(Field::Reply), need(Field::Tool));
    let mut bytes = 0u64;
    let _ = for_each_raw_line(&c.path, |l| {
        bytes += l.bytes.len() as u64 + 1;
        if !l.complete {
            return true;
        }
        let Ok(m) = decode_line(l.bytes) else { return true };
        let ts = m.get("ts").and_then(Value::as_str).unwrap_or("");
        let in_window = ts.parse::<Timestamp>().map(|t| window.contains(t)).unwrap_or(false);
        match m.get("k").and_then(Value::as_str).unwrap_or("") {
            // swai tool output: plain text, its own escape state.
            "o" if n_out && m.contains_key("call") => {
                if in_window { out.mark(ts) } else { out.mark("") }
                strip_tool.push(&rec_bytes(&m), &mut out.text);
                out.text.push('\n');
            }
            "m" if (n_prompt || n_reply) && in_window && m.get("aux").and_then(Value::as_bool) != Some(true) => {
                let role = m.get("role").and_then(Value::as_str).unwrap_or("");
                let s = if role == "user" && n_prompt { Some(&mut prompt) } else if role == "assistant" && n_reply { Some(&mut reply) } else { None };
                if let (Some(s), Some(t)) = (s, crate::ai::msg_text(role, m.get("content").unwrap_or(&Value::Null))) {
                    s.mark(ts);
                    s.text.push_str(&t);
                    s.text.push('\n');
                }
            }
            "t" if (n_tool || n_cmd) && in_window => {
                let args = m.get("args").cloned().unwrap_or(Value::Null);
                if n_tool {
                    tool.mark(ts);
                    tool.text.push_str(m.get("tool").and_then(Value::as_str).unwrap_or(""));
                    tool.text.push(' ');
                    tool.text.push_str(m.get("target").and_then(Value::as_str).unwrap_or(""));
                    tool.text.push(' ');
                    tool.text.push_str(&args.to_string());
                    tool.text.push('\n');
                }
                if let (true, Some(c)) = (n_cmd, args.get("command").and_then(Value::as_str)) {
                    cmd.mark(ts);
                    cmd.text.push_str(c);
                    cmd.text.push('\n');
                }
            }
            "o" if n_out => {
                // Stream everything (so escapes/lines join across chunks) but only map in-window ts.
                if in_window { out.mark(ts) } else { out.mark("") }
                strip.push(&rec_bytes(&m), &mut out.text);
            }
            "i" if n_keys => {
                if in_window { keys.mark(ts) } else { keys.mark("") }
                kr.push(&rec_bytes(&m), &mut keys.text);
            }
            "x" if n_cmd && in_window => {
                cmd.mark(ts);
                cmd.text.push_str(m.get("cmd").and_then(Value::as_str).unwrap_or(""));
                cmd.text.push('\n');
            }
            "f" if n_file && in_window => {
                file.mark(ts);
                // `host:path`, so a hit says where (SFTP sessions span hosts).
                let label = m.get("label").and_then(Value::as_str).unwrap_or("");
                for k in ["path", "path2"] {
                    if let Some(p) = m.get(k).and_then(Value::as_str) {
                        if !label.is_empty() {
                            file.text.push_str(label);
                            file.text.push(':');
                        }
                        file.text.push_str(p);
                        file.text.push(' ');
                    }
                }
                file.text.push('\n');
            }
            _ => {}
        }
        true
    });
    // Run commands: header cmd / script name count as `cmd`.
    if n_cmd && kind == "run" {
        let hc = format!("{} {}", hstr(&h, "cmd"), hstr(&h, "script"));
        cmd.mark(&start);
        cmd.text.push_str(&hc);
    }
    let mut hdr = Stream::new();
    hdr.mark(&start);
    hdr.text = header_text(&h);

    let mut hits = vec![];
    for t in &content {
        let streams: Vec<(&'static str, &Stream)> = match t.field {
            Field::Out => vec![("out", &out)],
            Field::Keys => vec![("keys", &keys)],
            Field::Cmd => vec![("cmd", &cmd)],
            Field::File => vec![("file", &file)],
            Field::Prompt => vec![("prompt", &prompt)],
            Field::Reply => vec![("reply", &reply)],
            Field::Tool => vec![("tool", &tool)],
            _ => vec![("prompt", &prompt), ("reply", &reply), ("tool", &tool), ("cmd", &cmd), ("out", &out), ("keys", &keys), ("file", &file), ("header", &hdr)],
        };
        let mut found = false;
        for (name, s) in streams {
            let mut pos = 0;
            while pos <= s.text.len() {
                let Some((a, b)) = (match &t.m {
                    Matcher::Re(r) => r.find_at(&s.text, pos).map(|m| (m.start(), m.end())),
                    other => if pos == 0 { other.find(&s.text) } else { None },
                }) else { break };
                let ts = s.ts_at(a);
                pos = if b > a { b } else { b + 1 };
                if ts.is_empty() {
                    continue; // outside window
                }
                found = true;
                if t.neg {
                    break;
                }
                if hits.len() < per_file_max {
                    hits.push(mk_hit(name, ts, snippet(&s.text, a, b)));
                } else {
                    break;
                }
            }
            if found && t.neg {
                break;
            }
        }
        if found == t.neg {
            return (vec![], bytes);
        }
    }
    hits.sort_by(|a, b| a.ts.cmp(&b.ts));
    (hits, bytes)
}

/// Run a search, streaming hits and progress to callbacks. Returns final progress.
pub fn run(
    q: &Query,
    opts: &SearchOpts,
    on_hit: &(dyn Fn(&Hit) + Sync),
    on_progress: &(dyn Fn(&Progress) + Sync),
) -> Result<Progress> {
    let window = q.window.unwrap_or_else(|| Interval::parse("P1D/now").unwrap());
    let kinds: Vec<String> = if opts.kinds.is_empty() {
        q.terms.iter().filter(|t| t.field == Field::Kind && !t.neg).map(|t| t.raw.clone()).collect()
    } else {
        opts.kinds.clone()
    };
    let mut cands = candidates(&opts.root, opts.users.as_deref(), &kinds, &window);
    cands.sort_by(|a, b| b.path.file_name().cmp(&a.path.file_name()));
    let total = cands.len() as u64;
    let scanned = AtomicU64::new(0);
    let bytes = AtomicU64::new(0);
    let nhits = AtomicUsize::new(0);
    let last_report = std::sync::Mutex::new(std::time::Instant::now());
    cands.par_iter().for_each(|c| {
        if opts.cancel.load(Ordering::Relaxed) || nhits.load(Ordering::Relaxed) >= opts.max_results {
            return;
        }
        let (hits, b) = scan_file(c, q, &window, 50);
        bytes.fetch_add(b, Ordering::Relaxed);
        for h in &hits {
            if nhits.fetch_add(1, Ordering::SeqCst) < opts.max_results {
                on_hit(h);
            }
        }
        let n = scanned.fetch_add(1, Ordering::Relaxed) + 1;
        let mut lr = last_report.lock().unwrap();
        if lr.elapsed().as_millis() > 200 {
            *lr = std::time::Instant::now();
            on_progress(&Progress { files_total: total, files_scanned: n, bytes_scanned: bytes.load(Ordering::Relaxed), hits: nhits.load(Ordering::Relaxed).min(opts.max_results) as u64 });
        }
    });
    let p = Progress {
        files_total: total,
        files_scanned: scanned.load(Ordering::Relaxed),
        bytes_scanned: bytes.load(Ordering::Relaxed),
        hits: nhits.load(Ordering::Relaxed).min(opts.max_results) as u64,
    };
    on_progress(&p);
    Ok(p)
}

pub fn is_record_file(p: &Path) -> bool {
    let n = p.to_string_lossy();
    n.ends_with(".swrec") || (is_gz(p) && n.ends_with(".swrec.gz"))
}

/// Locate a record file (or run directory) by ULID; `users` limits the search (None = all).
pub fn find_record(root: &Path, users: Option<&[String]>, id: &str) -> Option<PathBuf> {
    // ULIDs sort by time, so we can bound the scan by the id's timestamp when complete.
    let rec = root.join("rec");
    let mut dirs: Vec<PathBuf> = vec![];
    if let Ok(rd) = std::fs::read_dir(&rec) {
        for u in rd.flatten() {
            let n = u.file_name().to_string_lossy().to_string();
            if users.map(|us| us.contains(&n)).unwrap_or(true) {
                for k in ["sw", "shell", "sftp", "ai"] {
                    dirs.push(u.path().join(k));
                }
            }
        }
    }
    if users.is_none() {
        dirs.push(root.join("runs"));
    }
    let date = ulid::Ulid::from_string(id).ok().map(|u| {
        let ms = u.timestamp_ms();
        let t = jiff::Timestamp::from_millisecond(ms as i64).unwrap_or(jiff::Timestamp::UNIX_EPOCH);
        swrap_core::time::date_dir(t)
    });
    for base in dirs {
        let search_dirs: Vec<PathBuf> = match &date {
            Some(dd) => vec![base.join(dd)],
            None => walk_dirs(&base),
        };
        for dir in search_dirs {
            if let Some(p) = scan_dir_for(&dir, id) {
                return Some(p);
            }
        }
    }
    None
}

fn walk_dirs(base: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    let Ok(ys) = std::fs::read_dir(base) else { return out };
    for y in ys.flatten() {
        let Ok(ms) = std::fs::read_dir(y.path()) else { continue };
        for m in ms.flatten() {
            let Ok(ds) = std::fs::read_dir(m.path()) else { continue };
            for dd in ds.flatten() {
                out.push(dd.path());
            }
        }
    }
    out.sort();
    out.reverse();
    out
}

fn scan_dir_for(dir: &Path, id: &str) -> Option<PathBuf> {
    let rd = std::fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let p = e.path();
        let n = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if n.contains(id) {
                return Some(p);
            }
            if let Some(x) = scan_dir_for(&p, id) {
                return Some(x);
            }
        } else if n.contains(&format!("_{id}")) && is_record_file(&p) {
            return Some(p);
        }
    }
    None
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_query() {
        let q = Query::parse(r#"window:P7D/now host:web* cmd:/dnf .*install/ out:"permission denied" -ruser:deploy hello"#).unwrap();
        assert!(q.window.is_some());
        assert_eq!(q.terms.len(), 5);
        assert_eq!(q.terms[0].field, Field::Host);
        assert_eq!(q.terms[1].field, Field::Cmd);
        assert!(q.terms[1].m.is_match("dnf -y install x"));
        assert!(q.terms[2].m.is_match("xx Permission denied yy"));
        assert!(q.terms[3].neg);
        assert_eq!(q.terms[4].field, Field::Free);
        assert!(Query::parse("window:7d").is_err());
        assert!(Query::parse("out:\"unterminated").is_err());
    }
}
