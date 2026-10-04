//! swai recordings (spec 24.8): text of stored messages and a readable chat transcript.
//!
//! An `ai` file holds the TUI stream (o/i/r) plus `m` (message bodies, stored once and referenced
//! by hash), `q` (requests), `a` (responses), `t` (tool calls) and `o` records carrying `call`
//! (full tool output). Requests without tools are opencode's own helpers (titles, compaction).

use crate::render::{rec_bytes, strip_ansi};
use crate::text::CatOpts;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use swrap_core::time::fmt_display;

/// Is this an `ai` recording (by its records)?
pub fn is_ai(records: &[Map<String, Value>]) -> bool {
    records.iter().take(64).any(|m| matches!(m.get("k").and_then(Value::as_str), Some("q" | "m")))
}

/// Human text of a message: what the user typed (`user`) or the model wrote (`assistant`).
/// Tool results, tool calls, system prompts and tool lists are not text.
pub fn msg_text(role: &str, content: &Value) -> Option<String> {
    if role != "user" && role != "assistant" {
        return None;
    }
    // OpenAI-style bodies are stored as {content, tool_calls, …}.
    let c = match content {
        Value::Object(o) if o.contains_key("content") || o.contains_key("tool_calls") => o.get("content").unwrap_or(&Value::Null),
        other => other,
    };
    let text = match c {
        Value::String(s) => s.clone(),
        Value::Array(a) => a
            .iter()
            .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    };
    let t = text.trim();
    (!t.is_empty()).then(|| t.to_string())
}

fn when(ts: &str, o: &CatOpts) -> String {
    ts.parse::<jiff::Timestamp>().map(|t| fmt_display(t, o.tz, o.utc)).unwrap_or_else(|_| ts.to_string())
}

fn indent(s: &str, prefix: &str) -> String {
    s.lines().map(|l| format!("{prefix}{l}")).collect::<Vec<_>>().join("\n")
}

const TOOL_LINES: usize = 40;

/// Chat transcript: prompts, replies, tool calls with (capped) output, notes, errors.
pub fn transcript(records: &[Map<String, Value>], o: &CatOpts, out: &mut dyn std::io::Write) -> std::io::Result<()> {
    let mut msgs: HashMap<String, (String, Value)> = HashMap::new();
    let mut shown: HashSet<String> = HashSet::new();
    let mut aux: HashSet<u64> = HashSet::new();
    let mut tool_out: HashMap<String, (usize, usize)> = HashMap::new(); // call -> (lines shown, lines hidden)
    let mut open_call: Option<String> = None;
    let flush_call = |out: &mut dyn std::io::Write, call: &Option<String>, tool_out: &HashMap<String, (usize, usize)>| -> std::io::Result<()> {
        if let Some(c) = call {
            if let Some((_, hidden)) = tool_out.get(c) {
                if *hidden > 0 {
                    writeln!(out, "      … {hidden} more lines (full output in the recording)")?;
                }
            }
        }
        Ok(())
    };
    for m in records {
        let k = m.get("k").and_then(Value::as_str).unwrap_or("");
        let ts = m.get("ts").and_then(Value::as_str).unwrap_or("");
        let s = |f: &str| m.get(f).and_then(Value::as_str).unwrap_or("").to_string();
        if k != "o" && open_call.is_some() {
            flush_call(out, &open_call, &tool_out)?;
            open_call = None;
        }
        match k {
            "m" => {
                msgs.insert(s("h"), (s("role"), m.get("content").cloned().unwrap_or(Value::Null)));
            }
            "q" => {
                let n = m.get("n").and_then(Value::as_u64).unwrap_or(0);
                if m.get("tools").map(Value::is_null).unwrap_or(true) {
                    aux.insert(n);
                    continue;
                }
                for h in m.get("msgs").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                    if shown.insert(h.to_string()) {
                        if let Some((role, content)) = msgs.get(h) {
                            if role == "user" {
                                if let Some(t) = msg_text(role, content) {
                                    writeln!(out, "{}  ▶ you\n{}\n", when(ts, o), indent(&t, "    "))?;
                                }
                            }
                        }
                    }
                }
            }
            "a" => {
                let n = m.get("n").and_then(Value::as_u64).unwrap_or(0);
                if aux.contains(&n) {
                    continue;
                }
                let status = m.get("status").and_then(Value::as_u64).unwrap_or(200);
                if status >= 400 || m.get("error").map(|e| !e.is_null()).unwrap_or(false) {
                    let e = m.get("error").map(|e| e.as_str().map(String::from).unwrap_or_else(|| e.to_string())).unwrap_or_default();
                    writeln!(out, "{}  ✗ inference error {status}: {}\n", when(ts, o), e.chars().take(500).collect::<String>())?;
                    continue;
                }
                if let Some(h) = m.get("h").and_then(Value::as_str) {
                    shown.insert(h.to_string());
                    if let Some(t) = msgs.get(h).and_then(|(r, c)| msg_text(r, c)) {
                        writeln!(out, "{}  ◀ {}\n{}\n", when(ts, o), m.get("model").and_then(Value::as_str).unwrap_or("assistant"), indent(&t, "    "))?;
                    }
                }
            }
            "t" => {
                let call = s("call");
                let args = m.get("args").cloned().unwrap_or(Value::Null);
                let what = match s("tool").as_str() {
                    "exec" => args.get("command").and_then(Value::as_str).unwrap_or("").to_string(),
                    "read_file" | "write_file" | "edit_file" => args.get("path").and_then(Value::as_str).unwrap_or("").to_string(),
                    "search" => args.get("query").and_then(Value::as_str).unwrap_or("").to_string(),
                    "transcript" => args.get("id").and_then(Value::as_str).unwrap_or("").to_string(),
                    _ => String::new(),
                };
                let target = match (s("ruser"), s("target")) {
                    (r, t) if !t.is_empty() => format!(" {r}@{t}"),
                    _ => String::new(),
                };
                let result = if m.get("error").and_then(Value::as_bool) == Some(true) {
                    format!("error: {}", s("result").trim_start_matches("error: ").lines().next().unwrap_or(""))
                } else if let Some(x) = m.get("exit").and_then(Value::as_i64) {
                    format!("exit {x}")
                } else {
                    "ok".into()
                };
                writeln!(out, "{}  ⚙ {}{target}: {what}  → {result} ({})", when(ts, o), s("tool"), s("duration"))?;
                tool_out.insert(call.clone(), (0, 0));
                open_call = Some(call);
            }
            "o" => {
                let Some(call) = m.get("call").and_then(Value::as_str) else { continue };
                let text = if o.raw { String::from_utf8_lossy(&rec_bytes(m)).into_owned() } else { strip_ansi(&rec_bytes(m)) };
                let e = tool_out.entry(call.to_string()).or_insert((0, 0));
                let err = m.get("fd").and_then(Value::as_u64) == Some(2);
                for l in text.lines() {
                    if e.0 < TOOL_LINES {
                        writeln!(out, "    {}{l}", if err { "! " } else { "| " })?;
                        e.0 += 1;
                    } else {
                        e.1 += 1;
                    }
                }
            }
            "n" => {
                let msg = s("msg");
                if msg != "swai session totals" {
                    writeln!(out, "{}  [note] {msg}", when(ts, o))?;
                } else if let Some(st) = m.get("stats") {
                    writeln!(out, "{}  [totals] {st}", when(ts, o))?;
                }
            }
            "e" => {
                writeln!(out, "{}  [end] {} (exit code {})", when(ts, o), s("reason"), m.get("exit_code").map(|v| v.to_string()).unwrap_or_default())?;
            }
            _ => {}
        }
    }
    flush_call(out, &open_call, &tool_out)?;
    Ok(())
}

/// Up to `max` bytes of `s` (on a char boundary), and whether it was cut.
fn cap(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_string(), false);
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    (s[..i].to_string(), true)
}

/// Token counts of an answer, the same for Anthropic and OpenAI bodies:
/// (input incl. cache, output, cache read, cache write).
fn usage(u: &Value) -> Value {
    let n = |k: &str| u.get(k).and_then(Value::as_u64).unwrap_or(0);
    let (input, cache_read, cache_write) = if u.get("prompt_tokens").is_some() {
        (n("prompt_tokens"), u.pointer("/prompt_tokens_details/cached_tokens").and_then(Value::as_u64).unwrap_or(0), 0)
    } else {
        let (r, w) = (n("cache_read_input_tokens"), n("cache_creation_input_tokens"));
        (n("input_tokens") + r + w, r, w)
    };
    let output = if u.get("completion_tokens").is_some() { n("completion_tokens") } else { n("output_tokens") };
    serde_json::json!({"in": input, "out": output, "cache_read": cache_read, "cache_write": cache_write})
}

/// The tool name a harness gives swrap's tool `t` (`mcp__swrap__exec`, `swrap_exec`, `exec`).
fn names_tool(name: &str, tool: &str) -> bool {
    name == tool || name.ends_with(&format!("__{tool}")) || name.ends_with(&format!("_{tool}"))
}

/// Blocks of a message body, the same for both API styles: (texts, thinking, tool uses, context).
/// Context = Claude Code's `<system-reminder>` text blocks (not typed by anyone).
fn blocks(content: &Value) -> (Vec<String>, Vec<String>, Vec<Value>, Vec<String>) {
    let (mut text, mut think, mut tools, mut ctx) = (vec![], vec![], vec![], vec![]);
    let (body, calls) = match content {
        Value::Object(o) => (o.get("content").cloned().unwrap_or(Value::Null), o.get("tool_calls").cloned()),
        other => (other.clone(), None),
    };
    if let Value::Object(o) = content {
        for k in ["reasoning_content", "reasoning"] {
            if let Some(r) = o.get(k).and_then(Value::as_str).filter(|r| !r.trim().is_empty()) {
                think.push(r.to_string());
            }
        }
    }
    match &body {
        Value::String(t) if !t.trim().is_empty() => text.push(t.clone()),
        Value::Array(a) => {
            for b in a {
                match b.get("type").and_then(Value::as_str).unwrap_or("") {
                    "text" => {
                        let t = b.get("text").and_then(Value::as_str).unwrap_or("");
                        if t.trim_start().starts_with("<system-reminder>") {
                            ctx.push(t.to_string());
                        } else if !t.trim().is_empty() {
                            text.push(t.to_string());
                        }
                    }
                    "thinking" => think.push(b.get("thinking").and_then(Value::as_str).unwrap_or("").to_string()),
                    "redacted_thinking" => think.push(String::new()),
                    "tool_use" => tools.push(serde_json::json!({"id": b.get("id"), "name": b.get("name"), "input": b.get("input")})),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    for c in calls.as_ref().and_then(Value::as_array).into_iter().flatten() {
        let f = c.get("function").cloned().unwrap_or(Value::Null);
        let input = f.get("arguments").and_then(Value::as_str).and_then(|a| serde_json::from_str::<Value>(a).ok()).unwrap_or_else(|| f.get("arguments").cloned().unwrap_or(Value::Null));
        tools.push(serde_json::json!({"id": c.get("id"), "name": f.get("name"), "input": input}));
    }
    (text, think, tools, ctx)
}

const CHAT_TEXT_MAX: usize = 64 << 10;

/// Structured chat (spec 24.9, the web player's chat view): prompts, replies with their tokens
/// and latency, tool calls with arguments and results (the `t` record, matched to the model's
/// tool use), errors, helper requests, notes. Every item has `ts` and `t` (seconds from start).
pub fn chat(records: &[Map<String, Value>]) -> Value {
    use serde_json::json;
    let start = records.iter().find(|m| m.get("k").and_then(Value::as_str) == Some("h")).and_then(|h| h.get("start")).and_then(Value::as_str).unwrap_or("").to_string();
    let t0 = start.parse::<jiff::Timestamp>().ok();
    let rel = |ts: &str| -> f64 { match (t0, ts.parse::<jiff::Timestamp>().ok()) { (Some(a), Some(b)) => (b.as_microsecond() - a.as_microsecond()) as f64 / 1e6, _ => 0.0 } };
    let mut msgs: HashMap<String, (String, Value)> = HashMap::new();
    let mut shown: HashSet<String> = HashSet::new();
    let mut aux: HashSet<u64> = HashSet::new();
    let mut items: Vec<Value> = vec![];
    let mut tot = json!({"requests": 0, "helper_requests": 0, "in": 0, "out": 0, "cache_read": 0, "cache_write": 0, "tool_calls": 0, "errors": 0});
    let add = |tot: &mut Value, k: &str, n: u64| {
        tot[k] = json!(tot[k].as_u64().unwrap_or(0) + n);
    };
    let mut end = Value::Null;
    for m in records {
        let k = m.get("k").and_then(Value::as_str).unwrap_or("");
        let ts = m.get("ts").and_then(Value::as_str).unwrap_or("").to_string();
        let s = |f: &str| m.get(f).and_then(Value::as_str).unwrap_or("").to_string();
        match k {
            "m" => {
                msgs.insert(s("h"), (s("role"), m.get("content").cloned().unwrap_or(Value::Null)));
            }
            "q" => {
                let n = m.get("n").and_then(Value::as_u64).unwrap_or(0);
                if m.get("tools").map(Value::is_null).unwrap_or(true) {
                    aux.insert(n);
                    continue;
                }
                for h in m.get("msgs").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                    if !shown.insert(h.to_string()) {
                        continue;
                    }
                    let Some((role, content)) = msgs.get(h) else { continue };
                    if role != "user" {
                        continue;
                    }
                    let (text, _, _, ctx) = blocks(content);
                    if text.is_empty() && ctx.is_empty() {
                        continue;
                    }
                    let (text, cut) = cap(&text.join("\n\n"), CHAT_TEXT_MAX);
                    items.push(json!({"type": "prompt", "ts": ts, "t": rel(&ts), "text": text, "cut": cut, "context": ctx.iter().map(|c| cap(c, 8 << 10).0).collect::<Vec<_>>()}));
                }
            }
            "a" => {
                let n = m.get("n").and_then(Value::as_u64).unwrap_or(0);
                let u = usage(m.get("usage").unwrap_or(&Value::Null));
                for f in ["in", "out", "cache_read", "cache_write"] {
                    add(&mut tot, f, u[f].as_u64().unwrap_or(0));
                }
                if aux.contains(&n) {
                    add(&mut tot, "helper_requests", 1);
                    items.push(json!({"type": "helper", "ts": ts, "t": rel(&ts), "n": n, "model": s("model"), "usage": u, "latency": s("latency")}));
                    continue;
                }
                add(&mut tot, "requests", 1);
                let status = m.get("status").and_then(Value::as_u64).unwrap_or(200);
                if status >= 400 || status == 0 || m.get("error").map(|e| !e.is_null()).unwrap_or(false) {
                    add(&mut tot, "errors", 1);
                    let e = m.get("error").map(|e| e.as_str().map(String::from).unwrap_or_else(|| e.to_string())).unwrap_or_default();
                    items.push(json!({"type": "error", "ts": ts, "t": rel(&ts), "n": n, "status": status, "error": cap(&e, 4096).0, "cancelled": m.get("cancelled"), "latency": s("latency")}));
                    continue;
                }
                let h = s("h");
                shown.insert(h.clone());
                let (text, think, tools, _) = msgs.get(&h).map(|(_, c)| blocks(c)).unwrap_or_default();
                let (text, cut) = cap(&text.join("\n\n"), CHAT_TEXT_MAX);
                let thinking: Vec<String> = think.iter().map(|t| cap(t, CHAT_TEXT_MAX).0).collect();
                items.push(json!({
                    "type": "reply", "ts": ts, "t": rel(&ts), "n": n, "model": s("model"), "text": text, "cut": cut,
                    "thinking": thinking, "tools": tools, "usage": u, "latency": s("latency"), "ttft": s("ttft"), "stop": s("stop"),
                }));
            }
            "t" => {
                add(&mut tot, "tool_calls", 1);
                let tool = s("tool");
                let args = m.get("args").cloned().unwrap_or(Value::Null);
                let (result, cut) = cap(&s("result"), CHAT_TEXT_MAX);
                let started = m.get("started").and_then(Value::as_str).unwrap_or(&ts).to_string();
                let exec = json!({
                    "call": s("call"), "tool": tool, "target": s("target"), "ruser": s("ruser"), "args": args,
                    "exit": m.get("exit"), "error": m.get("error").and_then(Value::as_bool).unwrap_or(false), "duration": s("duration"),
                    "started": started, "started_t": rel(&started), "ts": ts, "result": result, "cut": cut,
                    "out_bytes": m.get("out_bytes"), "err_bytes": m.get("err_bytes"), "dropped": m.get("dropped"),
                });
                // The latest reply's tool use for this tool: same arguments first, else the first unmatched one.
                let mut placed = false;
                if let Some(r) = items.iter_mut().rev().find(|i| i["type"] == "reply") {
                    if let Some(tl) = r["tools"].as_array_mut() {
                        let free = |u: &Value| u.get("exec").is_none() && names_tool(u["name"].as_str().unwrap_or(""), &tool);
                        let i = tl.iter().position(|u| free(u) && u["input"] == args).or_else(|| tl.iter().position(|u| free(u)));
                        if let Some(i) = i {
                            tl[i]["exec"] = exec.clone();
                            placed = true;
                        }
                    }
                }
                if !placed {
                    items.push(json!({"type": "tool", "ts": ts, "t": rel(&ts), "exec": exec}));
                }
            }
            "n" => {
                let msg = s("msg");
                if msg == "swai session totals" {
                    continue;
                }
                items.push(json!({"type": "note", "ts": ts, "t": rel(&ts), "msg": msg}));
            }
            "e" => {
                end = json!({"ts": ts, "t": rel(&ts), "reason": s("reason"), "exit_code": m.get("exit_code")});
            }
            _ => {}
        }
    }
    // A harness may start a tool while the reply is still streaming, so its `t` can come before
    // the `a` of the reply that asked for it: pair those with the next replies' free tool uses.
    let mut i = 0;
    while i < items.len() {
        if items[i]["type"] != "tool" {
            i += 1;
            continue;
        }
        let exec = items[i]["exec"].clone();
        let (tool, args) = (exec["tool"].as_str().unwrap_or("").to_string(), exec["args"].clone());
        let mut target = None;
        for (j, r) in items.iter().enumerate().skip(i + 1).filter(|(_, r)| r["type"] == "reply").take(3) {
            if let Some(k) = r["tools"].as_array().and_then(|tl| tl.iter().position(|u| u.get("exec").is_none() && names_tool(u["name"].as_str().unwrap_or(""), &tool) && u["input"] == args)) {
                target = Some((j, k));
                break;
            }
        }
        match target {
            Some((j, k)) => {
                items[j]["tools"][k]["exec"] = exec;
                items.remove(i);
            }
            None => i += 1,
        }
    }
    json!({"start": start, "end": end, "items": items, "totals": tot})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn message_text() {
        assert_eq!(msg_text("user", &json!([{"type": "text", "text": "check disk"}, {"type": "tool_result", "content": "x"}])).as_deref(), Some("check disk"));
        assert_eq!(msg_text("user", &json!([{"type": "tool_result", "content": "x"}])), None);
        assert_eq!(msg_text("assistant", &json!({"content": "done", "tool_calls": []})).as_deref(), Some("done"));
        assert_eq!(msg_text("system", &json!("You are…")), None);
        assert_eq!(msg_text("tool", &json!({"content": "out"})), None);
    }

    fn rec(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn chat_pairs_tool_calls_and_counts_tokens() {
        let recs = vec![
            rec(json!({"k": "h", "kind": "ai", "start": "2026-10-03T10:00:00Z"})),
            rec(json!({"k": "m", "h": "s", "role": "system", "content": "sys"})),
            rec(json!({"k": "m", "h": "u1", "role": "user", "content": [{"type": "text", "text": "<system-reminder>\nctx\n</system-reminder>"}, {"type": "text", "text": "check disk"}]})),
            rec(json!({"k": "q", "ts": "2026-10-03T10:00:01Z", "n": 1, "msgs": ["s", "u1"], "tools": "x"})),
            rec(json!({"k": "m", "h": "a1", "role": "assistant", "content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": "Looking."}, {"type": "tool_use", "id": "tu1", "name": "mcp__swrap__exec", "input": {"command": "df -h"}}]})),
            rec(json!({"k": "a", "ts": "2026-10-03T10:00:03Z", "n": 1, "status": 200, "h": "a1", "stop": "tool_use", "usage": {"input_tokens": 2, "cache_creation_input_tokens": 100, "cache_read_input_tokens": 50, "output_tokens": 20}, "latency": "PT2S", "ttft": "PT1S", "model": "m"})),
            rec(json!({"k": "t", "ts": "2026-10-03T10:00:05Z", "call": "t1", "tool": "exec", "target": "web1", "ruser": "root", "args": {"command": "df -h"}, "exit": 0, "error": false, "duration": "PT1S", "started": "2026-10-03T10:00:04Z", "result": "exit 0\n/dev/sda1 50%"})),
            rec(json!({"k": "q", "ts": "2026-10-03T10:00:06Z", "n": 2, "msgs": ["t"], "tools": null})),
            rec(json!({"k": "a", "ts": "2026-10-03T10:00:07Z", "n": 2, "status": 200, "usage": {"prompt_tokens": 10, "completion_tokens": 3}, "model": "small"})),
            rec(json!({"k": "a", "ts": "2026-10-03T10:00:08Z", "n": 3, "status": 529, "error": "overloaded"})),
            rec(json!({"k": "e", "ts": "2026-10-03T10:00:09Z", "reason": "exit", "exit_code": 0})),
        ];
        let c = chat(&recs);
        let it = c["items"].as_array().unwrap();
        assert_eq!(it[0]["type"], "prompt");
        assert_eq!(it[0]["text"], "check disk");
        assert_eq!(it[0]["context"].as_array().unwrap().len(), 1);
        assert_eq!(it[1]["type"], "reply");
        assert_eq!(it[1]["usage"], json!({"in": 152, "out": 20, "cache_read": 50, "cache_write": 100}));
        assert_eq!(it[1]["tools"][0]["exec"]["target"], "web1");
        assert_eq!(it[1]["tools"][0]["exec"]["started_t"], 4.0);
        assert_eq!(it[2]["type"], "helper");
        assert_eq!(it[2]["usage"]["in"], 10);
        assert_eq!(it[3]["type"], "error");
        assert_eq!(c["totals"]["tool_calls"], 1);
        assert_eq!(c["totals"]["errors"], 1);
        assert_eq!(c["end"]["t"], 9.0);
    }

    #[test]
    fn chat_pairs_a_tool_that_ran_before_its_reply_ended() {
        let recs = vec![
            rec(json!({"k": "h", "kind": "ai", "start": "2026-10-03T10:00:00Z"})),
            rec(json!({"k": "q", "ts": "2026-10-03T10:00:01Z", "n": 1, "msgs": [], "tools": "x"})),
            rec(json!({"k": "t", "ts": "2026-10-03T10:00:02Z", "call": "t1", "tool": "exec", "args": {"command": "ls"}, "exit": 0})),
            rec(json!({"k": "m", "h": "a1", "role": "assistant", "content": [{"type": "tool_use", "id": "x", "name": "mcp__swrap__exec", "input": {"command": "ls"}}]})),
            rec(json!({"k": "a", "ts": "2026-10-03T10:00:03Z", "n": 1, "status": 200, "h": "a1"})),
        ];
        let c = chat(&recs);
        let it = c["items"].as_array().unwrap();
        assert_eq!(it.len(), 1);
        assert_eq!(it[0]["tools"][0]["exec"]["call"], "t1");
    }

    #[test]
    fn chat_reads_openai_tool_calls() {
        let (text, _, tools, _) = blocks(&json!({"content": "ok", "tool_calls": [{"id": "c1", "function": {"name": "swrap_exec", "arguments": "{\"command\":\"uptime\"}"}}]}));
        assert_eq!(text, vec!["ok"]);
        assert_eq!(tools[0]["input"]["command"], "uptime");
        assert!(names_tool("swrap_exec", "exec") && names_tool("mcp__swrap__read_file", "read_file") && !names_tool("exec_other", "exec"));
    }
}

#[cfg(test)]
mod dump {
    /// `SWREC_CHAT_FILE=<rec> SWREC_CHAT_OUT=<json> cargo test -p swrec dump_chat -- --ignored`
    #[test]
    #[ignore]
    fn dump_chat() {
        let (Ok(f), Ok(o)) = (std::env::var("SWREC_CHAT_FILE"), std::env::var("SWREC_CHAT_OUT")) else { return };
        let scan = crate::scan(std::path::Path::new(&f), crate::ScanOpts { verifier: None, keep_records: true, live: false }).unwrap();
        std::fs::write(o, super::chat(&scan.records).to_string()).unwrap();
    }
}
