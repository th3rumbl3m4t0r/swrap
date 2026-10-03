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
}
