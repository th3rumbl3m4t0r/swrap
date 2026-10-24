//! Tool calls parsed by swrap, not by the inference server (backend option `raw_tools`).
//!
//! llama-server recognises a tool call by its markup wherever it appears, also inside the
//! model's reasoning, and then forces the rest of the output into tool-call syntax (lazy
//! grammar). A model that *thinks about* tool calls (e.g. while designing an agent) writes an
//! example and gets it executed, often in a loop. With `raw_tools` the proxy renders the prompt
//! with the model's own template (`/apply-template`), generates raw text (`/completion`, no
//! grammar) and decides itself:
//! * after `</think>`, `<tool_call>…</tool_call>` blocks are calls (Qwen3 XML
//!   `<function=…><parameter=…>` or Hermes JSON `{"name", "arguments"}`);
//! * inside the reasoning they are reasoning text — except complete blocks that end the whole
//!   generation with the reasoning never closed (newer Qwen models call tools that way: the
//!   implicit end of reasoning), which are calls.
//!
//! The result goes to the harness as an ordinary OpenAI chat completion (stream or not).

use serde_json::{json, Map, Value};
use std::collections::HashMap;

const OPEN: &str = "<tool_call>";
const CLOSE: &str = "</tool_call>";
const END_THINK: &str = "</think>";

#[derive(Debug, PartialEq)]
pub enum Ev {
    Reasoning(String),
    Content(String),
    Call { name: String, arguments: String },
}

/// The raw-text state machine.
pub struct Conv {
    reasoning: bool,
    buf: String,
    /// In the reasoning, from a `<tool_call>` on: held until it is clear whether it was a call.
    pending: String,
    /// At the start of the answer: leading whitespace is dropped.
    lead: bool,
    /// Tool name → its JSON schema `properties` (parameter types).
    props: HashMap<String, Value>,
}

/// How many trailing bytes of `s` could start one of `tags` (kept back until more text comes).
fn partial_tail(s: &str, tags: &[&str]) -> usize {
    let mut keep = 0;
    for t in tags {
        for k in (1..t.len()).rev() {
            if k <= s.len() && s.is_char_boundary(s.len() - k) && t.starts_with(&s[s.len() - k..]) {
                keep = keep.max(k);
                break;
            }
        }
    }
    keep
}

impl Conv {
    /// `thinking`: the prompt leaves the reasoning open (ends with `<think>`).
    pub fn new(thinking: bool, tools: &Value) -> Self {
        let mut props = HashMap::new();
        for t in tools.as_array().into_iter().flatten() {
            let f = if t.get("function").is_some() { &t["function"] } else { t };
            if let Some(n) = f["name"].as_str() {
                props.insert(n.to_string(), f["parameters"]["properties"].clone());
            }
        }
        Conv { reasoning: thinking, buf: String::new(), pending: String::new(), lead: true, props }
    }

    pub fn feed(&mut self, text: &str) -> Vec<Ev> {
        self.buf.push_str(text);
        self.run(false)
    }

    /// End of the generation.
    pub fn finish(&mut self) -> Vec<Ev> {
        self.run(true)
    }

    fn content(&mut self, out: &mut Vec<Ev>, s: &str) {
        let s = if self.lead { s.trim_start() } else { s };
        if !s.is_empty() {
            self.lead = false;
            out.push(Ev::Content(s.to_string()));
        }
    }

    fn run(&mut self, eof: bool) -> Vec<Ev> {
        let mut out = vec![];
        loop {
            if self.reasoning && !self.pending.is_empty() {
                if !self.resolve_pending(eof, &mut out) {
                    break;
                }
                continue;
            }
            if self.reasoning {
                let think = self.buf.find(END_THINK);
                let open = self.buf.find(OPEN);
                // Whichever tag comes first.
                let (think, open) = match (think, open) {
                    (Some(t), Some(o)) if t < o => (Some(t), None),
                    (Some(_), Some(o)) => (None, Some(o)),
                    x => x,
                };
                match (think, open) {
                    (Some(t), _) => {
                        let r: String = self.buf.drain(..t).collect();
                        self.buf.drain(..END_THINK.len());
                        if !r.is_empty() {
                            out.push(Ev::Reasoning(r));
                        }
                        self.reasoning = false;
                    }
                    (_, Some(o)) => {
                        let r: String = self.buf.drain(..o).collect();
                        if !r.is_empty() {
                            out.push(Ev::Reasoning(r));
                        }
                        self.pending = std::mem::take(&mut self.buf);
                    }
                    (None, None) => {
                        let keep = if eof { 0 } else { partial_tail(&self.buf, &[END_THINK, OPEN]) };
                        let r: String = self.buf.drain(..self.buf.len() - keep).collect();
                        if !r.is_empty() {
                            out.push(Ev::Reasoning(r));
                        }
                        break;
                    }
                }
                continue;
            }
            // The answer: text, and tool-call blocks.
            match self.buf.find(OPEN) {
                Some(o) => {
                    let before: String = self.buf.drain(..o).collect();
                    self.content(&mut out, &before);
                    let Some(c) = self.buf.find(CLOSE) else {
                        if eof {
                            let rest = std::mem::take(&mut self.buf);
                            self.content(&mut out, &rest);
                        }
                        break;
                    };
                    let block: String = self.buf.drain(..c + CLOSE.len()).collect();
                    match self.parse_block(&block[OPEN.len()..block.len() - CLOSE.len()]) {
                        Some((name, arguments)) => {
                            self.lead = false;
                            out.push(Ev::Call { name, arguments });
                        }
                        None => self.content(&mut out, &block),
                    }
                }
                None => {
                    let keep = if eof { 0 } else { partial_tail(&self.buf, &[OPEN]) };
                    let s: String = self.buf.drain(..self.buf.len() - keep).collect();
                    self.content(&mut out, &s);
                    break;
                }
            }
        }
        out
    }

    /// Decides held reasoning text that starts with `<tool_call>`. Returns whether it progressed.
    fn resolve_pending(&mut self, eof: bool, out: &mut Vec<Ev>) -> bool {
        self.pending.push_str(&std::mem::take(&mut self.buf));
        // The reasoning closes: everything held was part of it.
        if let Some(t) = self.pending.find(END_THINK) {
            let r: String = self.pending[..t].to_string();
            self.buf = self.pending[t + END_THINK.len()..].to_string();
            self.pending.clear();
            out.push(Ev::Reasoning(r));
            self.reasoning = false;
            return true;
        }
        // Walk the complete blocks; whatever follows them decides.
        let mut pos = 0;
        let mut blocks = vec![];
        loop {
            let rest = &self.pending[pos..];
            let ws = rest.len() - rest.trim_start().len();
            let rest_t = &rest[ws..];
            if rest_t.starts_with(OPEN) {
                match rest_t.find(CLOSE) {
                    Some(c) => {
                        blocks.push(rest_t[OPEN.len()..c].to_string());
                        pos += ws + c + CLOSE.len();
                        continue;
                    }
                    None if eof => break,
                    None => return false, // a block still being written
                }
            }
            if rest_t.is_empty() || (!eof && OPEN.starts_with(rest_t)) {
                if !eof {
                    return false; // nothing after the blocks yet
                }
                // Generation ended right after complete blocks, reasoning never closed: calls.
                let calls: Vec<(String, String)> = blocks.iter().filter_map(|b| self.parse_block(b)).collect();
                if !calls.is_empty() && calls.len() == blocks.len() {
                    for (name, arguments) in calls {
                        out.push(Ev::Call { name, arguments });
                    }
                    self.pending.clear();
                    self.reasoning = false;
                    return true;
                }
                break;
            }
            // More reasoning after the blocks: they were text (an example, a quote).
            let r: String = self.pending.drain(..pos + ws).collect();
            out.push(Ev::Reasoning(r));
            self.buf = std::mem::take(&mut self.pending);
            return true;
        }
        // eof with an incomplete or unparsable block: reasoning text.
        out.push(Ev::Reasoning(std::mem::take(&mut self.pending)));
        true
    }

    /// `<function=name><parameter=p>v</parameter>…</function>` or `{"name", "arguments"}`.
    fn parse_block(&self, inner: &str) -> Option<(String, String)> {
        let t = inner.trim();
        if t.starts_with('{') {
            let v: Value = serde_json::from_str(t).ok()?;
            let name = v["name"].as_str()?.to_string();
            let args = v.get("arguments").cloned().unwrap_or_else(|| json!({}));
            let args = match args {
                Value::String(s) => s,
                o => o.to_string(),
            };
            return Some((name, args));
        }
        let (name, rest) = t.strip_prefix("<function=")?.split_once('>')?;
        let name = name.trim().to_string();
        if name.is_empty() || name.contains(char::is_whitespace) {
            return None;
        }
        let body = rest.rsplit_once("</function>").map(|x| x.0).unwrap_or(rest);
        let mut args = Map::new();
        let mut s = body;
        while let Some(i) = s.find("<parameter=") {
            let (pname, r) = s[i + "<parameter=".len()..].split_once('>')?;
            let (val, r2) = r.split_once("</parameter>")?;
            let val = val.strip_prefix('\n').unwrap_or(val);
            let val = val.strip_suffix('\n').unwrap_or(val);
            let pname = pname.trim();
            args.insert(pname.to_string(), self.typed(&name, pname, val));
            s = r2;
        }
        Some((name, Value::Object(args).to_string()))
    }

    /// A parameter value as its schema type (the XML carries text).
    fn typed(&self, tool: &str, param: &str, val: &str) -> Value {
        let ty = self.props.get(tool).and_then(|p| p[param]["type"].as_str()).unwrap_or("string");
        if ty == "string" {
            return json!(val);
        }
        serde_json::from_str(val.trim()).unwrap_or_else(|_| json!(val))
    }
}

// ---------------------------------------------------------------- requests

/// Whether the chat request carries images (those stay on the server's own chat endpoint).
pub fn has_images(body: &Value) -> bool {
    body["messages"].as_array().into_iter().flatten().any(|m| m["content"].as_array().into_iter().flatten().any(|p| p["type"] == "image_url" || p["type"] == "input_image"))
}

/// The `/apply-template` request: what decides the prompt.
pub fn template_request(body: &Value) -> Value {
    let mut t = Map::new();
    for k in ["messages", "tools", "tool_choice", "parallel_tool_calls", "chat_template_kwargs", "reasoning_effort"] {
        if let Some(v) = body.get(k).filter(|v| !v.is_null()) {
            t.insert(k.into(), v.clone());
        }
    }
    Value::Object(t)
}

/// The `/completion` request for `prompt`: sampling and length from the chat request.
pub fn completion_request(body: &Value, prompt: &str) -> Value {
    let mut c = Map::new();
    c.insert("prompt".into(), json!(prompt));
    c.insert("stream".into(), json!(true));
    c.insert("cache_prompt".into(), json!(true));
    if let Some(n) = body.get("max_completion_tokens").or(body.get("max_tokens")).and_then(Value::as_i64) {
        c.insert("n_predict".into(), json!(n));
    }
    for k in ["temperature", "top_p", "top_k", "min_p", "presence_penalty", "frequency_penalty", "repeat_penalty", "seed", "stop"] {
        if let Some(v) = body.get(k).filter(|v| !v.is_null()) {
            c.insert(k.into(), v.clone());
        }
    }
    Value::Object(c)
}

// ---------------------------------------------------------------- the answer

/// `/completion` SSE in, an OpenAI chat completion out (SSE chunks, or one JSON at the end).
pub struct Synth {
    conv: Conv,
    stream: bool,
    id: String,
    model: String,
    created: i64,
    started: bool,
    line: Vec<u8>,
    reasoning: String,
    content: String,
    calls: Vec<Value>,
    usage: Option<Value>,
    stop_type: String,
    error: Option<Value>,
    finished: bool,
}

impl Synth {
    pub fn new(body: &Value, prompt: &str, id: &str) -> Self {
        let thinking = prompt.trim_end_matches('\n').ends_with("<think>");
        Synth {
            conv: Conv::new(thinking, &body["tools"]),
            stream: body["stream"].as_bool().unwrap_or(false),
            id: format!("chatcmpl-swrap-{id}"),
            model: body["model"].as_str().unwrap_or("").to_string(),
            created: jiff::Timestamp::now().as_second(),
            started: false,
            line: vec![],
            reasoning: String::new(),
            content: String::new(),
            calls: vec![],
            usage: None,
            stop_type: String::new(),
            error: None,
            finished: false,
        }
    }

    pub fn content_type(&self) -> &'static str {
        if self.stream { "text/event-stream" } else { "application/json" }
    }

    fn chunk(&self, delta: Value, finish: Option<&str>) -> Vec<u8> {
        let mut c = json!({"id": self.id, "object": "chat.completion.chunk", "created": self.created, "model": self.model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]});
        if finish.is_some() {
            if let Some(u) = &self.usage {
                c["usage"] = u.clone();
            }
        }
        format!("data: {c}\n\n").into_bytes()
    }

    fn emit(&mut self, evs: Vec<Ev>) -> Vec<u8> {
        let mut out = vec![];
        for e in evs {
            if self.stream && !self.started {
                self.started = true;
                out.extend(self.chunk(json!({"role": "assistant", "content": null}), None));
            }
            match e {
                Ev::Reasoning(s) => {
                    self.reasoning.push_str(&s);
                    if self.stream {
                        out.extend(self.chunk(json!({"reasoning_content": s}), None));
                    }
                }
                Ev::Content(s) => {
                    self.content.push_str(&s);
                    if self.stream {
                        out.extend(self.chunk(json!({"content": s}), None));
                    }
                }
                Ev::Call { name, arguments } => {
                    let call = json!({"id": crate::util::random_hex(12), "type": "function", "function": {"name": name, "arguments": arguments}});
                    if self.stream {
                        let mut d = call.clone();
                        d["index"] = json!(self.calls.len());
                        out.extend(self.chunk(json!({"tool_calls": [d]}), None));
                    }
                    self.calls.push(call);
                }
            }
        }
        out
    }

    /// Bytes of the `/completion` stream; returns the bytes for the harness (maybe none yet).
    pub fn push(&mut self, b: &[u8]) -> Vec<u8> {
        self.line.extend_from_slice(b);
        let mut out = vec![];
        while let Some(i) = self.line.iter().position(|&c| c == b'\n') {
            let l: Vec<u8> = self.line.drain(..=i).collect();
            let l = String::from_utf8_lossy(&l);
            let Some(data) = l.trim().strip_prefix("data:") else { continue };
            let Ok(v) = serde_json::from_str::<Value>(data.trim()) else { continue };
            if let Some(e) = v.get("error") {
                self.error = Some(e.clone());
                continue;
            }
            if let Some(t) = v["content"].as_str() {
                let evs = self.conv.feed(t);
                out.extend(self.emit(evs));
            }
            if v["stop"] == true {
                let p = v["tokens_evaluated"].as_u64().unwrap_or(0);
                let n = v["tokens_predicted"].as_u64().unwrap_or(0);
                let mut u = json!({"prompt_tokens": p, "completion_tokens": n, "total_tokens": p + n});
                if let Some(c) = v["tokens_cached"].as_u64() {
                    u["prompt_tokens_details"] = json!({"cached_tokens": c});
                }
                self.usage = Some(u);
                self.stop_type = v["stop_type"].as_str().unwrap_or("").to_string();
            }
        }
        out
    }

    /// The end of the `/completion` stream: the rest, the finish reason, `[DONE]`.
    pub fn end(&mut self) -> Vec<u8> {
        if self.finished {
            return vec![];
        }
        self.finished = true;
        let evs = self.conv.finish();
        let mut out = self.emit(evs);
        if let Some(e) = &self.error {
            // The server cut the generation (e.g. UPS on battery): its error, as it sent it.
            let e = json!({"error": e});
            return if self.stream { [out, format!("data: {e}\n\n").into_bytes()].concat() } else { e.to_string().into_bytes() };
        }
        let finish = if !self.calls.is_empty() {
            "tool_calls"
        } else if self.stop_type == "limit" {
            "length"
        } else {
            "stop"
        };
        if self.stream {
            if !self.started {
                out.extend(self.chunk(json!({"role": "assistant", "content": null}), None));
            }
            out.extend(self.chunk(json!({}), Some(finish)));
            out.extend(b"data: [DONE]\n\n");
            return out;
        }
        let mut msg = json!({"role": "assistant", "content": if self.content.is_empty() { Value::Null } else { json!(self.content) }});
        if !self.reasoning.is_empty() {
            msg["reasoning_content"] = json!(self.reasoning);
        }
        if !self.calls.is_empty() {
            msg["tool_calls"] = json!(self.calls);
        }
        let mut r = json!({"id": self.id, "object": "chat.completion", "created": self.created, "model": self.model,
            "choices": [{"index": 0, "message": msg, "finish_reason": finish}]});
        if let Some(u) = &self.usage {
            r["usage"] = u.clone();
        }
        r.to_string().into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools() -> Value {
        json!([{"type": "function", "function": {"name": "swrap_read_file", "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "limit": {"type": "integer"}}}}}])
    }

    /// Feed `text` in pieces of `step` bytes (char-safe), then finish; merge adjacent text events.
    fn run(thinking: bool, text: &str, step: usize) -> Vec<Ev> {
        let mut c = Conv::new(thinking, &tools());
        let mut evs = vec![];
        let chars: Vec<char> = text.chars().collect();
        for piece in chars.chunks(step) {
            evs.extend(c.feed(&piece.iter().collect::<String>()));
        }
        evs.extend(c.finish());
        let mut out: Vec<Ev> = vec![];
        for e in evs {
            match (out.last_mut(), e) {
                (Some(Ev::Reasoning(a)), Ev::Reasoning(b)) => a.push_str(&b),
                (Some(Ev::Content(a)), Ev::Content(b)) => a.push_str(&b),
                (_, e) => out.push(e),
            }
        }
        out
    }

    const CALL: &str = "<tool_call>\n<function=swrap_read_file>\n<parameter=path>\n/etc/hostname\n</parameter>\n<parameter=limit>\n20\n</parameter>\n</function>\n</tool_call>";

    #[test]
    fn a_call_after_the_reasoning_is_a_call() {
        for step in [1, 3, 7, 1000] {
            let t = format!("Let me read it.\n</think>\n\n{CALL}");
            assert_eq!(
                run(true, &t, step),
                vec![Ev::Reasoning("Let me read it.\n".into()), Ev::Call { name: "swrap_read_file".into(), arguments: r#"{"path":"/etc/hostname","limit":20}"#.into() }],
                "step {step}"
            );
        }
    }

    #[test]
    fn a_call_written_inside_the_reasoning_stays_text() {
        // The incident: an example in the reasoning, then more reasoning, then the answer.
        for step in [1, 5, 1000] {
            let t = format!("model outputs e.g. `{CALL}` and the harness parses it.\n</think>\n\nUse a JSON block.");
            let evs = run(true, &t, step);
            assert_eq!(evs.len(), 2, "step {step}: {evs:?}");
            assert!(matches!(&evs[0], Ev::Reasoning(r) if r.contains("<function=swrap_read_file>") && r.ends_with("parses it.\n")), "{evs:?}");
            assert_eq!(evs[1], Ev::Content("Use a JSON block.".into()));
        }
        // Several examples, each on its own line, followed by more thinking.
        let t = format!("format like:\n{CALL}\nor\n{CALL}\nSo the protocol needs one tag.\n</think>\nDone.");
        let evs = run(true, &t, 4);
        assert!(evs.iter().all(|e| !matches!(e, Ev::Call { .. })), "{evs:?}");
    }

    #[test]
    fn a_call_that_ends_unclosed_reasoning_is_a_call() {
        // Newer Qwen models may call without closing </think>: the implicit end of reasoning.
        for step in [1, 9, 1000] {
            let t = format!("I need the hostname.\n{CALL}\n");
            let evs = run(true, &t, step);
            assert_eq!(evs.last(), Some(&Ev::Call { name: "swrap_read_file".into(), arguments: r#"{"path":"/etc/hostname","limit":20}"#.into() }), "step {step}");
            assert!(matches!(&evs[0], Ev::Reasoning(r) if r == "I need the hostname.\n"));
        }
    }

    #[test]
    fn content_tool_calls_hermes_json_and_no_thinking() {
        let t = "Reading.\n<tool_call>\n{\"name\": \"swrap_read_file\", \"arguments\": {\"path\": \"/a\"}}\n</tool_call>";
        assert_eq!(run(false, t, 3), vec![Ev::Content("Reading.\n".into()), Ev::Call { name: "swrap_read_file".into(), arguments: r#"{"path":"/a"}"#.into() }]);
        // An unparsable block in the answer is shown, not called; a cut block at the end is text.
        assert_eq!(run(false, "<tool_call>nonsense</tool_call>", 1000), vec![Ev::Content("<tool_call>nonsense</tool_call>".into())]);
        assert_eq!(run(false, "a <tool_call>\n<function=x>", 2), vec![Ev::Content("a <tool_call>\n<function=x>".into())]);
        // Plain text keeps its angle brackets.
        assert_eq!(run(true, "x < y </th", 1), vec![Ev::Reasoning("x < y </th".into())]);
    }

    #[test]
    fn synth_streams_an_openai_completion() {
        let body = json!({"model": "qwen", "stream": true, "tools": tools()});
        let mut s = Synth::new(&body, "…<|im_start|>assistant\n<think>\n", "1");
        let mut out = vec![];
        for piece in ["Need it.\n</th", "ink>\n\n<tool_", &CALL[6..], ""] {
            out.extend(s.push(format!("data: {}\n\n", json!({"content": piece, "stop": false})).as_bytes()));
        }
        out.extend(s.push(format!("data: {}\n\n", json!({"content": "", "stop": true, "stop_type": "eos", "tokens_evaluated": 300, "tokens_predicted": 40, "tokens_cached": 250})).as_bytes()));
        out.extend(s.end());
        let text = String::from_utf8(out).unwrap();
        let evs: Vec<Value> = text.lines().filter_map(|l| l.strip_prefix("data: ")).filter(|d| *d != "[DONE]").map(|d| serde_json::from_str(d).unwrap()).collect();
        assert_eq!(evs[0]["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(evs[1]["choices"][0]["delta"]["reasoning_content"], "Need it.\n");
        assert_eq!(evs[2]["choices"][0]["delta"]["tool_calls"][0]["function"]["name"], "swrap_read_file");
        let last = evs.last().unwrap();
        assert_eq!(last["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(last["usage"]["completion_tokens"], 40);
        assert!(text.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn synth_whole_answer_and_server_errors() {
        let body = json!({"model": "qwen", "stream": false});
        let mut s = Synth::new(&body, "x<think>\n", "2");
        s.push(b"data: {\"content\":\"hm\\n</think>\\n\\nHello\",\"stop\":true,\"stop_type\":\"eos\",\"tokens_evaluated\":5,\"tokens_predicted\":3}\n\n");
        let v: Value = serde_json::from_slice(&s.end()).unwrap();
        assert_eq!(v["choices"][0]["message"]["content"], "Hello");
        assert_eq!(v["choices"][0]["message"]["reasoning_content"], "hm\n");
        assert_eq!(v["choices"][0]["finish_reason"], "stop");
        // The gateway's battery drain ends a stream with an error event: passed on.
        let mut s = Synth::new(&json!({"model": "q", "stream": true}), "<think>\n", "3");
        s.push(b"data: {\"content\":\"thinking\",\"stop\":false}\n\n");
        s.push(b"data: {\"error\": {\"message\": \"UPS on battery: request aborted\", \"code\": 503}}\n\n");
        let t = String::from_utf8(s.end()).unwrap();
        assert!(t.contains("UPS on battery") && !t.contains("[DONE]"), "{t}");
        assert_eq!(completion_request(&json!({"max_tokens": 9, "temperature": 0.6, "messages": []}), "P")["n_predict"], 9);
        assert!(has_images(&json!({"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "data:"}}]}]})));
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// `SWAI_RAW_URL=http://…:8090 SWAI_RAW_KEY=… SWAI_RAW_ASK='…' cargo test -p swrapd raw_live -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn raw_live() {
        let (Ok(url), Ok(key), Ok(ask)) = (std::env::var("SWAI_RAW_URL"), std::env::var("SWAI_RAW_KEY"), std::env::var("SWAI_RAW_ASK")) else { return };
        let tools = json!([{"type": "function", "function": {"name": "swrap_read_file", "description": "Read a file on the target", "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["path"]}}}]);
        let body = json!({"model": "qwen3.8-27b", "stream": true, "max_tokens": 3000, "messages": [{"role": "user", "content": ask}], "tools": tools});
        let agent = crate::ai::http(std::time::Duration::from_secs(900));
        let auth = format!("Bearer {key}");
        let mut r = agent.post(&format!("{url}/apply-template")).header("Authorization", &auth).send(template_request(&body).to_string().as_bytes()).unwrap();
        let prompt = serde_json::from_str::<Value>(&r.body_mut().read_to_string().unwrap()).unwrap()["prompt"].as_str().unwrap().to_string();
        let r = agent.post(&format!("{url}/completion")).header("Authorization", &auth).send(completion_request(&body, &prompt).to_string().as_bytes()).unwrap();
        let mut s = Synth::new(&body, &prompt, "live");
        let mut out = vec![];
        let mut rd = r.into_body().into_reader();
        let mut buf = [0u8; 4096];
        loop {
            let n = std::io::Read::read(&mut rd, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend(s.push(&buf[..n]));
        }
        out.extend(s.end());
        let text = String::from_utf8_lossy(&out);
        let (mut reasoning, mut content, mut calls, mut finish) = (String::new(), String::new(), vec![], String::new());
        for d in text.lines().filter_map(|l| l.strip_prefix("data: ")).filter(|d| *d != "[DONE]") {
            let v: Value = serde_json::from_str(d).unwrap();
            let dl = &v["choices"][0]["delta"];
            reasoning += dl["reasoning_content"].as_str().unwrap_or("");
            content += dl["content"].as_str().unwrap_or("");
            for c in dl["tool_calls"].as_array().into_iter().flatten() {
                calls.push(format!("{} {}", c["function"]["name"], c["function"]["arguments"]));
            }
            if let Some(f) = v["choices"][0]["finish_reason"].as_str() {
                finish = f.to_string();
            }
        }
        println!("REASONING ({} chars, <tool_call> inside: {})\nCONTENT: {content:?}\nCALLS: {calls:?}\nFINISH: {finish}", reasoning.len(), reasoning.matches("<tool_call>").count());
    }
}
