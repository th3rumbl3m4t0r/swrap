//! Renderers: ANSI stripping, keystroke rendering, heuristic command reconstruction,
//! asciicast v2 export (spec 9.4, 16).

use crate::format::B64;
use base64::Engine;
use serde_json::{json, Map, Value};

/// Payload of an `o`/`i` record as bytes.
pub fn rec_bytes(m: &Map<String, Value>) -> Vec<u8> {
    if let Some(d) = m.get("d").and_then(Value::as_str) {
        return d.as_bytes().to_vec();
    }
    if let Some(b) = m.get("b").and_then(Value::as_str) {
        return B64.decode(b).unwrap_or_default();
    }
    vec![]
}

pub fn kind_of(m: &Map<String, Value>) -> &str {
    m.get("k").and_then(Value::as_str).unwrap_or("")
}

// ---------------------------------------------------------------- ANSI strip

struct Strip<'a> {
    out: &'a mut String,
}

impl vte::Perform for Strip<'_> {
    fn print(&mut self, c: char) {
        self.out.push(c);
    }
    fn execute(&mut self, b: u8) {
        match b {
            b'\n' => self.out.push('\n'),
            b'\t' => self.out.push('\t'),
            _ => {}
        }
    }
}

/// Stateful ANSI stripper, so escape sequences split across records are handled.
pub struct AnsiStripper {
    p: vte::Parser,
}

impl Default for AnsiStripper {
    fn default() -> Self {
        AnsiStripper { p: vte::Parser::new() }
    }
}

impl AnsiStripper {
    pub fn push(&mut self, data: &[u8], out: &mut String) {
        let mut s = Strip { out };
        for &b in data {
            self.p.advance(&mut s, b);
        }
    }
}

pub fn strip_ansi(data: &[u8]) -> String {
    let mut s = String::new();
    AnsiStripper::default().push(data, &mut s);
    s
}

// ---------------------------------------------------------------- keystrokes

/// Render keystrokes as text: printable as-is, `^C`, `<Up>`, `<Tab>`, `<Enter>`.
#[derive(Default)]
pub struct KeyRenderer {
    esc: Vec<u8>,
}

fn esc_name(seq: &[u8]) -> Option<&'static str> {
    Some(match seq {
        b"\x1b[A" | b"\x1bOA" => "<Up>",
        b"\x1b[B" | b"\x1bOB" => "<Down>",
        b"\x1b[C" | b"\x1bOC" => "<Right>",
        b"\x1b[D" | b"\x1bOD" => "<Left>",
        b"\x1b[H" | b"\x1bOH" | b"\x1b[1~" => "<Home>",
        b"\x1b[F" | b"\x1bOF" | b"\x1b[4~" => "<End>",
        b"\x1b[3~" => "<Del>",
        b"\x1b[5~" => "<PgUp>",
        b"\x1b[6~" => "<PgDn>",
        b"\x1b[2~" => "<Ins>",
        b"\x1b[Z" => "<S-Tab>",
        _ => return None,
    })
}

impl KeyRenderer {
    pub fn push(&mut self, data: &[u8], out: &mut String) {
        let text = String::from_utf8_lossy(data);
        for c in text.chars() {
            if !self.esc.is_empty() {
                let mut tmp = [0u8; 4];
                self.esc.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
                let done = self.esc.len() > 2 && (c.is_ascii_alphabetic() || c == '~') || (self.esc.len() == 2 && c != '[' && c != 'O');
                if done || self.esc.len() > 8 {
                    match esc_name(&self.esc) {
                        Some(n) => out.push_str(n),
                        None => {
                            if self.esc.len() == 2 {
                                out.push_str("<M-");
                                out.push(c);
                                out.push('>');
                            } else {
                                out.push_str("<Esc>");
                                out.push_str(&String::from_utf8_lossy(&self.esc[1..]));
                            }
                        }
                    }
                    self.esc.clear();
                }
                continue;
            }
            match c {
                '\x1b' => self.esc.push(0x1b),
                '\r' | '\n' => out.push_str("<Enter>"),
                '\t' => out.push_str("<Tab>"),
                '\x7f' | '\x08' => out.push_str("<BS>"),
                c if (c as u32) < 0x20 => {
                    out.push('^');
                    out.push((b'@' + c as u8) as char);
                }
                c => out.push(c),
            }
        }
    }
    pub fn finish(&mut self, out: &mut String) {
        if !self.esc.is_empty() {
            out.push_str("<Esc>");
            self.esc.clear();
        }
    }
}

pub fn render_keys(data: &[u8]) -> String {
    let mut s = String::new();
    let mut k = KeyRenderer::default();
    k.push(data, &mut s);
    k.finish(&mut s);
    s
}

// ---------------------------------------------------------------- heuristic command lines

/// Reconstructs command lines from keystrokes (fallback when no shell integration).
/// Applies BS, ^U, ^W, ^C; drops escape sequences; emits on CR. Misses history/completion.
#[derive(Default)]
pub struct LineEditor {
    line: Vec<char>,
    esc: u8,
}

impl LineEditor {
    pub fn push(&mut self, data: &[u8]) -> Vec<String> {
        let mut out = vec![];
        for c in String::from_utf8_lossy(data).chars() {
            if self.esc > 0 {
                // swallow CSI/SS3 sequence
                if self.esc == 1 && (c == '[' || c == 'O') {
                    self.esc = 2;
                } else if self.esc == 1 || c.is_ascii_alphabetic() || c == '~' || self.esc > 8 {
                    self.esc = 0;
                } else {
                    self.esc += 1;
                }
                continue;
            }
            match c {
                '\x1b' => self.esc = 1,
                '\r' | '\n' => {
                    let l: String = self.line.drain(..).collect();
                    if !l.trim().is_empty() {
                        out.push(l.trim().to_string());
                    }
                }
                '\x7f' | '\x08' => {
                    self.line.pop();
                }
                '\x15' => self.line.clear(),
                '\x03' => self.line.clear(),
                '\x17' => {
                    while self.line.last() == Some(&' ') {
                        self.line.pop();
                    }
                    while self.line.last().map(|c| *c != ' ').unwrap_or(false) {
                        self.line.pop();
                    }
                }
                c if (c as u32) < 0x20 => {}
                c => {
                    if self.line.len() < 8192 {
                        self.line.push(c)
                    }
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------- asciicast v2

pub struct Cast {
    pub text: String,
    /// (record ts, player time offset in seconds) for seek mapping.
    pub marks: Vec<(String, f64)>,
    pub duration: f64,
}

fn ts_secs(ts: &str) -> Option<f64> {
    let t: jiff::Timestamp = ts.parse().ok()?;
    Some(t.as_microsecond() as f64 / 1e6)
}

/// Generate asciicast v2 from records. Idle gaps are capped at `idle_cap` seconds.
/// Commands (`x`) become markers so the player can seek to them.
pub fn to_asciicast(header: &Map<String, Value>, records: &[Map<String, Value>], idle_cap: f64, with_keys: bool) -> Cast {
    let cols = header.get("cols").and_then(Value::as_u64).unwrap_or(80);
    let rows = header.get("rows").and_then(Value::as_u64).unwrap_or(24);
    let start = header.get("start").and_then(Value::as_str).and_then(ts_secs).unwrap_or(0.0);
    let mut hdr = json!({"version": 2, "width": cols, "height": rows, "timestamp": start as i64,
        "env": {"TERM": header.get("term").and_then(Value::as_str).unwrap_or("xterm-256color")}});
    if let Some(id) = header.get("id") {
        hdr["title"] = id.clone();
    }
    let mut text = serde_json::to_string(&hdr).unwrap();
    text.push('\n');
    let mut marks = vec![];
    let mut last_real = start;
    let mut t = 0.0f64;
    // Repeats (`p`) play back as the events they stand for, exactly as if never folded.
    let mut expander = crate::repeat::Expander::default();
    for m in records {
        let Some(ts) = m.get("ts").and_then(Value::as_str) else { continue };
        let Some(real) = ts_secs(ts) else { continue };
        let events = expander.feed(m).unwrap_or_default();
        if kind_of(m) == "p" {
            marks.push((ts.to_string(), t + (real - last_real).max(0.0).min(idle_cap)));
            for (us, d) in events {
                let real = us as f64 / 1e6;
                t += (real - last_real).max(0.0).min(idle_cap);
                last_real = real;
                text.push_str(&serde_json::to_string(&json!([t, "o", &*d])).unwrap());
                text.push('\n');
            }
            continue;
        }
        let gap = (real - last_real).max(0.0);
        t += gap.min(idle_cap);
        last_real = real;
        marks.push((ts.to_string(), t));
        let ev = match kind_of(m) {
            // swai tool output (`call`) is not part of the terminal stream.
            "o" if m.contains_key("call") => continue,
            "o" => {
                let b = rec_bytes(m);
                json!([t, "o", String::from_utf8_lossy(&b)])
            }
            "i" if with_keys => {
                json!([t, "i", String::from_utf8_lossy(&rec_bytes(m))])
            }
            "r" => {
                let c = m.get("cols").and_then(Value::as_u64).unwrap_or(cols);
                let r = m.get("rows").and_then(Value::as_u64).unwrap_or(rows);
                json!([t, "r", format!("{c}x{r}")])
            }
            "x" => json!([t, "m", m.get("cmd").and_then(Value::as_str).unwrap_or("")]),
            _ => continue,
        };
        text.push_str(&serde_json::to_string(&ev).unwrap());
        text.push('\n');
    }
    Cast { text, marks, duration: t }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strip() {
        assert_eq!(strip_ansi(b"\x1b[1;31mred\x1b[0m text\r\n"), "red text\n");
        let mut s = String::new();
        let mut st = AnsiStripper::default();
        st.push(b"a\x1b[3", &mut s);
        st.push(b"1mb", &mut s);
        assert_eq!(s, "ab");
    }
    #[test]
    fn keys() {
        assert_eq!(render_keys(b"ls\t\x1b[A\x03\r"), "ls<Tab><Up>^C<Enter>");
    }
    #[test]
    fn heuristic() {
        let mut e = LineEditor::default();
        assert_eq!(e.push(b"lx\x7fs -l\r"), vec!["ls -l"]);
        assert_eq!(e.push(b"rm -rf /\x03echo hi there\x17you\r"), vec!["echo hi you"]);
        assert_eq!(e.push(b"\x1b[Adnf up"), Vec::<String>::new());
        assert_eq!(e.push(b"date\x15uptime\r"), vec!["uptime"]);
    }
}
