//! Plain-text dump (`swcat`): ISO timestamps, output with ANSI stripped, optional keys/commands.

use crate::render::{rec_bytes, strip_ansi, render_keys};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::Arc;
use swrap_core::time::fmt_display_ms;

pub struct CatOpts<'a> {
    pub tz: &'a str,
    pub utc: bool,
    pub keys: bool,
    pub cmds: bool,
    pub raw: bool,
}

fn disp(ts: &str, o: &CatOpts) -> String {
    ts.parse::<jiff::Timestamp>().map(|t| fmt_display_ms(t, o.tz, o.utc)).unwrap_or_else(|_| ts.to_string())
}

/// A run of repeated output (`p` records), shown as one line instead of every copy.
struct Repeats {
    first: String,
    first_us: i64,
    last_us: i64,
    n: u64,
    frames: HashSet<Arc<str>>,
}

impl Repeats {
    fn line(&self, o: &CatOpts) -> String {
        let last = crate::repeat::fmt_us(self.last_us);
        let every = if self.n > 1 { format!(", every {:.3}s", (self.last_us - self.first_us) as f64 / 1e6 / (self.n - 1) as f64) } else { String::new() };
        let what = if self.frames.len() == 1 {
            let t = strip_ansi(self.frames.iter().next().unwrap().as_bytes());
            let t = t.trim();
            let short: String = t.chars().take(80).collect();
            if t.is_empty() { String::new() } else { format!(": {short:?}{}", if short.len() < t.len() { "…" } else { "" }) }
        } else {
            format!(", {}{} different frames", self.frames.len(), if self.frames.len() >= 64 { "+" } else { "" })
        };
        format!("{} | ⟳ earlier output repeated {}× until {}{every}{what}", disp(&self.first, o), self.n, disp(&last, o))
    }
}

pub fn cat(header: Option<&Map<String, Value>>, records: &[Map<String, Value>], o: &CatOpts, out: &mut dyn std::io::Write) -> std::io::Result<()> {
    if let Some(h) = header {
        let mut parts = vec![];
        for (k, v) in h {
            if k == "k" { continue; }
            let s = match v { Value::String(s) => s.clone(), other => other.to_string() };
            parts.push(format!("{k}={s}"));
        }
        writeln!(out, "# {}", parts.join(" "))?;
    }
    // swai sessions read best as a chat (the TUI itself is in the player).
    if crate::ai::is_ai(records) {
        return crate::ai::transcript(records, o, out);
    }
    // Output is shown as continuous text; each new line is prefixed with the ts of the record
    // where that line started.
    let mut at_line_start = true;
    let mut expander = crate::repeat::Expander::default();
    let mut reps: Option<Repeats> = None;
    for m in records {
        let k = m.get("k").and_then(Value::as_str).unwrap_or("");
        let ts = m.get("ts").and_then(Value::as_str).unwrap_or("");
        let events = expander.feed(m).unwrap_or_default();
        if k == "p" {
            let Some(&(first_us, _)) = events.first() else { continue };
            let r = reps.get_or_insert_with(|| Repeats { first: ts.to_string(), first_us, last_us: 0, n: 0, frames: HashSet::new() });
            for (us, d) in events {
                r.n += 1;
                r.last_us = us;
                if r.frames.len() < 64 {
                    r.frames.insert(d);
                }
            }
            continue;
        }
        if k != "c" {
            if let Some(r) = reps.take() {
                if !at_line_start { writeln!(out)?; at_line_start = true; }
                writeln!(out, "{}", r.line(o))?;
            }
        }
        match k {
            "o" => {
                let b = rec_bytes(m);
                let text = if o.raw { String::from_utf8_lossy(&b).into_owned() } else { strip_ansi(&b) };
                for piece in text.split_inclusive('\n') {
                    if at_line_start {
                        let fd = m.get("fd").and_then(Value::as_u64).map(|f| if f == 2 { " err" } else { "" }).unwrap_or("");
                        write!(out, "{}{} | ", disp(ts, o), fd)?;
                    }
                    write!(out, "{piece}")?;
                    at_line_start = piece.ends_with('\n');
                }
            }
            "i" if o.keys => {
                if !at_line_start { writeln!(out)?; at_line_start = true; }
                writeln!(out, "{} keys {}", disp(ts, o), render_keys(&rec_bytes(m)))?;
            }
            "x" if o.cmds => {
                if !at_line_start { writeln!(out)?; at_line_start = true; }
                let src = m.get("src").and_then(Value::as_str).unwrap_or("");
                let exit = m.get("exit").map(|e| format!(" exit={e}")).unwrap_or_default();
                writeln!(out, "{} cmd [{}] {}{}", disp(ts, o), src, m.get("cmd").and_then(Value::as_str).unwrap_or(""), exit)?;
            }
            "n" => {
                if !at_line_start { writeln!(out)?; at_line_start = true; }
                writeln!(out, "{} [note] {}", disp(ts, o), m.get("msg").and_then(Value::as_str).unwrap_or(""))?;
            }
            "l" | "e" | "f" | "a" | "g" | "r" => {
                if k == "r" && !o.cmds { continue; }
                if !at_line_start { writeln!(out)?; at_line_start = true; }
                let mut mm = m.clone();
                mm.remove("k"); mm.remove("s"); mm.remove("ts");
                if k == "e" { mm.remove("sig"); mm.remove("chain"); }
                writeln!(out, "{} [{}] {}", disp(ts, o), k, Value::Object(mm))?;
            }
            _ => {}
        }
    }
    if let Some(r) = reps.take() {
        if !at_line_start { writeln!(out)?; at_line_start = true; }
        writeln!(out, "{}", r.line(o))?;
    }
    if !at_line_start { writeln!(out)?; }
    Ok(())
}
