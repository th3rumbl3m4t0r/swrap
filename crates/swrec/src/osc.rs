//! Streaming filter for swrap's private OSC 7719 sequences (spec 9.4, 9.5):
//! `ESC ] 7719 ; <nonce> ; <payload> BEL` (ST `ESC \` also accepted).
//! Sequences with the right nonce are removed from the stream and turned into events;
//! sequences with a wrong nonce stay in the output and are flagged.

use crate::format::B64;
use base64::Engine;

const PREFIX: &[u8] = b"\x1b]7719;";
const MAX: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OscEvent {
    /// Command from shell integration.
    Cmd { cmd: String, cwd: Option<String>, exit: Option<i64> },
    /// `sw-start:<id>` / `sw-end:<id>` marker.
    Marker { start: bool, id: String },
    /// Sequence with a wrong nonce (left in the output).
    WrongNonce,
    /// Undecodable payload with the right nonce.
    Malformed(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Piece {
    Bytes(Vec<u8>),
    Event(OscEvent),
}

pub struct OscFilter {
    nonces: Vec<Vec<u8>>,
    held: Vec<u8>,
}

impl OscFilter {
    pub fn new(nonce: &str) -> Self {
        OscFilter { nonces: vec![nonce.as_bytes().to_vec()], held: Vec::new() }
    }
    /// Accept an additional nonce (e.g. the shell nonce and the `sw` session nonce).
    pub fn add_nonce(&mut self, n: &str) {
        self.nonces.push(n.as_bytes().to_vec());
    }

    pub fn push(&mut self, data: &[u8]) -> Vec<Piece> {
        let mut out = Vec::new();
        let mut plain = Vec::with_capacity(data.len());
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(data);
        let mut i = 0;
        while i < buf.len() {
            if buf[i] != 0x1b {
                // fast path: copy until next ESC
                let next = buf[i..].iter().position(|&b| b == 0x1b).map(|p| p + i).unwrap_or(buf.len());
                plain.extend_from_slice(&buf[i..next]);
                i = next;
                continue;
            }
            let rest = &buf[i..];
            let n = rest.len().min(PREFIX.len());
            if rest[..n] != PREFIX[..n] {
                plain.push(0x1b);
                i += 1;
                continue;
            }
            if rest.len() < PREFIX.len() {
                // could still become our prefix: hold
                self.held = rest.to_vec();
                break;
            }
            // Find terminator.
            let body = &rest[PREFIX.len()..];
            let mut term = None;
            for (j, &b) in body.iter().enumerate() {
                if b == 0x07 {
                    term = Some((j, 1));
                    break;
                }
                if b == 0x1b && body.get(j + 1) == Some(&b'\\') {
                    term = Some((j, 2));
                    break;
                }
                if b == 0x1b && j + 1 == body.len() {
                    break; // maybe ST split across chunks
                }
            }
            match term {
                None => {
                    if rest.len() > MAX {
                        plain.extend_from_slice(rest);
                    } else {
                        self.held = rest.to_vec();
                    }
                    break;
                }
                Some((j, tl)) => {
                    let whole = &rest[..PREFIX.len() + j + tl];
                    let content = &body[..j];
                    match self.decode(content) {
                        Some(ev) => {
                            if !plain.is_empty() {
                                out.push(Piece::Bytes(std::mem::take(&mut plain)));
                            }
                            out.push(Piece::Event(ev));
                        }
                        None => {
                            plain.extend_from_slice(whole);
                            if !plain.is_empty() {
                                out.push(Piece::Bytes(std::mem::take(&mut plain)));
                            }
                            out.push(Piece::Event(OscEvent::WrongNonce));
                        }
                    }
                    i += whole.len();
                }
            }
        }
        if !plain.is_empty() {
            out.push(Piece::Bytes(plain));
        }
        out
    }

    /// Flush held bytes (end of stream).
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }

    /// Returns None when the nonce doesn't match.
    fn decode(&self, content: &[u8]) -> Option<OscEvent> {
        let sep = content.iter().position(|&b| b == b';')?;
        let (nonce, payload) = (&content[..sep], &content[sep + 1..]);
        if nonce.is_empty() || !self.nonces.iter().any(|n| n.as_slice() == nonce) {
            return None;
        }
        let p = String::from_utf8_lossy(payload);
        if let Some(id) = p.strip_prefix("sw-start:") {
            return Some(OscEvent::Marker { start: true, id: id.to_string() });
        }
        if let Some(id) = p.strip_prefix("sw-end:") {
            return Some(OscEvent::Marker { start: false, id: id.to_string() });
        }
        let raw = match B64.decode(p.trim()) {
            Ok(r) => r,
            Err(e) => return Some(OscEvent::Malformed(format!("base64: {e}"))),
        };
        match serde_json::from_slice::<serde_json::Value>(&raw) {
            Ok(v) => {
                let cmd = v.get("cmd").and_then(|c| c.as_str()).unwrap_or("").to_string();
                let cwd = v.get("cwd").and_then(|c| c.as_str()).map(String::from);
                let exit = v.get("exit").and_then(|c| c.as_i64().or_else(|| c.as_str().and_then(|s| s.parse().ok())));
                Some(OscEvent::Cmd { cmd: strip_history_number(&cmd), cwd, exit })
            }
            Err(e) => Some(OscEvent::Malformed(format!("json: {e}"))),
        }
    }
}

/// `history 1` prints `  123  cmd`; strip the number.
fn strip_history_number(s: &str) -> String {
    let t = s.trim_start();
    let digits = t.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits > 0 && t[digits..].starts_with("  ") {
        t[digits..].trim_start().trim_end_matches('\n').to_string()
    } else {
        s.trim_end_matches('\n').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(nonce: &str, json: &str) -> Vec<u8> {
        format!("\x1b]7719;{};{}\x07", nonce, B64.encode(json)).into_bytes()
    }

    fn collect(f: &mut OscFilter, chunks: &[&[u8]]) -> (Vec<u8>, Vec<OscEvent>) {
        let mut out = vec![];
        let mut ev = vec![];
        for c in chunks {
            for p in f.push(c) {
                match p {
                    Piece::Bytes(b) => out.extend(b),
                    Piece::Event(e) => ev.push(e),
                }
            }
        }
        out.extend(f.finish());
        (out, ev)
    }

    #[test]
    fn strips_and_emits() {
        let mut f = OscFilter::new("N1");
        let mut data = b"hello ".to_vec();
        data.extend(seq("N1", r#"{"cmd":"  12  ls -la","cwd":"/root","exit":0}"#));
        data.extend(b"world\x1b]0;title\x07");
        // split at every position
        for cut in 0..data.len() {
            let mut f2 = OscFilter::new("N1");
            let (o, e) = collect(&mut f2, &[&data[..cut], &data[cut..]]);
            assert_eq!(o, b"hello world\x1b]0;title\x07", "cut {cut}");
            assert_eq!(e, vec![OscEvent::Cmd { cmd: "ls -la".into(), cwd: Some("/root".into()), exit: Some(0) }]);
        }
        let (_, e) = collect(&mut f, &[&data]);
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn wrong_nonce_stays() {
        let mut f = OscFilter::new("GOOD");
        let s = seq("BAD", r#"{"cmd":"x"}"#);
        let (o, e) = collect(&mut f, &[&s]);
        assert_eq!(o, s);
        assert_eq!(e, vec![OscEvent::WrongNonce]);
    }

    #[test]
    fn markers() {
        let mut f = OscFilter::new("S");
        let (o, e) = collect(&mut f, &[b"a\x1b]7719;S;sw-start:01ABC\x07b\x1b]7719;S;sw-end:01ABC\x1b\\c"]);
        assert_eq!(o, b"abc");
        assert_eq!(e, vec![OscEvent::Marker { start: true, id: "01ABC".into() }, OscEvent::Marker { start: false, id: "01ABC".into() }]);
    }
}
