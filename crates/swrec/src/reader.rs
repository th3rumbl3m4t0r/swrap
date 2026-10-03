//! Tolerant reader and verifier (spec 8.5). The reader never refuses a file:
//! a final line without LF is a truncated tail, bad CRC/JSON lines are skipped and reported,
//! sequence gaps are reported, and segments/chain/signature are verified.

use crate::format::{chain_step, decode_line, RecVerifier};
use anyhow::{Context, Result};
use serde_json::{Map, Value};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

pub struct RawLine<'a> {
    /// Line bytes without the trailing LF.
    pub bytes: &'a [u8],
    /// Offset of the line in the (decompressed) stream.
    pub off: u64,
    /// 1-based line number.
    pub lineno: u64,
    /// False for a final line without LF (truncated tail).
    pub complete: bool,
}

#[derive(Default, Debug, Clone)]
pub struct SourceReport {
    pub gz: bool,
    /// Human-readable descriptions of container-level damage (gzip members).
    pub damage: Vec<String>,
    pub bytes: u64,
}

pub fn is_gz(path: &Path) -> bool {
    path.extension().map(|e| e == "gz").unwrap_or(false) || path.to_string_lossy().ends_with(".gz.tmp")
}

struct Splitter {
    buf: Vec<u8>,
    off: u64,
    lineno: u64,
}

impl Splitter {
    fn feed(&mut self, data: &[u8], f: &mut dyn FnMut(RawLine) -> bool) -> bool {
        let mut start = 0;
        for (i, &b) in data.iter().enumerate() {
            if b == b'\n' {
                self.lineno += 1;
                let cont;
                if self.buf.is_empty() {
                    cont = f(RawLine { bytes: &data[start..i], off: self.off, lineno: self.lineno, complete: true });
                    self.off += (i - start + 1) as u64;
                } else {
                    self.buf.extend_from_slice(&data[start..i]);
                    let l = std::mem::take(&mut self.buf);
                    cont = f(RawLine { bytes: &l, off: self.off, lineno: self.lineno, complete: true });
                    self.off += l.len() as u64 + 1;
                }
                if !cont {
                    return false;
                }
                start = i + 1;
            }
        }
        self.buf.extend_from_slice(&data[start..]);
        if self.buf.len() > 64 << 20 {
            // Pathological line (no LF for 64 MiB): report as damaged and drop.
            self.lineno += 1;
            let l = std::mem::take(&mut self.buf);
            let c = f(RawLine { bytes: &l[..64.min(l.len())], off: self.off, lineno: self.lineno, complete: false });
            self.off += l.len() as u64;
            return c;
        }
        true
    }
    fn finish(&mut self, f: &mut dyn FnMut(RawLine) -> bool) {
        if !self.buf.is_empty() {
            self.lineno += 1;
            let l = std::mem::take(&mut self.buf);
            f(RawLine { bytes: &l, off: self.off, lineno: self.lineno, complete: false });
        }
    }
}

fn find_gz_header(data: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?.windows(3).position(|w| w == [0x1f, 0x8b, 0x08]).map(|p| p + from)
}

/// Iterate raw lines of a `.swrec` or multi-member `.swrec.gz`. `f` returns false to stop.
pub fn for_each_raw_line(path: &Path, mut f: impl FnMut(RawLine) -> bool) -> Result<SourceReport> {
    let mut rep = SourceReport { gz: is_gz(path), ..Default::default() };
    let mut sp = Splitter { buf: Vec::new(), off: 0, lineno: 0 };
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    if !rep.gz {
        let mut r = BufReader::with_capacity(256 << 10, file);
        loop {
            let chunk = r.fill_buf()?;
            if chunk.is_empty() {
                break;
            }
            let n = chunk.len();
            rep.bytes += n as u64;
            if !sp.feed(chunk, &mut f) {
                return Ok(rep);
            }
            r.consume(n);
        }
        sp.finish(&mut f);
        return Ok(rep);
    }
    let mut data = Vec::new();
    BufReader::new(file).read_to_end(&mut data)?;
    let mut pos = 0usize;
    let mut out = vec![0u8; 256 << 10];
    let mut member = 0;
    while pos < data.len() {
        member += 1;
        let mut dec = flate2::bufread::GzDecoder::new(&data[pos..]);
        let mut failed = false;
        loop {
            match dec.read(&mut out) {
                Ok(0) => break,
                Ok(n) => {
                    rep.bytes += n as u64;
                    if !sp.feed(&out[..n], &mut f) {
                        return Ok(rep);
                    }
                }
                Err(e) => {
                    rep.damage.push(format!("gzip member {member} at byte {pos}: {e}"));
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            // Force a line break so the partial line doesn't glue onto the next member.
            if !sp.buf.is_empty() {
                sp.buf.push(b'\x00');
                if !sp.feed(b"\n", &mut f) {
                    return Ok(rep);
                }
            }
            match find_gz_header(&data, pos + 1) {
                Some(p) => {
                    rep.damage.push(format!("resynchronised at byte {p}"));
                    pos = p;
                }
                None => break,
            }
        } else {
            let rest = dec.into_inner().len();
            let consumed = data.len() - pos - rest;
            if consumed == 0 {
                break;
            }
            pos += consumed;
            // Skip zero padding / garbage between members.
            if pos < data.len() && !data[pos..].starts_with(&[0x1f, 0x8b]) {
                match find_gz_header(&data, pos) {
                    Some(p) => {
                        rep.damage.push(format!("{} bytes of garbage after member {member}", p - pos));
                        pos = p;
                    }
                    None => {
                        if data[pos..].iter().any(|&b| b != 0) {
                            rep.damage.push(format!("{} trailing bytes of garbage", data.len() - pos));
                        }
                        break;
                    }
                }
            }
        }
    }
    sp.finish(&mut f);
    Ok(rep)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Ok,
    OkIncomplete,
    Damaged,
    Tampered,
    Live,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::OkIncomplete => "ok-incomplete",
            Status::Damaged => "damaged",
            Status::Tampered => "tampered",
            Status::Live => "live",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Report {
    pub status: Status,
    pub records: u64,
    pub damaged: Vec<String>,
    pub gaps: Vec<(u64, u64)>,
    pub notes: Vec<String>,
    pub truncated_tail: bool,
    pub segments_ok: u64,
    pub signature: Option<bool>,
    pub signer: Option<String>,
}

pub struct Scan {
    pub header: Option<Map<String, Value>>,
    pub end: Option<Map<String, Value>>,
    pub records: Vec<Map<String, Value>>,
    pub report: Report,
}

pub struct ScanOpts<'a> {
    pub verifier: Option<&'a RecVerifier>,
    pub keep_records: bool,
    pub live: bool,
}

/// Read, verify and optionally collect every good record (single pass).
pub fn scan(path: &Path, opts: ScanOpts) -> Result<Scan> {
    let mut header: Option<Map<String, Value>> = None;
    let mut end: Option<Map<String, Value>> = None;
    let mut records = vec![];
    let mut damaged = vec![];
    let mut gaps = vec![];
    let mut notes = vec![];
    let mut truncated = false;
    let mut tampered = false;
    let mut count = 0u64;
    let mut last_s: u64 = 0;
    let mut chain = [0u8; 32];
    let mut seg_hasher = blake3::Hasher::new();
    let mut seg_bad = false;
    let mut segments_ok = 0u64;
    let mut after_end = false;
    // Repeats (`p`) must expand to exactly what the writer folded.
    let mut expander = crate::repeat::Expander::default();

    let src = for_each_raw_line(path, |l| {
        if !l.complete {
            truncated = true;
            return true;
        }
        let m = match decode_line(l.bytes) {
            Ok(m) => m,
            Err(why) => {
                damaged.push(format!("line {} (offset {}): bad {}", l.lineno, l.off, why));
                seg_bad = true;
                seg_hasher.update(l.bytes);
                seg_hasher.update(b"\n");
                return true;
            }
        };
        count += 1;
        let k = m.get("k").and_then(Value::as_str).unwrap_or("").to_string();
        if after_end {
            notes.push(format!("line {}: record after end record", l.lineno));
            tampered = true;
        }
        if k == "h" {
            if header.is_some() {
                notes.push(format!("line {}: second header", l.lineno));
                tampered = true;
            } else {
                header = Some(m.clone());
            }
        } else {
            if header.is_none() && last_s == 0 {
                damaged.push("header missing or damaged".into());
            }
            if let Some(s) = m.get("s").and_then(Value::as_u64) {
                if s > last_s + 1 {
                    gaps.push((last_s + 1, s - 1));
                } else if s <= last_s {
                    notes.push(format!("line {}: sequence went backwards ({} after {})", l.lineno, s, last_s));
                    tampered = true;
                }
                last_s = s;
            }
        }
        if k == "c" || k == "e" {
            // Segment = raw lines since the previous checkpoint (inclusive) up to this line (exclusive).
            let seg_hash = *std::mem::replace(&mut seg_hasher, blake3::Hasher::new()).finalize().as_bytes();
            let expect = chain_step(&chain, &seg_hash);
            let rec_chain = m
                .get("chain")
                .and_then(Value::as_str)
                .and_then(|h| hex::decode(h).ok())
                .and_then(|v| <[u8; 32]>::try_from(v).ok());
            match rec_chain {
                Some(rc) if rc == expect => segments_ok += 1,
                Some(_) if seg_bad => {} // damage already reported; can't judge this segment
                Some(_) => {
                    let seg = m.get("seg").and_then(Value::as_u64).unwrap_or(0);
                    notes.push(format!("segment {seg} (ends line {}): chain mismatch", l.lineno));
                    tampered = true;
                }
                None => notes.push(format!("line {}: checkpoint without chain", l.lineno)),
            }
            if let Some(rc) = rec_chain {
                chain = rc; // continue from the recorded chain so later segments verify independently
            }
            seg_bad = false;
        }
        if k != "e" {
            seg_hasher.update(l.bytes);
            seg_hasher.update(b"\n");
        }
        if k == "o" || k == "p" {
            if let Err(e) = expander.feed(&m) {
                damaged.push(format!("line {}: {e}", l.lineno));
            }
        }
        if opts.keep_records {
            records.push(m.clone());
        }
        if k == "e" {
            end = Some(m);
            after_end = true;
        }
        true
    })?;

    damaged.extend(src.damage.iter().cloned());

    let mut signature = None;
    let mut signer = None;
    if let (Some(e), Some(h)) = (&end, &header) {
        let chain_v = e
            .get("chain")
            .and_then(Value::as_str)
            .and_then(|h| hex::decode(h).ok())
            .and_then(|v| <[u8; 32]>::try_from(v).ok());
        match (e.get("sig").and_then(Value::as_str), e.get("signer").and_then(Value::as_str), chain_v) {
            (Some(sig), Some(sg), Some(c)) => {
                signer = Some(sg.to_string());
                if let Some(v) = opts.verifier {
                    if v.has(sg) {
                        let id = h.get("id").and_then(Value::as_str).unwrap_or("");
                        let ok = v.verify(sg, &c, id, sig).unwrap_or(false);
                        signature = Some(ok);
                        if !ok {
                            tampered = true;
                            notes.push("end record signature invalid".into());
                        }
                    } else {
                        notes.push(format!("no public key for signer {sg}; signature not checked"));
                    }
                }
            }
            _ => notes.push("end record not signed".into()),
        }
    }

    let status = if tampered {
        Status::Tampered
    } else if !damaged.is_empty() || !gaps.is_empty() || header.is_none() {
        Status::Damaged
    } else if end.is_none() {
        if opts.live { Status::Live } else { Status::OkIncomplete }
    } else {
        Status::Ok
    };
    if truncated {
        notes.push("truncated tail ignored".into());
    }
    Ok(Scan {
        header,
        end,
        records,
        report: Report { status, records: count, damaged, gaps, notes, truncated_tail: truncated, segments_ok, signature, signer },
    })
}

/// Read only the header (first good line) quickly.
pub fn read_header(path: &Path) -> Option<Map<String, Value>> {
    let mut h = None;
    let _ = for_each_raw_line(path, |l| {
        if let Ok(m) = decode_line(l.bytes) {
            if m.get("k").and_then(Value::as_str) == Some("h") {
                h = Some(m);
            }
            return false;
        }
        l.lineno < 4
    });
    h
}

/// Header plus last record timestamp (for timeframe pruning / listings), cheap for plain files.
pub fn header_and_last_ts(path: &Path) -> (Option<Map<String, Value>>, Option<String>, Option<Map<String, Value>>) {
    let h = read_header(path);
    let mut last_ts = None;
    let mut end = None;
    if !is_gz(path) {
        // Read the tail of the file.
        if let Ok(mut f) = File::open(path) {
            use std::io::{Seek, SeekFrom};
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            let start = len.saturating_sub(64 << 10);
            if f.seek(SeekFrom::Start(start)).is_ok() {
                let mut buf = vec![];
                let _ = f.read_to_end(&mut buf);
                for line in buf.split(|&b| b == b'\n') {
                    if let Ok(m) = decode_line(line) {
                        if let Some(t) = m.get("ts").and_then(Value::as_str) {
                            last_ts = Some(t.to_string());
                        }
                        if m.get("k").and_then(Value::as_str) == Some("e") {
                            end = Some(m);
                        }
                    }
                }
            }
        }
    } else {
        let _ = for_each_raw_line(path, |l| {
            if let Ok(m) = decode_line(l.bytes) {
                if let Some(t) = m.get("ts").and_then(Value::as_str) {
                    last_ts = Some(t.to_string());
                }
                if m.get("k").and_then(Value::as_str) == Some("e") {
                    end = Some(m);
                }
            }
            true
        });
    }
    (h, last_ts, end)
}
