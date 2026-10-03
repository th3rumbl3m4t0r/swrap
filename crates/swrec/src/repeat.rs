//! Repeated output (spec 8.3 `p`, swrec 1.2).
//!
//! A TUI that animates while it waits (a spinner, a scanner bar, a progress line redrawn in
//! place) writes the same few screen updates over and over, for as long as it waits: one swai
//! session wrote 200 MB of a 52-frame "working" animation in a day. The writer stores such
//! repeats as references instead: a `p` record stands for `n` consecutive output events, each a
//! byte-for-byte copy of the event `dist` places earlier in the output stream, with its exact
//! time. Readers expand it back into exactly the records an unfolded recording would hold: same
//! bytes, same microsecond timestamps. Nothing is dropped; it is only stored smaller.
//!
//! The output stream is every `o` record without `fd` or `call`, in file order, with the events
//! of each `p` record in its place. `p` fields:
//!
//! - `n`: number of events; the first is at `ts`, the last at `end` (omitted when `n` is 1)
//! - `back`: the distances, `1 ≤ dist ≤` [`WINDOW`]
//! - `jit`: each event's offset in µs from an even spread over `ts`..`end`; omitted when all
//!   are zero (a timer firing on the dot)
//! - `crc`: crc32c of the expanded bytes, so a reader that lost its place notices
//!
//! `back` and `jit` are run-length packed: `[v, count]` for a run, a bare number otherwise.

use serde_json::{json, Map, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// How far back (in output events) a repeat may point; readers keep this many events.
pub const WINDOW: usize = 1024;
/// Longer events are never folded (and readers need not keep them).
pub const MAX_EVENT: usize = 4096;
/// Events per `p` record at most.
pub const MAX_TRACK: usize = 8192;

/// Is this record part of the output stream that `p` records refer to?
pub fn in_stream(m: &Map<String, Value>) -> bool {
    m.get("k").and_then(Value::as_str) == Some("o") && !m.contains_key("fd") && !m.contains_key("call")
}

/// The last [`WINDOW`] events of the output stream (`None`: binary, or too long to repeat).
#[derive(Default)]
struct History {
    ring: VecDeque<Option<Arc<str>>>,
    total: u64,
}

impl History {
    /// Append an event; returns the one that fell out of the window, with its index.
    fn push(&mut self, d: Option<Arc<str>>) -> Option<(u64, Arc<str>)> {
        let old = if self.ring.len() == WINDOW {
            let first = self.total - WINDOW as u64;
            self.ring.pop_front().flatten().map(|p| (first, p))
        } else {
            None
        };
        self.ring.push_back(d);
        self.total += 1;
        old
    }
    /// The event `dist` places before the next one (1 = the latest).
    fn back(&self, dist: usize) -> Option<&Arc<str>> {
        if dist == 0 || dist > self.ring.len() {
            return None;
        }
        self.ring[self.ring.len() - dist].as_ref()
    }
}

fn keep(d: &str) -> Option<Arc<str>> {
    (!d.is_empty() && d.len() <= MAX_EVENT).then(|| Arc::from(d))
}

// ---------------------------------------------------------------- writer side

/// Events folded so far, waiting to be written as one `p` record.
#[derive(Default)]
pub struct Track {
    times: Vec<i64>,
    back: Vec<[u64; 2]>,
    payloads: Vec<Arc<str>>,
    crc: u32,
}

impl Track {
    pub fn len(&self) -> usize {
        self.times.len()
    }
    pub fn is_empty(&self) -> bool {
        self.times.is_empty()
    }
    /// Time of the first event (µs since the epoch).
    pub fn first_us(&self) -> i64 {
        self.times[0]
    }
    /// The events one by one (time in µs, bytes): for writing them as plain `o` records when
    /// a `p` record would not be smaller.
    pub fn events(&self) -> impl Iterator<Item = (i64, &str)> {
        self.times.iter().copied().zip(self.payloads.iter().map(|p| &**p))
    }
    /// Rough size of the events as plain `o` records.
    pub fn plain_bytes(&self) -> usize {
        self.payloads.iter().map(|p| serde_json::to_string(&**p).map(|s| s.len()).unwrap_or(p.len()) + 60).sum()
    }
    fn add(&mut self, dist: usize, ts_us: i64, p: &Arc<str>) {
        match self.back.last_mut() {
            Some(l) if l[0] == dist as u64 => l[1] += 1,
            _ => self.back.push([dist as u64, 1]),
        }
        self.times.push(ts_us);
        self.crc = crc32c::crc32c_append(self.crc, p.as_bytes());
        self.payloads.push(p.clone());
    }
    /// The `p` record's fields besides `k`, `s` and `ts` (= the first event's time).
    pub fn fields(&self) -> Map<String, Value> {
        let n = self.times.len();
        let mut m = Map::new();
        m.insert("n".into(), n.into());
        if n > 1 {
            m.insert("end".into(), fmt_us(self.times[n - 1]).into());
        }
        let back: Vec<i64> = self.back.iter().flat_map(|&[d, c]| std::iter::repeat_n(d as i64, c as usize)).collect();
        m.insert("back".into(), pack(&back));
        let jit = jitter(&self.times);
        if jit.iter().any(|&j| j != 0) {
            m.insert("jit".into(), pack(&jit));
        }
        m.insert("crc".into(), format!("{:08x}", self.crc).into());
        m
    }
}

/// Writer-side folding state. For each text output event, [`Folder::offer`] decides: folded
/// into the open track (nothing to write now), or written as a plain `o` record — after the
/// open track is written ([`Folder::take`]) and followed by [`Folder::wrote`].
#[derive(Default)]
pub struct Folder {
    hist: History,
    seen: HashMap<Arc<str>, u64>,
    dist: usize,
    track: Option<Track>,
}

impl Folder {
    /// Fold `d` if it repeats one of the last [`WINDOW`] events. Prefers the distance of the
    /// previous repeat, so a cycle stays one run in `back` even where frames recur inside it.
    pub fn offer(&mut self, d: &str, ts_us: i64) -> bool {
        if d.is_empty() || d.len() > MAX_EVENT {
            return false;
        }
        let mut dist = 0;
        if self.dist > 0 && self.hist.back(self.dist).is_some_and(|p| &**p == d) {
            dist = self.dist;
        } else if let Some(&j) = self.seen.get(d) {
            dist = (self.hist.total - j) as usize;
        }
        let Some(p) = self.hist.back(dist).cloned() else { return false };
        self.track.get_or_insert_with(Track::default).add(dist, ts_us, &p);
        self.dist = dist;
        self.remember(Some(p));
        true
    }
    /// A plain stream event was written (text, or `None` for binary).
    pub fn wrote(&mut self, d: Option<&str>) {
        self.remember(d.and_then(keep));
    }
    fn remember(&mut self, p: Option<Arc<str>>) {
        let i = self.hist.total;
        if let Some(p) = &p {
            self.seen.insert(p.clone(), i);
        }
        if let Some((j, old)) = self.hist.push(p) {
            if self.seen.get(&old) == Some(&j) {
                self.seen.remove(&old);
            }
        }
    }
    pub fn track(&self) -> Option<&Track> {
        self.track.as_ref()
    }
    /// The open track, to be written now.
    pub fn take(&mut self) -> Option<Track> {
        self.track.take()
    }
}

// ---------------------------------------------------------------- reader side

/// Reader-side counterpart: feed every record in file order; `p` records come back as events.
#[derive(Default)]
pub struct Expander {
    hist: History,
}

impl Expander {
    /// The stream events a record stands for, as (time in µs, bytes): a stream `o` record
    /// itself, a `p` record its copies, anything else none. A `p` record that cannot be
    /// expanded (points outside what was read, or fails its crc) is an error.
    pub fn feed(&mut self, m: &Map<String, Value>) -> Result<Vec<(i64, Arc<str>)>, String> {
        match m.get("k").and_then(Value::as_str) {
            Some("p") => self.repeat(m),
            Some("o") if in_stream(m) => {
                let t = m.get("ts").and_then(Value::as_str).and_then(parse_us).unwrap_or(0);
                let d: Option<Arc<str>> = match m.get("d").and_then(Value::as_str) {
                    Some(s) => Some(Arc::from(s)),
                    None => Some(Arc::from(String::from_utf8_lossy(&crate::render::rec_bytes(m)).as_ref())),
                };
                self.hist.push(m.get("d").and_then(Value::as_str).and_then(keep));
                Ok(d.map(|d| vec![(t, d)]).unwrap_or_default())
            }
            _ => Ok(vec![]),
        }
    }

    fn repeat(&mut self, m: &Map<String, Value>) -> Result<Vec<(i64, Arc<str>)>, String> {
        let n = m.get("n").and_then(Value::as_u64).unwrap_or(0) as usize;
        let res = self.repeat_inner(m, n);
        if res.is_err() {
            // Keep later distances aligned even if this record is unusable.
            for _ in 0..n.min(MAX_TRACK) {
                self.hist.push(None);
            }
        }
        res
    }

    fn repeat_inner(&mut self, m: &Map<String, Value>, n: usize) -> Result<Vec<(i64, Arc<str>)>, String> {
        let s = m.get("s").and_then(Value::as_u64).unwrap_or(0);
        let t0 = m.get("ts").and_then(Value::as_str).and_then(parse_us).ok_or(format!("repeat s={s}: bad ts"))?;
        let tl = match m.get("end").and_then(Value::as_str) {
            Some(e) => parse_us(e).ok_or(format!("repeat s={s}: bad end"))?,
            None => t0,
        };
        let back = unrle(m.get("back")).ok_or(format!("repeat s={s}: bad back"))?;
        let jit = match m.get("jit") {
            Some(j) => unrle(Some(j)).ok_or(format!("repeat s={s}: bad jit"))?,
            None => vec![0; n],
        };
        if n == 0 || n > MAX_TRACK || back.len() != n || jit.len() != n {
            return Err(format!("repeat s={s}: counts do not add up to n={n}"));
        }
        // Resolve against a scratch copy first: a bad record must not half-update the history.
        let mut out = Vec::with_capacity(n);
        let mut scratch: Vec<Arc<str>> = Vec::with_capacity(n);
        let mut crc = 0u32;
        for (k, &dist) in back.iter().enumerate() {
            if dist < 1 || dist > WINDOW as i64 {
                return Err(format!("repeat s={s}: distance {dist} out of range"));
            }
            let dist = dist as usize;
            // Copies may overlap the events being expanded (a run longer than its distance).
            let p = if dist <= k { scratch[k - dist].clone() } else { self.hist.back(dist - k).cloned().ok_or(format!("repeat s={s}: refers to output that was not read"))? };
            crc = crc32c::crc32c_append(crc, p.as_bytes());
            let t = t0.checked_add(grid(k, n, tl.saturating_sub(t0))).and_then(|t| t.checked_add(jit[k])).ok_or(format!("repeat s={s}: time out of range"))?;
            out.push((t, p.clone()));
            scratch.push(p);
        }
        let want = m.get("crc").and_then(Value::as_str).and_then(|h| u32::from_str_radix(h, 16).ok());
        if want != Some(crc) {
            return Err(format!("repeat s={s}: expansion does not match its crc"));
        }
        for p in scratch {
            self.hist.push(Some(p));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------- helpers

/// Offset of event `k` of `n` spread evenly over `span` µs (integer math, same on both sides).
pub fn grid(k: usize, n: usize, span: i64) -> i64 {
    if n < 2 {
        return 0;
    }
    (span as i128 * k as i128 / (n as i128 - 1)) as i64
}

/// Each event's exact offset (µs) from the even spread between the first and the last.
fn jitter(times: &[i64]) -> Vec<i64> {
    let n = times.len();
    let (t0, span) = (times[0], times[n - 1] - times[0]);
    times.iter().enumerate().map(|(k, &t)| t - t0 - grid(k, n, span)).collect()
}

/// Run-length packing: `[v, count]` for runs of 3 or more, bare numbers otherwise.
fn pack(v: &[i64]) -> Value {
    let mut out = vec![];
    let mut i = 0;
    while i < v.len() {
        let mut j = i + 1;
        while j < v.len() && v[j] == v[i] {
            j += 1;
        }
        if j - i >= 3 {
            out.push(json!([v[i], j - i]));
        } else {
            out.extend(v[i..j].iter().map(|&x| json!(x)));
        }
        i = j;
    }
    Value::Array(out)
}

fn unrle(v: Option<&Value>) -> Option<Vec<i64>> {
    let mut out = vec![];
    for item in v?.as_array()? {
        let (x, c) = match item {
            Value::Array(a) if a.len() == 2 => (a[0].as_i64()?, a[1].as_u64()?),
            other => (other.as_i64()?, 1),
        };
        if c == 0 || out.len() as u64 + c > MAX_TRACK as u64 {
            return None;
        }
        out.extend(std::iter::repeat_n(x, c as usize));
    }
    Some(out)
}

pub fn parse_us(ts: &str) -> Option<i64> {
    ts.parse::<jiff::Timestamp>().ok().map(|t| t.as_microsecond())
}

pub fn fmt_us(us: i64) -> String {
    swrap_core::time::fmt_utc(jiff::Timestamp::from_microsecond(us).expect("timestamp in range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fold a stream the way the writer does, then expand it the way readers do.
    fn roundtrip(events: &[(i64, &str)]) -> (Vec<Map<String, Value>>, Vec<(i64, Arc<str>)>) {
        let mut f = Folder::default();
        let mut recs = vec![];
        let mut s = 0u64;
        let flush = |f: &mut Folder, recs: &mut Vec<Map<String, Value>>, s: &mut u64| {
            if let Some(t) = f.take() {
                *s += 1;
                let mut m = t.fields();
                m.insert("k".into(), "p".into());
                m.insert("s".into(), (*s).into());
                m.insert("ts".into(), fmt_us(t.first_us()).into());
                recs.push(m);
            }
        };
        for &(t, d) in events {
            if !f.offer(d, t) {
                flush(&mut f, &mut recs, &mut s);
                s += 1;
                recs.push(json!({"k": "o", "s": s, "ts": fmt_us(t), "d": d}).as_object().unwrap().clone());
                f.wrote(Some(d));
            }
        }
        flush(&mut f, &mut recs, &mut s);
        let mut e = Expander::default();
        let mut out = vec![];
        for m in &recs {
            out.extend(e.feed(m).unwrap());
        }
        (recs, out)
    }

    fn check(events: &[(i64, &str)], out: &[(i64, Arc<str>)]) {
        assert_eq!(events.len(), out.len());
        for ((t, d), (t2, d2)) in events.iter().zip(out) {
            assert_eq!(*d, &**d2);
            assert_eq!(t, t2, "timestamps come back exactly");
        }
    }

    #[test]
    fn scanner_animation_with_dropped_frames() {
        // A 52-frame cycle at ~42 ms, dropping a frame now and then, with jittery timing.
        let frames: Vec<String> = (0..52).map(|i| format!("\x1b[69;4H\x1b[38;2;{i};50;75m⬝■⬝ frame {i}")).collect();
        let mut ev = vec![];
        let mut t = 1_700_000_000_000_000i64;
        let mut k = 0usize;
        for step in 0..5000 {
            if step % 37 == 0 {
                k += 1; // dropped frame
            }
            ev.push((t, frames[k % 52].as_str()));
            k += 1;
            t += 42_000 + (step as i64 * 7919 % 3000) - 1500;
        }
        let (recs, out) = roundtrip(&ev);
        check(&ev, &out);
        let plain = recs.iter().filter(|m| m["k"] == "o").count();
        assert!(plain <= 104, "{plain} frames written in full");
        assert!(recs.len() < 200, "{} records for 5000 frames", recs.len());
    }

    #[test]
    fn same_line_every_five_seconds() {
        let ev: Vec<(i64, &str)> = (0..100).map(|i| (1_000_000_000 + i * 5_000_000, "waiting for lock...\r\n")).collect();
        let (recs, out) = roundtrip(&ev);
        check(&ev, &out);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[1]["back"], json!([[1, 99]]));
        assert_eq!(recs[1]["n"], 99);
        assert!(recs[1].get("jit").is_none());
    }

    #[test]
    fn overlapping_run_and_irregular_times() {
        let ev: Vec<(i64, &str)> = vec![(0, "a"), (10, "b"), (20_000, "a"), (40_000, "b"), (41_000, "a"), (900_000, "b"), (2_000_000, "c"), (2_000_001, "c")];
        let (_, out) = roundtrip(&ev);
        check(&ev, &out);
    }

    #[test]
    fn corrupt_repeat_is_reported_and_keeps_alignment() {
        let ev: Vec<(i64, &str)> = (0..20).map(|i| (i * 1000, if i % 2 == 0 { "x" } else { "y" })).collect();
        let (mut recs, _) = roundtrip(&ev);
        let i = recs.iter().position(|m| m["k"] == "p").unwrap();
        recs[i].insert("crc".into(), "00000000".into());
        let mut e = Expander::default();
        let errs = recs.iter().filter(|m| e.feed(m).is_err()).count();
        assert_eq!(errs, 1);
        assert_eq!(e.hist.total, 20);
    }

    #[test]
    fn distances_stay_in_the_window_and_memory_is_bounded() {
        let mut f = Folder::default();
        for i in 0..10 * WINDOW {
            let d = format!("line {}", i % (WINDOW + 5));
            if !f.offer(&d, i as i64) {
                f.wrote(Some(&d));
            }
        }
        assert!(f.seen.len() <= WINDOW);
        assert!(f.track().is_none(), "a period longer than the window must not fold");
    }
}
