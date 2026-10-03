//! swrec writer (spec 8.4): coalescing, one write(2) per record on O_APPEND, fdatasync at most
//! once per interval and always at checkpoints/end, checkpoints every PT10S or 256 KiB.
//! Output that repeats recent output is folded into `p` records (see `repeat`); folded events
//! are written no later than the sync interval, so a power loss costs no more than before.

use crate::format::{chain_step, encode_line, RecSigner, B64, VERSION};
use anyhow::{Context, Result};
use base64::Engine;
use serde_json::{json, Map, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use swrap_core::time::{fmt_duration, fmt_utc, EventClock};

#[derive(Clone, Debug)]
pub struct WriterOpts {
    pub coalesce: Duration,
    pub coalesce_max: usize,
    pub sync_interval: Duration,
    pub checkpoint_interval: Duration,
    pub checkpoint_bytes: u64,
    pub mode: u32,
    /// Fold repeated output into `p` records.
    pub fold: bool,
}

impl Default for WriterOpts {
    fn default() -> Self {
        WriterOpts {
            coalesce: Duration::from_millis(5),
            coalesce_max: 16384,
            sync_interval: Duration::from_secs(1),
            checkpoint_interval: Duration::from_secs(10),
            checkpoint_bytes: 262144,
            mode: 0o640,
            fold: true,
        }
    }
}

impl WriterOpts {
    pub fn from_cfg(c: &swrap_core::config::RecCfg) -> Self {
        WriterOpts {
            coalesce: c.coalesce.exact().unwrap_or(Duration::from_millis(5)),
            coalesce_max: c.coalesce_max_bytes,
            sync_interval: c.sync_interval.exact().unwrap_or(Duration::from_secs(1)),
            checkpoint_interval: c.checkpoint_interval.exact().unwrap_or(Duration::from_secs(10)),
            checkpoint_bytes: c.checkpoint_bytes,
            mode: 0o640,
            fold: c.fold_repeats,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PKey {
    Out(Option<u8>),
    In,
}

struct Pending {
    key: PKey,
    buf: Vec<u8>,
    since: Instant,
    ts: jiff::Timestamp,
}

/// Splits a byte stream into valid UTF-8 text, carrying an incomplete trailing sequence over.
#[derive(Default)]
pub struct Utf8Carry {
    carry: Vec<u8>,
}

pub enum Chunk {
    Text(String),
    Bin(Vec<u8>),
}

impl Utf8Carry {
    pub fn push(&mut self, data: &[u8]) -> Option<Chunk> {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(data);
        match std::str::from_utf8(&buf) {
            Ok(_) => Some(Chunk::Text(String::from_utf8(buf).unwrap())),
            Err(e) => {
                if e.error_len().is_none() {
                    // Incomplete sequence at the end: carry it (max 3 bytes).
                    let valid = e.valid_up_to();
                    self.carry = buf[valid..].to_vec();
                    buf.truncate(valid);
                    if buf.is_empty() {
                        None
                    } else {
                        Some(Chunk::Text(String::from_utf8(buf).unwrap()))
                    }
                } else {
                    Some(Chunk::Bin(buf))
                }
            }
        }
    }
    pub fn flush(&mut self) -> Option<Chunk> {
        if self.carry.is_empty() {
            None
        } else {
            Some(Chunk::Bin(std::mem::take(&mut self.carry)))
        }
    }
}

pub struct Writer {
    f: File,
    pub path: PathBuf,
    pub id: String,
    clock: EventClock,
    seq: u64,
    opts: WriterOpts,
    seg: u64,
    chain: [u8; 32],
    seg_hasher: blake3::Hasher,
    seg_first_s: u64,
    seg_bytes: u64,
    last_ckpt: Instant,
    last_sync: Instant,
    dirty: bool,
    pend: Option<Pending>,
    carry_out: Utf8Carry,
    carry_in: Utf8Carry,
    pub bytes_out: u64,
    pub bytes_in: u64,
    ended: bool,
    bg: Option<BgSync>,
    fold: crate::repeat::Folder,
}

/// Background I/O: an interactive relay must never stall on the disk (XFS can block a write()
/// while an fdatasync on the same file is running). Lines keep their order; the channel bound
/// gives backpressure if the disk falls far behind.
enum Io {
    Write(Vec<u8>),
    Sync,
    Barrier(std::sync::mpsc::Sender<std::io::Result<()>>),
}

struct BgSync {
    tx: std::sync::mpsc::SyncSender<Io>,
    failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

pub fn now_ts(c: &EventClock) -> String {
    fmt_utc(c.now())
}

fn ts_of(us: i64) -> jiff::Timestamp {
    jiff::Timestamp::from_microsecond(us).expect("timestamp in range")
}

impl Writer {
    /// Create a new file (must not exist), write and fdatasync the header, fsync the directory.
    /// `header` supplies kind-specific fields; `k`, `v`, `id`, `start` are filled in.
    pub fn create(path: &Path, id: &str, mut header: Map<String, Value>, opts: WriterOpts) -> Result<Self> {
        let dir = path.parent().context("no parent")?;
        std::fs::create_dir_all(dir)?;
        let f = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(opts.mode)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        let clock = EventClock::start();
        let mut h = Map::new();
        h.insert("k".into(), "h".into());
        h.insert("v".into(), VERSION.into());
        if let Some(kind) = header.remove("kind") {
            h.insert("kind".into(), kind);
        }
        h.insert("id".into(), id.into());
        h.insert("start".into(), fmt_utc(clock.wall).into());
        h.extend(header);
        let mut w = Writer {
            f,
            path: path.to_path_buf(),
            id: id.to_string(),
            clock,
            seq: 0,
            seg: 0,
            chain: [0u8; 32],
            seg_hasher: blake3::Hasher::new(),
            seg_first_s: 1,
            seg_bytes: 0,
            last_ckpt: Instant::now(),
            last_sync: Instant::now(),
            dirty: false,
            pend: None,
            carry_out: Utf8Carry::default(),
            carry_in: Utf8Carry::default(),
            bytes_out: 0,
            bytes_in: 0,
            ended: false,
            opts,
            bg: None,
            fold: Default::default(),
        };
        w.write_line(&Value::Object(h))?;
        w.f.sync_data()?;
        swrap_core::atomic::fsync_dir(dir)?;
        w.dirty = false;
        Ok(w)
    }

    /// Continue an existing, un-ended file (daily audit/log files after a restart).
    /// Terminates a torn final line with LF, restores sequence, chain and segment state.
    /// Returns Ok(None) if the file already has an end record.
    pub fn resume(path: &Path, opts: WriterOpts) -> Result<Option<Self>> {
        let mut last_s = 0u64;
        let mut chain = [0u8; 32];
        let mut seg = 0u64;
        let mut seg_hasher = blake3::Hasher::new();
        let mut seg_bytes = 0u64;
        let mut seg_first_s = 1u64;
        let mut id = String::new();
        let mut ended = false;
        let mut torn = false;
        crate::reader::for_each_raw_line(path, |l| {
            if !l.complete {
                torn = true;
            }
            let m = crate::format::decode_line(l.bytes).ok();
            let k = m.as_ref().and_then(|m| m.get("k")).and_then(Value::as_str).unwrap_or("").to_string();
            if let Some(m) = &m {
                if k == "h" {
                    id = m.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                }
                if let Some(s) = m.get("s").and_then(Value::as_u64) {
                    last_s = last_s.max(s);
                }
                if k == "c" {
                    if let Some(c) = m.get("chain").and_then(Value::as_str).and_then(|h| hex::decode(h).ok()).and_then(|v| <[u8; 32]>::try_from(v).ok()) {
                        chain = c;
                    }
                    seg = m.get("seg").and_then(Value::as_u64).unwrap_or(seg + 1);
                    seg_hasher = blake3::Hasher::new();
                    seg_bytes = 0;
                    seg_first_s = m.get("s").and_then(Value::as_u64).unwrap_or(last_s);
                }
                if k == "e" {
                    ended = true;
                }
            }
            seg_hasher.update(l.bytes);
            seg_hasher.update(b"\n");
            seg_bytes += l.bytes.len() as u64 + 1;
            true
        })?;
        if ended {
            return Ok(None);
        }
        let mut f = OpenOptions::new().append(true).open(path)?;
        if torn {
            f.write_all(b"\n")?;
        }
        let mut w = Writer {
            f,
            path: path.to_path_buf(),
            id,
            clock: EventClock::start(),
            seq: last_s,
            opts,
            seg,
            chain,
            seg_hasher,
            seg_first_s,
            seg_bytes,
            last_ckpt: Instant::now(),
            last_sync: Instant::now(),
            dirty: torn,
            pend: None,
            carry_out: Utf8Carry::default(),
            carry_in: Utf8Carry::default(),
            bytes_out: 0,
            bytes_in: 0,
            ended: false,
            bg: None,
            fold: Default::default(),
        };
        w.note("resumed after restart")?;
        Ok(Some(w))
    }

    pub fn clock(&self) -> &EventClock {
        &self.clock
    }

    fn write_line(&mut self, v: &Value) -> Result<()> {
        let line = encode_line(&serde_json::to_vec(v)?);
        if let Some(bg) = &self.bg {
            if bg.failed.load(std::sync::atomic::Ordering::SeqCst) {
                anyhow::bail!("recording write failed");
            }
            self.seg_hasher.update(&line);
            self.seg_bytes += line.len() as u64;
            self.dirty = true;
            bg.tx.send(Io::Write(line)).map_err(|_| anyhow::anyhow!("recording writer thread gone"))?;
            return Ok(());
        }
        self.f.write_all(&line)?;
        self.seg_hasher.update(&line);
        self.seg_bytes += line.len() as u64;
        self.dirty = true;
        Ok(())
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Write a record with explicit timestamp. `k` and fields; `s` and `ts` are added. Folded
    /// repeats go first, so the file stays in time order.
    fn emit_at(&mut self, k: &str, ts: jiff::Timestamp, fields: Map<String, Value>) -> Result<()> {
        self.flush_fold()?;
        if self.opts.fold && k == "o" && !fields.contains_key("fd") && !fields.contains_key("call") {
            // Readers count every stream event, however it was written; so must the folder.
            self.fold.wrote(fields.get("d").and_then(Value::as_str));
        }
        self.emit_raw(k, ts, fields)
    }

    fn emit_raw(&mut self, k: &str, ts: jiff::Timestamp, fields: Map<String, Value>) -> Result<()> {
        let s = self.next_seq();
        let mut m = Map::with_capacity(fields.len() + 3);
        m.insert("k".into(), k.into());
        m.insert("s".into(), s.into());
        m.insert("ts".into(), fmt_utc(ts).into());
        m.extend(fields);
        self.write_line(&Value::Object(m))?;
        if self.seg_bytes >= self.opts.checkpoint_bytes {
            self.checkpoint_inner(false)?;
        }
        Ok(())
    }

    /// Non-coalesced record (flushes pending data first so ordering is preserved).
    pub fn record(&mut self, k: &str, fields: Map<String, Value>) -> Result<()> {
        self.flush_pending()?;
        let ts = self.clock.now();
        self.emit_at(k, ts, fields)
    }

    pub fn record_json(&mut self, k: &str, v: Value) -> Result<()> {
        match v {
            Value::Object(m) => self.record(k, m),
            _ => self.record(k, Map::new()),
        }
    }

    pub fn note(&mut self, msg: &str) -> Result<()> {
        self.record_json("n", json!({ "msg": msg }))
    }

    fn push(&mut self, key: PKey, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        match key {
            PKey::In => self.bytes_in += data.len() as u64,
            PKey::Out(_) => self.bytes_out += data.len() as u64,
        }
        if let Some(p) = &self.pend {
            if p.key != key || p.buf.len() + data.len() > self.opts.coalesce_max || p.since.elapsed() >= self.opts.coalesce {
                self.flush_pending()?;
            }
        }
        match &mut self.pend {
            Some(p) => p.buf.extend_from_slice(data),
            None => {
                self.pend = Some(Pending { key, buf: data.to_vec(), since: Instant::now(), ts: self.clock.now() });
            }
        }
        if self.pend.as_ref().map(|p| p.buf.len() >= self.opts.coalesce_max).unwrap_or(false) {
            self.flush_pending()?;
        }
        Ok(())
    }

    pub fn output(&mut self, data: &[u8]) -> Result<()> {
        self.push(PKey::Out(None), data)
    }
    pub fn output_fd(&mut self, fd: u8, data: &[u8]) -> Result<()> {
        self.push(PKey::Out(Some(fd)), data)
    }
    pub fn input(&mut self, data: &[u8]) -> Result<()> {
        self.push(PKey::In, data)
    }

    pub fn flush_pending(&mut self) -> Result<()> {
        let Some(p) = self.pend.take() else { return Ok(()) };
        let (k, carry) = match p.key {
            PKey::In => ("i", &mut self.carry_in),
            PKey::Out(_) => ("o", &mut self.carry_out),
        };
        let chunk = carry.push(&p.buf);
        let mut m = Map::new();
        if let PKey::Out(Some(fd)) = p.key {
            m.insert("fd".into(), fd.into());
        }
        match chunk {
            None => return Ok(()),
            Some(crate::writer::Chunk::Text(t)) => {
                if self.opts.fold && p.key == PKey::Out(None) && self.fold.offer(&t, p.ts.as_microsecond()) {
                    // A repeat: kept in the open track, written with it (spec 8.3 `p`).
                    if self.fold.track().is_some_and(|t| t.len() >= crate::repeat::MAX_TRACK) {
                        self.flush_fold()?;
                    }
                    return Ok(());
                }
                m.insert("d".into(), t.into());
            }
            Some(crate::writer::Chunk::Bin(b)) => {
                m.insert("b".into(), B64.encode(&b).into());
            }
        }
        self.emit_at(k, p.ts, m)
    }

    /// Write the folded repeats: one `p` record, or the events as plain `o` records with their
    /// own times when that is not larger (a short, accidental repeat).
    fn flush_fold(&mut self) -> Result<()> {
        let Some(t) = self.fold.take() else { return Ok(()) };
        let fields = t.fields();
        if serde_json::to_vec(&fields)?.len() + 60 < t.plain_bytes() {
            return self.emit_raw("p", ts_of(t.first_us()), fields);
        }
        for (us, d) in t.events() {
            let mut m = Map::new();
            m.insert("d".into(), d.into());
            self.emit_raw("o", ts_of(us), m)?;
        }
        Ok(())
    }

    /// Periodic maintenance. Returns how long until the next call is useful.
    pub fn tick(&mut self) -> Result<Duration> {
        let mut next = Duration::from_secs(1);
        // Folded repeats reach the file within the sync interval, like any other output:
        // a power loss costs no more than it does without folding.
        if let Some(first) = self.fold.track().map(|t| t.first_us()) {
            let age = Duration::from_micros((self.clock.now().as_microsecond() - first).max(0) as u64);
            if age >= self.opts.sync_interval {
                self.flush_fold()?;
            } else {
                next = next.min(self.opts.sync_interval - age);
            }
        }
        if let Some(p) = &self.pend {
            let el = p.since.elapsed();
            if el >= self.opts.coalesce {
                self.flush_pending()?;
            } else {
                next = next.min(self.opts.coalesce - el);
            }
        }
        if self.seg_bytes > 0 && self.last_ckpt.elapsed() >= self.opts.checkpoint_interval {
            self.checkpoint()?;
        }
        if self.dirty {
            let el = self.last_sync.elapsed();
            if el >= self.opts.sync_interval {
                self.sync()?;
            } else {
                next = next.min(self.opts.sync_interval - el);
            }
        }
        Ok(next.max(Duration::from_millis(1)))
    }

    /// Periodic/checkpoint flush: in the background when enabled (the at-most-once-per-interval
    /// cadence is unchanged; only the caller no longer waits for the disk).
    pub fn sync(&mut self) -> Result<()> {
        if let Some(bg) = &self.bg {
            let _ = bg.tx.send(Io::Sync);
        } else {
            self.f.sync_data()?;
        }
        self.last_sync = Instant::now();
        self.dirty = false;
        Ok(())
    }

    /// Flush now and wait (header, end record).
    pub fn sync_now(&mut self) -> Result<()> {
        if let Some(bg) = &self.bg {
            let (tx, rx) = std::sync::mpsc::channel();
            bg.tx.send(Io::Barrier(tx)).map_err(|_| anyhow::anyhow!("recording writer thread gone"))?;
            rx.recv().map_err(|_| anyhow::anyhow!("recording writer thread gone"))??;
        } else {
            self.f.sync_data()?;
        }
        self.last_sync = Instant::now();
        self.dirty = false;
        Ok(())
    }

    /// Move writes and periodic fdatasync to an I/O thread (interactive sessions).
    pub fn enable_background_sync(&mut self) -> Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        let mut f = self.f.try_clone()?;
        // ~16 MiB of lines at most in flight (coalesced records are <= 16 KiB).
        let (tx, rx) = std::sync::mpsc::sync_channel::<Io>(1024);
        let failed = std::sync::Arc::new(AtomicBool::new(false));
        let fl = failed.clone();
        std::thread::Builder::new().name("swrec-io".into()).spawn(move || {
            let mut pending_sync = false;
            loop {
                // Drain what is queued, then sync once (coalesces bursts of Sync requests).
                let msg = if pending_sync {
                    match rx.try_recv() {
                        Ok(m) => Some(m),
                        Err(std::sync::mpsc::TryRecvError::Empty) => None,
                        Err(_) => break,
                    }
                } else {
                    match rx.recv() {
                        Ok(m) => Some(m),
                        Err(_) => break,
                    }
                };
                match msg {
                    Some(Io::Write(b)) => {
                        if f.write_all(&b).is_err() {
                            fl.store(true, Ordering::SeqCst);
                        }
                    }
                    Some(Io::Sync) => pending_sync = true,
                    Some(Io::Barrier(reply)) => {
                        let _ = reply.send(f.sync_data());
                        pending_sync = false;
                    }
                    None => {
                        let _ = f.sync_data();
                        pending_sync = false;
                    }
                }
            }
            let _ = f.sync_data();
        })?;
        self.bg = Some(BgSync { tx, failed });
        Ok(())
    }

    fn close_segment(&mut self) -> (u64, [u8; 32], u64) {
        let hasher = std::mem::replace(&mut self.seg_hasher, blake3::Hasher::new());
        let seg_hash = *hasher.finalize().as_bytes();
        self.chain = chain_step(&self.chain, &seg_hash);
        self.seg += 1;
        let first = self.seg_first_s;
        self.seg_first_s = self.seq + 1; // the closing checkpoint line opens the next segment
        self.seg_bytes = 0;
        (self.seg, self.chain, first)
    }

    /// Time-triggered (or explicit) checkpoint: always fdatasync'd.
    pub fn checkpoint(&mut self) -> Result<()> {
        self.checkpoint_inner(true)
    }

    /// Byte-triggered checkpoints under bulk output still respect "fdatasync at most once per
    /// sync interval"; the pending sync happens on the next tick.
    fn checkpoint_inner(&mut self, force_sync: bool) -> Result<()> {
        self.flush_fold()?;
        let last_s = self.seq;
        let (seg, chain, first) = self.close_segment();
        let s = self.next_seq();
        let ts = self.clock.now();
        let v = json!({"k":"c","s":s,"ts":fmt_utc(ts),"seg":seg,"chain":hex::encode(chain),"first_s":first,"last_s":last_s});
        self.write_line(&v)?;
        self.last_ckpt = Instant::now();
        if force_sync || self.last_sync.elapsed() >= self.opts.sync_interval {
            self.sync()?;
        }
        Ok(())
    }

    /// Write the end record (signed if a signer is given) and fdatasync.
    pub fn end(&mut self, reason: &str, exit_code: Option<i32>, signer: Option<&RecSigner>) -> Result<()> {
        if self.ended {
            return Ok(());
        }
        self.flush_pending()?;
        self.flush_fold()?;
        for (k, c) in [("o", self.carry_out.flush()), ("i", self.carry_in.flush())] {
            if let Some(crate::writer::Chunk::Bin(b)) = c {
                let s = self.next_seq();
                let ts = self.clock.now();
                self.write_line(&json!({"k":k,"s":s,"ts":fmt_utc(ts),"b":B64.encode(&b)}))?;
            }
        }
        let last_s = self.seq;
        let (seg, chain, first) = self.close_segment();
        let s = self.next_seq();
        let ts = self.clock.now();
        let mut m = Map::new();
        m.insert("k".into(), "e".into());
        m.insert("s".into(), s.into());
        m.insert("ts".into(), fmt_utc(ts).into());
        m.insert("reason".into(), reason.into());
        m.insert("exit_code".into(), exit_code.map(Value::from).unwrap_or(Value::Null));
        m.insert("bytes_out".into(), self.bytes_out.into());
        m.insert("bytes_in".into(), self.bytes_in.into());
        m.insert("duration".into(), fmt_duration(self.clock.elapsed()).into());
        m.insert("seg".into(), seg.into());
        m.insert("chain".into(), hex::encode(chain).into());
        m.insert("first_s".into(), first.into());
        m.insert("last_s".into(), last_s.into());
        if let Some(sg) = signer {
            m.insert("sig".into(), sg.sign(&chain, &self.id).into());
            m.insert("signer".into(), sg.name.clone().into());
        }
        self.write_line(&Value::Object(m))?;
        self.sync_now()?;
        self.ended = true;
        Ok(())
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.flush_pending();
        let _ = self.flush_fold();
        let _ = self.sync_now(); // waits for the I/O thread when enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::{scan, ScanOpts};
    use crate::{RecSigner, RecVerifier, Status};

    #[test]
    fn write_verify_resume() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.swrec");
        let s = RecSigner::generate("core");
        let mut v = RecVerifier::new();
        v.add_pub_text("core", &s.public_text()).unwrap();
        let opts = WriterOpts { checkpoint_bytes: 300, ..Default::default() };
        let mut w = Writer::create(&p, "ID1", json!({"kind":"audit"}).as_object().unwrap().clone(), opts.clone()).unwrap();
        for i in 0..20 {
            w.record_json("a", json!({"action": format!("x{i}")})).unwrap();
        }
        drop(w);
        // simulate a torn write
        std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"deadbeef {\"k\":\"a\"").unwrap();
        let mut w = Writer::resume(&p, opts).unwrap().unwrap();
        for i in 0..20 {
            w.record_json("a", json!({"action": format!("y{i}")})).unwrap();
        }
        w.end("exit", None, Some(&s)).unwrap();
        drop(w);
        let r = scan(&p, ScanOpts { verifier: Some(&v), keep_records: false, live: false }).unwrap();
        // The torn line is reported as damage; everything else verifies and the signature holds.
        assert_eq!(r.report.status, Status::Damaged, "{:?}", r.report);
        assert_eq!(r.report.damaged.len(), 1);
        assert_eq!(r.report.signature, Some(true));
        assert!(Writer::resume(&p, WriterOpts::default()).unwrap().is_none());
    }

    #[test]
    fn background_io_writes_identical_verified_file() {
        let d = tempfile::tempdir().unwrap();
        let s = RecSigner::generate("core");
        let mut v = RecVerifier::new();
        v.add_pub_text("core", &s.public_text()).unwrap();
        let p = d.path().join("bg.swrec");
        let mut w = Writer::create(&p, "IDBG", json!({"kind":"sw"}).as_object().unwrap().clone(), WriterOpts { checkpoint_bytes: 500, ..Default::default() }).unwrap();
        w.enable_background_sync().unwrap();
        for i in 0..2000 {
            w.output(format!("line {i}\r\n").as_bytes()).unwrap();
            if i % 50 == 0 {
                w.sync().unwrap();
            }
        }
        w.end("exit", Some(0), Some(&s)).unwrap();
        drop(w);
        let r = scan(&p, ScanOpts { verifier: Some(&v), keep_records: false, live: false }).unwrap();
        assert_eq!(r.report.status, Status::Ok, "{:?}", r.report);
        assert_eq!(r.report.signature, Some(true));
    }

    /// Everything the terminal received, in order, from a recording (repeats expanded).
    fn stream_of(p: &Path) -> Vec<(i64, String)> {
        let r = scan(p, ScanOpts { verifier: None, keep_records: true, live: false }).unwrap();
        let mut ex = crate::repeat::Expander::default();
        r.records.iter().flat_map(|m| ex.feed(m).unwrap()).map(|(t, d)| (t, d.to_string())).collect()
    }

    #[test]
    fn repeats_fold_and_expand_to_the_same_stream() {
        let d = tempfile::tempdir().unwrap();
        let s = RecSigner::generate("core");
        let mut v = RecVerifier::new();
        v.add_pub_text("core", &s.public_text()).unwrap();
        let p = d.path().join("spin.swrec");
        let mut w = Writer::create(&p, "IDSPIN", json!({"kind":"sw"}).as_object().unwrap().clone(), WriterOpts { checkpoint_bytes: 4096, ..Default::default() }).unwrap();
        w.enable_background_sync().unwrap();
        let frames = ["\x1b[5;1H⠋ working", "\x1b[5;1H⠙ working", "\x1b[5;1H⠹ working", "\x1b[5;1H⠸ working"];
        let mut sent = vec![];
        for i in 0..3000 {
            let f = if i % 500 == 250 { format!("real output {i}\r\n") } else { frames[i % 4].to_string() };
            w.output(f.as_bytes()).unwrap();
            w.flush_pending().unwrap();
            if i % 700 == 0 {
                w.input(b"x").unwrap(); // keystrokes interleave with a fold
            }
            sent.push(f);
        }
        w.end("exit", Some(0), Some(&s)).unwrap();
        drop(w);
        let r = scan(&p, ScanOpts { verifier: Some(&v), keep_records: true, live: false }).unwrap();
        assert_eq!(r.report.status, Status::Ok, "{:?}", r.report);
        assert_eq!(r.report.signature, Some(true));
        let kinds = |k: &str| r.records.iter().filter(|m| m["k"] == k).count();
        assert!(kinds("p") >= 1 && kinds("o") < 40, "{} plain, {} repeat records", kinds("o"), kinds("p"));
        let got = stream_of(&p);
        assert_eq!(got.iter().map(|(_, d)| d.as_str()).collect::<Vec<_>>(), sent.iter().map(|s| s.as_str()).collect::<Vec<_>>());
        assert!(got.windows(2).all(|w| w[0].0 <= w[1].0), "times stay in order");
        // Byte counts are those of the real stream.
        assert_eq!(r.end.unwrap()["bytes_out"], sent.iter().map(|s| s.len()).sum::<usize>());
    }

    #[test]
    fn folded_repeats_are_written_within_the_sync_interval() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sync.swrec");
        let opts = WriterOpts { sync_interval: Duration::from_millis(20), ..Default::default() };
        let mut w = Writer::create(&p, "IDSYNC", json!({"kind":"sw"}).as_object().unwrap().clone(), opts).unwrap();
        for _ in 0..10 {
            w.output(b"tick").unwrap();
            w.flush_pending().unwrap();
        }
        assert!(!std::fs::read_to_string(&p).unwrap().contains("\"k\":\"p\""), "still folding");
        std::thread::sleep(Duration::from_millis(30));
        w.tick().unwrap();
        // On disk now, without an end record or any further output: a crash would keep it.
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("\"k\":\"p\""), "{text}");
        let got = stream_of(&p);
        assert_eq!(got.len(), 10);
        std::mem::forget(w); // simulate the power cut: no end record, no final flush
        let r = scan(&p, ScanOpts { verifier: None, keep_records: false, live: false }).unwrap();
        assert!(r.report.damaged.is_empty(), "{:?}", r.report);
    }

    #[test]
    fn folding_can_be_turned_off() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("nofold.swrec");
        let mut w = Writer::create(&p, "IDNF", json!({"kind":"sw"}).as_object().unwrap().clone(), WriterOpts { fold: false, ..Default::default() }).unwrap();
        for _ in 0..50 {
            w.output(b"same").unwrap();
            w.flush_pending().unwrap();
        }
        w.end("exit", Some(0), None).unwrap();
        drop(w);
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.matches("\"k\":\"o\"").count(), 50);
        assert!(!text.contains("\"k\":\"p\""));
    }

    #[test]
    fn clean_file_is_ok_and_tamper_detected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("b.swrec");
        let s = RecSigner::generate("core");
        let mut v = RecVerifier::new();
        v.add_pub_text("core", &s.public_text()).unwrap();
        let mut w = Writer::create(&p, "ID2", json!({"kind":"sw"}).as_object().unwrap().clone(), WriterOpts { checkpoint_bytes: 200, ..Default::default() }).unwrap();
        for i in 0..50 {
            w.output(format!("out {i}\r\n").as_bytes()).unwrap();
            w.flush_pending().unwrap();
        }
        w.end("exit", Some(0), Some(&s)).unwrap();
        drop(w);
        let r = scan(&p, ScanOpts { verifier: Some(&v), keep_records: false, live: false }).unwrap();
        assert_eq!(r.report.status, Status::Ok, "{:?}", r.report);
        // Re-encode one line with a valid CRC but different content: tampered, not damaged.
        let text = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        let idx = lines.iter().position(|l| l.contains("\"k\":\"o\"") && l.contains("out 7")).unwrap();
        let json = lines[idx][9..].replace("out 7", "OUT 7");
        lines[idx] = String::from_utf8(crate::format::encode_line(json.as_bytes())).unwrap().trim_end().to_string();
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        let r = scan(&p, ScanOpts { verifier: Some(&v), keep_records: false, live: false }).unwrap();
        assert_eq!(r.report.status, Status::Tampered, "{:?}", r.report);
    }
}
