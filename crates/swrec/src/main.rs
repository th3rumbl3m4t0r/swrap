//! `swrec` tool: verify, cat, compress, recover, bench, fuzz, cast, refold.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use rand::{Rng, SeedableRng};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Instant;
use swrec::reader::{scan, ScanOpts};
use swrec::{RecSigner, RecVerifier, Writer, WriterOpts};

#[derive(Parser)]
#[command(name = "swrec", about = "swrec v1.2 recording format tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify files (CRC, sequence, segments, chain, signature).
    Verify {
        files: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Treat files without an end record as live.
        #[arg(long)]
        live: bool,
    },
    /// Plain-text dump with ISO timestamps.
    Cat {
        file: PathBuf,
        #[arg(long)]
        keys: bool,
        #[arg(long)]
        cmds: bool,
        #[arg(long)]
        utc: bool,
        #[arg(long)]
        raw: bool,
    },
    /// Compress a closed file into multi-member gzip (verified, crash-safe).
    Compress {
        file: PathBuf,
        #[arg(long, default_value_t = 262144)]
        member_bytes: usize,
    },
    /// Resolve leftovers of interrupted compressions in a directory.
    Recover { dir: PathBuf },
    /// Export asciicast v2.
    Cast { file: PathBuf, #[arg(long)] keys: bool },
    /// What folding repeated output (`p` records) saves on an existing recording, checked by
    /// expanding the result against the original. Reads only; the file is not changed.
    Refold { file: PathBuf },
    /// Recorder throughput benchmark.
    Bench {
        #[arg(long, default_value_t = 512)]
        mib: usize,
        #[arg(long, default_value = "/var/lib/swrap/index")]
        dir: PathBuf,
    },
    /// Search throughput over a generated corpus (plain and gzip).
    SearchBench {
        #[arg(long, default_value_t = 256)]
        mib: usize,
        #[arg(long, default_value = "/var/lib/swrap/index/searchbench")]
        dir: PathBuf,
    },
    /// Fuzz the reader with damaged files (bit flips, deleted bytes/LFs, truncation).
    Fuzz {
        #[arg(long, default_value_t = 10000)]
        iterations: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
}

fn verifier() -> RecVerifier {
    RecVerifier::for_core(&swrap_core::Paths::from_env())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Verify { files, json, live } => {
            let v = verifier();
            let mut bad = 0;
            for f in files {
                let s = scan(&f, ScanOpts { verifier: Some(&v), keep_records: false, live })?;
                let r = &s.report;
                if json {
                    println!("{}", serde_json::to_string(&json!({"file": f, "report": r}))?);
                } else {
                    println!("{}: {} ({} records, {} segments ok{})", f.display(), r.status.as_str(), r.records, r.segments_ok,
                        match r.signature { Some(true) => format!(", signed by {}", r.signer.clone().unwrap_or_default()), Some(false) => ", BAD SIGNATURE".into(), None => String::new() });
                    for d in &r.damaged { println!("  damaged: {d}"); }
                    for (a, b) in &r.gaps { println!("  gap: s={a}..{b}"); }
                    for n in &r.notes { println!("  note: {n}"); }
                }
                if !matches!(r.status, swrec::Status::Ok | swrec::Status::OkIncomplete | swrec::Status::Live) {
                    bad += 1;
                }
            }
            if bad > 0 {
                std::process::exit(1);
            }
        }
        Cmd::Cat { file, keys, cmds, utc, raw } => {
            let s = scan(&file, ScanOpts { verifier: None, keep_records: true, live: false })?;
            let cfg = swrap_core::config::SwrapConfig::load(&swrap_core::Paths::from_env()).unwrap_or_default();
            let o = swrec::text::CatOpts { tz: cfg.tz(), utc, keys, cmds, raw };
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            swrec::text::cat(s.header.as_ref(), &s.records, &o, &mut lock)?;
        }
        Cmd::Compress { file, member_bytes } => {
            let p = swrec::compress::compress_file(&file, member_bytes, None)?;
            println!("{}", p.display());
        }
        Cmd::Recover { dir } => {
            for a in swrec::compress::recover_dir(&dir)? {
                println!("{a}");
            }
        }
        Cmd::Cast { file, keys } => {
            let s = scan(&file, ScanOpts { verifier: None, keep_records: true, live: false })?;
            let Some(h) = s.header else { bail!("no header") };
            print!("{}", swrec::render::to_asciicast(&h, &s.records, 2.0, keys).text);
        }
        Cmd::Refold { file } => refold(&file)?,
        Cmd::Bench { mib, dir } => bench(mib, &dir)?,
        Cmd::SearchBench { mib, dir } => search_bench(mib, &dir)?,
        Cmd::Fuzz { iterations, seed } => fuzz(iterations, seed)?,
    }
    Ok(())
}

/// Replay a recording's output through the writer's folding and check the expansion.
fn refold(file: &Path) -> Result<()> {
    use serde_json::{Map, Value};
    use std::collections::VecDeque;
    use swrec::format::{decode_line, encode_value};
    use swrec::repeat::{fmt_us, in_stream, Expander, Folder, MAX_TRACK};

    struct Sim {
        folder: Folder,
        ex: Expander,
        pending: VecDeque<(i64, String)>,
        s: u64,
        bytes: u64,
        records: u64,
        p_records: u64,
        checked: u64,
        bad: Vec<String>,
        by_kind: std::collections::BTreeMap<String, u64>,
        sample: Option<String>,
    }
    impl Sim {
        fn emit(&mut self, m: Map<String, Value>) {
            let line = encode_value(&Value::Object(m.clone()));
            self.bytes += line.len() as u64;
            *self.by_kind.entry(m.get("k").and_then(Value::as_str).unwrap_or("?").to_string()).or_default() += line.len() as u64;
            if self.sample.is_none() && m.get("k").and_then(Value::as_str) == Some("p") && m.get("n").and_then(Value::as_u64).unwrap_or(0) >= 20 {
                self.sample = Some(String::from_utf8_lossy(&line).trim_end().to_string());
            }
            self.records += 1;
            match self.ex.feed(&m) {
                Ok(evs) => {
                    for (t, d) in evs {
                        match self.pending.pop_front() {
                            Some((t0, d0)) if t0 == t && d0 == *d => self.checked += 1,
                            other => {
                                if self.bad.len() < 5 {
                                    self.bad.push(format!("expected {:?}, got ({t}, {:?})", other.map(|(t, d)| (t, d.chars().take(40).collect::<String>())), d.chars().take(40).collect::<String>()));
                                }
                            }
                        }
                    }
                }
                Err(e) => self.bad.push(e),
            }
        }
        fn rec(&mut self, k: &str, us: i64, fields: Map<String, Value>) {
            self.s += 1;
            let mut m = Map::new();
            m.insert("k".into(), k.into());
            m.insert("s".into(), self.s.into());
            m.insert("ts".into(), fmt_us(us).into());
            m.extend(fields);
            self.emit(m);
        }
        fn flush(&mut self) {
            let Some(t) = self.folder.take() else { return };
            let fields = t.fields();
            if serde_json::to_vec(&fields).map(|v| v.len()).unwrap_or(0) + 60 < t.plain_bytes() {
                self.p_records += 1;
                self.rec("p", t.first_us(), fields);
            } else {
                let evs: Vec<(i64, String)> = t.events().map(|(u, d)| (u, d.to_string())).collect();
                for (u, d) in evs {
                    let mut m = Map::new();
                    m.insert("d".into(), d.into());
                    self.rec("o", u, m);
                }
            }
        }
    }
    let mut sim = Sim { folder: Folder::default(), ex: Expander::default(), pending: VecDeque::new(), s: 0, bytes: 0, records: 0, p_records: 0, checked: 0, bad: vec![], by_kind: Default::default(), sample: None };
    let (mut orig_bytes, mut orig_records, mut events, mut folded) = (0u64, 0u64, 0u64, 0u64);
    // The recording's own output events (a 1.2 file's repeats expanded), folded afresh.
    let mut orig = Expander::default();
    swrec::reader::for_each_raw_line(file, |l| {
        let Ok(m) = decode_line(l.bytes) else { return true };
        orig_bytes += l.bytes.len() as u64 + 1;
        orig_records += 1;
        let text = in_stream(&m) && m.contains_key("d");
        if text || m.get("k").and_then(Value::as_str) == Some("p") {
            let Ok(evs) = orig.feed(&m) else { return true };
            for (us, d) in evs {
                events += 1;
                // The writer writes folded events out within the sync interval (1 s).
                if sim.folder.track().is_some_and(|t| us - t.first_us() >= 1_000_000) {
                    sim.flush();
                }
                sim.pending.push_back((us, d.to_string()));
                if sim.folder.offer(&d, us) {
                    folded += 1;
                    if sim.folder.track().is_some_and(|t| t.len() >= MAX_TRACK) {
                        sim.flush();
                    }
                } else {
                    sim.flush();
                    sim.folder.wrote(Some(&d));
                    let mut f = Map::new();
                    f.insert("d".into(), (*d).into());
                    sim.rec("o", us, f);
                }
            }
            return true;
        }
        sim.flush();
        if in_stream(&m) {
            // binary output: written as is, counted in the stream
            let _ = orig.feed(&m);
            events += 1;
            sim.folder.wrote(None);
            if let Ok(evs) = sim.ex.feed(&m) {
                sim.checked += evs.len() as u64;
            }
        }
        sim.bytes += l.bytes.len() as u64 + 1;
        *sim.by_kind.entry(m.get("k").and_then(Value::as_str).unwrap_or("?").to_string()).or_default() += l.bytes.len() as u64 + 1;
        sim.records += 1;
        true
    })?;
    sim.flush();
    let unmatched = sim.pending.len();
    println!("{}", file.display());
    println!("  original: {:>12} bytes  {:>9} records  {} output events", orig_bytes, orig_records, events);
    println!("  folded:   {:>12} bytes  {:>9} records  ({:.1}% of the size; {} events in {} p records)", sim.bytes, sim.records, 100.0 * sim.bytes as f64 / orig_bytes.max(1) as f64, folded, sim.p_records);
    println!("  folded bytes by kind: {}", sim.by_kind.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", "));
    if let Some(p) = &sim.sample {
        println!("  a p record: {}", p.chars().take(600).collect::<String>());
    }
    if sim.bad.is_empty() && unmatched == 0 && sim.checked == events {
        println!("  expansion: exact ({} events: same bytes, same timestamps)", sim.checked);
        Ok(())
    } else {
        for b in &sim.bad {
            println!("  MISMATCH: {b}");
        }
        bail!("expansion differs: {} of {events} events matched, {unmatched} never came back", sim.checked)
    }
}

fn bench(mib: usize, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("bench-{}.swrec", swrap_core::new_id()));
    let signer = RecSigner::generate("core");
    let mut w = Writer::create(&path, "BENCH", json!({"kind":"sw"}).as_object().unwrap().clone(), WriterOpts::default())?;
    // Same I/O mode as session workers (writes and fdatasync on a helper thread).
    w.enable_background_sync()?;
    // Realistic terminal output: text with ANSI colours, 4 KiB chunks.
    let mut chunk = Vec::new();
    while chunk.len() < 4096 {
        chunk.extend_from_slice(b"\x1b[32m2026-09-23 10:14:02\x1b[0m kernel: eth0: link up, 1000Mbps, full-duplex \"quoted\" \\ path/x\r\n");
    }
    chunk.truncate(4096);
    let total = mib << 20;
    let t0 = Instant::now();
    let mut done = 0;
    while done < total {
        w.output(&chunk)?;
        done += chunk.len();
    }
    w.end("exit", Some(0), Some(&signer))?;
    let el = t0.elapsed().as_secs_f64();
    let fsize = std::fs::metadata(&path)?.len();
    println!("recorder: {} MiB terminal output in {:.3}s = {:.1} MB/s (file {:.1} MiB, overhead {:.0}%)",
        mib, el, total as f64 / el / 1e6, fsize as f64 / 1048576.0, (fsize as f64 / total as f64 - 1.0) * 100.0);
    let t0 = Instant::now();
    let s = scan(&path, ScanOpts { verifier: None, keep_records: false, live: false })?;
    let el = t0.elapsed().as_secs_f64();
    println!("verify: {:.1} MB/s ({})", fsize as f64 / el / 1e6, s.report.status.as_str());
    let _ = std::fs::remove_file(&path);
    Ok(())
}

fn make_sample(dir: &Path) -> Result<(PathBuf, PathBuf, u64)> {
    let p = dir.join("sample.swrec");
    let signer = RecSigner::generate("core");
    let opts = WriterOpts { checkpoint_bytes: 8192, coalesce: std::time::Duration::ZERO, ..Default::default() };
    let mut w = Writer::create(&p, "SAMPLE", json!({"kind":"sw","label":"x"}).as_object().unwrap().clone(), opts)?;
    let spin = ["\x1b[s\x1b[1;70H⠋ busy\x1b[u", "\x1b[s\x1b[1;70H⠙ busy\x1b[u", "\x1b[s\x1b[1;70H⠹ busy\x1b[u", "\x1b[s\x1b[1;70H⠸ busy\x1b[u"];
    for i in 0..600 {
        w.output(format!("line {i} some output text ünïcödé\r\n").as_bytes())?;
        w.flush_pending()?;
        // a spinner between lines, so damaged repeat (`p`) records get fuzzed too
        for j in 0..5 {
            w.output(spin[(i * 5 + j) % 4].as_bytes())?;
            w.flush_pending()?;
        }
        if i % 7 == 0 {
            w.input(b"ls\r")?;
            w.flush_pending()?;
        }
    }
    w.end("exit", Some(0), Some(&signer))?;
    let n = w.seq() + 1;
    drop(w);
    let gzp = dir.join("sample2.swrec");
    std::fs::copy(&p, &gzp)?;
    let gz = swrec::compress::compress_file(&gzp, 2048, None)?;
    Ok((p, gz, n))
}

fn fuzz(iterations: usize, seed: u64) -> Result<()> {
    let d = tempfile_dir()?;
    let (plain, gz, total) = make_sample(&d)?;
    let plain_bytes = std::fs::read(&plain)?;
    let gz_bytes = std::fs::read(&gz)?;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut worst_plain = 0u64;
    let mut worst_gz = 0u64;
    let target_p = d.join("fuzz.swrec");
    let target_g = d.join("fuzz.swrec.gz");
    for it in 0..iterations {
        for (src, target, is_gz) in [(&plain_bytes, &target_p, false), (&gz_bytes, &target_g, true)] {
            let mut data = src.clone();
            let op = rng.gen_range(0..4);
            let mut truncated_at = None;
            match op {
                0 => { let i = rng.gen_range(0..data.len()); data[i] ^= 1 << rng.gen_range(0..8); }
                1 => { let i = rng.gen_range(0..data.len()); data.remove(i); }
                2 => {
                    let lfs: Vec<usize> = data.iter().enumerate().filter(|(_, &b)| b == b'\n').map(|(i, _)| i).collect();
                    if !lfs.is_empty() && !is_gz { let i = lfs[rng.gen_range(0..lfs.len())]; data.remove(i); }
                    else { let i = rng.gen_range(0..data.len()); data.remove(i); }
                }
                _ => { let n = rng.gen_range(0..data.len()); data.truncate(n); truncated_at = Some(n); }
            }
            std::fs::write(target, &data)?;
            let res = std::panic::catch_unwind(|| scan(target, ScanOpts { verifier: None, keep_records: false, live: false }));
            let s = match res {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => bail!("iteration {it}: reader error {e}"),
                Err(_) => bail!("iteration {it}: reader panicked (op {op}, gz {is_gz})"),
            };
            if truncated_at.is_none() {
                let lost = total.saturating_sub(s.report.records);
                if is_gz { worst_gz = worst_gz.max(lost) } else { worst_plain = worst_plain.max(lost) }
            }
        }
    }
    println!("fuzz: {iterations} iterations x 2 formats, no panics; {total} records per file");
    println!("worst loss from a single bit flip / deleted byte / deleted LF: plain {worst_plain} records, gzip {worst_gz} records (member = 2 KiB)");
    if worst_plain > 2 {
        bail!("damage not local in plain file ({worst_plain} records lost)");
    }
    let _ = std::fs::remove_dir_all(&d);
    Ok(())
}

fn tempfile_dir() -> Result<PathBuf> {
    let d = std::env::temp_dir().join(format!("swrec-fuzz-{}", swrap_core::new_id()));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

fn search_bench(mib: usize, dir: &Path) -> Result<()> {
    use std::sync::atomic::AtomicBool;
    let _ = std::fs::remove_dir_all(dir);
    let day = swrap_core::time::date_dir(swrap_core::time::now());
    let base = dir.join("rec/bench/sw").join(&day);
    std::fs::create_dir_all(&base)?;
    let files = 64usize;
    let per_file = (mib << 20) / files;
    let mut chunk = Vec::new();
    while chunk.len() < 4096 {
        chunk.extend_from_slice(b"\x1b[32mSep 25 10:14:02\x1b[0m host kernel: eth0 link up 1000Mbps full-duplex /var/log/messages rotated\r\n");
    }
    chunk.truncate(4096);
    let t0 = Instant::now();
    let mut paths = vec![];
    for i in 0..files {
        let id = swrap_core::new_id();
        let p = base.join(format!("{}_{}_bench_root.swrec", swrap_core::time::fmt_basic(swrap_core::time::now()), id));
        let mut w = Writer::create(&p, &id, json!({"kind":"sw","label":"bench","ruser":"root","aaa_user":"bench"}).as_object().unwrap().clone(), WriterOpts::default())?;
        w.enable_background_sync()?;
        let mut n = 0;
        while n < per_file {
            w.output(&chunk)?;
            n += chunk.len();
        }
        if i == files / 2 {
            w.output(b"the rare NEEDLE-4711 appears once\r\n")?;
        }
        w.end("exit", Some(0), None)?;
        drop(w);
        paths.push(p);
    }
    let raw: u64 = paths.iter().map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)).sum();
    println!("corpus: {files} files, {:.0} MiB record bytes (written in {:.1}s)", raw as f64 / 1048576.0, t0.elapsed().as_secs_f64());
    let run = |label: &str| -> Result<()> {
        let cancel = AtomicBool::new(false);
        for q in ["window:P1D/now out:NEEDLE-4711", "window:P1D/now cmd:nothing-matches", "window:P1D/now NEEDLE-4711"] {
            let query = swrec::search::Query::parse(q)?;
            let opts = swrec::search::SearchOpts { root: dir.to_path_buf(), users: None, max_results: 1000, cancel: &cancel, kinds: vec![] };
            let t = Instant::now();
            let p = swrec::search::run(&query, &opts, &|_| {}, &|_| {})?;
            let el = t.elapsed().as_secs_f64();
            println!("{label:<5} {q:<42} hits={:<3} {:>6.0} MiB/s ({:.0} MiB in {:.2}s, {} threads)", p.hits, p.bytes_scanned as f64 / 1048576.0 / el, p.bytes_scanned as f64 / 1048576.0, el, rayon::current_num_threads());
        }
        Ok(())
    };
    run("plain")?;
    for p in &paths {
        swrec::compress::compress_file(p, 262144, None)?;
    }
    let gz: u64 = std::fs::read_dir(&base)?.flatten().map(|e| e.metadata().map(|m| m.len()).unwrap_or(0)).sum();
    println!("gzip: {:.1} MiB on disk (x{:.1})", gz as f64 / 1048576.0, raw as f64 / gz as f64);
    run("gzip")?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}
