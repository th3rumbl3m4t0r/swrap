//! Compression: multi-member gzip, new member every N bytes of input, cut at line boundaries
//! (spec 8.7). Procedure: write `.gz.tmp` + fsync → decompress and compare blake3 → rename →
//! fsync dir → unlink original → fsync dir. A crash leaves the original alone or both files.

use anyhow::{bail, Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use swrap_core::atomic::fsync_dir;

pub fn gz_path(p: &Path) -> PathBuf {
    PathBuf::from(format!("{}.gz", p.display()))
}
pub fn tmp_path(p: &Path) -> PathBuf {
    PathBuf::from(format!("{}.gz.tmp", p.display()))
}

/// Compress a plain byte stream into multi-member gzip written to `out`.
pub fn compress_stream<R: Read, W: Write>(input: R, mut out: W, member_bytes: usize) -> Result<blake3::Hash> {
    let mut r = BufReader::with_capacity(256 << 10, input);
    let mut h = blake3::Hasher::new();
    let mut member: Vec<u8> = Vec::with_capacity(member_bytes + 4096);
    let mut line = Vec::new();
    let flush_member = |member: &mut Vec<u8>, out: &mut W| -> Result<()> {
        if member.is_empty() {
            return Ok(());
        }
        let mut enc = GzEncoder::new(Vec::with_capacity(member.len() / 4), Compression::new(6));
        enc.write_all(member)?;
        out.write_all(&enc.finish()?)?;
        member.clear();
        Ok(())
    };
    loop {
        line.clear();
        let n = r.read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        h.update(&line);
        if !member.is_empty() && member.len() + line.len() > member_bytes {
            flush_member(&mut member, &mut out)?;
        }
        member.extend_from_slice(&line);
    }
    flush_member(&mut member, &mut out)?;
    out.flush()?;
    Ok(h.finalize())
}

fn blake3_of_gz(p: &Path) -> Result<blake3::Hash> {
    let f = File::open(p)?;
    let mut d = flate2::read::MultiGzDecoder::new(BufReader::new(f));
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 256 << 10];
    loop {
        let n = d.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize())
}

fn blake3_of_file(p: &Path) -> Result<blake3::Hash> {
    let mut h = blake3::Hasher::new();
    let mut f = File::open(p)?;
    let mut buf = vec![0u8; 256 << 10];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize())
}

/// Hook used by crash tests: called with the step number just completed.
pub type StepHook<'a> = &'a mut dyn FnMut(u8) -> Result<()>;

/// Compress `src` (a `.swrec`) in place. Returns the new path.
pub fn compress_file(src: &Path, member_bytes: usize, mut hook: Option<StepHook>) -> Result<PathBuf> {
    let dir = src.parent().context("no parent")?;
    let tmp = tmp_path(src);
    let dst = gz_path(src);
    let meta = fs::metadata(src)?;
    let orig_hash = blake3_of_file(src)?;
    {
        let out = OpenOptions::new().write(true).create(true).truncate(true).mode(meta.permissions().mode() & 0o777).open(&tmp)?;
        let mut bw = std::io::BufWriter::new(out);
        let h = compress_stream(File::open(src)?, &mut bw, member_bytes)?;
        let out = bw.into_inner().map_err(|e| anyhow::anyhow!("{e}"))?;
        out.sync_all()?;
        if h != orig_hash {
            let _ = fs::remove_file(&tmp);
            bail!("source changed while compressing {}", src.display());
        }
        // keep owner
        use std::os::unix::fs::MetadataExt;
        let _ = std::os::unix::fs::fchown(&out, Some(meta.uid()), Some(meta.gid()));
    }
    // Carry POSIX ACLs over by copying xattrs (best-effort).
    copy_acl(src, &tmp);
    if let Some(h) = hook.as_mut() {
        h(1)?;
    }
    // 2. verify
    if blake3_of_gz(&tmp)? != orig_hash {
        let _ = fs::remove_file(&tmp);
        bail!("verification of {} failed", tmp.display());
    }
    if let Some(h) = hook.as_mut() {
        h(2)?;
    }
    // 3. rename + fsync dir
    fs::rename(&tmp, &dst)?;
    fsync_dir(dir)?;
    if let Some(h) = hook.as_mut() {
        h(3)?;
    }
    // 4. unlink original + fsync dir
    fs::remove_file(src)?;
    fsync_dir(dir)?;
    Ok(dst)
}

fn copy_acl(src: &Path, dst: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let (Ok(s), Ok(d)) = (CString::new(src.as_os_str().as_bytes()), CString::new(dst.as_os_str().as_bytes())) else { return };
    for name in [c"system.posix_acl_access"] {
        let mut buf = vec![0u8; 4096];
        let n = unsafe { libc::getxattr(s.as_ptr(), name.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len()) };
        if n > 0 {
            unsafe { libc::setxattr(d.as_ptr(), name.as_ptr(), buf.as_ptr() as *const _, n as usize, 0) };
        }
    }
}

/// Crash recovery for a directory (doctor): resolves leftovers of interrupted compressions.
/// Returns a description of each action taken.
pub fn recover_dir(dir: &Path) -> Result<Vec<String>> {
    let mut acts = vec![];
    for e in fs::read_dir(dir)? {
        let p = e?.path();
        let s = p.to_string_lossy().to_string();
        if let Some(base) = s.strip_suffix(".gz.tmp") {
            // Step 1/2 crash: the original must still exist; drop the tmp.
            let orig = PathBuf::from(base);
            if orig.exists() {
                fs::remove_file(&p)?;
                acts.push(format!("removed incomplete {}", p.display()));
            } else {
                acts.push(format!("orphan {} without original (kept for inspection)", p.display()));
            }
        } else if let Some(base) = s.strip_suffix(".gz") {
            let orig = PathBuf::from(base);
            if orig.exists() {
                // Step 3 crash: both exist. Keep gz only if it verifies against the original.
                if blake3_of_gz(&p).ok() == blake3_of_file(&orig).ok() {
                    fs::remove_file(&orig)?;
                    acts.push(format!("removed original {} (verified gz exists)", orig.display()));
                } else {
                    fs::remove_file(&p)?;
                    acts.push(format!("removed unverified {}", p.display()));
                }
            }
        }
    }
    if !acts.is_empty() {
        fsync_dir(dir)?;
    }
    Ok(acts)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn members_cut_on_lines() {
        let mut data = Vec::new();
        for i in 0..20000 {
            data.extend_from_slice(format!("line number {i} with some text\n").as_bytes());
        }
        let mut out = Vec::new();
        compress_stream(&data[..], &mut out, 4096).unwrap();
        let members = out.windows(3).filter(|w| *w == [0x1f, 0x8b, 0x08]).count();
        assert!(members > 50, "{members}");
        let mut d = flate2::read::MultiGzDecoder::new(&out[..]);
        let mut back = vec![];
        d.read_to_end(&mut back).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn crash_at_each_step_recovers() {
        for step in 1..=3u8 {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("x.swrec");
            let data: Vec<u8> = (0..5000).flat_map(|i| format!("{i:08x} {{\"k\":\"o\"}}\n").into_bytes()).collect();
            fs::write(&p, &data).unwrap();
            let mut hook = |s: u8| if s == step { bail!("crash") } else { Ok(()) };
            assert!(compress_file(&p, 1024, Some(&mut hook)).is_err());
            recover_dir(d.path()).unwrap();
            let names: Vec<_> = fs::read_dir(d.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
            assert_eq!(names.len(), 1, "step {step}: {names:?}");
            let only = d.path().join(&names[0]);
            let content = if names[0].ends_with(".gz") { let mut v = vec![]; flate2::read::MultiGzDecoder::new(File::open(&only).unwrap()).read_to_end(&mut v).unwrap(); v } else { fs::read(&only).unwrap() };
            assert_eq!(content, data);
        }
    }
}
