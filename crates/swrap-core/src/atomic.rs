//! Atomic writes with read-back verification (spec section 12.2):
//! temp file → fsync → read back and compare blake3 → rename → fsync directory.

use anyhow::{bail, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

#[derive(Clone, Copy, Debug, Default)]
pub struct Owner {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl Owner {
    pub const NONE: Owner = Owner { uid: None, gid: None };
    pub fn new(uid: u32, gid: u32) -> Self {
        Owner { uid: Some(uid), gid: Some(gid) }
    }
}

pub fn fsync_dir(dir: &Path) -> Result<()> {
    let d = File::open(dir).with_context(|| format!("open dir {}", dir.display()))?;
    d.sync_all().with_context(|| format!("fsync dir {}", dir.display()))?;
    Ok(())
}

/// Atomically replace `path` with `data`. The file is verified by reading it back before rename.
pub fn write(path: &Path, data: &[u8], mode: u32, owner: Owner) -> Result<()> {
    let dir = path.parent().context("path has no parent")?;
    let name = path.file_name().context("path has no file name")?.to_string_lossy();
    let tmp = dir.join(format!(".{}.tmp.{}", name, std::process::id()));
    let want = blake3::hash(data);
    let res = (|| -> Result<()> {
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        if owner.uid.is_some() || owner.gid.is_some() {
            std::os::unix::fs::fchown(&f, owner.uid, owner.gid).context("fchown")?;
        }
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        // read back
        let mut back = Vec::with_capacity(data.len());
        File::open(&tmp)?.read_to_end(&mut back)?;
        if blake3::hash(&back) != want {
            bail!("read-back verification failed for {}", tmp.display());
        }
        fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
        fsync_dir(dir)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

/// Create directories with a mode and owner (only newly created components are chowned).
pub fn mkdirs(path: &Path, mode: u32, owner: Owner) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    if let Some(p) = path.parent() {
        mkdirs(p, mode, owner)?;
    }
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            if owner.uid.is_some() || owner.gid.is_some() {
                std::os::unix::fs::chown(path, owner.uid, owner.gid)?;
            }
            if let Some(p) = path.parent() {
                fsync_dir(p)?;
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e).with_context(|| format!("mkdir {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.toml");
        write(&p, b"hello", 0o640, Owner::NONE).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"hello");
        write(&p, b"world", 0o640, Owner::NONE).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"world");
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }
}
