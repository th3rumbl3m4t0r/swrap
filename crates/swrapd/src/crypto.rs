//! Crypto profile validation per node (spec 9.3): capability sets from `ssh -Q …` / `ssh -V`,
//! cached by binary path, size, mtime and blake3.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use swrap_core::config::Profile;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Caps {
    pub bin: String,
    pub size: u64,
    pub mtime: i64,
    pub b3: String,
    pub version: String,
    pub kex: BTreeSet<String>,
    pub cipher: BTreeSet<String>,
    pub mac: BTreeSet<String>,
    pub hostkey: BTreeSet<String>,
    pub keysig: BTreeSet<String>,
}

fn q(bin: &str, what: &str) -> Result<BTreeSet<String>> {
    let o = Command::new(bin).arg("-Q").arg(what).output().with_context(|| format!("{bin} -Q {what}"))?;
    Ok(String::from_utf8_lossy(&o.stdout).lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
}

pub fn ssh_version(bin: &str) -> String {
    Command::new(bin)
        .arg("-V")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
        .unwrap_or_default()
}

pub fn caps(cache_dir: &Path, bin: &str) -> Result<Caps> {
    let md = std::fs::metadata(bin).with_context(|| format!("ssh binary {bin}"))?;
    let key = blake3::hash(bin.as_bytes()).to_hex().to_string();
    let cache = cache_dir.join(format!("{}.json", &key[..16]));
    if let Ok(s) = std::fs::read_to_string(&cache) {
        if let Ok(c) = serde_json::from_str::<Caps>(&s) {
            if c.size == md.len() && c.mtime == md.mtime() && c.bin == bin {
                return Ok(c);
            }
        }
    }
    let b3 = blake3::hash(&std::fs::read(bin)?).to_hex().to_string();
    let c = Caps {
        bin: bin.into(),
        size: md.len(),
        mtime: md.mtime(),
        b3,
        version: ssh_version(bin),
        kex: q(bin, "kex")?,
        cipher: q(bin, "cipher")?,
        mac: q(bin, "mac")?,
        hostkey: q(bin, "HostKeyAlgorithms")?,
        keysig: q(bin, "key-sig")?,
    };
    std::fs::create_dir_all(cache_dir)?;
    let _ = std::fs::write(&cache, serde_json::to_vec(&c)?);
    Ok(c)
}

/// Every algorithm listed by the profile must exist in the node's binary.
pub fn missing(p: &Profile, c: &Caps) -> Vec<String> {
    let mut m = vec![];
    let chk = |list: &[String], set: &BTreeSet<String>, what: &str, m: &mut Vec<String>| {
        for a in list {
            if !set.contains(a) {
                m.push(format!("{what} {a}"));
            }
        }
    };
    chk(&p.kex, &c.kex, "kex", &mut m);
    chk(&p.ciphers, &c.cipher, "cipher", &mut m);
    chk(&p.macs, &c.mac, "mac", &mut m);
    chk(&p.host_key_algorithms, &c.hostkey, "hostkey", &mut m);
    chk(&p.key_preference, &c.keysig, "key", &mut m);
    chk(&p.pubkey_accepted_algorithms, &c.keysig, "pubkey", &mut m);
    m
}

pub fn validate(cache_dir: &Path, p: &Profile, node: &str) -> Result<Caps> {
    let c = caps(cache_dir, p.ssh_bin_for(node))?;
    let m = missing(p, &c);
    if !m.is_empty() {
        bail!("crypto profile {:?} is not valid on {node} ({}): missing {}", p.name, c.version, m.join(", "));
    }
    Ok(c)
}
