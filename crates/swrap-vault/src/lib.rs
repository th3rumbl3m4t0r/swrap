//! Vault (spec section 14): a random DEK encrypts every key file with XChaCha20-Poly1305;
//! the DEK is wrapped per admin with argon2id(password) and once with a recovery key.
//! A blake3 keyed commitment makes a bit flip give a clean error instead of a wrong key.

pub mod keyring;

use anyhow::{bail, Context, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use swrap_core::atomic::{self, Owner};
use swrap_core::config::VaultCfg;
use swrap_core::paths::safe_component;
use swrap_core::Paths;
use zeroize::{Zeroize, Zeroizing};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const COMMIT_CTX: &[u8] = b"swrap vault DEK commitment v1";
const FILE_MAGIC: &str = "SWVK1";

// ---------------------------------------------------------------- DEK in locked memory

/// The data encryption key. Lives in mlock'ed memory and is zeroized on drop.
pub struct Dek {
    k: Box<[u8; 32]>,
}

impl Dek {
    fn lock(k: Box<[u8; 32]>) -> Self {
        unsafe {
            libc::mlock(k.as_ptr() as *const _, 32);
        }
        Dek { k }
    }
    pub fn random() -> Self {
        let mut k = Box::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut k[..]);
        Self::lock(k)
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 32 {
            bail!("bad DEK length");
        }
        let mut k = Box::new([0u8; 32]);
        k.copy_from_slice(b);
        Ok(Self::lock(k))
    }
    pub fn bytes(&self) -> &[u8; 32] {
        &self.k
    }
    pub fn commitment(&self) -> [u8; 32] {
        *blake3::keyed_hash(&self.k, COMMIT_CTX).as_bytes()
    }
    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(self.k.as_ref().into())
    }
}

impl Drop for Dek {
    fn drop(&mut self) {
        self.k.zeroize();
        unsafe {
            libc::munlock(self.k.as_ptr() as *const _, 32);
        }
    }
}

// ---------------------------------------------------------------- wraps

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Argon {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Wrap {
    pub v: u32,
    /// `password` or `recovery`.
    pub kind: String,
    pub user: String,
    pub created: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argon2id: Option<Argon>,
    pub nonce: String,
    pub ct: String,
    /// blake3 keyed commitment of the DEK (hex).
    pub commitment: String,
}

fn wrap_path(p: &Paths, name: &str) -> PathBuf {
    p.wraps().join(format!("{name}.wrap"))
}

fn kek_password(password: &[u8], a: &Argon) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(a.m_kib, a.t, a.p, Some(32)).map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let salt = B64.decode(&a.salt)?;
    let mut out = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(password, &salt, out.as_mut()).map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(out)
}

fn kek_recovery(recovery: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key("swrap vault recovery KEK v1", recovery))
}

fn seal_dek(dek: &Dek, kek: &[u8; 32], aad: &[u8]) -> (String, String) {
    let c = XChaCha20Poly1305::new(kek.into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = c.encrypt(XNonce::from_slice(&nonce), Payload { msg: dek.bytes(), aad }).expect("encrypt");
    (B64.encode(nonce), B64.encode(ct))
}

fn open_dek(w: &Wrap, kek: &[u8; 32], aad: &[u8]) -> Result<Dek> {
    let c = XChaCha20Poly1305::new(kek.into());
    let nonce = B64.decode(&w.nonce).context("wrap nonce")?;
    let ct = B64.decode(&w.ct).context("wrap ciphertext")?;
    if nonce.len() != 24 {
        bail!("wrap damaged (nonce)");
    }
    let pt = Zeroizing::new(
        c.decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct, aad })
            .map_err(|_| anyhow::anyhow!("wrong password or damaged wrap"))?,
    );
    let dek = Dek::from_bytes(&pt)?;
    if hex(&dek.commitment()) != w.commitment {
        bail!("DEK commitment mismatch: wrap file is damaged");
    }
    Ok(dek)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn wrap_aad(kind: &str, user: &str) -> Vec<u8> {
    format!("swrap-wrap-v1\n{kind}\n{user}").into_bytes()
}

fn read_wrap(path: &Path) -> Result<Wrap> {
    let s = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&s).map_err(|e| anyhow::anyhow!("wrap file {} damaged: {e}", path.display()))
}

fn write_wrap(p: &Paths, name: &str, w: &Wrap, owner: Owner) -> Result<()> {
    atomic::mkdirs(&p.wraps(), 0o700, owner)?;
    atomic::write(&wrap_path(p, name), toml::to_string_pretty(w)?.as_bytes(), 0o600, owner)
}

pub struct Vault<'a> {
    pub paths: &'a Paths,
    pub owner: Owner,
}

/// Recovery key formatted as base32 groups: `ABCDE-FGHIJ-…`.
pub fn format_recovery(k: &[u8; 32]) -> String {
    let s = data_encoding::BASE32_NOPAD.encode(k);
    s.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

pub fn parse_recovery(s: &str) -> Result<Zeroizing<[u8; 32]>> {
    let clean: String = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_uppercase();
    let v = Zeroizing::new(data_encoding::BASE32_NOPAD.decode(clean.as_bytes()).map_err(|_| anyhow::anyhow!("recovery key is not valid base32"))?);
    if v.len() != 32 {
        bail!("recovery key must be 256 bits");
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&v);
    Ok(k)
}

impl<'a> Vault<'a> {
    pub fn new(paths: &'a Paths, owner: Owner) -> Self {
        Vault { paths, owner }
    }

    pub fn initialized(&self) -> bool {
        self.paths.wraps().join("recovery.wrap").exists()
    }

    pub fn admins(&self) -> Vec<String> {
        let mut v = vec![];
        if let Ok(rd) = std::fs::read_dir(self.paths.wraps()) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if let Some(u) = n.strip_suffix(".wrap") {
                    if u != "recovery" {
                        v.push(u.to_string());
                    }
                }
            }
        }
        v.sort();
        v
    }

    /// Create the vault: new DEK, first admin wrap, recovery wrap. Returns (DEK, recovery key text).
    pub fn init(&self, admin: &str, password: &[u8], cfg: &VaultCfg) -> Result<(Dek, Zeroizing<String>)> {
        if self.initialized() {
            bail!("vault already initialized");
        }
        atomic::mkdirs(&self.paths.vault(), 0o700, self.owner)?;
        let dek = Dek::random();
        self.add_admin(&dek, admin, password, cfg)?;
        let mut rk = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(rk.as_mut());
        let kek = kek_recovery(&rk);
        let (nonce, ct) = seal_dek(&dek, &kek, &wrap_aad("recovery", "recovery"));
        let w = Wrap {
            v: 1,
            kind: "recovery".into(),
            user: "recovery".into(),
            created: swrap_core::time::fmt_utc_secs(swrap_core::time::now()),
            argon2id: None,
            nonce,
            ct,
            commitment: hex(&dek.commitment()),
        };
        write_wrap(self.paths, "recovery", &w, self.owner)?;
        self.manifest_update()?;
        Ok((dek, Zeroizing::new(format_recovery(&rk))))
    }

    /// Add (or replace) an admin wrap.
    pub fn add_admin(&self, dek: &Dek, admin: &str, password: &[u8], cfg: &VaultCfg) -> Result<()> {
        if !safe_component(admin) || admin == "recovery" {
            bail!("bad admin name");
        }
        if password.len() < 8 {
            bail!("vault password must be at least 8 characters");
        }
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let a = Argon { m_kib: cfg.argon2_m_kib, t: cfg.argon2_t, p: cfg.argon2_p, salt: B64.encode(salt) };
        let kek = kek_password(password, &a)?;
        let (nonce, ct) = seal_dek(dek, &kek, &wrap_aad("password", admin));
        let w = Wrap {
            v: 1,
            kind: "password".into(),
            user: admin.into(),
            created: swrap_core::time::fmt_utc_secs(swrap_core::time::now()),
            argon2id: Some(a),
            nonce,
            ct,
            commitment: hex(&dek.commitment()),
        };
        write_wrap(self.paths, admin, &w, self.owner)?;
        self.manifest_update()
    }

    pub fn remove_admin(&self, admin: &str) -> Result<()> {
        if !safe_component(admin) || admin == "recovery" {
            bail!("bad admin name");
        }
        if self.admins().len() <= 1 {
            bail!("refusing to remove the last admin wrap");
        }
        std::fs::remove_file(wrap_path(self.paths, admin))?;
        atomic::fsync_dir(&self.paths.wraps())?;
        self.manifest_update()
    }

    /// Unwrap with an admin password. Authentication succeeds iff unwrap and commitment pass.
    pub fn unwrap_password(&self, admin: &str, password: &[u8]) -> Result<Dek> {
        if !safe_component(admin) || admin == "recovery" {
            bail!("bad admin name");
        }
        let p = wrap_path(self.paths, admin);
        if !p.exists() {
            bail!("no vault wrap for {admin}");
        }
        let w = read_wrap(&p)?;
        if w.kind != "password" || w.user != admin {
            bail!("wrap file for {admin} is inconsistent");
        }
        let a = w.argon2id.as_ref().context("wrap missing argon2 parameters")?;
        let kek = kek_password(password, a)?;
        open_dek(&w, &kek, &wrap_aad("password", admin))
    }

    pub fn unwrap_recovery(&self, recovery: &str) -> Result<Dek> {
        let rk = parse_recovery(recovery)?;
        let w = read_wrap(&wrap_path(self.paths, "recovery"))?;
        let kek = kek_recovery(&rk);
        open_dek(&w, &kek, &wrap_aad("recovery", "recovery"))
    }

    // ------------------------------------------------------------ key files

    fn rel(&self, path: &Path) -> Result<String> {
        Ok(path.strip_prefix(self.paths.vault()).context("path outside vault")?.to_string_lossy().into_owned())
    }

    /// Encrypt `plain` into `path` (inside the vault). AAD = relative path + key id.
    pub fn put(&self, dek: &Dek, path: &Path, key_id: &str, plain: &[u8]) -> Result<()> {
        if key_id.contains('\n') {
            bail!("bad key id");
        }
        let rel = self.rel(path)?;
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = format!("{rel}\n{key_id}");
        let ct = dek
            .cipher()
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad: aad.as_bytes() })
            .map_err(|_| anyhow::anyhow!("encrypt"))?;
        let mut data = format!("{FILE_MAGIC} {key_id}\n").into_bytes();
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ct);
        if let Some(parent) = path.parent() {
            atomic::mkdirs(parent, 0o700, self.owner)?;
        }
        atomic::write(path, &data, 0o600, self.owner)?;
        // Verify decryptability before anyone relies on it (spec 12.4).
        let back = self.get(dek, path)?;
        if back.as_slice() != plain {
            bail!("vault write verification failed for {rel}");
        }
        self.manifest_update()
    }

    /// Decrypt a key file. Returns the plaintext in zeroizing memory.
    pub fn get(&self, dek: &Dek, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
        let rel = self.rel(path)?;
        let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let nl = data.iter().position(|&b| b == b'\n').context("vault file damaged")?;
        let head = std::str::from_utf8(&data[..nl]).context("vault file damaged")?;
        let key_id = head.strip_prefix(FILE_MAGIC).map(str::trim).context("vault file damaged (magic)")?;
        let rest = &data[nl + 1..];
        if rest.len() < 24 + 16 {
            bail!("vault file damaged (short)");
        }
        let aad = format!("{rel}\n{key_id}");
        let pt = dek
            .cipher()
            .decrypt(XNonce::from_slice(&rest[..24]), Payload { msg: &rest[24..], aad: aad.as_bytes() })
            .map_err(|_| anyhow::anyhow!("vault file {rel} failed authentication (damaged or moved)"))?;
        Ok(Zeroizing::new(pt))
    }

    // ------------------------------------------------------------ manifest

    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, PathBuf)>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                Self::walk(&p, base, out);
            } else {
                let rel = p.strip_prefix(base).unwrap().to_string_lossy().to_string();
                if rel != "MANIFEST.b3" && !rel.contains("/.") && !rel.starts_with('.') {
                    out.push((rel, p));
                }
            }
        }
    }

    pub fn manifest_compute(&self) -> Result<String> {
        let mut files = vec![];
        Self::walk(&self.paths.vault(), &self.paths.vault(), &mut files);
        files.sort();
        let mut s = String::new();
        for (rel, p) in files {
            let h = blake3::hash(&std::fs::read(&p)?);
            s += &format!("{}  {}\n", h.to_hex(), rel);
        }
        Ok(s)
    }

    pub fn manifest_update(&self) -> Result<()> {
        let s = self.manifest_compute()?;
        atomic::write(&self.paths.manifest(), s.as_bytes(), 0o600, self.owner)
    }

    /// Compare files against MANIFEST.b3; returns findings (empty = ok).
    pub fn manifest_verify(&self) -> Result<Vec<String>> {
        let want = std::fs::read_to_string(self.paths.manifest()).unwrap_or_default();
        let have = self.manifest_compute()?;
        if want == have {
            return Ok(vec![]);
        }
        let parse = |s: &str| -> std::collections::BTreeMap<String, String> {
            s.lines().filter_map(|l| l.split_once("  ").map(|(h, p)| (p.to_string(), h.to_string()))).collect()
        };
        let (w, h) = (parse(&want), parse(&have));
        let mut f = vec![];
        for (p, hw) in &w {
            match h.get(p) {
                None => f.push(format!("vault: {p} missing")),
                Some(hh) if hh != hw => f.push(format!("vault: {p} checksum mismatch")),
                _ => {}
            }
        }
        for p in h.keys() {
            if !w.contains_key(p) {
                f.push(format!("vault: {p} not in manifest"));
            }
        }
        Ok(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> VaultCfg {
        VaultCfg { argon2_m_kib: 1024, argon2_t: 1, argon2_p: 1 }
    }

    #[test]
    fn full_cycle() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::at(d.path(), d.path().join("run"));
        let v = Vault::new(&p, Owner::NONE);
        let (dek, rec) = v.init("admin", b"correct horse", &cfg()).unwrap();
        assert!(v.unwrap_password("admin", b"wrong password").is_err());
        let d2 = v.unwrap_password("admin", b"correct horse").unwrap();
        assert_eq!(d2.bytes(), dek.bytes());
        let d3 = v.unwrap_recovery(&rec.to_lowercase()).unwrap();
        assert_eq!(d3.bytes(), dek.bytes());
        let kp = p.vault().join("keys/hosts/m/root/id_ed25519.enc");
        v.put(&dek, &kp, "SHA256:abc", b"PRIVATE KEY").unwrap();
        assert_eq!(v.get(&dek, &kp).unwrap().as_slice(), b"PRIVATE KEY");
        assert!(v.manifest_verify().unwrap().is_empty());
        // moved file fails AAD
        let kp2 = p.vault().join("keys/hosts/n/root/id_ed25519.enc");
        std::fs::create_dir_all(kp2.parent().unwrap()).unwrap();
        std::fs::copy(&kp, &kp2).unwrap();
        assert!(v.get(&dek, &kp2).is_err());
        assert!(!v.manifest_verify().unwrap().is_empty());
    }

    #[test]
    fn bitflip_in_wrap_is_clean_error() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::at(d.path(), d.path().join("run"));
        let v = Vault::new(&p, Owner::NONE);
        v.init("admin", b"correct horse", &cfg()).unwrap();
        let wp = p.wraps().join("admin.wrap");
        let orig = std::fs::read(&wp).unwrap();
        for i in 0..orig.len() {
            for bit in [0u8, 3, 6] {
                let mut b = orig.clone();
                b[i] ^= 1 << bit;
                std::fs::write(&wp, &b).unwrap();
                // Must never panic and never return a wrong key.
                if let Ok(k) = v.unwrap_password("admin", b"correct horse") {
                    std::fs::write(&wp, &orig).unwrap();
                    let good = v.unwrap_password("admin", b"correct horse").unwrap();
                    assert_eq!(k.bytes(), good.bytes(), "flip at {i} gave a wrong key");
                }
            }
        }
    }
}
