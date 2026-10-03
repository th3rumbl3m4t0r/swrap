//! swrec v1.2 line framing (spec 8.1) and recording signing keys (spec 8.6).
//!
//! Each line: `<crc32c, 8 lowercase hex> <SP> <compact JSON> <LF>`; the CRC covers only the JSON.

use anyhow::{bail, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde_json::{Map, Value};
use std::path::Path;

/// 1.2 adds `p` (repeated output) records; 1.1 files read unchanged.
pub const VERSION: &str = "1.2";
pub const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub fn encode_line(json: &[u8]) -> Vec<u8> {
    debug_assert!(!json.contains(&b'\n'));
    let mut v = Vec::with_capacity(json.len() + 10);
    v.extend_from_slice(format!("{:08x} ", crc32c::crc32c(json)).as_bytes());
    v.extend_from_slice(json);
    v.push(b'\n');
    v
}

pub fn encode_value(v: &Value) -> Vec<u8> {
    encode_line(&serde_json::to_vec(v).expect("json"))
}

/// Parse one line (without LF). Returns the JSON object or why it is bad.
pub fn decode_line(line: &[u8]) -> std::result::Result<Map<String, Value>, &'static str> {
    if line.len() < 11 || line[8] != b' ' {
        return Err("framing");
    }
    let crc = std::str::from_utf8(&line[..8]).ok().and_then(|s| u32::from_str_radix(s, 16).ok()).ok_or("framing")?;
    if !line[..8].iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)) {
        return Err("framing");
    }
    let json = &line[9..];
    if crc32c::crc32c(json) != crc {
        return Err("crc");
    }
    match serde_json::from_slice::<Value>(json) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err("json"),
    }
}

// ---------------------------------------------------------------- signing

const PRIV_TAG: &str = "swrap-recsign-ed25519";
const PUB_TAG: &str = "swrap-recsign-ed25519-pub";

pub struct RecSigner {
    pub name: String,
    key: SigningKey,
}

impl RecSigner {
    pub fn generate(name: &str) -> Self {
        RecSigner { name: name.into(), key: SigningKey::generate(&mut rand::rngs::OsRng) }
    }
    pub fn load(path: &Path, name: &str) -> Result<Self> {
        let s = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let b64 = s.trim().strip_prefix(PRIV_TAG).context("bad key file")?.trim();
        let seed: [u8; 32] = B64.decode(b64)?.try_into().map_err(|_| anyhow::anyhow!("bad key length"))?;
        Ok(RecSigner { name: name.into(), key: SigningKey::from_bytes(&seed) })
    }
    pub fn private_text(&self) -> String {
        format!("{} {}\n", PRIV_TAG, B64.encode(self.key.to_bytes()))
    }
    pub fn public_text(&self) -> String {
        format!("{} {}\n", PUB_TAG, B64.encode(self.key.verifying_key().to_bytes()))
    }
    pub fn sign(&self, chain: &[u8; 32], id: &str) -> String {
        let mut m = chain.to_vec();
        m.extend_from_slice(id.as_bytes());
        B64.encode(self.key.sign(&m).to_bytes())
    }
}

#[derive(Clone)]
pub struct RecVerifier {
    keys: Vec<(String, VerifyingKey)>,
}

impl RecVerifier {
    pub fn new() -> Self {
        RecVerifier { keys: vec![] }
    }
    pub fn add_pub_text(&mut self, signer: &str, text: &str) -> Result<()> {
        let b64 = text.trim().strip_prefix(PUB_TAG).context("bad pub key")?.trim();
        let raw: [u8; 32] = B64.decode(b64)?.try_into().map_err(|_| anyhow::anyhow!("bad key length"))?;
        self.keys.push((signer.into(), VerifyingKey::from_bytes(&raw)?));
        Ok(())
    }
    pub fn add_pub_file(&mut self, signer: &str, path: &Path) -> Result<()> {
        if path.exists() {
            self.add_pub_text(signer, &std::fs::read_to_string(path)?)?;
        }
        Ok(())
    }
    /// Standard verifier for a core node: core key from `recsign/`, edge key from `trust/`.
    pub fn for_core(p: &swrap_core::Paths) -> Self {
        let mut v = RecVerifier::new();
        let _ = v.add_pub_file("core", &p.recsign().join("ed25519.pub"));
        let _ = v.add_pub_file("edge", &p.trust().join("edge-recsign.pub"));
        v
    }
    pub fn has(&self, signer: &str) -> bool {
        self.keys.iter().any(|(n, _)| n == signer)
    }
    pub fn verify(&self, signer: &str, chain: &[u8; 32], id: &str, sig_b64: &str) -> Result<bool> {
        let Some((_, k)) = self.keys.iter().find(|(n, _)| n == signer) else { bail!("no key for signer {signer}") };
        let sig: [u8; 64] = B64.decode(sig_b64)?.try_into().map_err(|_| anyhow::anyhow!("bad signature length"))?;
        let mut m = chain.to_vec();
        m.extend_from_slice(id.as_bytes());
        Ok(k.verify(&m, &ed25519_dalek::Signature::from_bytes(&sig)).is_ok())
    }
}

impl Default for RecVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Chain step: `chain' = blake3(chain ‖ blake3(segment bytes))`.
pub fn chain_step(prev: &[u8; 32], seg_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(prev);
    h.update(seg_hash);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn line_roundtrip() {
        let l = encode_value(&serde_json::json!({"k":"o","s":1,"d":"a\nb"}));
        assert_eq!(*l.last().unwrap(), b'\n');
        assert_eq!(l.iter().filter(|&&b| b == b'\n').count(), 1);
        let m = decode_line(&l[..l.len() - 1]).unwrap();
        assert_eq!(m["d"], "a\nb");
        let mut bad = l.clone();
        bad[15] ^= 1;
        assert!(decode_line(&bad[..bad.len() - 1]).is_err());
    }
    #[test]
    fn sign_verify() {
        let s = RecSigner::generate("core");
        let mut v = RecVerifier::new();
        v.add_pub_text("core", &s.public_text()).unwrap();
        let chain = [7u8; 32];
        let sig = s.sign(&chain, "ID");
        assert!(v.verify("core", &chain, "ID", &sig).unwrap());
        assert!(!v.verify("core", &chain, "ID2", &sig).unwrap());
    }
}
