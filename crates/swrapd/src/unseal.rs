//! `/run/swrap/unseal.sock` (root-only, SO_PEERCRED uid 0): swrap-pam-unlock hands over the DEK
//! after verifying an admin password, and reports every attempt for the audit log.

use crate::daemon::Daemon;
use anyhow::{Context, Result};
use base64::Engine;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use swrap_core::api::{Resp, UnsealReq};
use swrap_core::frame::{aio, kind, Frame};
use tokio::net::UnixListener;

pub async fn serve(d: Arc<Daemon>) -> Result<()> {
    let sock = d.paths.unseal_sock();
    let _ = std::fs::remove_file(&sock);
    let l = UnixListener::bind(&sock).with_context(|| format!("bind {}", sock.display()))?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (mut s, _) = l.accept().await?;
        let d = d.clone();
        tokio::spawn(async move {
            let Ok(cred) = swrap_core::sys::peer_cred(&s) else { return };
            if cred.uid != 0 {
                return;
            }
            let Ok(Some(f)) = aio::read_frame(&mut s).await else { return };
            let resp = match f.parse::<UnsealReq>() {
                Ok(UnsealReq::Unseal { user, dek, via, rhost }) => {
                    let r = base64::engine::general_purpose::STANDARD
                        .decode(dek.as_bytes())
                        .map_err(anyhow::Error::from)
                        .and_then(|b| {
                            let dek = swrap_vault::Dek::from_bytes(&zeroize::Zeroizing::new(b))?;
                            // Never trust the caller blindly: the DEK must match the vault commitment.
                            let w: swrap_vault::Wrap = toml::from_str(&std::fs::read_to_string(d.paths.wraps().join("recovery.wrap"))?)?;
                            if w.commitment != crate::daemon::hex(&dek.commitment()) {
                                anyhow::bail!("DEK does not match the vault");
                            }
                            d.unseal(dek, &user, &format!("{via} {rhost}").trim().to_string())
                        });
                    match r {
                        Ok(fresh) => Resp::ok(json!({"unsealed": fresh})),
                        Err(e) => Resp::err(e),
                    }
                }
                Ok(UnsealReq::Attempt { user, result, via, rhost, detail }) => {
                    d.audit_event(&user, "auth.admin-password", via.as_str(), "", &result, json!({"rhost": rhost, "detail": detail}), "");
                    Resp::ok(json!({}))
                }
                Err(e) => Resp::err(e),
            };
            let _ = aio::write_frame(&mut s, &Frame::json(kind::RESP, &resp)).await;
        });
    }
}
