//! Audit log: daily swrec files `audit/YYYY/MM/DD.swrec`, signed at day rollover.

use anyhow::Result;
use serde_json::{json, Map, Value};
use swrap_core::atomic::Owner;
use swrap_core::time::{date_dir, now};
use swrap_core::Paths;
use swrec::{RecSigner, Writer, WriterOpts};

pub struct AuditLog {
    paths: Paths,
    signer: RecSigner,
    owner: Owner,
    day: String,
    w: Option<Writer>,
}

impl AuditLog {
    pub fn new(paths: Paths, signer: RecSigner, owner: Owner) -> Self {
        AuditLog { paths, signer, owner, day: String::new(), w: None }
    }

    fn writer(&mut self) -> Result<&mut Writer> {
        let day = date_dir(now());
        if self.day != day || self.w.is_none() {
            if let Some(mut old) = self.w.take() {
                let _ = old.end("exit", None, Some(&self.signer));
            }
            let path = self.paths.audit().join(format!("{day}.swrec"));
            let dir = path.parent().unwrap().to_path_buf();
            swrap_core::atomic::mkdirs(&dir, 0o750, self.owner)?;
            let opts = WriterOpts { mode: 0o640, ..Default::default() };
            let w = if path.exists() {
                match Writer::resume(&path, opts.clone())? {
                    Some(w) => w,
                    None => {
                        // Already ended today (e.g. clean shutdown): continue in a numbered part.
                        let mut n = 1;
                        loop {
                            let p = self.paths.audit().join(format!("{day}.{n}.swrec"));
                            if !p.exists() {
                                break Writer::create(&p, &swrap_core::new_id(), hdr(), opts.clone())?;
                            }
                            if let Some(w) = Writer::resume(&p, opts.clone())? {
                                break w;
                            }
                            n += 1;
                        }
                    }
                }
            } else {
                Writer::create(&path, &swrap_core::new_id(), hdr(), opts)?
            };
            let _ = std::os::unix::fs::chown(&w.path, self.owner.uid, self.owner.gid);
            self.w = Some(w);
            self.day = day;
        }
        Ok(self.w.as_mut().unwrap())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log(&mut self, user: &str, action: &str, target: &str, ruser: &str, result: &str, detail: Value, reference: &str) -> Result<()> {
        let w = self.writer()?;
        let mut m = Map::new();
        m.insert("node".into(), "core".into());
        m.insert("user".into(), user.into());
        m.insert("action".into(), action.into());
        m.insert("target".into(), target.into());
        m.insert("ruser".into(), ruser.into());
        m.insert("result".into(), result.into());
        m.insert("detail".into(), detail);
        m.insert("ref".into(), reference.into());
        w.record("a", m)?;
        w.sync()?;
        Ok(())
    }

    pub fn tick(&mut self) {
        if let Some(w) = self.w.as_mut() {
            let _ = w.tick();
        }
        // Roll over at midnight UTC even when idle.
        if !self.day.is_empty() && self.day != date_dir(now()) {
            let _ = self.writer();
        }
    }
}

fn hdr() -> Map<String, Value> {
    json!({"kind":"audit","origin":"core","exec":"core"}).as_object().unwrap().clone()
}
