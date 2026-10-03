//! Core → edge work for hosts only edge can reach (`network = "edge"`). Edge long-polls
//! (`EdgeReq::Jobs`) over the existing link, so no new listener or sshd change is needed.
//! Results come back with `JobResult`; interactive sessions attach with `Attach`.

use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::os::unix::net::UnixStream;
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use swrap_core::api::EdgeJob;

#[derive(Default)]
struct Jobs {
    queue: Mutex<VecDeque<(Instant, EdgeJob)>>,
    waiters: Mutex<HashMap<String, mpsc::Sender<Value>>>,
    parked: Mutex<HashMap<String, (Instant, UnixStream)>>,
}

fn jobs() -> &'static Jobs {
    static J: OnceLock<Jobs> = OnceLock::new();
    J.get_or_init(Default::default)
}

fn job_id(j: &EdgeJob) -> &str {
    match j {
        EdgeJob::Keyscan { id, .. } | EdgeJob::Exec { id, .. } | EdgeJob::Session { id, .. } => id,
    }
}

/// Queue a job and wait for edge's result (blocking; call from blocking context).
pub fn submit(job: EdgeJob, timeout: Duration) -> Result<Value> {
    let id = job_id(&job).to_string();
    let (tx, rx) = mpsc::channel();
    jobs().waiters.lock().unwrap().insert(id.clone(), tx);
    jobs().queue.lock().unwrap().push_back((Instant::now(), job));
    let r = rx.recv_timeout(timeout);
    jobs().waiters.lock().unwrap().remove(&id);
    jobs().queue.lock().unwrap().retain(|(_, j)| job_id(j) != id);
    match r {
        Ok(v) => Ok(v),
        Err(_) => bail!("edge did not answer within {} (link down?)", swrap_core::time::fmt_duration_ms(timeout)),
    }
}

/// Queue without waiting (sessions: the result is the attach).
pub fn enqueue(job: EdgeJob) {
    jobs().queue.lock().unwrap().push_back((Instant::now(), job));
}

/// Next job for edge (drops jobs nobody fetched within PT2M).
pub fn next() -> Option<EdgeJob> {
    let mut q = jobs().queue.lock().unwrap();
    while let Some((t, j)) = q.pop_front() {
        if t.elapsed() < Duration::from_secs(120) {
            return Some(j);
        }
    }
    None
}

pub fn result(id: &str, v: Value) {
    if let Some(tx) = jobs().waiters.lock().unwrap().remove(id) {
        let _ = tx.send(v);
    }
}

/// Park the core-side client of a session edge will run; edge picks it up with `Attach`.
pub fn park(id: &str, s: UnixStream) {
    let mut p = jobs().parked.lock().unwrap();
    p.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(60));
    p.insert(id.to_string(), (Instant::now(), s));
}

pub fn take(id: &str) -> Option<UnixStream> {
    jobs().parked.lock().unwrap().remove(id).map(|(_, s)| s)
}
