//! Fleet jobs (spec 10.6-10.10). `swupdate`: dnf upgrade on the hosts a user may act on as root.

use crate::daemon::{Caller, Console, Daemon};
use crate::hosts::{remote_stream, RemoteOpts, Run};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use swrap_core::api::{Resp, SecretEnv};
use swrap_core::config::{Host, Profile};
use swrap_core::rbac;
use swrap_core::time::{fmt_duration_ms, now};

/// How long one host may take. dnf itself is not bound to it: it runs detached on the host (see
/// the script), so a timeout only stops the waiting, never a transaction half way.
const UPDATE_TIMEOUT: Duration = Duration::from_secs(3600);

const MARK: &str = "SWUPDATE-RESULT";

/// Runs on the target as the granted account (`$1` = package or empty, `$2` = run id).
const UPDATE_SCRIPT: &str = r#"set -u
export LC_ALL=C
APP="${1:-}"; RUN="${2:-run}"; MARK=SWUPDATE-RESULT
S=""; [ "$(id -u)" = 0 ] || S="sudo -n"
if ! command -v dnf >/dev/null 2>&1; then echo "$MARK result=unsupported detail=no-dnf"; exit 0; fi
if [ -n "$APP" ] && ! rpm -q "$APP" >/dev/null 2>&1; then echo "$MARK result=not-installed"; exit 0; fi
pkgs() { rpm -qa --qf '%{NAME}.%{ARCH} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort; }
needs_reboot() {
  if command -v needs-restarting >/dev/null 2>&1; then $S needs-restarting -r >/dev/null 2>&1; r=$?
  else $S dnf needs-restarting -r >/dev/null 2>&1; r=$?; fi
  case $r in 0) echo no; return;; 1) echo yes; return;; esac
  k=$(rpm -q --last kernel-core 2>/dev/null | awk 'NR==1 && $1 ~ /^kernel-core-/ {print substr($1, 13)}')
  if [ -z "$k" ]; then echo unknown; elif [ "$k" = "$(uname -r)" ]; then echo no; else echo yes; fi
}
before=$(mktemp); after=$(mktemp); log=/var/tmp/swupdate-$RUN.log
pkgs >"$before"
: >"$log"
# dnf runs detached from this SSH session: a dropped link or a timeout must never kill it in the
# middle of a transaction. Its output goes to a log that is followed here.
setsid -w sh -c 'trap "" HUP PIPE; exec "$@" >>"$0" 2>&1 </dev/null' "$log" $S dnf -y upgrade --refresh ${APP:+"$APP"} &
pid=$!
tail -n +1 --pid=$pid -f "$log" 2>/dev/null
wait $pid; rc=$?
pkgs >"$after"
changed=$(comm -13 "$before" "$after" | wc -l)
rm -f "$before" "$after"
reboot=$(needs_reboot)
if [ $rc -eq 0 ]; then rm -f "$log"; res=ok; else res=failed; fi
echo "$MARK result=$res rc=$rc changed=$changed reboot=$reboot log=$log"
exit $rc
"#;

struct Job {
    host: Host,
    ruser: String,
    sudo: bool,
}

#[derive(Default, Clone)]
struct Outcome {
    label: String,
    ruser: String,
    result: String,
    changed: String,
    reboot: String,
    duration: String,
    code: i32,
    detail: String,
}

impl Outcome {
    fn failed(&self) -> bool {
        !matches!(self.result.as_str(), "ok" | "not-installed" | "unsupported")
    }
}

/// Run `f` for every item on up to `[fleet] parallel` threads, inside the daemon's runtime (the
/// SSH signing agents live there). A job that fails or panics still gives a row, from `failed`.
pub fn parallel<T, R>(d: &Daemon, items: Vec<T>, f: impl Fn(&T) -> Result<R> + Send + Sync + 'static, failed: impl Fn(&T, String) -> R + Send + Sync + 'static) -> Vec<R>
where
    T: Send + 'static,
    R: Send + 'static,
{
    let n = d.cfg().fleet.parallel.clamp(1, 32).min(items.len().max(1));
    let queue = Arc::new(Mutex::new(items.into_iter().collect::<VecDeque<T>>()));
    let out = Arc::new(Mutex::new(Vec::new()));
    let (f, failed) = (Arc::new(f), Arc::new(failed));
    let rt = tokio::runtime::Handle::current();
    let threads: Vec<_> = (0..n)
        .map(|_| {
            let (q, out, f, failed, rt) = (queue.clone(), out.clone(), f.clone(), failed.clone(), rt.clone());
            std::thread::spawn(move || {
                let _rt = rt.enter();
                loop {
                    let Some(item) = q.lock().unwrap().pop_front() else { break };
                    let r = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&item))) {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) => failed(&item, format!("{e:#}")),
                        Err(p) => failed(&item, format!("internal error: {}", p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default())),
                    };
                    out.lock().unwrap().push(r);
                }
            })
        })
        .collect();
    for t in threads {
        let _ = t.join();
    }
    let rows = std::mem::take(&mut *out.lock().unwrap());
    rows
}

fn valid_pkg(p: &str) -> bool {
    !p.is_empty() && p.len() <= 200 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-:".contains(&b)) && !p.starts_with('-')
}

/// `swupdate <targets> [--app <pkg>]` (spec 10.10).
pub fn update(d: &Arc<Daemon>, c: &Caller, targets: &str, app: Option<&str>, con: &Console) -> Result<Resp> {
    let user = c.aaa()?.clone();
    if d.is_sealed() {
        bail!("the swrap vault is sealed; fleet jobs are unavailable until an admin logs in");
    }
    if let Some(p) = app {
        if !valid_pkg(p) {
            bail!("--app takes one package name (letters, digits and ._+-:), got {p:?}");
        }
    }
    let t = now();
    let all = Host::all(&d.paths)?;
    // Only hosts where the caller can act as root, directly or via swrap-managed NOPASSWD sudo.
    let root_ok = |h: &Host| rbac::root_capable_account(&user, h, c.origin, t).is_some();
    let picked = rbac::expand(targets, &all, root_ok).map_err(|e| match e.to_string() {
        m if m.starts_with("no grant for host") => anyhow!("{m}: swupdate needs root there (or swrap-managed sudo)"),
        m => anyhow!(m),
    })?;
    if picked.is_empty() {
        bail!("no host in {targets:?} where you can act as root");
    }
    let jobs: Vec<Job> = picked
        .iter()
        .map(|h| {
            let (ruser, sudo) = rbac::root_capable_account(&user, h, c.origin, t).expect("filtered above");
            Job { host: (*h).clone(), ruser, sudo }
        })
        .collect();
    let labels: Vec<String> = jobs.iter().map(|j| j.host.label.clone()).collect();
    let reinventory: Vec<(Host, String)> = jobs.iter().map(|j| (j.host.clone(), j.ruser.clone())).collect();
    let run = Run::new(d, "swupdate", &c.name, targets, json!({"app": app, "hosts": labels, "origin": c.origin.as_str()}))?;
    d.audit_event(&c.name, "fleet.update", targets, "", "start", json!({"run": run.id, "app": app, "hosts": labels}), &run.id);
    let width = labels.iter().map(|l| l.len()).max().unwrap_or(4);
    con.err(format!(
        "swupdate {}: {} on {} ({}), recorded as run {}",
        targets,
        match app { Some(p) => format!("dnf -y upgrade --refresh {p}"), None => "dnf -y upgrade --refresh".into() },
        labels.join(", "),
        if jobs.len() == 1 { "1 host".to_string() } else { format!("{} hosts, {} at a time", jobs.len(), d.cfg().fleet.parallel.clamp(1, 32).min(jobs.len())) },
        run.id
    ));

    let signer = Arc::new(swrec::RecSigner::load(&d.paths.recsign().join("ed25519.key"), "core").context("load recording signing key")?);
    let run = Arc::new(run);
    let (d2, run2, con2, app2, who2, sg2) = (d.clone(), run.clone(), con.clone(), app.map(str::to_string), c.name.clone(), signer.clone());
    let con3 = con.clone();
    let mut out = parallel(
        d,
        jobs,
        move |job: &Job| update_host(&d2, &who2, &run2, job, app2.as_deref(), &con2, width, &sg2),
        move |job: &Job, why: String| {
            con3.out(format!("{:<width$} | swrap: {why}", job.host.label));
            Outcome { label: job.host.label.clone(), ruser: job.ruser.clone(), result: "error".into(), code: -1, detail: why, ..Default::default() }
        },
    );
    out.sort_by(|a, b| a.label.cmp(&b.label));

    // Summary table (spec 10.10): label, result, packages changed, needs-reboot, duration.
    let mut text = format!("\n{:<width$}  {:<13}  {:>7}  {:<12}  {}\n", "HOST", "RESULT", "CHANGED", "NEEDS-REBOOT", "DURATION");
    for o in &out {
        text += &format!("{:<width$}  {:<13}  {:>7}  {:<12}  {}\n", o.label, o.result, o.changed, o.reboot, o.duration);
    }
    for o in out.iter().filter(|o| o.failed() && !o.detail.is_empty()) {
        text += &format!("{}: {}\n", o.label, o.detail);
    }
    let failed = out.iter().filter(|o| o.failed()).count();
    // Spec 10.10: the affected hosts are inventoried again.
    let changed: Vec<crate::inventory::Target> = reinventory
        .into_iter()
        .filter(|(h, _)| out.iter().any(|o| o.label == h.label && o.result == "ok"))
        .map(|(host, ruser)| crate::inventory::Target { host, ruser })
        .collect();
    if !changed.is_empty() {
        match crate::inventory::collect(d, &c.name, targets, changed, None) {
            Ok(r) => text += &format!("inventory refreshed ({})\n", r.data["run"].as_str().unwrap_or("")),
            Err(e) => text += &format!("inventory refresh failed: {e:#}\n"),
        }
    }
    text += &format!("run {} · {} ok, {} failed, {} skipped\n", run.id, out.iter().filter(|o| o.result == "ok").count(), failed, out.iter().filter(|o| matches!(o.result.as_str(), "not-installed" | "unsupported")).count());
    let rows: Vec<Value> = out.iter().map(|o| json!({"label": o.label, "ruser": o.ruser, "result": o.result, "changed": o.changed, "needs_reboot": o.reboot, "duration": o.duration, "exit": o.code, "detail": o.detail})).collect();
    d.audit_event(&c.name, "fleet.update", targets, "", if failed == 0 { "ok" } else { "failed" }, json!({"run": run.id, "app": app, "hosts": rows}), &run.id);
    let mut r = Resp::ok(json!({"run": run.id, "hosts": rows}));
    r.text = text;
    r.exit = if failed == 0 { 0 } else { 1 };
    Ok(r)
}

#[allow(clippy::too_many_arguments)]
fn update_host(d: &Arc<Daemon>, who: &str, run: &Run, job: &Job, app: Option<&str>, con: &Console, width: usize, signer: &swrec::RecSigner) -> Result<Outcome> {
    let h = &job.host;
    let (enc, _) = crate::session::credential(d, &h.label, &job.ruser).ok_or_else(|| anyhow!("no credential for {}@{}", job.ruser, h.label))?;
    let profile = Profile::load(&d.paths, &h.profile)?;
    let known = std::fs::read_to_string(d.paths.known_hosts(&h.label)).context("host keys not pinned")?;
    let cmd = format!("bash -c {} swupdate {} {}", crate::ai::q(UPDATE_SCRIPT), crate::ai::q(app.unwrap_or("")), run.id);
    let shown = match app { Some(p) => format!("swupdate --app {p}"), None => "swupdate".into() };
    let mut rec = run.host_writer(d, h, &job.ruser, who, &shown)?;
    if job.sudo {
        rec.note(&format!("{} is not root: dnf runs via sudo -n (swrap-managed NOPASSWD)", job.ruser))?;
    }
    let t0 = Instant::now();
    // Live output, one prefixed line at a time (per stream, partial lines held back).
    let mut partial: [Vec<u8>; 2] = [vec![], vec![]];
    let mut marker = String::new();
    let label = h.label.clone();
    let mut show = |fd: u8, bytes: &[u8], flush: bool| {
        let buf = &mut partial[(fd == 2) as usize];
        buf.extend_from_slice(bytes);
        let mut lines: Vec<Vec<u8>> = vec![];
        while let Some(i) = buf.iter().position(|&b| b == b'\n') {
            lines.push(buf.drain(..=i).collect());
        }
        if flush && !buf.is_empty() {
            lines.push(std::mem::take(buf));
        }
        for l in lines {
            let l = String::from_utf8_lossy(&l);
            let l = l.trim_end_matches(['\n', '\r']);
            if let Some(m) = l.strip_prefix(MARK) {
                marker = m.trim().to_string();
                continue;
            }
            con.out(format!("{label:<width$} | {}{l}", if fd == 2 { "! " } else { "" }));
        }
    };
    let r = remote_stream(d, who, h, &job.ruser, &enc, &profile, &known, &cmd, b"", Some(&mut rec), RemoteOpts { timeout: Some(UPDATE_TIMEOUT), cap: 1 << 20 }, &mut |fd, b| show(fd, b, false));
    show(1, b"", true);
    show(2, b"", true);
    let dur = t0.elapsed();
    let r = match r {
        Ok(r) => r,
        Err(e) => {
            let _ = rec.end("error", None, Some(signer));
            return Err(e);
        }
    };
    let field = |k: &str| marker.split_whitespace().find_map(|kv| kv.strip_prefix(&format!("{k}=")).map(str::to_string));
    let mut o = Outcome {
        label: h.label.clone(),
        ruser: job.ruser.clone(),
        result: field("result").unwrap_or_default(),
        changed: field("changed").unwrap_or_else(|| "-".into()),
        reboot: field("reboot").unwrap_or_else(|| "-".into()),
        duration: fmt_duration_ms(dur),
        code: r.code,
        detail: String::new(),
    };
    if o.result.is_empty() {
        // No result line: the script did not finish.
        o.result = if r.timed_out { "timeout".into() } else if r.code == 255 { "unreachable".into() } else { "failed".into() };
        o.detail = if r.timed_out {
            format!("no result after {}; dnf keeps running on the host, its log is /var/tmp/swupdate-{}.log", fmt_duration_ms(UPDATE_TIMEOUT), run.id)
        } else if r.code == 255 {
            format!("ssh: {}", r.why())
        } else {
            format!("exit {}", r.code)
        };
    } else if o.result == "failed" {
        o.detail = format!("dnf exit {}; log kept on the host: {}", field("rc").unwrap_or_default(), field("log").unwrap_or_default());
    } else if o.result == "unsupported" {
        o.detail = "no dnf on this host".into();
        o.changed = "-".into();
    }
    if o.result == "unsupported" || o.result == "not-installed" {
        o.reboot = "-".into();
        o.changed = "-".into();
    }
    let rc_path = run.dir.join(format!("{}.rc", h.label));
    let rc = json!({"exit": r.code, "result": o.result, "changed": o.changed, "needs_reboot": o.reboot, "duration": o.duration, "detail": o.detail});
    swrap_core::atomic::write(&rc_path, format!("{}\n", rc).as_bytes(), 0o640, swrap_core::atomic::Owner::new(d.swrap_uid, d.admin_gid))?;
    rec.end(if r.timed_out { "timeout" } else { "exit" }, Some(r.code), Some(signer))?;
    Ok(o)
}

// ---------------------------------------------------------------- swr / swx (spec 10.9)

/// Runs on the target (`$1` = bytes of secret env, `$2` = bytes of script, then the script's
/// arguments). stdin carries both; the secrets file is sourced and deleted before the script
/// starts, the script's own stdin is /dev/null, and the directory goes when it ends. The
/// interpreter line is honoured without executing from the temp dir (it may be noexec).
const RUN_WRAPPER: &str = r##"set -u
umask 077
d=$(mktemp -d "${TMPDIR:-/tmp}/swr.XXXXXXXX") || exit 97
trap 'rm -rf "$d"' EXIT
cat > "$d/bundle"
head -c "$1" "$d/bundle" > "$d/env"
tail -c +"$(( $1 + 1 ))" "$d/bundle" | head -c "$2" > "$d/script"
rm -f "$d/bundle"
shift 2
(
  . "$d/env"; rm -f "$d/env"
  if [ "$(head -c 2 "$d/script")" = "#!" ]; then
    IFS= read -r first < "$d/script"
    exec ${first#\#!} "$d/script" "$@"
  fi
  exec bash "$d/script" "$@"
) </dev/null
"##;

/// Replaces every occurrence of a secret value (4 bytes or longer) with `[REDACTED:NAME]`,
/// also when it arrives split across chunks: what could be the start of a secret at the end of
/// a chunk is held back until the next one (or the end).
pub struct Redactor {
    secrets: Vec<(Vec<u8>, Vec<u8>, String)>,
    carry: Vec<u8>,
    pub counts: std::collections::BTreeMap<String, u64>,
}

impl Redactor {
    pub fn new(secrets: &[SecretEnv]) -> Self {
        let mut v: Vec<(Vec<u8>, Vec<u8>, String)> = secrets
            .iter()
            .filter(|s| s.value.len() >= 4)
            .map(|s| (s.value.as_bytes().to_vec(), format!("[REDACTED:{}]", s.name).into_bytes(), s.name.clone()))
            .collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.0.len())); // longest first
        Redactor { secrets: v, carry: vec![], counts: Default::default() }
    }
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        self.process(data, false)
    }
    pub fn finish(&mut self) -> Vec<u8> {
        self.process(&[], true)
    }
    pub fn text(&mut self, s: &str) -> String {
        let mut v = self.push(s.as_bytes());
        v.extend(self.finish());
        String::from_utf8_lossy(&v).into_owned()
    }
    fn process(&mut self, data: &[u8], end: bool) -> Vec<u8> {
        if self.secrets.is_empty() {
            let mut v = std::mem::take(&mut self.carry);
            v.extend_from_slice(data);
            return v;
        }
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(data);
        let longest = self.secrets[0].0.len();
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        'scan: while i < buf.len() {
            for (v, mark, name) in &self.secrets {
                if buf[i..].starts_with(v) {
                    out.extend_from_slice(mark);
                    *self.counts.entry(name.clone()).or_default() += 1;
                    i += v.len();
                    continue 'scan;
                }
            }
            if !end && buf.len() - i < longest {
                let rest = &buf[i..];
                if self.secrets.iter().any(|(v, _, _)| v.len() > rest.len() && v.starts_with(rest)) {
                    break;
                }
            }
            out.push(buf[i]);
            i += 1;
        }
        self.carry = buf[i..].to_vec();
        out
    }
}

/// Whole output lines per stream, for the live `label | line` display.
#[derive(Default)]
struct Lines {
    partial: [Vec<u8>; 2],
}

impl Lines {
    fn feed(&mut self, fd: u8, bytes: &[u8], flush: bool) -> Vec<String> {
        let buf = &mut self.partial[(fd == 2) as usize];
        buf.extend_from_slice(bytes);
        let mut out = vec![];
        while let Some(i) = buf.iter().position(|&b| b == b'\n') {
            let l: Vec<u8> = buf.drain(..=i).collect();
            out.push(String::from_utf8_lossy(&l).trim_end_matches(['\n', '\r']).to_string());
        }
        if flush && !buf.is_empty() {
            out.push(String::from_utf8_lossy(&std::mem::take(buf)).trim_end_matches('\r').to_string());
        }
        out
    }
}

struct RunJob {
    host: Host,
    ruser: String,
}

#[derive(Default)]
struct RunOut {
    label: String,
    ruser: String,
    result: String,
    code: i32,
    duration: String,
    redacted: u64,
    detail: String,
}

fn valid_env_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.bytes().next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_') && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `swr <script> <targets> …` / `swx <targets> -- <command>` (spec 10.9).
#[allow(clippy::too_many_arguments)]
pub fn run(d: &Arc<Daemon>, c: &Caller, targets: &str, ruser: Option<&str>, script_name: &str, script_b64: &str, args: &[String], secrets: &[SecretEnv], con: &Console) -> Result<Resp> {
    use base64::Engine;
    let user = c.aaa()?.clone();
    if d.is_sealed() {
        bail!("the swrap vault is sealed; fleet jobs are unavailable until an admin logs in");
    }
    let script = base64::engine::general_purpose::STANDARD.decode(script_b64).context("bad script encoding")?;
    if script.is_empty() || script.len() > 1 << 20 {
        bail!("the script must be between 1 byte and 1 MiB");
    }
    let mut seen = std::collections::HashSet::new();
    for s in secrets {
        if !valid_env_name(&s.name) {
            bail!("--secret-env: {:?} is not a valid variable name", s.name);
        }
        if !seen.insert(s.name.clone()) {
            bail!("--secret-env {} given twice", s.name);
        }
    }
    if let Some(r) = ruser {
        if r.is_empty() || !r.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
            bail!("bad -u account {r:?}");
        }
    }
    let kind = if script_name.is_empty() { "swx" } else { "swr" };
    let t = now();
    let all = Host::all(&d.paths)?;
    let account = |h: &Host| -> Option<String> {
        let ok = |a: &str| crate::session::credential(d, &h.label, a).is_some();
        match ruser {
            Some(r) => (rbac::allowed(&user, h, r, c.origin, t) && ok(r)).then(|| r.to_string()),
            None => rbac::granted_accounts(&user, h, c.origin, t).into_iter().find(|a| ok(a)),
        }
    };
    let picked = rbac::expand(targets, &all, |h| account(h).is_some()).map_err(|e| match (e.to_string(), ruser) {
        (m, Some(r)) if m.starts_with("no grant for host") => anyhow!("{m} as {r}"),
        (m, _) => anyhow!(m),
    })?;
    if picked.is_empty() {
        bail!("no host in {targets:?} you may use{}", ruser.map(|r| format!(" as {r}")).unwrap_or_default());
    }
    let jobs: Vec<RunJob> = picked.iter().map(|h| RunJob { host: (*h).clone(), ruser: account(h).expect("filtered above") }).collect();
    let labels: Vec<String> = jobs.iter().map(|j| j.host.label.clone()).collect();
    let names: Vec<String> = secrets.iter().map(|s| s.name.clone()).collect();
    // What is shown and kept: never a secret value, even if one was typed into the command.
    let mut red = Redactor::new(secrets);
    let script_kept = red.text(&String::from_utf8_lossy(&script));
    let shown = if kind == "swx" { format!("swx {}", script_kept.trim()) } else { format!("swr {} {}", script_name, args.iter().map(|a| crate::ai::q(a)).collect::<Vec<_>>().join(" ")).trim_end().to_string() };
    let b3 = blake3::hash(&script).to_hex().to_string();
    let run = Run::new(d, kind, &c.name, targets, json!({"script": if kind == "swr" { script_name } else { "(command)" }, "script_b3": b3, "args": args, "ruser": ruser, "secret_env": names, "hosts": labels, "origin": c.origin.as_str()}))?;
    swrap_core::atomic::write(&run.dir.join("script"), script_kept.as_bytes(), 0o640, swrap_core::atomic::Owner::new(d.swrap_uid, d.admin_gid))?;
    d.audit_event(&c.name, "fleet.run", targets, ruser.unwrap_or(""), "start", json!({"run": run.id, "kind": kind, "script": script_name, "script_b3": b3, "secret_env": names, "hosts": labels}), &run.id);
    let width = labels.iter().map(|l| l.len()).max().unwrap_or(4);
    con.err(format!("{} on {} ({} host{}), recorded as run {}", shown, labels.join(", "), labels.len(), if labels.len() == 1 { "" } else { "s" }, run.id));
    // The secrets as a file the wrapper sources: `export NAME='value'`.
    let mut env = String::new();
    for s in secrets {
        env += &format!("export {}={}\n", s.name, crate::ai::q(&s.value));
    }
    let mut stdin = env.into_bytes();
    let env_len = stdin.len();
    stdin.extend_from_slice(&script);
    let cmd = format!(
        "bash -c {} swr {} {}{}",
        crate::ai::q(RUN_WRAPPER),
        env_len,
        script.len(),
        args.iter().map(|a| format!(" {}", crate::ai::q(a))).collect::<String>()
    );
    let timeout = d.cfg().fleet.default_timeout.exact().unwrap_or(Duration::from_secs(600));
    let signer = Arc::new(swrec::RecSigner::load(&d.paths.recsign().join("ed25519.key"), "core").context("load recording signing key")?);
    let (d2, run2, con2, who2, sg2) = (d.clone(), Arc::new(run), con.clone(), c.name.clone(), signer);
    let run_id = run2.id.clone();
    let (secrets2, cmd2, stdin2, shown2) = (secrets.to_vec(), cmd, stdin, shown.clone());
    let con3 = con.clone();
    let mut out = parallel(
        d,
        jobs,
        move |job: &RunJob| run_host(&d2, &who2, &run2, job, &cmd2, &stdin2, &secrets2, &shown2, timeout, &con2, width, &sg2),
        move |job: &RunJob, why: String| {
            con3.out(format!("{:<width$} | swrap: {why}", job.host.label));
            RunOut { label: job.host.label.clone(), ruser: job.ruser.clone(), result: "error".into(), code: -1, detail: why, ..Default::default() }
        },
    );
    out.sort_by(|a, b| a.label.cmp(&b.label));
    let mut text = format!("\n{:<width$}  {:<10}  {:<12}  {:>5}  {:<14}  {}\n", "HOST", "ACCOUNT", "RESULT", "EXIT", "DURATION", "REDACTED");
    for o in &out {
        text += &format!("{:<width$}  {:<10}  {:<12}  {:>5}  {:<14}  {}\n", o.label, o.ruser, o.result, o.code, o.duration, o.redacted);
    }
    for o in out.iter().filter(|o| !o.detail.is_empty()) {
        text += &format!("{}: {}\n", o.label, o.detail);
    }
    let failed = out.iter().filter(|o| o.result != "ok").count();
    text += &format!("run {run_id} · {} ok, {failed} failed\n", out.len() - failed);
    let rows: Vec<Value> = out.iter().map(|o| json!({"label": o.label, "ruser": o.ruser, "result": o.result, "exit": o.code, "duration": o.duration, "redacted": o.redacted, "detail": o.detail})).collect();
    d.audit_event(&c.name, "fleet.run", targets, ruser.unwrap_or(""), if failed == 0 { "ok" } else { "failed" }, json!({"run": run_id, "kind": kind, "hosts": rows}), &run_id);
    let mut r = Resp::ok(json!({"run": run_id, "hosts": rows}));
    r.text = text;
    r.exit = if failed == 0 { 0 } else { 1 };
    Ok(r)
}

/// A job swrap itself runs on one host (recorded as a run of its own, like `swr`): `script` goes
/// through the same wrapper, `env` is sourced from stdin and never recorded, and every value in
/// `redact` is masked in the output, the recording and the kept script.
/// Returns (run id, exit code, result, detail).
#[allow(clippy::too_many_arguments)]
pub fn system_job(d: &Arc<Daemon>, who: &str, kind: &str, host: &Host, ruser: &str, shown: &str, script: &[u8], env: &[SecretEnv], redact: &[SecretEnv], timeout: Duration, con: &Console) -> Result<(String, i32, String, String)> {
    let names: Vec<String> = env.iter().map(|s| s.name.clone()).collect();
    let b3 = blake3::hash(script).to_hex().to_string();
    let run = Run::new(d, kind, who, &host.label, json!({"script": shown, "script_b3": b3, "ruser": ruser, "secret_env": names, "hosts": [host.label]}))?;
    let kept = Redactor::new(redact).text(&String::from_utf8_lossy(script));
    swrap_core::atomic::write(&run.dir.join("script"), kept.as_bytes(), 0o640, swrap_core::atomic::Owner::new(d.swrap_uid, d.admin_gid))?;
    let mut stdin = zeroize::Zeroizing::new(Vec::new());
    for s in env {
        stdin.extend_from_slice(format!("export {}={}\n", s.name, crate::ai::q(&s.value)).as_bytes());
    }
    let env_len = stdin.len();
    stdin.extend_from_slice(script);
    let sudo = if ruser == "root" { "" } else { "sudo -n " };
    let cmd = format!("{sudo}bash -c {} {kind} {env_len} {}", crate::ai::q(RUN_WRAPPER), script.len());
    let signer = swrec::RecSigner::load(&d.paths.recsign().join("ed25519.key"), "core").context("load recording signing key")?;
    let job = RunJob { host: host.clone(), ruser: ruser.to_string() };
    let o = run_host(d, who, &run, &job, &cmd, &stdin, redact, shown, timeout, con, host.label.len(), &signer)?;
    Ok((run.id, o.code, o.result, o.detail))
}

#[allow(clippy::too_many_arguments)]
fn run_host(d: &Arc<Daemon>, who: &str, run: &Run, job: &RunJob, cmd: &str, stdin: &[u8], secrets: &[SecretEnv], shown: &str, timeout: Duration, con: &Console, width: usize, signer: &swrec::RecSigner) -> Result<RunOut> {
    let h = &job.host;
    let (enc, _) = crate::session::credential(d, &h.label, &job.ruser).ok_or_else(|| anyhow!("no credential for {}@{}", job.ruser, h.label))?;
    let profile = Profile::load(&d.paths, &h.profile)?;
    let known = std::fs::read_to_string(d.paths.known_hosts(&h.label)).context("host keys not pinned")?;
    let mut rec = run.host_writer(d, h, &job.ruser, who, shown)?;
    if !secrets.is_empty() {
        rec.note(&format!("secret env: {} (values never recorded)", secrets.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(" ")))?;
    }
    let mut reds = [Redactor::new(secrets), Redactor::new(secrets)];
    let mut lines = Lines::default();
    let mut rec_err: Option<anyhow::Error> = None;
    let label = h.label.clone();
    let mut emit = |fd: u8, clean: &[u8], rec: &mut swrec::Writer, flush: bool| {
        if !clean.is_empty() {
            if let Err(e) = rec.output_fd(fd, clean) {
                rec_err.get_or_insert(e);
            }
        }
        for l in lines.feed(fd, clean, flush) {
            con.out(format!("{label:<width$} | {}{l}", if fd == 2 { "! " } else { "" }));
        }
    };
    let t0 = Instant::now();
    // Output is recorded here, after redaction, not by remote_stream.
    let r = remote_stream(d, who, h, &job.ruser, &enc, &profile, &known, cmd, stdin, None, RemoteOpts { timeout: Some(timeout), cap: 1 << 20 }, &mut |fd, b| {
        let clean = reds[(fd == 2) as usize].push(b);
        emit(fd, &clean, &mut rec, false);
    });
    for fd in [1u8, 2] {
        let rest = reds[(fd == 2) as usize].finish();
        emit(fd, &rest, &mut rec, true);
    }
    let mut counts: std::collections::BTreeMap<String, u64> = Default::default();
    for r in &reds {
        for (k, v) in &r.counts {
            *counts.entry(k.clone()).or_default() += v;
        }
    }
    let redacted: u64 = counts.values().sum();
    if redacted > 0 {
        rec.note(&format!("redacted: {}", counts.iter().map(|(k, v)| format!("{k} ×{v}")).collect::<Vec<_>>().join(", ")))?;
    }
    if let Some(e) = rec_err {
        let _ = rec.end("error", None, Some(signer));
        return Err(e.context("recording"));
    }
    let r = match r {
        Ok(r) => r,
        Err(e) => {
            let _ = rec.end("error", None, Some(signer));
            return Err(e);
        }
    };
    let mut why = Redactor::new(secrets);
    let (result, detail) = if r.timed_out {
        ("timeout".to_string(), format!("stopped after {}", fmt_duration_ms(timeout)))
    } else if r.code == 255 && r.raw_out.is_empty() {
        ("unreachable".to_string(), format!("ssh: {}", why.text(&r.why())))
    } else if r.code == 0 {
        ("ok".to_string(), String::new())
    } else {
        ("failed".to_string(), String::new())
    };
    let o = RunOut { label: h.label.clone(), ruser: job.ruser.clone(), result, code: r.code, duration: fmt_duration_ms(t0.elapsed()), redacted, detail };
    let rc = json!({"exit": o.code, "result": o.result, "duration": o.duration, "redacted": counts, "detail": o.detail});
    swrap_core::atomic::write(&run.dir.join(format!("{}.rc", h.label)), format!("{rc}\n").as_bytes(), 0o640, swrap_core::atomic::Owner::new(d.swrap_uid, d.admin_gid))?;
    rec.end(if r.timed_out { "timeout" } else { "exit" }, Some(r.code), Some(signer))?;
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec(n: &str, v: &str) -> SecretEnv {
        SecretEnv { name: n.into(), value: v.into() }
    }

    #[test]
    fn redaction_survives_any_chunking() {
        let secrets = [sec("TOKEN", "s3cr3t-value"), sec("PW", "hunter22"), sec("SHORT", "abc")];
        let input = b"token=s3cr3t-value pw=hunter22 abc s3cr3t-valu hunter2 end s3cr3t-values";
        for cut in 1..input.len() {
            let mut r = Redactor::new(&secrets);
            let mut out = r.push(&input[..cut]);
            out.extend(r.push(&input[cut..]));
            out.extend(r.finish());
            assert_eq!(
                String::from_utf8(out).unwrap(),
                "token=[REDACTED:TOKEN] pw=[REDACTED:PW] abc s3cr3t-valu hunter2 end [REDACTED:TOKEN]s",
                "cut at {cut}"
            );
            assert_eq!(r.counts.values().sum::<u64>(), 3);
        }
        // byte by byte
        let mut r = Redactor::new(&secrets);
        let mut out = vec![];
        for b in input {
            out.extend(r.push(&[*b]));
        }
        out.extend(r.finish());
        assert!(!String::from_utf8(out).unwrap().contains("s3cr3t-value"));
    }

    #[test]
    fn no_secrets_is_a_pass_through() {
        let mut r = Redactor::new(&[]);
        assert_eq!(r.push(b"abc"), b"abc");
        assert!(r.finish().is_empty());
    }
}
