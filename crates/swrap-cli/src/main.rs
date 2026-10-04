//! `swrap`: multi-call client (sw, swls, swlog, swcat, swplay, swsearch, swpasswd, swunlock,
//! swadm, swadd, swenroll, swdel, swcrypto) and the installer (`swrap-install`).

mod client;
mod install;
mod install_edge;
mod install_selinux;
mod replica;
mod sftp;
mod sw;
mod swai;
mod term;

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::Value;
use std::io::Write;
use swrap_core::api::Req;
use swrap_core::time::{fmt_display, IsoDuration, Interval};

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let argv0 = std::path::Path::new(&args[0]).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let cmd = if argv0 == "swrap" {
        if args.len() < 2 {
            eprintln!("usage: swrap <command> …  (sw, swls, swlog, swcat, swplay, swsearch, swpasswd, swunlock, swadm, swadd, swenroll, swdel, swcrypto, status, install)");
            std::process::exit(2);
        }
        args.remove(0);
        match args[0].as_str() {
            "status" => "swstatus".to_string(),
            "install" => "swrap-install".to_string(),
            "edge" => "swedge".to_string(),
            other => other.to_string(),
        }
    } else {
        argv0
    };
    let rest = args[1..].to_vec();
    let code = match run(&cmd, rest) {
        Ok(c) => c,
        Err(e) => {
            let m = format!("{e:#}");
            eprintln!("{}", if m.starts_with("swrap:") { m } else { format!("swrap: {m}") });
            1
        }
    };
    std::process::exit(code);
}

fn run(cmd: &str, args: Vec<String>) -> Result<i32> {
    match cmd {
        "sw" => sw::main(&args),
        "swai" => swai::main(args),
        "swai-sandbox" => swai::sandbox(args),
        "swai-mcp" => swai::mcp(),
        "swls" => {
            if let Some(a) = args.first() {
                anyhow::bail!("swls takes no arguments (got {a}); it lists the hosts and accounts you may use");
            }
            Ok(client::finish(&client::call(&Req::Ls)?))
        }
        "swlog" => swlog(args),
        "swcat" => swcat(args),
        "swplay" => swplay(args),
        "swupdate" => swupdate(args),
        "swinv" => swinv(args),
        "swr" => swr(args),
        "swx" => swx(args),
        "sftp-dispatch" => sftp::dispatch(),
        "swsearch" => swsearch(args),
        "swpasswd" => {
            let p1 = term::prompt_secret("new web password: ")?;
            let p2 = term::prompt_secret("again: ")?;
            if *p1 != *p2 {
                bail!("passwords differ");
            }
            Ok(client::finish(&client::call(&Req::Passwd { password: p1.to_string() })?))
        }
        "swstatus" => Ok(client::finish(&client::call(&Req::Status)?)),
        "swunlock" => {
            let pw = term::prompt_secret("vault password: ")?;
            admin("swunlock", args, Some(pw.to_string()))
        }
        "swadm" => swadm(args),
        "swadd" | "swdel" | "swcrypto" | "swedge" | "swuser" | "swrotate" => admin(cmd, args, None),
        "swfw" => {
            // --my-ip: the address this SSH session comes from.
            let mut args = args;
            if let Some(i) = args.iter().position(|a| a == "--my-ip") {
                let ip = std::env::var("SSH_CONNECTION").ok().and_then(|c| c.split_whitespace().next().map(String::from)).context("--my-ip needs an SSH session (SSH_CONNECTION unset)")?;
                args[i] = ip;
            }
            admin("swfw", args, None)
        }
        "swenroll" => swenroll(args),
        "swrap-install" => install::main(args),
        "replica" => replica::main(args),
        "claude-code-update" => install::claude_update(args),
        "doctor" => admin("doctor", args, None),
        "table" => {
            // Tokens and the admin password come from stdin (or a no-echo prompt), never from the
            // command line.
            let ask = match args.first().map(String::as_str) {
                Some("token") => Some("form token: "),
                Some("admin-password") => Some("table admin password: "),
                _ => None,
            };
            let stdin = if let Some(ask) = ask {
                Some(if term::isatty(0) {
                    term::prompt_secret(ask)?.to_string()
                } else {
                    let mut s = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
                    s
                })
            } else {
                None
            };
            admin("table", args, stdin)
        }
        other => bail!("unknown command {other}"),
    }
}

fn admin(cmd: &str, args: Vec<String>, stdin: Option<String>) -> Result<i32> {
    let r = client::call(&Req::Admin { cmd: cmd.into(), args, stdin })?;
    Ok(client::finish(&r))
}

fn swadm(args: Vec<String>) -> Result<i32> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let stdin = match a.as_slice() {
        ["vault", "passwd", ..] => {
            let old = term::prompt_secret("current vault password: ")?;
            let n1 = term::prompt_secret("new vault password: ")?;
            let n2 = term::prompt_secret("again: ")?;
            if *n1 != *n2 {
                bail!("passwords differ");
            }
            Some(format!("{}\n{}", *old, *n1))
        }
        ["vault", "add-admin", user, ..] => {
            let n1 = term::prompt_secret(&format!("vault password for {user} (also their SSH password): "))?;
            let n2 = term::prompt_secret("again: ")?;
            if *n1 != *n2 {
                bail!("passwords differ");
            }
            Some(n1.to_string())
        }
        ["vault", "recover", ..] => Some(term::prompt_secret("recovery key: ")?.to_string()),
        _ => None,
    };
    admin("swadm", args, stdin)
}

fn swenroll(mut args: Vec<String>) -> Result<i32> {
    let r = client::call(&Req::Admin { cmd: "swenroll".into(), args: args.clone(), stdin: None })?;
    if r.exit == 3 && term::isatty(0) {
        print!("{}", r.text);
        let ans = term::prompt_line("type the SHA256 fingerprint you verified out of band (or 'no'): ")?;
        if !ans.starts_with("SHA256:") {
            eprintln!("swrap: enrollment cancelled");
            return Ok(1);
        }
        args.push("--fingerprint".into());
        args.push(ans);
        let r = client::call(&Req::Admin { cmd: "swenroll".into(), args, stdin: None })?;
        return Ok(client::finish(&r));
    }
    Ok(client::finish(&r))
}

// ---------------------------------------------------------------- records

fn tz() -> String {
    swrap_core::config::SwrapConfig::load(&swrap_core::Paths::from_env()).map(|c| c.general.display_timezone).unwrap_or_else(|_| "UTC".into())
}

#[derive(Parser)]
#[command(name = "swlog", about = "List records (ISO 8601 windows only)")]
struct SwlogArgs {
    /// ISO 8601 interval, e.g. P1D/now or 2026-09-01T00:00Z/PT6H
    #[arg(long)]
    window: Option<String>,
    /// ISO 8601 duration back from now, e.g. P7D
    #[arg(long)]
    since: Option<String>,
    #[arg(long)]
    kind: Option<String>,
    #[arg(long)]
    all: bool,
}

fn swlog(args: Vec<String>) -> Result<i32> {
    let a = SwlogArgs::try_parse_from(std::iter::once("swlog".to_string()).chain(args)).unwrap_or_else(|e| e.exit());
    let window = match (a.window, a.since) {
        (Some(_), Some(_)) => bail!("use either --window or --since"),
        (Some(w), None) => {
            Interval::parse(&w)?;
            w
        }
        (None, Some(s)) => {
            IsoDuration::parse(&s)?;
            format!("{s}/now")
        }
        (None, None) => "P1D/now".into(),
    };
    Ok(client::finish(&client::call(&Req::Log { window, kind: a.kind, all: a.all })?))
}

fn find(id: &str) -> Result<(std::path::PathBuf, bool)> {
    if swrap_core::paths::is_edge() {
        // Records live on core: fetch into a private temp file.
        let mut data = vec![];
        let r = client::call_frames(&Req::Fetch { id: id.into() }, |f| data.extend_from_slice(&f.payload))?;
        if !r.ok {
            bail!("{}", r.error.unwrap_or_default());
        }
        let name = r.data["name"].as_str().unwrap_or("record.swrec").to_string();
        let dir = std::env::temp_dir().join(format!("swrap-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let p = dir.join(name);
        std::fs::write(&p, data)?;
        return Ok((p, r.data["live"].as_bool().unwrap_or(false)));
    }
    let r = client::call(&Req::Find { id: id.into() })?;
    if !r.ok {
        bail!("{}", r.error.unwrap_or_default());
    }
    Ok((r.data["path"].as_str().context("path")?.into(), r.data["live"].as_bool().unwrap_or(false)))
}

#[derive(Parser)]
#[command(name = "swcat", about = "Plain-text dump of a record with ISO timestamps")]
struct SwcatArgs {
    id: String,
    #[arg(long)]
    keys: bool,
    #[arg(long)]
    cmds: bool,
    #[arg(long)]
    utc: bool,
    #[arg(long)]
    raw: bool,
    /// Also print the verification report.
    #[arg(long)]
    verify: bool,
}

fn swcat(args: Vec<String>) -> Result<i32> {
    let a = SwcatArgs::try_parse_from(std::iter::once("swcat".to_string()).chain(args)).unwrap_or_else(|e| e.exit());
    let (path, live) = find(&a.id)?;
    let v = swrec::RecVerifier::for_core(&swrap_core::Paths::from_env());
    let s = swrec::scan(&path, swrec::ScanOpts { verifier: Some(&v), keep_records: true, live })?;
    let tz = tz();
    let o = swrec::text::CatOpts { tz: &tz, utc: a.utc, keys: a.keys, cmds: a.cmds, raw: a.raw };
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    swrec::text::cat(s.header.as_ref(), &s.records, &o, &mut lock)?;
    if a.verify {
        writeln!(lock, "# verify: {} {}", s.report.status.as_str(), serde_json::to_string(&s.report)?)?;
    }
    Ok(0)
}

#[derive(Parser)]
#[command(
    name = "swupdate",
    about = "dnf -y upgrade --refresh on the hosts where you can act as root, recorded as a run",
    after_help = "Targets: a label, a wildcard ('web*'), @tag, @all, comma-separated lists, !label to exclude.\nOnly hosts where you can act as root count; quote wildcards so the shell leaves them alone.\nHosts without dnf are reported and skipped. dnf runs detached on each host, so a dropped\nconnection never stops it half way."
)]
struct SwupdateArgs {
    /// Hosts: label, 'web*', @tag, @all, lists, !exclusions
    targets: Vec<String>,
    /// Upgrade only this package; hosts without it are skipped (it is never installed)
    #[arg(long)]
    app: Option<String>,
}

fn swupdate(args: Vec<String>) -> Result<i32> {
    let a = SwupdateArgs::try_parse_from(std::iter::once("swupdate".to_string()).chain(args)).unwrap_or_else(|e| e.exit());
    let targets = match a.targets.as_slice() {
        [] => bail!("usage: swupdate <targets> [--app <pkg>]"),
        [t] => t.clone(),
        many => bail!(
            "one targets expression please (got {}): lists are comma-separated, and wildcards need quotes so the shell does not expand them against file names, e.g. swupdate 'web*'",
            many.join(" ")
        ),
    };
    if targets.contains('/') || (!targets.contains(['*', '?', '@', ',']) && std::path::Path::new(&targets).exists() && targets.contains('.')) {
        eprintln!("swrap: note: {targets:?} is also a file here; if you typed a wildcard, quote it");
    }
    let r = client::call(&Req::Update { targets, app: a.app })?;
    Ok(client::finish(&r))
}

const TARGETS_HELP: &str = "Targets: a label, a wildcard ('web*'), @tag, @all, comma-separated lists, !label to exclude.\nQuote wildcards so the shell leaves them alone.";

#[derive(Parser)]
#[command(name = "swinv", about = "Refresh the inventory of hosts you may use (recorded; kept in state/)", after_help = TARGETS_HELP)]
struct SwinvArgs {
    /// Hosts (default: all you may use)
    targets: Vec<String>,
}

fn one_target(v: &[String], cmd: &str) -> Result<String> {
    match v {
        [] => Ok(String::new()),
        [t] => Ok(t.clone()),
        many => bail!("one targets expression please (got {}): lists are comma-separated, and wildcards need quotes, e.g. {cmd} 'web*'", many.join(" ")),
    }
}

fn swinv(args: Vec<String>) -> Result<i32> {
    let a = SwinvArgs::try_parse_from(std::iter::once("swinv".to_string()).chain(args)).unwrap_or_else(|e| e.exit());
    let targets = one_target(&a.targets, "swinv")?;
    let r = client::call(&Req::Inventory { targets })?;
    Ok(client::finish(&r))
}

/// `--secret-env NAME`: the value comes from this shell's environment (in the AAA shell:
/// `read -rs NAME; export NAME`), travels to core in memory only, and is redacted from output.
fn secret_env(names: &[String]) -> Result<Vec<swrap_core::api::SecretEnv>> {
    names
        .iter()
        .map(|n| match std::env::var(n) {
            Ok(v) if !v.is_empty() => Ok(swrap_core::api::SecretEnv { name: n.clone(), value: v }),
            _ => bail!("--secret-env {n}: {n} is not set; in the AAA shell: read -rs {n}; export {n}"),
        })
        .collect()
}

#[derive(Parser)]
#[command(name = "swr", about = "Run a script on hosts, 8 at a time, recorded as a run", after_help = TARGETS_HELP)]
struct SwrArgs {
    /// The script (its own interpreter line, else bash)
    script: std::path::PathBuf,
    /// Hosts
    targets: String,
    /// Account on the hosts (default: your most privileged one per host)
    #[arg(short = 'u')]
    ruser: Option<String>,
    /// Pass this environment variable to the script without recording it (repeatable)
    #[arg(long = "secret-env", value_name = "NAME")]
    secret_env: Vec<String>,
    /// Arguments for the script
    #[arg(last = true)]
    args: Vec<String>,
}

fn swr(args: Vec<String>) -> Result<i32> {
    use base64::Engine;
    let a = SwrArgs::try_parse_from(std::iter::once("swr".to_string()).chain(args)).unwrap_or_else(|e| e.exit());
    let script = std::fs::read(&a.script).with_context(|| format!("read {}", a.script.display()))?;
    let name = a.script.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "script".into());
    let r = client::call(&Req::Run {
        targets: a.targets,
        ruser: a.ruser,
        script_name: name,
        script_b64: base64::engine::general_purpose::STANDARD.encode(script),
        args: a.args,
        secrets: secret_env(&a.secret_env)?,
    })?;
    Ok(client::finish(&r))
}

#[derive(Parser)]
#[command(name = "swx", about = "Run a command on hosts, 8 at a time, recorded as a run", after_help = TARGETS_HELP)]
struct SwxArgs {
    /// Hosts
    targets: String,
    /// Account on the hosts (default: your most privileged one per host)
    #[arg(short = 'u')]
    ruser: Option<String>,
    /// Pass this environment variable to the command without recording it (repeatable)
    #[arg(long = "secret-env", value_name = "NAME")]
    secret_env: Vec<String>,
    /// The command (after --), run by bash on each host
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn swx(args: Vec<String>) -> Result<i32> {
    use base64::Engine;
    let a = SwxArgs::try_parse_from(std::iter::once("swx".to_string()).chain(args)).unwrap_or_else(|e| e.exit());
    let cmd = a.command.join(" ") + "\n";
    let r = client::call(&Req::Run {
        targets: a.targets,
        ruser: a.ruser,
        script_name: String::new(),
        script_b64: base64::engine::general_purpose::STANDARD.encode(cmd),
        args: vec![],
        secrets: secret_env(&a.secret_env)?,
    })?;
    Ok(client::finish(&r))
}

#[derive(Parser)]
#[command(name = "swplay", about = "Replay a recording in the terminal")]
struct SwplayArgs {
    id: String,
    #[arg(long, default_value_t = 1.0)]
    speed: f64,
    /// Start offset as an ISO 8601 duration, e.g. PT5M
    #[arg(long)]
    from: Option<String>,
    /// Idle cap as an ISO 8601 duration (default PT2S)
    #[arg(long, default_value = "PT2S")]
    idle: String,
}

fn swplay(args: Vec<String>) -> Result<i32> {
    let a = SwplayArgs::try_parse_from(std::iter::once("swplay".to_string()).chain(args)).unwrap_or_else(|e| e.exit());
    let from = match &a.from {
        Some(f) => IsoDuration::parse(f)?.exact().context("--from must not use calendar units")?.as_secs_f64(),
        None => 0.0,
    };
    let idle = IsoDuration::parse(&a.idle)?.exact().context("bad --idle")?.as_secs_f64();
    let (path, live) = find(&a.id)?;
    let s = swrec::scan(&path, swrec::ScanOpts { verifier: None, keep_records: true, live })?;
    let Some(h) = &s.header else { bail!("record has no readable header") };
    let tz = tz();
    let start = h.get("start").and_then(Value::as_str).and_then(|t| t.parse::<jiff::Timestamp>().ok());
    eprintln!("swrap: replay {} started {} (speed {}×, idle cap {})", a.id, start.map(|t| fmt_display(t, &tz, false)).unwrap_or_default(), a.speed, a.idle);
    let mut out = std::io::stdout();
    let mut last: Option<f64> = None;
    let mut t_play = 0.0;
    // Every `o` record (tool output included), and the output events repeats (`p`) stand for.
    let mut expander = swrec::repeat::Expander::default();
    for m in &s.records {
        let events: Vec<(i64, Vec<u8>)> = match m.get("k").and_then(Value::as_str) {
            Some("p") => expander.feed(m).unwrap_or_default().into_iter().map(|(us, d)| (us, d.as_bytes().to_vec())).collect(),
            Some("o") => {
                let _ = expander.feed(m);
                let Some(ts) = m.get("ts").and_then(Value::as_str).and_then(|t| t.parse::<jiff::Timestamp>().ok()) else { continue };
                vec![(ts.as_microsecond(), swrec::render::rec_bytes(m))]
            }
            _ => continue,
        };
        for (us, bytes) in events {
            let real = us as f64 / 1e6;
            let gap = last.map(|l| (real - l).clamp(0.0, idle)).unwrap_or(0.0);
            last = Some(real);
            t_play += gap;
            if t_play >= from && gap > 0.0 {
                std::thread::sleep(std::time::Duration::from_secs_f64(gap / a.speed.max(0.01)));
            }
            out.write_all(&bytes)?;
            out.flush()?;
        }
    }
    eprintln!("\r\nswrap: replay finished ({})", s.report.status.as_str());
    Ok(0)
}

fn swsearch(args: Vec<String>) -> Result<i32> {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        println!("usage: swsearch <query>\n  e.g. swsearch 'window:P7D/now host:web* cmd:/dnf .*install/ out:\"permission denied\" -ruser:deploy'");
        return Ok(0);
    }
    let q = args.join(" ");
    swrec::search::Query::parse(&q)?;
    let r = client::call(&Req::Search { query: q })?;
    if let Some(e) = &r.error {
        bail!("{e}");
    }
    eprintln!("{}", r.text);
    Ok(0)
}
