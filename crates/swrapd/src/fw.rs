//! Firewall model and CLI (spec 13). Core side: `config/firewall.toml` + the `inet swrap`
//! nftables table, which only ever refuses traffic (accepting is left to firewalld). swrap never touches any
//! other table. Edge enforcement arrives with the edge node (via the signed snapshot).

use crate::daemon::{Caller, Daemon};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use swrap_core::api::Resp;
use swrap_core::config::{Firewall, FwEntry, SwrapConfig};
use swrap_core::time::{fmt_utc_secs, now, parse_datetime, IsoDuration};

#[derive(Parser, Debug)]
#[command(name = "swfw", about = "swrap firewall: web allow-list and SSH blocks (executed on core)")]
struct Swfw {
    #[command(subcommand)]
    cmd: FwCmd,
}

#[derive(Subcommand, Debug)]
enum FwCmd {
    /// Web GUI allow-list.
    Web {
        #[command(subcommand)]
        cmd: WebCmd,
    },
    /// SSH blocks (enforced on edge).
    Ssh {
        #[command(subcommand)]
        cmd: SshCmd,
    },
    List,
    Status,
}

#[derive(Subcommand, Debug)]
enum WebCmd {
    /// Allow <ip|cidr|lan>; `--my-ip` is resolved by the client from SSH_CONNECTION.
    Allow {
        what: String,
        #[arg(long = "for")]
        for_: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value = "")]
        comment: String,
    },
    Revoke { id: String },
}

#[derive(Subcommand, Debug)]
enum SshCmd {
    Block {
        cidr: String,
        #[arg(long = "for")]
        for_: Option<String>,
        #[arg(long, default_value = "")]
        comment: String,
    },
    Unblock { id: String },
}

fn norm_cidr(s: &str) -> Result<String> {
    if let Ok(n) = s.parse::<ipnet::IpNet>() {
        return Ok(n.trunc().to_string());
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(ipnet::IpNet::from(ip).to_string());
    }
    bail!("not an IP address or CIDR: {s:?}")
}

fn until_of(for_: Option<String>, until: Option<String>) -> Result<Option<String>> {
    Ok(match (for_, until) {
        (Some(_), Some(_)) => bail!("use either --for or --until"),
        (Some(f), None) => Some(fmt_utc_secs(IsoDuration::parse(&f)?.after(now()))),
        (None, Some(u)) => Some(fmt_utc_secs(parse_datetime(&u)?)),
        _ => None,
    })
}

fn save(d: &Daemon, fw: &Firewall, msg: &str) -> Result<()> {
    d.write_config("firewall.toml", &toml::to_string_pretty(fw)?)?;
    d.commit(msg)?;
    apply(d)
}

pub fn run(d: &Arc<Daemon>, c: &Caller, argv: &[String]) -> Result<Resp> {
    let a = Swfw::try_parse_from(argv)?;
    c.require_admin()?;
    let _g = d.config_lock.lock().unwrap();
    let mut fw = Firewall::load(&d.paths)?;
    let tz = d.tz();
    match a.cmd {
        FwCmd::Web { cmd: WebCmd::Allow { what, for_, until, comment } } => {
            let cidrs = if what == "lan" { d.cfg().network.lan_cidrs } else { vec![norm_cidr(&what)?] };
            if cidrs.is_empty() {
                bail!("network.lan_cidrs is empty");
            }
            let na = until_of(for_, until)?;
            let mut ids = vec![];
            for cidr in cidrs {
                let e = FwEntry {
                    id: swrap_core::new_id(),
                    cidr: norm_cidr(&cidr)?,
                    not_before: Some(fmt_utc_secs(now())),
                    not_after: na.clone(),
                    comment: comment.clone(),
                    created_by: c.name.clone(),
                    created: fmt_utc_secs(now()),
                };
                ids.push(format!("{} {}", e.id, e.cidr));
                fw.web_allow.push(e);
            }
            save(d, &fw, &format!("swfw web allow {what} by {}", c.name))?;
            d.audit_event(&c.name, "fw.web.allow", &what, "", "ok", json!({"ids": ids, "not_after": na}), "");
            Ok(Resp::text(format!("allowed: {}\n", ids.join(", "))))
        }
        FwCmd::Web { cmd: WebCmd::Revoke { id } } => {
            let n = fw.web_allow.len();
            fw.web_allow.retain(|e| e.id != id);
            if n == fw.web_allow.len() {
                bail!("no web allow entry {id}");
            }
            save(d, &fw, &format!("swfw web revoke {id} by {}", c.name))?;
            d.audit_event(&c.name, "fw.web.revoke", &id, "", "ok", json!({}), "");
            Ok(Resp::text("revoked\n"))
        }
        FwCmd::Ssh { cmd: SshCmd::Block { cidr, for_, comment } } => {
            let e = FwEntry { id: swrap_core::new_id(), cidr: norm_cidr(&cidr)?, not_before: None, not_after: until_of(for_, None)?, comment, created_by: c.name.clone(), created: fmt_utc_secs(now()) };
            let id = e.id.clone();
            fw.ssh_block.push(e);
            save(d, &fw, &format!("swfw ssh block {cidr} by {}", c.name))?;
            d.audit_event(&c.name, "fw.ssh.block", &cidr, "", "ok", json!({"id": id}), "");
            Ok(Resp::text(format!("blocked {cidr} ({id}); enforced on edge once it exists\n")))
        }
        FwCmd::Ssh { cmd: SshCmd::Unblock { id } } => {
            let n = fw.ssh_block.len();
            fw.ssh_block.retain(|e| e.id != id);
            if n == fw.ssh_block.len() {
                bail!("no ssh block {id}");
            }
            save(d, &fw, &format!("swfw ssh unblock {id} by {}", c.name))?;
            Ok(Resp::text("unblocked\n"))
        }
        FwCmd::List => {
            let f = |t: &Option<String>| t.as_deref().and_then(|s| parse_datetime(s).ok()).map(|t| swrap_core::time::fmt_display(t, &tz, false)).unwrap_or_else(|| "-".into());
            let mut t = String::from("WEB ALLOW\n");
            for e in &fw.web_allow {
                t += &format!("  {}  {:<20} from {}  until {}  {}\n", e.id, e.cidr, f(&e.not_before), f(&e.not_after), e.comment);
            }
            t += "SSH BLOCK\n";
            for e in &fw.ssh_block {
                t += &format!("  {}  {:<20} until {}  {}\n", e.id, e.cidr, f(&e.not_after), e.comment);
            }
            Ok(Resp::text(t))
        }
        FwCmd::Status => {
            let o = Command::new("nft").args(["list", "table", "inet", "swrap"]).output()?;
            Ok(Resp::text(format!("config rev {}\n{}", d.config_rev(), String::from_utf8_lossy(&o.stdout))))
        }
    }
}

/// Render and atomically load the `inet swrap` table. Core is LAN-only, so non-allow-listed
/// clients get an immediate TCP reset instead of a silent drop (a drop looks like a hang).
pub fn render(fw: &Firewall, cfg: &SwrapConfig) -> String {
    let t = now();
    let mut v4 = vec![];
    let mut v6 = vec![];
    for e in &fw.web_allow {
        let nb = e.not_before.as_deref().and_then(|s| parse_datetime(s).ok());
        let na = e.not_after.as_deref().and_then(|s| parse_datetime(s).ok());
        if nb.map(|x| t < x).unwrap_or(false) || na.map(|x| t >= x).unwrap_or(false) {
            continue;
        }
        let Ok(n) = e.cidr.parse::<ipnet::IpNet>() else { continue };
        let timeout = na.map(|x| format!(" timeout {}s", (x.as_second() - t.as_second()).max(1))).unwrap_or_default();
        match n {
            ipnet::IpNet::V4(_) => v4.push(format!("{n}{timeout}")),
            ipnet::IpNet::V6(_) => v6.push(format!("{n}{timeout}")),
        }
    }
    let ports: Vec<String> = cfg.web.bind.iter().filter_map(|b| b.rsplit_once(':').map(|x| x.1.to_string())).filter(|p| p.parse::<u16>().is_ok()).collect();
    let ports = if ports.is_empty() { "443".to_string() } else { ports.join(", ") };
    let el = |v: &Vec<String>| if v.is_empty() { String::new() } else { format!("elements = {{ {} }}", v.join(", ")) };
    format!(
        "table inet swrap {{}}\ndelete table inet swrap\ntable inet swrap {{\n  set web4 {{ type ipv4_addr; flags interval, timeout; {} }}\n  set web6 {{ type ipv6_addr; flags interval, timeout; {} }}\n  chain input {{\n    type filter hook input priority -5; policy accept;\n    iif \"lo\" accept\n    tcp dport {{ {ports} }} ip saddr != @web4 reject with tcp reset\n    tcp dport {{ {ports} }} ip6 saddr != @web6 reject with tcp reset\n  }}\n}}\n",
        el(&v4),
        el(&v6)
    )
}

pub fn apply(d: &Daemon) -> Result<()> {
    let fw = Firewall::load(&d.paths)?;
    let rules = render(&fw, &d.cfg());
    let mut c = Command::new("nft").arg("-f").arg("-").stdin(Stdio::piped()).stderr(Stdio::piped()).spawn().context("nft")?;
    c.stdin.take().unwrap().write_all(rules.as_bytes())?;
    let o = c.wait_with_output()?;
    if !o.status.success() {
        bail!("nft: {}", String::from_utf8_lossy(&o.stderr));
    }
    Ok(())
}
