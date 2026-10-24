//! `swreload` (spec 10.11): reload systemd services so they run the code installed now, without
//! a restart. nginx: `nginx -t`, then a binary upgrade (`nginx-upgrade`: a new master from the
//! new binary, the old one finishes its connections) when it runs replaced code, else
//! `systemctl reload`. sshd: `sshd -t`, then its reload, by which sshd executes itself anew
//! (started again should the listener be gone, so the host stays reachable). Any other service:
//! `systemctl reload`, never a restart. Internet hosts get this by themselves after an inventory
//! (`autofix`, see `table::TableCfg::internet_reload`).

use crate::daemon::{Caller, Console, Daemon};
use crate::inventory::{Fix, Target};
use anyhow::{anyhow, bail, Result};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use swrap_core::api::Resp;
use swrap_core::config::Host;
use swrap_core::rbac;
use swrap_core::time::now;

const RELOAD_TIMEOUT: Duration = Duration::from_secs(600);
/// dnf with fresh metadata first; it runs detached on the host, so a timeout only stops waiting.
const AUTOFIX_TIMEOUT: Duration = Duration::from_secs(1800);

/// Runs as root on the host; the caller appends `main <always|stale> '<packages>' <service>…`.
/// `stale`: only services that still run replaced code (a binary or library replaced since
/// they started, as the inventory's `listen` section sees it) are reloaded. Exit 1 when any
/// step failed.
const RELOAD_SCRIPT: &str = r#"set -u
export LC_ALL=C
old_code() {
  local p=${1:-0}
  [ "$p" != 0 ] && [ -d "/proc/$p" ] || return 1
  case $(readlink "/proc/$p/exe" 2>/dev/null) in *" (deleted)") return 0 ;; esac
  awk '$6 ~ /^\// && $6 ~ /\.so/ && $6 !~ /^\/(dev|memfd:)/ && $7 == "(deleted)" {f = 1} END {exit !f}' "/proc/$p/maps" 2>/dev/null
}
unit_of() {
  local u
  for u in "${1%.service}.service" $(case ${1%.service} in sshd) echo ssh.service ;; ssh) echo sshd.service ;; esac); do
    [ "$(systemctl show -p LoadState --value "$u" 2>/dev/null)" = loaded ] && { echo "$u"; return 0; }
  done
  return 1
}
main_pid() { systemctl show -p MainPID --value "$1" 2>/dev/null; }
upgrade() {
  # Detached from this SSH session: a dropped link must never stop it in the middle of a transaction.
  local log rc pid
  log=/var/tmp/swreload-$(date -u +%Y%m%dT%H%M%SZ).log
  : >"$log"
  if command -v dnf >/dev/null 2>&1; then set -- dnf -y upgrade --refresh "$@"
  elif command -v apt-get >/dev/null 2>&1; then apt-get -qq update >/dev/null 2>&1; set -- env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confold install --only-upgrade "$@"
  else echo "no dnf or apt-get here"; return 1; fi
  echo "== $*"
  setsid -w sh -c 'trap "" HUP PIPE; exec "$@" >>"$0" 2>&1 </dev/null' "$log" "$@" &
  pid=$!
  tail -n +1 --pid=$pid -f "$log" 2>/dev/null
  wait $pid; rc=$?
  if [ $rc = 0 ]; then rm -f "$log"; else echo "the upgrade failed (exit $rc); its log stays: $log"; fi
  return $rc
}
reload_one() {
  local mode=$1 svc=$2 u pid before how r new t note=""
  u=$(unit_of "$svc") || { echo "$svc: no such service here, skipped"; return 0; }
  [ "$(systemctl is-active "$u")" = active ] || { echo "$u: not running, left alone"; return 0; }
  pid=$(main_pid "$u"); before=no; old_code "$pid" && before=yes
  if [ "$mode" = stale ] && [ $before = no ]; then echo "$u: runs the installed code already (pid $pid)"; return 0; fi
  case $u in
    nginx.service)
      t=$(nginx -t 2>&1) || { echo "$t"; echo "$u: FAILED: nginx -t fails, nothing reloaded"; return 1; }
      if [ $before = yes ]; then
        [ -x /usr/bin/nginx-upgrade ] || { echo "$u: FAILED: it runs replaced code, and this host has no nginx-upgrade to start the new binary without a restart"; return 1; }
        how="binary upgrade"; /usr/bin/nginx-upgrade; r=$?
        new=$(cat /run/nginx.pid 2>/dev/null)
        # nginx-upgrade gives up waiting after 15 s while the old master still finishes long connections
        [ $r != 0 ] && [ -n "$new" ] && [ "$new" != "$pid" ] && ! old_code "$new" && r=0
        [ -f /run/nginx.pid.oldbin ] && note="; the old master (pid $(cat /run/nginx.pid.oldbin)) still finishes its open connections"
      else
        how="reload"; systemctl reload "$u"; r=$?; sleep 1; new=$(main_pid "$u")
      fi ;;
    sshd.service|ssh.service)
      t=$("$(command -v sshd || echo /usr/sbin/sshd)" -t 2>&1) || { echo "$t"; echo "$u: FAILED: sshd -t fails, nothing reloaded"; return 1; }
      how="reload"; systemctl reload "$u"; r=$?
      sleep 2
      if [ "$(systemctl is-active "$u")" != active ]; then
        echo "$u: not running after the reload: starting it again so the host stays reachable"
        systemctl restart "$u"; r=$?; how="reload, then a restart"; sleep 1
      fi
      new=$(main_pid "$u") ;;
    *)
      [ "$(systemctl show -p CanReload --value "$u")" = yes ] || { echo "$u: FAILED: it has no reload; a restart would load the new code"; return 1; }
      how="reload"; systemctl reload "$u"; r=$?; sleep 1; new=$(main_pid "$u") ;;
  esac
  if [ "$(systemctl is-active "$u")" != active ]; then echo "$u: FAILED: not running after the $how"; return 1; fi
  if [ $r != 0 ]; then echo "$u: FAILED: the $how exited $r"; return 1; fi
  if old_code "$new"; then echo "$u: FAILED: $how done, but it still runs replaced code (pid $new); only a restart loads it"; return 1; fi
  echo "$u: ok, $how; it runs the installed code (pid $pid -> $new)$note"
}
main() {
  local mode=$1 pkgs=$2 s fail=0
  shift 2
  if [ -n "$pkgs" ]; then
    # shellcheck disable=SC2086 # one word per package
    upgrade $pkgs || exit 1
  fi
  for s in "$@"; do reload_one "$mode" "$s" || fail=1; done
  exit $fail
}
"#;

fn valid_service(s: &str) -> bool {
    !s.is_empty() && s.len() <= 100 && !s.starts_with('-') && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"@._:-".contains(&b))
}

fn script(mode: &str, packages: &[String], services: &[String]) -> String {
    format!("{RELOAD_SCRIPT}main {mode} {} {}\n", crate::ai::q(&packages.join(" ")), services.iter().map(|s| crate::ai::q(s)).collect::<Vec<_>>().join(" "))
}

/// `swreload <targets> <service>…`: on the hosts where the caller can act as root, recorded as
/// a run; the hosts that reloaded are inventoried again (their services and conditions).
pub fn reload(d: &Arc<Daemon>, c: &Caller, targets: &str, services: &[String], con: &Console) -> Result<Resp> {
    let user = c.aaa()?.clone();
    if d.is_sealed() {
        bail!("the swrap vault is sealed; fleet jobs are unavailable until an admin logs in");
    }
    if services.is_empty() || services.len() > 16 {
        bail!("name 1 to 16 services, e.g. swreload web1 nginx");
    }
    if let Some(s) = services.iter().find(|s| !valid_service(s)) {
        bail!("{s:?} is not a service name (letters, digits and @._:-)");
    }
    let t = now();
    let all = Host::all(&d.paths)?;
    let root_ok = |h: &Host| rbac::root_capable_account(&user, h, c.origin, t).is_some();
    let picked = rbac::expand(targets, &all, root_ok).map_err(|e| match e.to_string() {
        m if m.starts_with("no grant for host") => anyhow!("{m}: swreload needs root there (or swrap-managed sudo)"),
        m => anyhow!(m),
    })?;
    if picked.is_empty() {
        bail!("no host in {targets:?} where you can act as root");
    }
    let jobs: Vec<(Host, String, bool)> = picked
        .iter()
        .map(|h| {
            let (ruser, sudo) = rbac::root_capable_account(&user, h, c.origin, t).expect("filtered above");
            ((*h).clone(), ruser, sudo)
        })
        .collect();
    let again: Vec<Target> = jobs.iter().map(|(host, ruser, _)| Target { host: host.clone(), ruser: ruser.clone() }).collect();
    let shown = format!("swreload {}", services.join(" "));
    let mut r = crate::fleet::root_run(d, &c.name, "swreload", "fleet.reload", targets, jobs, &shown, script("always", &[], services).as_bytes(), RELOAD_TIMEOUT, json!({"services": services, "origin": c.origin.as_str()}), con)?;
    let ok: Vec<String> = r.data["hosts"].as_array().into_iter().flatten().filter(|h| h["result"] == "ok").filter_map(|h| h["label"].as_str().map(String::from)).collect();
    let again: Vec<Target> = again.into_iter().filter(|t| ok.contains(&t.host.label)).collect();
    if !again.is_empty() {
        match crate::inventory::collect(d, &c.name, targets, again, None) {
            Ok(i) => r.text += &format!("inventory refreshed ({})\n", i.data["run"].as_str().unwrap_or("")),
            Err(e) => r.text += &format!("inventory refresh failed: {e:#}\n"),
        }
    }
    Ok(r)
}

/// On internet host `h`, as swrap: install `fix.packages`, then reload those of `fix.services`
/// that still run replaced code. Recorded as an `autofix` run. Returns (run, result).
pub fn autofix(d: &Arc<Daemon>, h: &Host, fix: &Fix) -> Result<(String, String)> {
    let ruser = crate::inventory::system_account(d, h).ok_or_else(|| anyhow!("no account with a credential on {}", h.label))?;
    // Names from the host's own inventory: never let one through as an option or more words.
    if let Some(p) = fix.packages.iter().chain(&fix.services).find(|p| !crate::fleet::valid_pkg(p)) {
        bail!("not fixing {}: {p:?} is not a package or service name", h.label);
    }
    let packages: Vec<String> = fix.packages.iter().cloned().collect();
    let services: Vec<String> = fix.services.iter().cloned().collect();
    let shown = if packages.is_empty() { format!("swreload {}", services.join(" ")) } else { format!("swreload {} after installing {}", services.join(" "), packages.join(" ")) };
    let (run, code, result, detail) = crate::fleet::system_job(d, "swrap", "autofix", h, &ruser, &shown, script("stale", &packages, &services).as_bytes(), &[], &[], AUTOFIX_TIMEOUT, &Console::null())?;
    d.audit_event("swrap", "table.autofix", &h.label, &ruser, if result == "ok" { "ok" } else { "failed" }, json!({"run": run, "packages": packages, "services": services, "exit": code, "detail": detail}), &run);
    Ok((run, if result == "ok" { "ok".into() } else { format!("{result}, exit {code}{}", if detail.is_empty() { String::new() } else { format!(": {detail}") }) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_names() {
        for s in ["nginx", "sshd.service", "getty@tty1", "systemd-resolved"] {
            assert!(valid_service(s), "{s}");
        }
        for s in ["", "-x", "a b", "a;b", "$(x)", "a/b"] {
            assert!(!valid_service(s), "{s}");
        }
    }

    #[test]
    fn the_script_ends_with_its_call() {
        let s = script("stale", &["nginx-core".into(), "openssl-libs".into()], &["nginx".into(), "sshd".into()]);
        assert!(s.ends_with("main stale 'nginx-core openssl-libs' 'nginx' 'sshd'\n"), "{}", &s[s.len() - 80..]);
        assert!(script("always", &[], &["nginx".into()]).ends_with("main always '' 'nginx'\n"));
    }
}
