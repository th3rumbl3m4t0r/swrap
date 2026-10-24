//! Inventory (spec 10.7): `swinv [targets]` and a PT6H run over every host. One SSH call per
//! host runs a read-only collector; its output lands in `state/` (a git repository), committed
//! as `inventory <ISO> <ulid>`. Changes that need attention raise alerts (monitoring).

use crate::daemon::{Caller, Console, Daemon};
use crate::hosts::{remote_stream, RemoteOpts, Run};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use swrap_core::api::Resp;
use swrap_core::atomic::{self, Owner};
use swrap_core::config::{Host, HostState, Profile, Route};
use swrap_core::rbac;
use swrap_core::time::{fmt_duration_ms, fmt_utc, fmt_utc_secs, now};

/// Per-host limit (spec 10.7). The collector bounds its own slow steps below this.
const HOST_TIMEOUT: Duration = Duration::from_secs(120);
/// Scheduled run interval.
const EVERY: Duration = Duration::from_secs(6 * 3600);

/// Read-only. Sections start with `@@SWINV <name>`. dnf4, dnf5 and apt are understood.
const COLLECTOR: &str = r#"export LC_ALL=C
S=""; [ "$(id -u)" = 0 ] || S="sudo -n"
sec() { printf '\n@@SWINV %s\n' "$1"; }
PM=none
if command -v dnf >/dev/null 2>&1; then
  if dnf --version 2>/dev/null | head -1 | grep -qE '^dnf5|^5\.'; then PM=dnf5; else PM=dnf4; fi
elif command -v dpkg-query >/dev/null 2>&1; then PM=apt; fi
sec facts
echo "user=$(id -un)"
echo "hostname=$(hostname 2>/dev/null)"
echo "kernel=$(uname -r)"
echo "arch=$(uname -m)"
echo "uptime_s=$(cut -d. -f1 /proc/uptime)"
echo "selinux=$(getenforce 2>/dev/null || echo none)"
echo "ssh_server=$( (sshd -V 2>&1 || /usr/sbin/sshd -V 2>&1) | grep -m1 -o 'OpenSSH[^ ,]*')"
echo "package_manager=$PM"
v=$(systemd-detect-virt 2>/dev/null); echo "virt=${v:-none}"
case $PM in
  dnf*) for p in basesystem filesystem setup; do t=$(rpm -q --qf '%{INSTALLTIME}\n' $p 2>/dev/null | head -1); case $t in ''|*[!0-9]*) t= ;; *) break ;; esac; done; echo "installed=$t" ;;
  apt) echo "installed=$(stat -c %W /var/lib/dpkg 2>/dev/null)" ;;
esac
if [ -x /usr/local/sbin/endpoint-agent.py ]; then
  echo "endpoint_agent=$(/usr/local/sbin/endpoint-agent.py --version 2>/dev/null || echo unknown) $(systemctl is-enabled endpoint-agent.timer 2>/dev/null || echo no-timer)"
  echo "endpoint_agent_table=$(sed -n 's/^TABLE_ENDPOINT=//p' /etc/endpoint-agent/env 2>/dev/null | head -1)"
else echo "endpoint_agent=none"; fi
sec ips
ip -o addr show scope global 2>/dev/null | awk '$2 !~ /^(lo|podman|cni|docker|virbr|veth|br-|flannel|cali|cilium|kube|lxc)/ && $0 !~ /temporary|deprecated/ {split($4, a, "/"); print $3"\t"a[1]}'
sec os-release
cat /etc/os-release 2>/dev/null
sec packages
case $PM in
  dnf*) rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null | sort ;;
  apt) dpkg-query -W -f '${Package}\t${Version}\t${Architecture}\n' 2>/dev/null | sort ;;
esac
sec updates
case $PM in
  dnf4) timeout 75 dnf -q ${SWINV_REFRESH:+--refresh} repoquery --upgrades --latest-limit 1 --qf '%{name}.%{arch}\t%{evr}\t%{repoid}' 2>/dev/null ;;
  dnf5) timeout 75 dnf -q ${SWINV_REFRESH:+--refresh} repoquery --upgrades --latest-limit 1 --qf '%{name}.%{arch}\t%{evr}\t%{repoid}\n' 2>/dev/null ;;
  apt) [ -n "$SWINV_REFRESH" ] && $S timeout 60 apt-get -qq update >/dev/null 2>&1
       apt list --upgradable 2>/dev/null | awk -F'[/ ]' 'NF>=3 && $0 ~ /upgradable/ {print $1"\t"$3"\t"$2}' ;;
esac
echo "@@SWINV-RC $?"
sec security
case $PM in
  dnf4) timeout 25 dnf -q -C updateinfo list --security --available 2>/dev/null | awk 'NF>=3 {print $1"\t"$2"\t"$3}' ;;
  dnf5) timeout 25 dnf -q -C advisory list --security --updates 2>/dev/null | awk 'NF>=4 && $1 != "Name" {print $1"\t"$3"\t"$4}' ;;
  apt) apt list --upgradable 2>/dev/null | awk -F'[/ ]' '$2 ~ /security/ {print "-\t-\t"$1}' ;;
esac
sec needs-reboot
if [ -f /var/run/reboot-required ]; then echo yes
elif command -v needs-restarting >/dev/null 2>&1; then $S needs-restarting -r >/dev/null 2>&1; case $? in 0) echo no;; 1) echo yes;; *) echo unknown;; esac
elif [ "$PM" = dnf4 ] || [ "$PM" = dnf5 ]; then
  $S dnf -q needs-restarting -r >/dev/null 2>&1; r=$?
  case $r in 0) echo no;; 1) echo yes;; *)
    k=$(rpm -q --last kernel-core 2>/dev/null | awk 'NR==1 && $1 ~ /^kernel-core-/ {print substr($1, 13)}')
    if [ -z "$k" ]; then echo unknown; elif [ "$k" = "$(uname -r)" ]; then echo no; else echo yes; fi;;
  esac
else echo no; fi
sec listen
# Listening sockets (S: proto, address, port, program, pid), each process's binary (X; it ends
# in " (deleted)" when replaced since the process started), the shared objects it mapped (M,
# "deleted" likewise) and the packages owning those files (O).
listen() {
  socks=$(ss -Htulnp 2>/dev/null | awk '{
    port = $5; sub(/.*:/, "", port); addr = substr($5, 1, length($5) - length(port) - 1); s = $0
    while (match(s, /\("[^"]+",pid=[0-9]+/)) {
      u = substr(s, RSTART + 2, RLENGTH - 2); s = substr(s, RSTART + RLENGTH); i = index(u, "\",pid=")
      print "S\t" $1 "\t" addr "\t" port "\t" substr(u, 1, i - 1) "\t" substr(u, i + 6)
    }
  }')
  [ -n "$socks" ] || return 0
  printf '%s\n' "$socks"
  procs=$(for pid in $(printf '%s\n' "$socks" | cut -f6 | sort -un); do
    e=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
    printf 'X\t%s\t%s\n' "$pid" "$e"
    awk -v pid="$pid" '$6 ~ /^\// && $6 ~ /\.so/ && $6 !~ /^\/(dev|memfd:)/ {print "M\t" pid "\t" $6 "\t" ($7 == "(deleted)" ? "deleted" : "-")}' "/proc/$pid/maps" 2>/dev/null | sort -u
  done)
  printf '%s\n' "$procs"
  files=$(printf '%s\n' "$procs" | awk -F'\t' '$1 == "X" {sub(/ \(deleted\)$/, "", $3); print $3} $1 == "M" && $4 != "deleted" {print $3}' | sort -u)
  case $1 in
    dnf*) for f in $files; do o=$(rpm -qf --qf '%{NAME}\n' "$f" 2>/dev/null | head -1); case $o in *' '*|'') ;; *) printf 'O\t%s\t%s\n' "$f" "$o" ;; esac; done ;;
    apt) dpkg-query -S $files $(printf '%s\n' "$files" | sed -n 's|^/usr/|/|p') 2>/dev/null | awk -F': ' '!/^diversion/ && NF >= 2 {split($1, p, ", "); sub(/:.*/, "", p[1]); print "O\t" $2 "\t" p[1]}' ;;
  esac
}
$S timeout 40 bash -c "$(declare -f listen); listen $PM"
sec accounts
getent passwd | awk -F: '($3==0 || $3>=1000) && $3!=65534 {print $1"\t"$3"\t"$7"\t"$6}' | while IFS="$(printf '\t')" read -r u uid sh home; do
  s=-; case " $(id -nG "$u" 2>/dev/null) " in *" wheel "*|*" sudo "*|*" admin "*) s=group;; esac
  k=unknown; if $S test -r "$home/.ssh/authorized_keys" 2>/dev/null; then k=no; $S grep -qs ' swrap:' "$home/.ssh/authorized_keys" && k=yes; fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$u" "$uid" "$sh" "$s" "$k"
done
sec sudoers
for f in /etc/sudoers.d/swrap-*; do [ -e "$f" ] && printf '%s\t%s\n' "$f" "$($S sha256sum "$f" 2>/dev/null | cut -c1-16)"; done
sec sshd
$S sshd -T 2>/dev/null
sec repos
case $PM in
  dnf*) awk -F= '/^\[/{if(id)print id"\t"n"\t"e; id=substr($0,2,length($0)-2); n=""; e=1} /^name *=/{sub(/^name *= */,""); n=$0} /^enabled *=/{e=$2+0} END{if(id)print id"\t"n"\t"e}' /etc/yum.repos.d/*.repo 2>/dev/null ;;
  apt) grep -hsE '^(deb|URIs:|Suites:)' /etc/apt/sources.list /etc/apt/sources.list.d/* ;;
esac
"#;

/// Git working trees on a host: path, origin, last commit (unix time), used by a running
/// process (cwd or executable inside it), files changed in the last 30 days, systemd units
/// naming it. Read-only; also run on the core itself for its own asset.
pub const GIT_SCAN: &str = r#"procs=$(for p in /proc/[0-9]*; do readlink "$p/cwd"; readlink "$p/exe"; done 2>/dev/null | sort -u)
timeout 40 find /opt /srv /root /home /var/www /usr/local/src -xdev -maxdepth 4 -name .git -prune 2>/dev/null | sort -u | head -200 | while IFS= read -r g; do
  w=${g%/.git}
  o=$(git -c safe.directory='*' -C "$w" config --get remote.origin.url 2>/dev/null)
  c=$(git -c safe.directory='*' -C "$w" log -1 --format=%ct 2>/dev/null)
  m=$(timeout 10 find "$w" -maxdepth 3 -type f -newermt '30 days ago' -not -path '*/.git/*' 2>/dev/null | head -1)
  u=no; printf '%s\n' "$procs" | awk -v w="$w" '$0==w || index($0, w"/")==1 {f=1} END {exit !f}' && u=yes
  units=$(grep -ls -- "$w" /etc/systemd/system/*.service /etc/systemd/system/*.timer 2>/dev/null | xargs -r -n1 basename | paste -sd, -)
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$w" "${o:--}" "${c:-0}" "$u" "$([ -n "$m" ] && echo yes || echo no)" "$units"
done
"#;

/// `refresh`: fetch fresh package metadata first (internet hosts, see `table::TableCfg`).
fn collector(refresh: bool) -> String {
    format!("{}{COLLECTOR}\nsec gitrepos\n{GIT_SCAN}\nsec end\n", if refresh { "SWINV_REFRESH=1\n" } else { "" })
}

static LOCK: Mutex<()> = Mutex::new(());

pub struct Target {
    pub host: Host,
    pub ruser: String,
}

#[derive(Default, Clone)]
struct Row {
    label: String,
    os: String,
    kernel: String,
    updates: String,
    security: String,
    reboot: String,
    status: String,
    duration: String,
}

fn owner(d: &Daemon) -> Owner {
    Owner::new(d.swrap_uid, d.admin_gid)
}

/// Replaces a set of files crash-safely with two disk flushes in all (this disk takes ~190 ms
/// per flush, and an inventory writes over a thousand files): every new file is written next to
/// its target, one `syncfs`, then all renames, then one more `syncfs`. A power cut leaves each
/// file old or new, never torn.
struct Stage {
    moves: Vec<(PathBuf, PathBuf)>,
    uid: u32,
    gid: u32,
}

impl Stage {
    fn new(d: &Daemon) -> Self {
        Stage { moves: vec![], uid: d.swrap_uid, gid: d.admin_gid }
    }
    fn put(&mut self, path: &Path, data: &[u8]) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let tmp = path.with_file_name(format!(".{}.swinv-tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("f")));
        std::fs::write(&tmp, data).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640))?;
        std::os::unix::fs::chown(&tmp, Some(self.uid), Some(self.gid))?;
        self.moves.push((tmp, path.to_path_buf()));
        Ok(())
    }
    fn commit(self, root: &Path) -> Result<()> {
        syncfs(root)?;
        for (tmp, dst) in &self.moves {
            std::fs::rename(tmp, dst)?;
        }
        syncfs(root)
    }
}

fn syncfs(p: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(p)?;
    if unsafe { libc::syncfs(f.as_raw_fd()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Names of packages with a security advisory *and* an update available (`security` lines are
/// advisory, severity, package; `updates` lines start with `name.arch` or, for apt, `name`).
fn actionable_security(security: &[String], updates: &[String]) -> BTreeSet<String> {
    let upgradable: BTreeSet<&str> = updates.iter().filter_map(|l| l.split('\t').next()).map(update_name).collect();
    security.iter().filter_map(|l| security_pkg(l)).filter(|n| upgradable.contains(n)).map(String::from).collect()
}

/// The package a `security` line names: a NEVRA for dnf (`openssl-1:3.0.7-27.el9.x86_64`), the
/// name itself for apt (`-\t-\topenssh-sftp-server`).
fn security_pkg(l: &str) -> Option<&str> {
    let f: Vec<&str> = l.split('\t').collect();
    let p = *f.get(2)?;
    Some(if f[0] == "-" { p } else { nevra_name(p) })
}

/// The name in an `updates` line's first column: `name.arch` (dnf) or `name` (apt).
fn update_name(n: &str) -> &str {
    match n.rsplit_once('.') {
        Some((name, arch)) if ["x86_64", "noarch", "i686", "aarch64", "src"].contains(&arch) => name,
        _ => n,
    }
}

/// name → installed version from `packages` lines (name, version, arch); a zero epoch is left
/// out (`0:1.20.1-22.el9_6.3` → `1.20.1-22.el9_6.3`).
fn versions(packages: &[String]) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for l in packages {
        let mut f = l.split('\t');
        if let (Some(n), Some(v)) = (f.next(), f.next()) {
            m.entry(n.to_string()).or_insert_with(|| v.strip_prefix("0:").unwrap_or(v).to_string());
        }
    }
    m
}

/// Where a listening address answers from.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Reach {
    Loopback,
    Private,
    /// A wildcard address: every interface.
    Any,
    Public,
}

fn reach(addr: &str) -> Reach {
    let (a, ifc) = addr.split_once('%').unwrap_or((addr, ""));
    let a = a.trim_start_matches('[').trim_end_matches(']');
    match a.parse::<std::net::IpAddr>() {
        _ if ifc == "lo" => Reach::Loopback,
        _ if a == "*" => Reach::Any,
        Ok(ip) if ip.is_loopback() => Reach::Loopback,
        Ok(ip) if ip.is_unspecified() => Reach::Any,
        Ok(std::net::IpAddr::V4(v)) if v.is_private() || v.is_link_local() || (v.octets()[0] == 100 && v.octets()[1] & 0xc0 == 64) => Reach::Private,
        Ok(std::net::IpAddr::V6(v)) if v.segments()[0] & 0xfe00 == 0xfc00 || v.segments()[0] & 0xffc0 == 0xfe80 => Reach::Private,
        Ok(_) => Reach::Public,
        // Not understood: counted as reachable from anywhere.
        Err(_) => Reach::Any,
    }
}

/// A listening program of a host, a line of `services.tsv`.
#[derive(Debug, PartialEq)]
struct Service {
    /// `tcp/443`
    port: String,
    addr: String,
    reach: Reach,
    program: String,
    exe: String,
    package: String,
    version: String,
    /// Its binary or a library it mapped was replaced since it started: it still runs old code.
    restart: bool,
    /// Packages of the libraries it mapped.
    libs: BTreeSet<String>,
}

impl Service {
    fn line(&self) -> String {
        let reach = match self.reach {
            Reach::Loopback => "loopback",
            Reach::Private => "private",
            Reach::Any => "any",
            Reach::Public => "public",
        };
        let dash = |s: &str| if s.is_empty() { "-".to_string() } else { s.to_string() };
        let libs = self.libs.iter().cloned().collect::<Vec<_>>().join(",");
        format!("{}\t{}\t{reach}\t{}\t{}\t{}\t{}\t{}\t{}", self.port, self.addr, self.program, dash(&self.exe), dash(&self.package), dash(&self.version), if self.restart { "yes" } else { "no" }, dash(&libs))
    }

    fn parse(l: &str) -> Option<Service> {
        let f: Vec<&str> = l.split('\t').collect();
        let undash = |s: &str| if s == "-" { String::new() } else { s.to_string() };
        let reach = match *f.get(2)? {
            "private" => Reach::Private,
            "public" => Reach::Public,
            "loopback" => Reach::Loopback,
            _ => Reach::Any,
        };
        Some(Service {
            port: f[0].into(),
            addr: f[1].into(),
            reach,
            program: f.get(3)?.to_string(),
            exe: undash(f.get(4)?),
            package: undash(f.get(5)?),
            version: undash(f.get(6)?),
            restart: *f.get(7)? == "yes",
            libs: f.get(8).filter(|s| **s != "-").map(|s| s.split(',').map(String::from).collect()).unwrap_or_default(),
        })
    }

    /// Reachable from the internet, on a host that is: on a wildcard or public address, or on
    /// any address when the host has no public one (behind NAT, ports forwarded to it).
    fn internet(&self, host_public: bool) -> bool {
        matches!(self.reach, Reach::Any | Reach::Public) || (!host_public && self.reach == Reach::Private)
    }
}

/// The listening programs in the collector's `listen` section, loopback left out: one per
/// port, address and program, ordered by port (an unchanged host writes the same file).
fn services(listen: &str, versions: &BTreeMap<String, String>) -> Vec<Service> {
    let (mut socks, mut exe, mut maps, mut owner) = (BTreeMap::new(), BTreeMap::new(), BTreeMap::<&str, Vec<(&str, bool)>>::new(), BTreeMap::new());
    for l in listen.lines() {
        match l.split('\t').collect::<Vec<_>>().as_slice() {
            ["S", proto, addr, port, prog, pid] if reach(addr) != Reach::Loopback => {
                let pid: u64 = pid.parse().unwrap_or(u64::MAX);
                let e = socks.entry((format!("{proto}/{port}"), addr.to_string(), prog.to_string())).or_insert(pid);
                *e = (*e).min(pid);
            }
            ["X", pid, path] => {
                exe.insert(pid.parse::<u64>().unwrap_or(0), *path);
            }
            ["M", pid, path, flag] => maps.entry(*pid).or_default().push((*path, *flag == "deleted")),
            ["O", path, pkg] => {
                // dpkg may know a file under /lib while it was mapped from /usr/lib
                owner.insert(path.strip_prefix("/usr").unwrap_or(path).to_string(), *pkg);
            }
            _ => {}
        }
    }
    let own = |p: &str| owner.get(p.strip_prefix("/usr").unwrap_or(p)).map(|s| s.to_string()).unwrap_or_default();
    let mut v: Vec<Service> = socks
        .into_iter()
        .map(|((port, addr, program), pid)| {
            let raw = exe.get(&pid).copied().unwrap_or("");
            let path = raw.strip_suffix(" (deleted)").unwrap_or(raw);
            let mapped = maps.get(pid.to_string().as_str()).map(Vec::as_slice).unwrap_or(&[]);
            let package = own(path);
            Service {
                reach: reach(&addr),
                version: versions.get(&package).cloned().unwrap_or_default(),
                restart: raw.ends_with(" (deleted)") || mapped.iter().any(|(_, gone)| *gone),
                libs: mapped.iter().filter(|(_, gone)| !gone).map(|(p, _)| own(p)).filter(|o| !o.is_empty() && *o != package).collect(),
                exe: path.to_string(),
                package,
                port,
                addr,
                program,
            }
        })
        .collect();
    let key = |s: &Service| {
        let (proto, n) = s.port.split_once('/').unwrap_or(("", ""));
        (proto.to_string(), n.parse::<u32>().unwrap_or(0), s.addr.clone(), s.program.clone())
    };
    v.sort_by_key(key);
    v
}

/// `openssl-1:3.0.7-27.el9.x86_64` → `openssl`.
fn nevra_name(p: &str) -> &str {
    let mut it = p.rsplitn(3, '-');
    let (_, _, name) = (it.next(), it.next(), it.next());
    name.unwrap_or(p)
}

/// swrap-* sudoers files against what swuser wrote for the host's accounts (spec 10.5):
/// unexpected, modified (by content hash) or missing.
fn sudoers_drift(h: &Host, found: &[String]) -> Vec<String> {
    use sha2::Digest;
    let want: BTreeMap<String, String> = h
        .accounts
        .iter()
        .filter(|a| a.managed_by_swrap && a.sudo == "nopasswd")
        .map(|a| (format!("/etc/sudoers.d/swrap-{}", a.name), format!("{:x}", sha2::Sha256::digest(swrap_core::config::swrap_sudoers(&a.name).as_bytes()))[..16].to_string()))
        .collect();
    let mut drift = vec![];
    for l in found {
        let (path, hash) = l.split_once('\t').unwrap_or((l.as_str(), ""));
        match want.get(path) {
            None => drift.push(format!("unexpected {path}")),
            Some(w) if w != hash.trim() => drift.push(format!("modified {path}")),
            _ => {}
        }
    }
    for p in want.keys() {
        if !found.iter().any(|l| l.split('\t').next() == Some(p.as_str())) {
            drift.push(format!("missing {p}"));
        }
    }
    drift
}

fn host_dir(d: &Daemon, label: &str) -> PathBuf {
    d.paths.state().join("hosts").join(label)
}

/// The account inventory uses on a host for the scheduled run: root, else swrap-managed sudo,
/// else the default account; one with a credential.
pub fn system_account(d: &Daemon, h: &Host) -> Option<String> {
    let has = |a: &str| crate::session::credential(d, &h.label, a).is_some();
    if h.accounts.iter().any(|a| a.name == "root") && has("root") {
        return Some("root".into());
    }
    if let Some(a) = h.accounts.iter().find(|a| a.sudo == "nopasswd" && a.managed_by_swrap && has(&a.name)) {
        return Some(a.name.clone());
    }
    has(&h.default_user).then(|| h.default_user.clone()).or_else(|| h.accounts.iter().find(|a| has(&a.name)).map(|a| a.name.clone()))
}

/// `swinv [targets]`: hosts the caller may use, each with their most privileged account.
pub fn inventory(d: &Arc<Daemon>, c: &Caller, targets: &str, con: &Console) -> Result<Resp> {
    let user = c.aaa()?.clone();
    let t = now();
    let all = Host::all(&d.paths)?;
    let pick = |h: &Host| rbac::granted_accounts(&user, h, c.origin, t).into_iter().find(|a| crate::session::credential(d, &h.label, a).is_some());
    let expr = if targets.trim().is_empty() { "@all" } else { targets };
    let hosts = rbac::expand(expr, &all, |h| pick(h).is_some())?;
    if hosts.is_empty() {
        bail!("no host in {expr:?} you may use");
    }
    let list: Vec<Target> = hosts.iter().map(|h| Target { host: (*h).clone(), ruser: pick(h).expect("filtered") }).collect();
    collect(d, &c.name, expr, list, Some(con))
}

/// Inventory of `list` (also used after `swupdate` and by the scheduled run). Returns the
/// summary table as the response text.
pub fn collect(d: &Arc<Daemon>, who: &str, expr: &str, list: Vec<Target>, con: Option<&Console>) -> Result<Resp> {
    if d.is_sealed() {
        bail!("the swrap vault is sealed; inventory needs an admin login first");
    }
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let labels: Vec<String> = list.iter().map(|t| t.host.label.clone()).collect();
    let run = Arc::new(Run::new(d, "swinv", who, expr, json!({"hosts": labels}))?);
    let id = run.id.clone();
    if let Some(con) = con {
        con.err(format!("swinv: {} host{}, recorded as run {id}", labels.len(), if labels.len() == 1 { "" } else { "s" }));
    }
    let signer = Arc::new(swrec::RecSigner::load(&d.paths.recsign().join("ed25519.key"), "core").context("load recording signing key")?);
    let (d2, run2, who2, con2) = (d.clone(), run.clone(), who.to_string(), con.cloned());
    let mut rows = crate::fleet::parallel(
        d,
        list,
        move |t: &Target| {
            let r = one(&d2, &who2, &run2, t, &signer);
            if let (Some(c), Ok(r)) = (&con2, &r) {
                c.out(format!("{} {} ({})", t.host.label, r.status, r.duration));
            }
            r
        },
        |t: &Target, why: String| Row { label: t.host.label.clone(), status: format!("error: {why}"), ..Default::default() },
    );
    rows.sort_by(|a, b| a.label.cmp(&b.label));
    rebuild_indexes(d)?;
    let repo = swrap_core::git::Repo::new(d.paths.state()).run_as(d.swrap_uid, d.swrap_gid);
    let commit = repo.commit_all(&format!("inventory {} {id}", fmt_utc_secs(now())))?;
    let ok = rows.iter().filter(|r| r.status == "ok").count();
    d.audit_event(who, "inventory", expr, "", if ok == rows.len() { "ok" } else { "partial" }, json!({"run": id, "hosts": rows.len(), "ok": ok, "commit": commit}), &id);
    let w = rows.iter().map(|r| r.label.len()).max().unwrap_or(4).max(4);
    let mut text = format!("{:<w$}  {:<34}  {:<34}  {:>7}  {:>8}  {:<6}  {}\n", "HOST", "OS", "KERNEL", "UPDATES", "SECURITY", "REBOOT", "STATUS");
    for r in &rows {
        text += &format!("{:<w$}  {:<34}  {:<34}  {:>7}  {:>8}  {:<6}  {}\n", r.label, cut(&r.os, 34), cut(&r.kernel, 34), r.updates, r.security, r.reboot, r.status);
    }
    text += &format!("run {id} · {ok} of {} inventoried · state/ {}\n", rows.len(), commit.as_deref().map(|c| &c[..c.len().min(12)]).unwrap_or("unchanged"));
    // Monitoring and the asset record: table sync, host conditions, tickets.
    crate::table::after_inventory(d);
    let mut r = Resp::ok(json!({"run": id, "commit": commit}));
    r.text = text;
    r.exit = if ok == rows.len() { 0 } else { 1 };
    Ok(r)
}

fn cut(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { s.chars().take(n - 1).collect::<String>() + "…" }
}

/// Collect one host and write its files (the previous data stays if collection fails).
fn one(d: &Arc<Daemon>, who: &str, run: &Run, t: &Target, signer: &swrec::RecSigner) -> Result<Row> {
    let h = &t.host;
    let dir = host_dir(d, &h.label);
    atomic::mkdirs(&dir, 0o2750, owner(d))?;
    let old = read_facts(&dir);
    let mut stage = Stage::new(d);
    let (enc, _) = crate::session::credential(d, &h.label, &t.ruser).ok_or_else(|| anyhow!("no credential for {}@{}", t.ruser, h.label))?;
    let profile = Profile::load(&d.paths, &h.profile)?;
    let known = std::fs::read_to_string(d.paths.known_hosts(&h.label)).context("host keys not pinned")?;
    let mut rec = run.host_writer(d, h, &t.ruser, who, "swinv")?;
    let t0 = Instant::now();
    let refresh = crate::table::cfg(d).internet_hosts.contains(&h.label);
    let cmd = format!("bash -c {}", crate::ai::q(&collector(refresh)));
    let r = remote_stream(d, who, h, &t.ruser, &enc, &profile, &known, &cmd, b"", Some(&mut rec), RemoteOpts { timeout: Some(HOST_TIMEOUT), cap: 64 << 20 }, &mut |_, _| {});
    let dur = fmt_duration_ms(t0.elapsed());
    let when = fmt_utc(now());
    let mut facts = old.clone();
    facts.insert("label".into(), h.label.clone().into());
    facts.insert("route".into(), route(h.route).into());
    facts.insert("network".into(), route(h.network).into());
    facts.insert("last_attempt".into(), when.clone().into());
    let status = match &r {
        Err(e) => format!("error: {e:#}"),
        Ok(r) if r.timed_out => "timeout".into(),
        Ok(r) if !r.stdout.contains("@@SWINV end") => format!("unreachable: {}", r.why()),
        Ok(_) => "ok".into(),
    };
    let _ = rec.end(if matches!(&r, Ok(x) if x.timed_out) { "timeout" } else { "exit" }, r.as_ref().ok().map(|x| x.code), Some(signer));
    let mut row = Row { label: h.label.clone(), duration: dur, ..Default::default() };
    if status == "ok" {
        let out = r.as_ref().map(|x| x.stdout.clone()).unwrap_or_default();
        let secs = sections(&out);
        let kv: BTreeMap<String, String> = secs.get("facts").map(|s| s.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.trim().to_string())).collect()).unwrap_or_default();
        let osr = secs.get("os-release").cloned().unwrap_or_default();
        let pretty = osr.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=")).map(|v| v.trim_matches('"').to_string()).unwrap_or_default();
        let uptime: u64 = kv.get("uptime_s").and_then(|v| v.parse().ok()).unwrap_or(0);
        let boot = now().as_second() - uptime as i64;
        let pm = kv.get("package_manager").cloned().unwrap_or_default();
        let updates_ok = !out.contains("@@SWINV-RC 124");
        let tsv = |name: &str, cols: usize| -> Vec<String> {
            secs.get(name).map(|s| s.lines().filter(|l| l.split('\t').count() >= cols && !l.starts_with("@@")).map(String::from).collect()).unwrap_or_default()
        };
        let packages = tsv("packages", 3);
        let updates = tsv("updates", 3);
        let security: Vec<String> = tsv("security", 3).into_iter().map(|l| l.replacen("/Sec.", "", 1)).collect();
        // Packages with a security fix still to install: advisories also name older installed
        // versions of install-only packages (kernels), which only need the reboot.
        let security_pkgs = actionable_security(&security, &updates).len();
        let reboot = secs.get("needs-reboot").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "unknown".into());
        let services: Vec<String> = services(secs.get("listen").map(String::as_str).unwrap_or(""), &versions(&packages)).iter().map(Service::line).collect();
        // Global addresses, filtered and ordered like the endpoint agent's (same strings, no churn).
        let (mut v4, mut v6) = (BTreeSet::new(), BTreeSet::new());
        for l in secs.get("ips").map(|s| s.lines().collect::<Vec<_>>()).unwrap_or_default() {
            match l.split_once('\t') {
                Some(("inet", a)) => {
                    v4.insert(a.to_string());
                }
                Some(("inet6", a)) => {
                    v6.insert(a.to_string());
                }
                _ => {}
            }
        }
        let mut v4: Vec<String> = v4.into_iter().collect();
        v4.sort_by_key(|a| a.split('.').map(|x| x.parse::<u32>().unwrap_or(999)).collect::<Vec<_>>());
        let accounts = tsv("accounts", 5);
        let sudoers: Vec<String> = tsv("sudoers", 2);
        let sshd = secs.get("sshd").cloned().unwrap_or_default();
        let log = r.as_ref().map(|x| x.ssh_log.clone()).unwrap_or_default();
        let find = |pfx: &str| log.lines().find_map(|l| l.split_once(pfx).map(|(_, v)| v.trim().to_string())).unwrap_or_default();
        let cipher_line = find("kex: server->client cipher: ");
        let partial = if kv.get("user").map(|u| u != "root").unwrap_or(false) && sshd.trim().is_empty() { " (not root: no sshd config, keys of other accounts unknown)" } else { "" };
        for (k, v) in [
            ("os", json!(pretty)),
            ("hostname", json!(kv.get("hostname").cloned().unwrap_or_default())),
            ("kernel", json!(kv.get("kernel").cloned().unwrap_or_default())),
            ("arch", json!(kv.get("arch").cloned().unwrap_or_default())),
            ("uptime", json!(fmt_duration_ms(Duration::from_secs(uptime)))),
            ("last_boot", json!(jiff::Timestamp::from_second(boot).map(fmt_utc_secs).unwrap_or_default())),
            ("selinux", json!(kv.get("selinux").cloned().unwrap_or_default())),
            ("ssh_server", json!(kv.get("ssh_server").cloned().unwrap_or_default())),
            ("kex", json!(find("kex: algorithm: "))),
            ("hostkey_algorithm", json!(find("kex: host key algorithm: "))),
            ("cipher", json!(cipher_line.split(" MAC: ").next().unwrap_or("").to_string())),
            ("mac", json!(cipher_line.split(" MAC: ").nth(1).and_then(|m| m.split(" compression").next()).unwrap_or("").to_string())),
            ("package_manager", json!(pm)),
            ("virt", json!(kv.get("virt").cloned().unwrap_or_default())),
            ("installed", json!(kv.get("installed").and_then(|v| v.parse::<i64>().ok()).filter(|t| *t > 0).map(|t| jiff::Timestamp::from_second(t).map(fmt_utc_secs).unwrap_or_default()).unwrap_or_default())),
            ("endpoint_agent", json!(kv.get("endpoint_agent").cloned().unwrap_or_default())),
            ("endpoint_agent_table", json!(kv.get("endpoint_agent_table").cloned().unwrap_or_default())),
            ("ipv4", json!(v4.join(", "))),
            ("ipv6", json!(v6.into_iter().collect::<Vec<_>>().join(", "))),
            ("account", json!(t.ruser)),
            ("updates", json!(updates.len())),
            ("updates_complete", json!(updates_ok)),
            ("security_updates", json!(security_pkgs)),
            ("security_advisories", json!(security.iter().filter_map(|l| l.split('\t').next()).collect::<BTreeSet<_>>().len())),
            ("needs_reboot", json!(reboot)),
            ("sudoers_drift", json!(sudoers_drift(&t.host, &sudoers))),
            ("last_inventory", json!(when)),
        ] {
            facts.insert(k.into(), v);
        }
        facts.insert("inventory_status".into(), format!("ok{partial}").into());
        let mut w = |name: &str, body: String| stage.put(&dir.join(name), body.as_bytes());
        let lines = |v: &[String]| if v.is_empty() { String::new() } else { v.join("\n") + "\n" };
        w("os-release", osr)?;
        w("packages.tsv", lines(&packages))?;
        w("updates.tsv", lines(&updates))?;
        w("security-updates.tsv", lines(&security))?;
        w("needs-reboot", format!("{reboot}\n"))?;
        w("services.tsv", lines(&services))?;
        w("accounts.tsv", lines(&accounts))?;
        if !sshd.trim().is_empty() {
            w("sshd-effective.txt", sshd)?;
        }
        w("repos.tsv", secs.get("repos").cloned().unwrap_or_default())?;
        w("gitrepos.tsv", secs.get("gitrepos").cloned().unwrap_or_default())?;
        row.updates = updates.len().to_string();
        row.security = security_pkgs.to_string();
        row.reboot = reboot;
        row.status = "ok".into();
    } else {
        facts.insert("inventory_status".into(), status.clone().into());
        row.updates = "-".into();
        row.security = "-".into();
        row.reboot = "-".into();
        row.status = status;
    }
    row.os = facts.get("os").and_then(|v| v.as_str()).unwrap_or("").to_string();
    row.kernel = facts.get("kernel").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let tv: toml::Value = serde_json::from_value(Value::Object(facts.clone()))?;
    stage.put(&dir.join("facts.toml"), toml::to_string_pretty(&tv)?.as_bytes())?;
    stage.commit(&dir)?;
    watch(d, h, &old, &facts);
    Ok(row)
}

fn route(r: Route) -> &'static str {
    match r {
        Route::Core => "core",
        Route::Edge => "edge",
    }
}

fn sections(out: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut cur: Option<String> = None;
    let mut buf = String::new();
    for l in out.lines() {
        if let Some(name) = l.strip_prefix("@@SWINV ") {
            if let Some(c) = cur.take() {
                m.insert(c, std::mem::take(&mut buf));
            }
            cur = Some(name.trim().to_string());
            continue;
        }
        if cur.is_some() {
            buf.push_str(l);
            buf.push('\n');
        }
    }
    if let Some(c) = cur {
        m.insert(c, buf);
    }
    m
}

/// A host's internet-exposed services from its last inventory: on a wildcard or public address,
/// or on any address but loopback when the host has no public one (see `Service::internet`).
fn exposed(dir: &Path, f: &serde_json::Map<String, Value>) -> Vec<Service> {
    let s = |k: &str| f.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let public = s("ipv4").split(", ").chain(s("ipv6").split(", ")).any(|a| !a.is_empty() && reach(a) == Reach::Public);
    std::fs::read_to_string(dir.join("services.tsv")).unwrap_or_default().lines().filter_map(Service::parse).filter(|x| x.internet(public)).collect()
}

/// What swrap fixes by itself on an internet host (`table::TableCfg::internet_reload`).
#[derive(Default, Debug, PartialEq)]
pub struct Fix {
    /// Packages with a security fix that those services run (their binary or a library).
    pub packages: BTreeSet<String>,
    /// Services to reload afterwards (`internet_reload` names, their program names).
    pub services: BTreeSet<String>,
    /// What was found (the fixed versions, the services running replaced code): swrap tries
    /// the same at most once a day.
    pub id: String,
}

/// The fix for internet host `label` from its last good inventory, if one is due: its
/// internet-exposed `internet_reload` services with a security fix pending for what they run,
/// or still running replaced code.
pub fn internet_fix(d: &Daemon, label: &str) -> Option<Fix> {
    let c = crate::table::cfg(d);
    if c.internet_reload.is_empty() || !c.internet_hosts.iter().any(|h| h == label) {
        return None;
    }
    let dir = host_dir(d, label);
    let f = read_facts(&dir);
    if !f.get("inventory_status").and_then(|v| v.as_str()).is_some_and(|s| s.starts_with("ok")) {
        return None;
    }
    let lines = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap_or_default().lines().map(String::from).collect::<Vec<_>>();
    let updates = lines("updates.tsv");
    let pending = actionable_security(&lines("security-updates.tsv"), &updates);
    fix_of(&exposed(&dir, &f), &pending, &updates, &c.internet_reload)
}

fn fix_of(exposed: &[Service], pending: &BTreeSet<String>, updates: &[String], reload: &[String]) -> Option<Fix> {
    let newer: BTreeMap<&str, &str> = updates.iter().filter_map(|l| l.split_once('\t')).map(|(n, rest)| (update_name(n), rest.split('\t').next().unwrap_or(""))).collect();
    let mut fix = Fix::default();
    let mut stale = BTreeSet::new();
    for x in exposed.iter().filter(|x| reload.contains(&x.program)) {
        let used: Vec<&String> = pending.iter().filter(|p| x.package == **p || x.libs.contains(*p)).collect();
        if x.restart {
            stale.insert(x.program.clone());
        }
        if x.restart || !used.is_empty() {
            fix.services.insert(x.program.clone());
        }
        fix.packages.extend(used.into_iter().cloned());
    }
    if fix.services.is_empty() {
        return None;
    }
    let fixed: Vec<String> = fix.packages.iter().map(|p| format!("{p} {}", newer.get(p.as_str()).copied().unwrap_or("?"))).collect();
    fix.id = format!("{} | {}", fixed.join(", "), stale.into_iter().collect::<Vec<_>>().join(", "));
    Some(fix)
}

fn read_facts(dir: &Path) -> serde_json::Map<String, Value> {
    std::fs::read_to_string(dir.join("facts.toml"))
        .ok()
        .and_then(|s| toml::from_str::<toml::Value>(&s).ok())
        .and_then(|t| serde_json::to_value(t).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

/// The actionable conditions of a host, from its last inventory (tickets, spec: monitoring).
pub fn conditions(d: &Daemon, label: &str) -> Vec<crate::table::Condition> {
    use crate::table::Condition;
    let dir = host_dir(d, label);
    let f = read_facts(&dir);
    if f.is_empty() {
        return vec![];
    }
    let s = |k: &str| f.get(k).map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default();
    let mut v = vec![];
    let status = s("inventory_status");
    if !status.starts_with("ok") {
        v.push(Condition {
            kind: "unreachable",
            summary: "not reachable for inventory".into(),
            detail: format!("The inventory could not read {label} ({status}); last good inventory {}. Check the host, its network and its swrap enrollment (sw {label}).", s("last_inventory")),
            ..Default::default()
        });
        return v; // the other facts are stale
    }
    if s("needs_reboot") == "yes" {
        v.push(Condition {
            kind: "reboot",
            summary: "reboot needed".into(),
            detail: format!("{label} needs a reboot: a newer kernel or core library is installed than is running (running kernel {}, up since {}).", s("kernel"), s("last_boot")),
            ..Default::default()
        });
    }
    let lines = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap_or_default().lines().map(String::from).collect::<Vec<_>>();
    let (security, updates) = (lines("security-updates.tsv"), lines("updates.tsv"));
    let mut pkgs = actionable_security(&security, &updates);
    let advisories = |p: &str| security.iter().filter(|l| security_pkg(l) == Some(p)).filter_map(|l| l.split('\t').next()).filter(|a| *a != "-").map(String::from).collect::<BTreeSet<_>>();
    // Internet hosts: fixes for what their internet-exposed services run (binary or library)
    // and replaced code those still run are ticketed when found; the rest monthly (table).
    if crate::table::cfg(d).internet_hosts.iter().any(|h| h == label) {
        let exposed = exposed(&dir, &f);
        let installed = versions(&lines("packages.tsv"));
        let newer: BTreeMap<&str, &str> = updates.iter().filter_map(|l| l.split_once('\t')).map(|(n, rest)| (update_name(n), rest.split('\t').next().unwrap_or(""))).collect();
        for p in pkgs.clone() {
            let users: BTreeSet<String> = exposed.iter().filter(|x| x.package == p || x.libs.contains(&p)).map(|x| format!("{} {}", x.port, x.program)).collect();
            if users.is_empty() {
                continue;
            }
            pkgs.remove(&p);
            let new = newer.get(p.as_str()).copied().unwrap_or("?");
            let adv = advisories(&p);
            v.push(Condition {
                kind: "internet-security",
                summary: "security fixes for internet-exposed services".into(),
                id: format!("{p} {new}"),
                detail: format!(
                    "{label} is reachable from the internet, and its internet-exposed {} use {p} {}, which has a security fix in {new}{}.\nApply it now: swupdate {label}, then swreload {label} <service> for what still runs the old code (a restart where it has no reload).",
                    users.into_iter().collect::<Vec<_>>().join(", "),
                    installed.get(&p).map(String::as_str).unwrap_or("?"),
                    if adv.is_empty() { String::new() } else { format!(" ({})", adv.into_iter().collect::<Vec<_>>().join(", ")) }
                ),
            });
        }
        for x in exposed.iter().filter(|x| x.restart) {
            v.push(Condition {
                kind: "internet-restart",
                summary: "internet-exposed services run replaced code".into(),
                id: format!("{}@{}", x.program, x.port),
                detail: format!(
                    "{label}: {} {} ({}) is reachable from the internet and still runs a binary or library that an update replaced after it started, so fixes in it are not in effect. Reload it (swreload {label} <service>), or restart it where a reload does not load new code.",
                    x.port,
                    x.program,
                    if x.package.is_empty() { x.exe.clone() } else { format!("{} {}", x.package, x.version) }
                ),
            });
        }
    }
    if !pkgs.is_empty() {
        let list: Vec<&String> = pkgs.iter().take(25).collect();
        let adv: BTreeSet<String> = pkgs.iter().flat_map(|p| advisories(p)).collect();
        v.push(Condition {
            kind: "security",
            summary: format!("{} packages with security fixes", pkgs.len()),
            detail: format!(
                "{label} has security fixes pending for {} packages ({} advisories), e.g. {}{}.\nApply them: swupdate {label}",
                pkgs.len(),
                adv.len(),
                list.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                if pkgs.len() > list.len() { ", …" } else { "" }
            ),
            ..Default::default()
        });
    }
    if s("endpoint_agent") == "none" {
        v.push(Condition {
            kind: "agent",
            summary: "endpoint agent not deployed".into(),
            detail: format!("{label} has no endpoint agent, so its disks, SMART health and a full root filesystem are not monitored. swrap deploys it by itself when the table admin login is in the vault (`swrap table admin-password`); otherwise, or when that failed (the reason is below), run `swrap table agent {label}` as a swrap admin."),
            ..Default::default()
        });
    }
    if let Some(drift) = f.get("sudoers_drift").and_then(Value::as_array).filter(|a| !a.is_empty()) {
        v.push(Condition {
            kind: "sudoers",
            summary: "swrap sudoers files differ from what swuser wrote".into(),
            detail: format!("{label}: {}. swrap-* files are written by swuser (swuser sudo <host> <account> on|off restores them); check who changed them.", drift.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")),
            ..Default::default()
        });
    }
    v
}

/// Monitoring: alert on changes that need someone (not on every run).
fn watch(d: &Daemon, h: &Host, old: &serde_json::Map<String, Value>, new: &serde_json::Map<String, Value>) {
    let s = |m: &serde_json::Map<String, Value>, k: &str| m.get(k).map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default();
    let n = |m: &serde_json::Map<String, Value>, k: &str| m.get(k).and_then(Value::as_i64).unwrap_or(0);
    let (was, is) = (s(old, "inventory_status"), s(new, "inventory_status"));
    let first = old.is_empty();
    if !is.starts_with("ok") && (first || was.starts_with("ok")) {
        crate::motd::alert(d, "host.unreachable", json!({"label": h.label, "status": is}));
    }
    if is.starts_with("ok") && !first && !was.starts_with("ok") {
        d.audit_event("", "host.reachable", &h.label, "", "ok", json!({"was": was}), "");
    }
    // A host's first inventory is its baseline (the status line shows it); alert on changes.
    if is.starts_with("ok") && !first {
        if n(new, "security_updates") > 0 && n(old, "security_updates") == 0 {
            crate::motd::alert(d, "host.security_updates", json!({"label": h.label, "count": n(new, "security_updates")}));
        }
        if s(new, "needs_reboot") == "yes" && s(old, "needs_reboot") != "yes" {
            crate::motd::alert(d, "host.needs_reboot", json!({"label": h.label, "kernel": s(new, "kernel")}));
        }
        let drift = new.get("sudoers_drift").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
        let drift_old = old.get("sudoers_drift").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
        if drift > drift_old {
            crate::motd::alert(d, "host.sudoers_drift", json!({"label": h.label, "files": new.get("sudoers_drift")}));
        }
    }
}

/// `packages/<name>.tsv`, `tags/<tag>/<label>` and `summary.tsv` from every host's files.
fn rebuild_indexes(d: &Daemon) -> Result<()> {
    let st = d.paths.state();
    let hosts_dir = st.join("hosts");
    let mut labels: Vec<String> = std::fs::read_dir(&hosts_dir).map(|rd| rd.flatten().filter(|e| e.path().is_dir()).map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    labels.sort();
    let known: BTreeMap<String, Host> = Host::all(&d.paths)?.into_iter().map(|h| (h.label.clone(), h)).collect();
    // Hosts that were deleted leave the index (their history stays in git).
    for l in labels.iter().filter(|l| !known.contains_key(*l)) {
        let _ = std::fs::remove_dir_all(hosts_dir.join(l));
    }
    labels.retain(|l| known.contains_key(l));
    let mut pk: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut summary = String::from("label\troute\tos\tkernel\tupdates\tsecurity\treboot\tlast_seen\tstatus\n");
    for l in &labels {
        let dir = hosts_dir.join(l);
        for line in std::fs::read_to_string(dir.join("packages.tsv")).unwrap_or_default().lines() {
            let mut f = line.split('\t');
            let (Some(name), Some(ver)) = (f.next(), f.next()) else { continue };
            if !name.is_empty() && name.len() <= 200 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)) && !name.starts_with('.') {
                pk.entry(name.to_string()).or_default().push(format!("{l}\t{ver}"));
            }
        }
        let f = read_facts(&dir);
        let g = |k: &str| f.get(k).map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default();
        summary += &format!("{l}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n", g("route"), g("os"), g("kernel"), g("updates"), g("security_updates"), g("needs_reboot"), g("last_inventory"), g("inventory_status"));
    }
    // packages/: built beside the old one, flushed once, then swapped in.
    let pdir = st.join("packages");
    let pnew = st.join(".packages.new");
    let _ = std::fs::remove_dir_all(&pnew);
    atomic::mkdirs(&pnew, 0o2750, owner(d))?;
    {
        use std::os::unix::fs::PermissionsExt;
        for (name, rows) in &pk {
            let mut rows = rows.clone();
            rows.sort();
            let p = pnew.join(format!("{name}.tsv"));
            std::fs::write(&p, rows.join("\n") + "\n")?;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640))?;
            std::os::unix::fs::chown(&p, Some(d.swrap_uid), Some(d.admin_gid))?;
        }
    }
    syncfs(&st)?;
    let pold = st.join(".packages.old");
    let _ = std::fs::remove_dir_all(&pold);
    if pdir.exists() {
        std::fs::rename(&pdir, &pold)?;
    }
    std::fs::rename(&pnew, &pdir)?;
    syncfs(&st)?;
    let _ = std::fs::remove_dir_all(&pold);
    let tdir = st.join("tags");
    let _ = std::fs::remove_dir_all(&tdir);
    let tags: BTreeSet<(String, String)> = known.values().filter(|h| labels.contains(&h.label)).flat_map(|h| h.tags.iter().map(|t| (t.clone(), h.label.clone())).collect::<Vec<_>>()).collect();
    for (tag, label) in tags {
        if !swrap_core::paths::safe_component(&tag) {
            continue;
        }
        let dir = tdir.join(&tag);
        atomic::mkdirs(&dir, 0o2750, owner(d))?;
        let link = dir.join(&label);
        std::os::unix::fs::symlink(format!("../../hosts/{label}"), &link)?;
        let _ = std::os::unix::fs::lchown(&link, Some(d.swrap_uid), Some(d.admin_gid));
    }
    atomic::write(&st.join("summary.tsv"), summary.as_bytes(), 0o640, owner(d))?;
    Ok(())
}

/// The PT6H run over every active host (spec 10.7), and in between the internet hosts every
/// `internet_every` (table settings). Waits for an unsealed vault.
pub async fn run_loop(d: Arc<Daemon>) {
    tokio::time::sleep(Duration::from_secs(300)).await;
    let (mut last, mut last_net): (Option<Instant>, Option<Instant>) = (None, None);
    loop {
        let tc = crate::table::cfg(&d);
        let net_every = swrap_core::time::IsoDuration::parse(&tc.internet_every).ok().and_then(|x| x.exact()).unwrap_or(Duration::from_secs(3600)).max(Duration::from_secs(600));
        let all = last.map(|l| l.elapsed() >= EVERY).unwrap_or(true);
        let net = !tc.internet_hosts.is_empty() && last_net.map(|l| l.elapsed() >= net_every).unwrap_or(true);
        if !d.is_sealed() && (all || net) {
            let d2 = d.clone();
            let r = tokio::task::spawn_blocking(move || {
                let list: Vec<Target> = Host::all(&d2.paths)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|h| h.state == HostState::Active && (all || tc.internet_hosts.contains(&h.label)))
                    .filter_map(|h| system_account(&d2, &h).map(|ruser| Target { host: h, ruser }))
                    .collect();
                if list.is_empty() {
                    return Ok(Resp::ok(json!({})));
                }
                collect(&d2, "swrap", if all { "@all" } else { "@internet" }, list, None)
            })
            .await;
            match r {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => eprintln!("swrapd: inventory: {e:#}"),
                Err(e) => eprintln!("swrapd: inventory: {e}"),
            }
            if all {
                last = Some(Instant::now());
            }
            last_net = Some(Instant::now());
        }
        tokio::time::sleep(Duration::from_secs(600)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudoers_drift_compares_with_what_swuser_wrote() {
        use sha2::Digest;
        let mut h: Host = toml::from_str("label = \"t\"\naddress = \"x\"\nport = 22\nroute = \"core\"\nprofile = \"modern\"\ndefault_user = \"root\"\nstate = \"active\"\n").unwrap();
        for (n, sudo) in [("ok", "nopasswd"), ("gone", "nopasswd"), ("plain", "none")] {
            h.accounts.push(swrap_core::config::Account { name: n.into(), key_algo: "ssh-ed25519".into(), key_fingerprint: String::new(), created: String::new(), sudo: sudo.into(), managed_by_swrap: true, integration: true, locked: false });
        }
        let hash = |u: &str| format!("{:x}", sha2::Sha256::digest(swrap_core::config::swrap_sudoers(u).as_bytes()))[..16].to_string();
        let found = vec![
            format!("/etc/sudoers.d/swrap-ok\t{}", hash("ok")),
            "/etc/sudoers.d/swrap-plain\t0123456789abcdef".to_string(),
            "/etc/sudoers.d/swrap-stranger\t0123456789abcdef".to_string(),
        ];
        let mut d = sudoers_drift(&h, &found);
        d.sort();
        assert_eq!(d, vec!["missing /etc/sudoers.d/swrap-gone", "unexpected /etc/sudoers.d/swrap-plain", "unexpected /etc/sudoers.d/swrap-stranger"]);
        let modified = vec![format!("/etc/sudoers.d/swrap-ok\t{}", "f".repeat(16)), format!("/etc/sudoers.d/swrap-gone\t{}", hash("gone"))];
        assert_eq!(sudoers_drift(&h, &modified), vec!["modified /etc/sudoers.d/swrap-ok"]);
    }

    #[test]
    fn installed_kernel_fixes_are_not_pending() {
        let sec = vec!["RLSA-1\tImportant\tkernel-6.12.0-211.60.1.el10_2.x86_64".to_string(), "RLSA-2\tModerate\topenssl-1:3.5.1-2.el10.x86_64".to_string()];
        let upd = vec!["openssl.x86_64\t1:3.5.1-2.el10\tbaseos".to_string()];
        assert_eq!(actionable_security(&sec, &upd).into_iter().collect::<Vec<_>>(), vec!["openssl".to_string()]);
        assert!(actionable_security(&sec, &[]).is_empty());
    }

    #[test]
    fn apt_security_names_stay_whole() {
        let sec = vec!["-\t-\topenssh-sftp-server".to_string(), "-\t-\tlibssl3t64".to_string()];
        let upd = vec!["openssh-sftp-server\t1:10.0p1-7+deb13u1\ttrixie-security".to_string(), "libssl3t64\t3.5.1-1+deb13u2\ttrixie-security".to_string()];
        assert_eq!(actionable_security(&sec, &upd).into_iter().collect::<Vec<_>>(), vec!["libssl3t64".to_string(), "openssh-sftp-server".to_string()]);
    }

    #[test]
    fn listening_addresses() {
        for (a, r) in [
            ("0.0.0.0", Reach::Any),
            ("*", Reach::Any),
            ("[::]", Reach::Any),
            ("127.0.0.53%lo", Reach::Loopback),
            ("[::1]", Reach::Loopback),
            ("*%lo", Reach::Loopback),
            ("10.0.0.3", Reach::Private),
            ("192.168.10.5%ens18", Reach::Private),
            ("100.64.1.2", Reach::Private),
            ("[fd00:1::1]", Reach::Private),
            ("[fe80::1%eth0]", Reach::Private),
            ("203.0.113.42", Reach::Public),
            ("[2001:db8:1::1]", Reach::Public),
        ] {
            assert_eq!(reach(a), r, "{a}");
        }
    }

    #[test]
    fn services_from_the_listen_section() {
        let listen = "S\ttcp\t0.0.0.0\t443\tnginx\t912\nS\ttcp\t0.0.0.0\t443\tnginx\t910\nS\ttcp\t[::]\t443\tnginx\t910\n\
            S\ttcp\t127.0.0.1\t8080\tapp\t20\nS\ttcp\t10.0.0.3\t22\tsshd\t700\nS\tudp\t*\t53\tunbound\t30\n\
            X\t910\t/usr/sbin/nginx (deleted)\nX\t700\t/usr/sbin/sshd\nX\t30\t/opt/unbound/sbin/unbound\n\
            M\t910\t/usr/lib64/libssl.so.3.2.2\t-\nM\t910\t/usr/lib64/libc.so.6\t-\nM\t700\t/usr/lib64/libcrypto.so.3.5.8\tdeleted\nM\t700\t/usr/lib/x86_64-linux-gnu/libz.so.1\t-\n\
            O\t/usr/sbin/nginx\tnginx\nO\t/usr/lib64/libssl.so.3.2.2\topenssl-libs\nO\t/usr/lib64/libc.so.6\tglibc\nO\t/usr/sbin/sshd\topenssh-server\nO\t/lib/x86_64-linux-gnu/libz.so.1\tzlib1g\n";
        let pkgs = vec!["nginx\t2:1.26.3-1.el10\tx86_64".to_string(), "openssh-server\t0:9.9p1-27.el10_2\tx86_64".to_string(), "glibc\t0:2.39-58.el10\tx86_64".to_string()];
        let v = services(listen, &versions(&pkgs));
        let lines: Vec<String> = v.iter().map(Service::line).collect();
        assert_eq!(
            lines,
            vec![
                "tcp\t22\t10.0.0.3\tprivate\tsshd\t/usr/sbin/sshd\topenssh-server\t9.9p1-27.el10_2\tyes\tzlib1g".replace("tcp\t22", "tcp/22"),
                "tcp/443\t0.0.0.0\tany\tnginx\t/usr/sbin/nginx\tnginx\t2:1.26.3-1.el10\tyes\tglibc,openssl-libs".to_string(),
                "tcp/443\t[::]\tany\tnginx\t/usr/sbin/nginx\tnginx\t2:1.26.3-1.el10\tyes\tglibc,openssl-libs".to_string(),
                "udp/53\t*\tany\tunbound\t/opt/unbound/sbin/unbound\t-\t-\tno\t-".to_string(),
            ]
        );
        for l in &lines {
            assert_eq!(Service::parse(l).unwrap().line(), *l);
        }
        let sshd = Service::parse(&lines[0]).unwrap();
        assert!(!sshd.internet(true), "a private address on a host with a public one");
        assert!(sshd.internet(false), "behind NAT, ports forwarded to it");
        assert!(Service::parse(&lines[1]).unwrap().internet(true));
    }

    #[test]
    fn internet_fixes_for_the_reload_services() {
        let svc = |l: &str| Service::parse(l).unwrap();
        let exposed = vec![
            svc("tcp/22\t0.0.0.0\tany\tsshd\t/usr/sbin/sshd\topenssh-server\t9.9p1-12.el9_8\tno\tglibc,openssl-libs"),
            svc("tcp/443\t0.0.0.0\tany\tnginx\t/usr/sbin/nginx\tnginx-core\t2:1.20.1-28.el9_8.6\tno\tglibc,openssl-libs,pcre"),
            svc("tcp/3128\t*\tany\tsquid\t/usr/sbin/squid\tsquid\t7:5.5-26.el9_8\tyes\tglibc,openssl-libs"),
        ];
        let reload = vec!["nginx".to_string(), "sshd".to_string()];
        let updates = vec!["openssl-libs.x86_64\t1:3.5.1-9.el9_8\tbaseos".to_string(), "squid.x86_64\t7:5.5-27.el9_8\tappstream".to_string()];
        let set = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        // A library fix: both get it; squid is no reload service (tickets only).
        let f = fix_of(&exposed, &set(&["openssl-libs", "squid"]), &updates, &reload).unwrap();
        assert_eq!(f.packages, set(&["openssl-libs"]));
        assert_eq!(f.services, set(&["nginx", "sshd"]));
        assert_eq!(f.id, "openssl-libs 1:3.5.1-9.el9_8 | ");
        // Nothing pending for them, nothing replaced: no fix.
        assert_eq!(fix_of(&exposed, &set(&["squid"]), &updates, &reload), None);
        assert_eq!(fix_of(&exposed, &set(&["openssl-libs"]), &updates, &[]), None);
        // Replaced code alone: a reload, nothing to install.
        let mut e2 = exposed;
        e2[1].restart = true;
        let f = fix_of(&e2, &set(&[]), &updates, &reload).unwrap();
        assert!(f.packages.is_empty());
        assert_eq!(f.services, set(&["nginx"]));
        assert_eq!(f.id, " | nginx");
    }

    #[test]
    fn package_names() {
        assert_eq!(nevra_name("openssl-1:3.0.7-27.el9.x86_64"), "openssl");
        assert_eq!(nevra_name("python3-libs-3.12.1-2.el10.x86_64"), "python3-libs");
        assert_eq!(nevra_name("odd"), "odd");
    }

    #[test]
    fn sections_split() {
        let s = sections("noise\n@@SWINV facts\nuser=root\n\n@@SWINV packages\na\t1:2-3\tx86_64\n@@SWINV end\n");
        assert_eq!(s["facts"].trim(), "user=root");
        assert_eq!(s["packages"], "a\t1:2-3\tx86_64\n");
        assert!(s.contains_key("end"));
    }
}
