//! MOTD and status text: seal state with ISO timestamps, doctor findings, alerts.

use crate::daemon::Daemon;
use swrap_core::time::now;

pub fn status_text(d: &Daemon) -> String {
    let sealed = d.is_sealed();
    let mut s = if sealed {
        format!("swrap: vault SEALED since {} — an admin must log in with password (sessions unavailable)\n", d.disp(*d.sealed_since.lock().unwrap()))
    } else {
        format!("swrap: vault unsealed since {}\n", d.disp(d.unsealed_at.lock().unwrap().unwrap_or_else(now)))
    };
    if let Some(f) = fleet_line(d) {
        s += &f;
    }
    if let Ok(a) = std::fs::read_to_string(d.paths.alerts()) {
        let lines: Vec<&str> = a.lines().rev().take(5).collect();
        if !lines.is_empty() {
            s += "swrap: recent alerts:\n";
            for l in lines.iter().rev() {
                s += &format!("  {l}\n");
            }
        }
    }
    s
}

/// What the last inventory says needs attention (monitoring, spec 10.7).
fn fleet_line(d: &Daemon) -> Option<String> {
    let t = std::fs::read_to_string(d.paths.state().join("summary.tsv")).ok()?;
    let rows: Vec<Vec<&str>> = t.lines().skip(1).map(|l| l.split('\t').collect()).filter(|r: &Vec<&str>| r.len() >= 9).collect();
    if rows.is_empty() {
        return None;
    }
    let list = |v: Vec<String>| if v.is_empty() { "-".to_string() } else { v.join(", ") };
    let down = rows.iter().filter(|r| !r[8].starts_with("ok")).map(|r| r[0].to_string()).collect();
    let sec = rows.iter().filter(|r| r[5].parse::<u64>().unwrap_or(0) > 0).map(|r| format!("{} ({})", r[0], r[5])).collect();
    let reboot = rows.iter().filter(|r| r[6] == "yes").map(|r| r[0].to_string()).collect();
    let last = rows.iter().map(|r| r[7]).max().unwrap_or("");
    Some(format!(
        "swrap: fleet of {} (inventory {}): unreachable {} · security updates {} · reboot needed {}\n",
        rows.len(),
        last.get(..16).map(|s| format!("{s}Z")).unwrap_or_default(),
        list(down),
        list(sec),
        list(reboot)
    ))
}

pub fn update(d: &Daemon) {
    let _ = std::fs::write(d.paths.motd(), status_text(d));
}

/// Record an alert (audit + alerts.tsv shown in the MOTD).
pub fn alert(d: &Daemon, what: &str, detail: serde_json::Value) {
    d.audit_event("", "alert", what, "", "alert", detail.clone(), "");
    // Actionable alerts become tickets in table (deduplicated there).
    crate::table::alert(d, what, &detail);
    let line = format!("{}\t{}\t{}\n", swrap_core::time::fmt_utc_secs(now()), what, detail);
    let p = d.paths.alerts();
    let _ = std::fs::create_dir_all(p.parent().unwrap());
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        let _ = f.write_all(line.as_bytes());
    }
    update(d);
}
