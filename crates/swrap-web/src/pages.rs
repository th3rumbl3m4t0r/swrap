//! HTML shells. All dynamic data is fetched by /assets/app.js (strict CSP: no inline scripts).

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn shell(title: &str, body: &str, extra_head: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{} · swrap</title><link rel="stylesheet" href="/assets/app.css">{extra_head}</head><body>{body}</body></html>"#,
        esc(title)
    )
}

fn topbar(user: &str, admin: bool) -> String {
    format!(
        r#"<header class="top"><a class="brand" href="/">swrap</a><span class="sub">playback &amp; search</span>
<span class="grow"></span><label class="utc"><input type="checkbox" id="utc"> UTC</label>
<span class="who">{}{}</span><form method="post" action="/logout"><button class="link">log out</button></form></header>"#,
        esc(user),
        if admin { " <b class=\"badge\">admin</b>" } else { "" }
    )
}

pub fn login(msg: &str) -> String {
    let m = if msg.is_empty() { String::new() } else { format!("<p class=\"err\">{}</p>", esc(msg)) };
    shell(
        "Log in",
        &format!(
            r#"<main class="login"><h1>swrap</h1><p class="muted">Recorded sessions: playback and search.</p>{m}
<form method="post" action="/login"><label>User <input name="user" autocomplete="username" required autofocus></label>
<label>Web password <input name="password" type="password" autocomplete="current-password" required></label>
<button>Log in</button></form><p class="muted small">Set your web password with <code>swpasswd</code>.</p></main>"#
        ),
        "",
    )
}

pub fn search(user: &str, admin: bool, default_window: &str) -> String {
    let user_field = if admin { r#"<label>user <input data-f="user" placeholder="glob"></label>"# } else { "" };
    shell(
        "Search",
        &format!(
            r#"{top}<main class="search" data-page="search">
<form id="sf" autocomplete="off">
<div class="row"><label class="wide">timeframe <input id="window" value="{w}" required title="ISO 8601 interval, e.g. P1D/now or 2026-09-01T00:00Z/PT6H"></label>
<span class="quick"><button type="button" data-w="PT1H/now">PT1H</button><button type="button" data-w="P1D/now">P1D</button><button type="button" data-w="P7D/now">P7D</button><button type="button" data-w="P30D/now">P30D</button></span></div>
<div class="row fields"><label>host <input data-f="host" placeholder="label or address glob"></label><label>ruser <input data-f="ruser" placeholder="glob"></label>{uf}
<label>kind <select data-f="kind"><option value="">any</option><option>sw</option><option>shell</option><option>sftp</option><option>run</option></select></label>
<label>node <select data-f="node"><option value="">any</option><option>core</option><option>edge</option></select></label></div>
<div class="row fields"><label>cmd <input data-f="cmd" placeholder="literal, /regex/ or -term"></label><label>keys <input data-f="keys"></label><label>out <input data-f="out"></label><label>file <input data-f="file"></label></div>
<div class="row"><label class="wide">free text / query <input id="free" placeholder='e.g. host:web* cmd:/dnf .*install/ out:"permission denied" -ruser:deploy'></label></div>
<div class="row"><button id="go">Search</button><button type="button" id="cancel" disabled>Cancel</button><span id="progress" class="muted"></span></div>
</form>
<p id="qline" class="muted small mono"></p>
<table id="hits"><thead><tr><th>time</th><th>kind</th><th>user</th><th>target</th><th>node</th><th>field</th><th class="num" title="record file size on disk">bytes</th><th>match</th></tr></thead><tbody></tbody></table>
</main><script src="/assets/app.js"></script>"#,
            top = topbar(user, admin),
            w = esc(default_window),
            uf = user_field
        ),
        "",
    )
}

pub fn player(user: &str, admin: bool, id: &str) -> String {
    shell(
        id,
        &format!(
            r#"{top}<main class="player" data-page="player" data-id="{id}">
<section class="stage">
<div class="controls">
  <span class="tabs"><button type="button" id="tab-play" class="on">Player</button><button type="button" id="tab-text">Transcript</button></span>
  <span class="grow"></span>
  <label><input type="checkbox" id="keys"> keystrokes</label>
  <label>speed <select id="speed"><option>0.5</option><option selected>1</option><option>2</option><option>4</option><option>8</option></select></label>
  <span class="font"><button type="button" id="font-dn" title="smaller text">A−</button><button type="button" id="font-up" title="larger text">A+</button></span>
  <span id="livebadge" class="badge live" hidden>LIVE</span>
</div>
<div id="termbox" class="termbox"><div id="term"></div></div>
<pre id="text" class="transcript" hidden></pre>
<p class="muted small" id="sizeinfo"></p>
</section>
<aside class="side"><h2>Session</h2><dl id="meta"></dl><h2>Verification</h2><div id="verify"></div>
<h2>Commands</h2><ol id="cmds" class="timeline"></ol><h2>Nested sessions</h2><ul id="links"></ul><h2>Notes</h2><ul id="notes" class="small"></ul></aside>
</main><script src="/assets/asciinema-player.min.js"></script><script src="/assets/app.js"></script>"#,
            top = topbar(user, admin),
            id = esc(id)
        ),
        r#"<link rel="stylesheet" href="/assets/asciinema-player.css">"#,
    )
}
