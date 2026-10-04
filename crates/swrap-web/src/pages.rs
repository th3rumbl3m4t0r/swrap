//! HTML shells. All dynamic data is fetched by /assets/app.js (strict CSP: no inline scripts).

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn shell(title: &str, body: &str, extra_head: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en" class="theme-night"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{} · swrap</title><link rel="icon" href="/assets/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/assets/x11.css"><link rel="stylesheet" href="/assets/app.css">{extra_head}<script src="/assets/x11.js"></script></head><body>{body}</body></html>"#,
        esc(title)
    )
}

/// The x11 top bar: brand, the pages, then time zone, who, log out and the theme controls.
fn topbar(user: &str, admin: bool, page: &str) -> String {
    format!(
        r#"<header id="topbar"><div class="bar"><a class="brand" href="/">swrap <small>// aaa</small></a>
<nav><a href="/"{search_on}>search</a>{player}</nav><span class="spacer"></span>
<label class="tz" title="times are UTC (Z); this shows them in the display zone instead"><input type="checkbox" id="local"> local time</label>
<span class="who">{}{}</span><form method="post" action="/logout"><button>log out</button></form><span data-x11-controls></span></div></header>"#,
        esc(user),
        if admin { " <b class=\"badge\">admin</b>" } else { "" },
        search_on = if page == "search" { r#" class="on""# } else { "" },
        player = if page == "player" { r#"<a class="on">player</a>"# } else { "" },
    )
}

fn statusbar(left: &str) -> String {
    format!(r#"<footer class="statusbar"><span>{left}</span><span class="spacer"></span><span>swrap · every session recorded · times UTC</span></footer>"#)
}

fn win(title: &str, extra: &str, body: &str) -> String {
    format!(r#"<section class="win"><div class="titlebar"><span class="grip">::</span>{title}<span class="spacer"></span>{extra}</div><div class="body">{body}</div></section>"#)
}

pub fn login(msg: &str) -> String {
    let m = if msg.is_empty() { String::new() } else { format!("<p class=\"err\">{}</p>", esc(msg)) };
    shell(
        "Log in",
        &format!(
            r#"<main class="login">{w}</main>{sb}"#,
            w = win(
                "swrap · log in",
                "",
                &format!(
                    r#"<p class="dim">recorded sessions: playback and search</p>{m}
<form method="post" action="/login"><label class="lbl" for="u">user</label><input id="u" name="user" autocomplete="username" required autofocus>
<label class="lbl" for="p">web password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<button class="primary">log in</button></form><p class="dim small">set your web password with <code>swpasswd</code></p>"#
                )
            ),
            sb = statusbar("not logged in")
        ),
        "",
    )
}

pub fn search(user: &str, admin: bool, default_window: &str) -> String {
    let user_field = if admin { r#"<label>user <input data-f="user" placeholder="glob"></label>"# } else { "" };
    let form = format!(
        r#"<form id="sf" autocomplete="off">
<div class="row"><label class="wide">timeframe <input id="window" value="{w}" required title="ISO 8601 interval, e.g. P1D/now or 2026-09-01T00:00Z/PT6H"></label>
<span class="quick"><button type="button" data-w="PT1H/now">PT1H</button><button type="button" data-w="P1D/now">P1D</button><button type="button" data-w="P7D/now">P7D</button><button type="button" data-w="P30D/now">P30D</button></span></div>
<div class="row fields"><label>host <input data-f="host" placeholder="label or address glob"></label><label>ruser <input data-f="ruser" placeholder="glob"></label>{uf}
<label>kind <select data-f="kind"><option value="">any</option><option>sw</option><option>shell</option><option>sftp</option><option>run</option><option>ai</option></select></label>
<label>node <select data-f="node"><option value="">any</option><option>core</option><option>edge</option></select></label></div>
<div class="row fields"><label>cmd <input data-f="cmd" placeholder="literal, /regex/ or -term"></label><label>keys <input data-f="keys"></label><label>out <input data-f="out"></label><label>file <input data-f="file"></label></div>
<div class="row fields"><label>prompt <input data-f="prompt" placeholder="swai: what the user asked"></label><label>reply <input data-f="reply"></label><label>tool <input data-f="tool"></label><label>args <input data-f="args" placeholder="key=value"></label></div>
<div class="row"><label class="wide">free text / query <input id="free" placeholder='e.g. host:web* cmd:/dnf .*install/ out:"permission denied" -ruser:deploy'></label></div>
<div class="row"><button id="go" class="primary">search</button><button type="button" id="cancel" disabled>cancel</button><span id="progress" class="dim"></span></div>
</form>"#,
        w = esc(default_window),
        uf = user_field
    );
    let results = r#"<p id="qline" class="dim small"></p>
<table id="hits" class="x11"><thead><tr><th>time</th><th>kind</th><th>user</th><th>target</th><th>node</th><th>field</th><th class="num" title="record file size on disk">bytes</th><th>match</th></tr></thead><tbody></tbody></table>"#;
    shell(
        "Search",
        &format!(
            r#"{top}<main class="search" data-page="search">{f}{r}</main>{sb}<script src="/assets/app.js"></script>"#,
            top = topbar(user, admin, "search"),
            f = win("search", r#"<span class="count">ISO 8601 times and durations</span>"#, &form),
            r = win("results", "", results),
            sb = statusbar(&format!("{} · search", esc(user))),
        ),
        "",
    )
}

pub fn player(user: &str, admin: bool, id: &str) -> String {
    let stage = r#"<div class="controls">
  <span class="tabs"><button type="button" id="tab-chat" hidden>chat</button><button type="button" id="tab-play" class="on">player</button><button type="button" id="tab-text">transcript</button></span>
  <span class="grow"></span>
  <label><input type="checkbox" id="keys"> keystrokes</label>
  <label>speed <select id="speed"><option>0.5</option><option selected>1</option><option>2</option><option>4</option><option>8</option></select></label>
  <span class="font"><button type="button" id="font-dn" title="smaller text">a−</button><button type="button" id="font-up" title="larger text">a+</button></span>
  <span id="livebadge" class="badge live" hidden>live</span>
</div>
<div id="termbox" class="termbox"><div id="term"></div></div>
<pre id="text" class="transcript" hidden></pre>
<div id="chatbox" hidden>
  <div class="scrub"><input type="range" id="scrub" min="0" max="0" step="0.1" value="0" aria-label="time"><time id="scrubt"></time><span id="chattotals" class="dim small"></span></div>
  <div id="chat" class="chat"></div>
</div>
<p class="dim small" id="sizeinfo"></p>"#;
    shell(
        id,
        &format!(
            r#"{top}<main class="player" data-page="player" data-id="{id}">
<section class="stage">{st}</section>
<aside class="side">{m}{v}{c}{l}{n}</aside>
</main>{sb}<script src="/assets/asciinema-player.min.js"></script><script src="/assets/app.js"></script>"#,
            top = topbar(user, admin, "player"),
            id = esc(id),
            st = win(&format!("recording {}", esc(id)), "", stage),
            m = win("session", "", r#"<dl id="meta"></dl>"#),
            v = win("verification", "", r#"<div id="verify"></div>"#),
            c = win("commands", "", r#"<ol id="cmds" class="timeline"></ol>"#),
            l = win("nested sessions", "", r#"<ul id="links"></ul>"#),
            n = win("notes", "", r#"<ul id="notes" class="small"></ul>"#),
            sb = statusbar(&format!("{} · {}", esc(user), esc(id))),
        ),
        r#"<link rel="stylesheet" href="/assets/asciinema-player.css">"#,
    )
}
