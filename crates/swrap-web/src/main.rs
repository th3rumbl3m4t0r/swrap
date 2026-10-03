//! swrap-web: playback and search GUI on core (spec 16). Read-only apart from login/logout.
//!
//! * TLS terminates here (rustls). Every request's source address must be on the web allow-list
//!   (`config/firewall.toml`, re-read per request); the GUI denies everyone by default.
//! * Login: AAA user + web password (argon2id, set with `swpasswd`); cookie `HttpOnly; Secure;
//!   SameSite=Strict`, lifetime from `web.session_lifetime`; backoff per source and per user;
//!   every attempt audited.
//! * Users see their own records; admins see everything.

mod pages;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::{Form, Path as UrlPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, Response, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Extension, Router};
use futures_util::Stream;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use swrap_core::config::{Firewall, Role, SwrapConfig, User};
use swrap_core::time::{fmt_display, fmt_utc_secs, now};
use swrap_core::Paths;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

#[derive(Clone, Copy)]
struct ClientIp(IpAddr);

struct Sess {
    user: String,
    admin: bool,
    expires: Instant,
}

struct AppState {
    paths: Paths,
    sessions: Mutex<HashMap<String, Sess>>,
    fails: Mutex<HashMap<String, (u32, Instant)>>,
}

type St = Arc<AppState>;

fn cfg(s: &AppState) -> SwrapConfig {
    SwrapConfig::load(&s.paths).unwrap_or_default()
}

fn audit(action: &str, result: &str, detail: Value) {
    use swrap_core::frame::{kind, read_frame, write_frame, Frame};
    if let Ok(mut s) = std::os::unix::net::UnixStream::connect(Paths::from_env().api_sock()) {
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        let req = swrap_core::api::Req::Audit { action: action.into(), target: "web".into(), result: result.into(), detail };
        let _ = write_frame(&mut s, &Frame::json(kind::REQ, &req));
        let _ = read_frame(&mut s);
    }
}

// ---------------------------------------------------------------- allow-list

fn active(e: &swrap_core::config::FwEntry, t: jiff::Timestamp) -> bool {
    let nb = e.not_before.as_deref().and_then(|s| swrap_core::time::parse_datetime(s).ok());
    let na = e.not_after.as_deref().and_then(|s| swrap_core::time::parse_datetime(s).ok());
    nb.map(|x| t >= x).unwrap_or(true) && na.map(|x| t < x).unwrap_or(true)
}

fn allowed(s: &AppState, ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    let fw = Firewall::load(&s.paths).unwrap_or_default();
    let t = now();
    fw.web_allow.iter().filter(|e| active(e, t)).any(|e| e.cidr.parse::<ipnet::IpNet>().map(|n| n.contains(&ip)).unwrap_or(false))
}

async fn allowlist(State(s): State<St>, Extension(ClientIp(ip)): Extension<ClientIp>, req: Request<Body>, next: axum::middleware::Next) -> Response<Body> {
    if !allowed(&s, ip) {
        return (StatusCode::FORBIDDEN, "swrap: this source address is not on the web allow-list (swfw web allow)\n").into_response();
    }
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    );
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

// ---------------------------------------------------------------- auth

fn cookie_token(h: &HeaderMap) -> Option<String> {
    let c = h.get(header::COOKIE)?.to_str().ok()?;
    c.split(';').map(str::trim).find_map(|kv| kv.strip_prefix("swrap_session=").map(String::from))
}

fn who(s: &AppState, h: &HeaderMap) -> Option<(String, bool)> {
    let t = cookie_token(h)?;
    let mut m = s.sessions.lock().unwrap();
    match m.get(&t) {
        Some(x) if x.expires > Instant::now() => {
            // Re-check the account on every request (disabled users lose access immediately).
            match User::load(&s.paths, &x.user) {
                Ok(u) if !u.disabled => Some((x.user.clone(), u.role == Role::Admin)),
                _ => None,
            }
        }
        Some(_) => {
            m.remove(&t);
            None
        }
        None => None,
    }
}

#[derive(Deserialize)]
struct LoginForm {
    user: String,
    password: String,
}

fn backoff_left(s: &AppState, key: &str) -> Option<u64> {
    let f = s.fails.lock().unwrap();
    let (n, at) = f.get(key)?;
    if *n < 3 {
        return None;
    }
    let wait = Duration::from_secs((1u64 << (*n - 3).min(6)).min(60));
    let el = at.elapsed();
    (el < wait).then(|| (wait - el).as_secs() + 1)
}

fn note_fail(s: &AppState, key: &str) {
    let mut f = s.fails.lock().unwrap();
    let e = f.entry(key.to_string()).or_insert((0, Instant::now()));
    e.0 += 1;
    e.1 = Instant::now();
}

fn verify_password(paths: &Paths, user: &str, pw: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    if !swrap_core::paths::safe_component(user) {
        return false;
    }
    let Ok(stored) = std::fs::read_to_string(paths.webpw(user)) else { return false };
    let Ok(h) = PasswordHash::new(stored.trim()) else { return false };
    argon2::Argon2::default().verify_password(pw.as_bytes(), &h).is_ok()
}

async fn login(State(s): State<St>, Extension(ClientIp(ip)): Extension<ClientIp>, Form(f): Form<LoginForm>) -> Response<Body> {
    let src_key = format!("ip:{ip}");
    let user_key = format!("user:{}", f.user);
    if let Some(w) = backoff_left(&s, &src_key).or_else(|| backoff_left(&s, &user_key)) {
        audit("web.login", "backoff", json!({"user": f.user, "src": ip.to_string()}));
        // The journal line fail2ban's swrap-web jail reads.
        eprintln!("swrap-web: login throttled for {:?} from {ip}", f.user);
        return Html(pages::login(&format!("Too many failed attempts; wait PT{w}S."))).into_response();
    }
    let paths = s.paths.clone();
    let (u, p) = (f.user.clone(), f.password.clone());
    let ok = tokio::task::spawn_blocking(move || {
        let acct = User::load(&paths, &u).ok().filter(|x| !x.disabled);
        acct.is_some() && verify_password(&paths, &u, &p)
    })
    .await
    .unwrap_or(false);
    if !ok {
        note_fail(&s, &src_key);
        note_fail(&s, &user_key);
        audit("web.login", "fail", json!({"user": f.user, "src": ip.to_string()}));
        eprintln!("swrap-web: login failed for {:?} from {ip}", f.user);
        return Html(pages::login("Login failed.")).into_response();
    }
    s.fails.lock().unwrap().remove(&user_key);
    let admin = User::load(&s.paths, &f.user).map(|u| u.role == Role::Admin).unwrap_or(false);
    let lifetime = cfg(&s).web.session_lifetime.exact().unwrap_or(Duration::from_secs(12 * 3600));
    let token: String = {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect()
    };
    s.sessions.lock().unwrap().insert(token.clone(), Sess { user: f.user.clone(), admin, expires: Instant::now() + lifetime });
    audit("web.login", "ok", json!({"user": f.user, "src": ip.to_string()}));
    let mut r = Redirect::to("/").into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!("swrap_session={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}", lifetime.as_secs())).unwrap(),
    );
    r
}

async fn logout(State(s): State<St>, h: HeaderMap) -> Response<Body> {
    if let Some(t) = cookie_token(&h) {
        if let Some(x) = s.sessions.lock().unwrap().remove(&t) {
            audit("web.logout", "ok", json!({"user": x.user}));
        }
    }
    let mut r = Redirect::to("/").into_response();
    r.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_static("swrap_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"));
    r
}

// ---------------------------------------------------------------- pages

async fn index(State(s): State<St>, h: HeaderMap) -> Response<Body> {
    match who(&s, &h) {
        None => Html(pages::login("")).into_response(),
        Some((u, admin)) => Html(pages::search(&u, admin, &cfg(&s).web.search_default_window)).into_response(),
    }
}

async fn play_page(State(s): State<St>, h: HeaderMap, UrlPath(id): UrlPath<String>) -> Response<Body> {
    match who(&s, &h) {
        None => Redirect::to("/").into_response(),
        Some((u, admin)) => {
            if !swrap_core::paths::safe_component(&id) {
                return StatusCode::BAD_REQUEST.into_response();
            }
            Html(pages::player(&u, admin, &id)).into_response()
        }
    }
}

async fn asset(UrlPath(name): UrlPath<String>) -> Response<Body> {
    let (ct, body): (&str, &'static [u8]) = match name.as_str() {
        "asciinema-player.min.js" => ("text/javascript", include_bytes!("../assets/asciinema-player.min.js")),
        "asciinema-player.css" => ("text/css", include_bytes!("../assets/asciinema-player.css")),
        "app.js" => ("text/javascript", include_bytes!("../assets/app.js")),
        "app.css" => ("text/css", include_bytes!("../assets/app.css")),
        "LICENSE-asciinema-player.txt" => ("text/plain", include_bytes!("../assets/asciinema-player.LICENSE")),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    ([(header::CONTENT_TYPE, ct)], body).into_response()
}

// ---------------------------------------------------------------- record APIs

fn resolve(s: &AppState, h: &HeaderMap, id: &str) -> Result<(PathBuf, String, bool), StatusCode> {
    let (u, admin) = who(s, h).ok_or(StatusCode::UNAUTHORIZED)?;
    if id.len() < 26 || !swrap_core::paths::safe_component(id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let users = if admin { None } else { Some(vec![u.clone()]) };
    let p = swrec::search::find_record(&s.paths.root, users.as_deref(), id).ok_or(StatusCode::NOT_FOUND)?;
    Ok((p, u, admin))
}

fn is_live(s: &AppState, id: &str) -> bool {
    let p = s.paths.live().join(id);
    std::fs::read_to_string(p)
        .ok()
        .and_then(|x| serde_json::from_str::<Value>(&x).ok())
        .and_then(|j| j["pid"].as_i64())
        .map(|pid| pid > 0 && (unsafe { libc::kill(pid as i32, 0) } == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)))
        .unwrap_or(false)
}

fn disp(ts: &str, tz: &str) -> Value {
    match ts.parse::<jiff::Timestamp>() {
        Ok(t) => json!({"utc": fmt_utc_secs(t), "local": fmt_display(t, tz, false)}),
        Err(_) => json!({"utc": ts, "local": ts}),
    }
}

#[derive(Deserialize)]
struct MetaQ {
    at: Option<String>,
}

async fn rec_meta(State(s): State<St>, h: HeaderMap, UrlPath(id): UrlPath<String>, Query(q): Query<MetaQ>) -> Response<Body> {
    let (path, user, admin) = match resolve(&s, &h, &id) {
        Ok(x) => x,
        Err(c) => return c.into_response(),
    };
    let live = is_live(&s, &id);
    let tz = cfg(&s).general.display_timezone;
    let st = s.clone();
    let r = tokio::task::spawn_blocking(move || -> Result<Value> {
        let v = swrec::RecVerifier::for_core(&st.paths);
        let scan = swrec::scan(&path, swrec::ScanOpts { verifier: Some(&v), keep_records: true, live })?;
        let header = scan.header.clone().unwrap_or_default();
        let cast = swrec::render::to_asciicast(&header, &scan.records, 2.0, false);
        let offset_of = |ts: &str| -> f64 {
            let i = cast.marks.partition_point(|(t, _)| t.as_str() < ts);
            cast.marks.get(i).or_else(|| cast.marks.last()).map(|x| x.1).unwrap_or(0.0)
        };
        let mut cmds = vec![];
        let mut links = vec![];
        let mut notes = vec![];
        let mut crypto = Value::Null;
        for m in &scan.records {
            let ts = m.get("ts").and_then(Value::as_str).unwrap_or("");
            match m.get("k").and_then(Value::as_str) {
                Some("x") => cmds.push(json!({"t": offset_of(ts), "ts": disp(ts, &tz), "cmd": m.get("cmd"), "src": m.get("src"), "exit": m.get("exit")})),
                Some("l") => links.push(json!({"t": offset_of(ts), "ts": disp(ts, &tz), "sw": m.get("sw"), "phase": m.get("phase")})),
                Some("n") => {
                    if m.get("kex").is_some() {
                        crypto = Value::Object(m.clone());
                    }
                    notes.push(json!({"ts": disp(ts, &tz), "msg": m.get("msg")}));
                }
                Some("f") => notes.push(json!({"ts": disp(ts, &tz), "msg": format!("{} {} {} {}", m.get("op").and_then(Value::as_str).unwrap_or(""), m.get("path").and_then(Value::as_str).unwrap_or(""), m.get("result").and_then(Value::as_str).unwrap_or(""), m.get("bytes").map(|b| b.to_string()).unwrap_or_default())})),
                _ => {}
            }
        }
        let start_at = q.at.as_deref().map(|ts| (offset_of(ts) - 2.0).max(0.0)).unwrap_or(0.0);
        let mut hdr = Map::new();
        for (k, v) in &header {
            if k != "k" {
                hdr.insert(k.clone(), v.clone());
            }
        }
        let start = header.get("start").and_then(Value::as_str).unwrap_or("");
        Ok(json!({
            "id": id, "viewer": user, "admin": admin, "live": live,
            "header": hdr, "start": disp(start, &tz),
            "end": scan.end.as_ref().map(|e| json!({"reason": e.get("reason"), "exit_code": e.get("exit_code"), "duration": e.get("duration"), "ts": disp(e.get("ts").and_then(Value::as_str).unwrap_or(""), &tz)})),
            "verify": scan.report, "commands": cmds, "links": links, "notes": notes, "crypto": crypto,
            "start_at": start_at, "duration": cast.duration,
        }))
    })
    .await;
    match r {
        Ok(Ok(v)) => axum::Json(v).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
struct CastQ {
    keys: Option<String>,
}

async fn rec_cast(State(s): State<St>, h: HeaderMap, UrlPath(id): UrlPath<String>, Query(q): Query<CastQ>) -> Response<Body> {
    let (path, _, _) = match resolve(&s, &h, &id) {
        Ok(x) => x,
        Err(c) => return c.into_response(),
    };
    let keys = q.keys.as_deref() == Some("1");
    let r = tokio::task::spawn_blocking(move || -> Result<String> {
        let scan = swrec::scan(&path, swrec::ScanOpts { verifier: None, keep_records: true, live: false })?;
        let h = scan.header.context("no header")?;
        Ok(swrec::render::to_asciicast(&h, &scan.records, 2.0, keys).text)
    })
    .await;
    match r {
        Ok(Ok(t)) => ([(header::CONTENT_TYPE, "application/x-asciicast")], t).into_response(),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Plain transcript (the same rendering as `swcat --cmds`), for reading instead of watching.
async fn rec_text(State(s): State<St>, h: HeaderMap, UrlPath(id): UrlPath<String>, Query(q): Query<CastQ>) -> Response<Body> {
    let (path, _, _) = match resolve(&s, &h, &id) {
        Ok(x) => x,
        Err(c) => return c.into_response(),
    };
    let keys = q.keys.as_deref() == Some("1");
    let tz = cfg(&s).general.display_timezone;
    let r = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let scan = swrec::scan(&path, swrec::ScanOpts { verifier: None, keep_records: true, live: false })?;
        let mut out = vec![];
        let o = swrec::text::CatOpts { tz: &tz, utc: false, keys, cmds: true, raw: false };
        swrec::text::cat(None, &scan.records, &o, &mut out)?;
        Ok(out)
    })
    .await;
    match r {
        Ok(Ok(t)) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], t).into_response(),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Live follow: asciinema-player's eventsource driver. Header with the output so far, then events.
async fn rec_live(State(s): State<St>, h: HeaderMap, UrlPath(id): UrlPath<String>) -> Response<Body> {
    let (path, _, _) = match resolve(&s, &h, &id) {
        Ok(x) => x,
        Err(c) => return c.into_response(),
    };
    let (tx, rx) = tokio::sync::mpsc::channel::<Event>(256);
    let st = s.clone();
    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Seek, SeekFrom};
        let mut init = String::new();
        let mut cols = 80;
        let mut rows = 24;
        let mut pos = 0u64;
        let mut start: Option<f64> = None;
        let mut ended = false;
        let consume = |buf: &[u8], init_mode: bool, start: &mut Option<f64>, init: &mut String, cols: &mut u64, rows: &mut u64, out: &mut Vec<Value>, ended: &mut bool, ex: &mut swrec::repeat::Expander| -> usize {
            let mut used = 0;
            for line in buf.split_inclusive(|&b| b == b'\n') {
                if !line.ends_with(b"\n") {
                    break;
                }
                used += line.len();
                let Ok(m) = swrec::format::decode_line(&line[..line.len() - 1]) else { continue };
                let k = m.get("k").and_then(Value::as_str).unwrap_or("");
                if k == "h" {
                    *cols = m.get("cols").and_then(Value::as_u64).unwrap_or(80);
                    *rows = m.get("rows").and_then(Value::as_u64).unwrap_or(24);
                    *start = m.get("start").and_then(Value::as_str).and_then(|t| t.parse::<jiff::Timestamp>().ok()).map(|t| t.as_microsecond() as f64 / 1e6);
                    continue;
                }
                let t = m.get("ts").and_then(Value::as_str).and_then(|t| t.parse::<jiff::Timestamp>().ok()).map(|t| t.as_microsecond() as f64 / 1e6).unwrap_or(0.0) - start.unwrap_or(0.0);
                // Repeats (`p`) stand for output events: expand them in place.
                let events = ex.feed(&m).unwrap_or_default();
                match k {
                    "o" if m.contains_key("call") => {}
                    "o" => {
                        let d = String::from_utf8_lossy(&swrec::render::rec_bytes(&m)).into_owned();
                        if init_mode { init.push_str(&d) } else { out.push(json!([t, "o", d])) }
                    }
                    "p" => {
                        for (us, d) in events {
                            if init_mode {
                                init.push_str(&d);
                            } else {
                                out.push(json!([us as f64 / 1e6 - start.unwrap_or(0.0), "o", &*d]));
                            }
                        }
                    }
                    "r" => {
                        *cols = m.get("cols").and_then(Value::as_u64).unwrap_or(*cols);
                        *rows = m.get("rows").and_then(Value::as_u64).unwrap_or(*rows);
                        if !init_mode {
                            out.push(json!([t, "r", format!("{}x{}", cols, rows)]));
                        }
                    }
                    "e" => *ended = true,
                    _ => {}
                }
            }
            used
        };
        let Ok(mut f) = std::fs::File::open(&path) else { return };
        let mut buf = vec![];
        let _ = f.read_to_end(&mut buf);
        let mut ev = vec![];
        let mut ex = swrec::repeat::Expander::default();
        pos += consume(&buf, true, &mut start, &mut init, &mut cols, &mut rows, &mut ev, &mut ended, &mut ex) as u64;
        let elapsed = start.map(|s0| now().as_microsecond() as f64 / 1e6 - s0).unwrap_or(0.0);
        let hdr = json!({"cols": cols, "rows": rows, "time": elapsed, "init": init});
        if tx.blocking_send(Event::default().data(hdr.to_string())).is_err() {
            return;
        }
        let mut idle = 0;
        while !ended {
            std::thread::sleep(Duration::from_millis(200));
            let mut b = vec![];
            if f.seek(SeekFrom::Start(pos)).is_err() || f.read_to_end(&mut b).is_err() {
                break;
            }
            let mut out = vec![];
            let mut dummy = String::new();
            pos += consume(&b, false, &mut start, &mut dummy, &mut cols, &mut rows, &mut out, &mut ended, &mut ex) as u64;
            for e in out {
                if tx.blocking_send(Event::default().data(e.to_string())).is_err() {
                    return;
                }
            }
            if b.is_empty() && !is_live(&st, &id) {
                idle += 1;
                if idle > 10 {
                    break;
                }
            }
        }
        let _ = tx.blocking_send(Event::default().event("done").data("{}"));
    });
    let stream = ReceiverStream::new(rx).map(Ok::<_, Infallible>);
    Sse::new(stream).keep_alive(KeepAlive::default()).into_response()
}

#[derive(Deserialize)]
struct SearchQ {
    q: String,
}

async fn api_search(State(s): State<St>, h: HeaderMap, Query(sq): Query<SearchQ>) -> Response<Body> {
    let Some((user, admin)) = who(&s, &h) else { return StatusCode::UNAUTHORIZED.into_response() };
    let c = cfg(&s);
    let mut q = match swrec::search::Query::parse(&sq.q) {
        Ok(q) => q,
        Err(e) => return sse_error(e.to_string()),
    };
    if q.window.is_none() {
        q.window = swrap_core::time::Interval::parse(&c.web.search_default_window).ok();
    }
    if !admin && q.terms.iter().any(|t| t.field == swrec::search::Field::User) {
        return sse_error("user: is for admins".into());
    }
    audit("web.search", "ok", json!({"user": user, "query": sq.q}));
    let (tx, rx) = tokio::sync::mpsc::channel::<Event>(512);
    let root = s.paths.root.clone();
    let tz = c.general.display_timezone.clone();
    let max = c.web.search_max_results;
    tokio::task::spawn_blocking(move || {
        let cancel = AtomicBool::new(false);
        let opts = swrec::search::SearchOpts { root, users: if admin { None } else { Some(vec![user]) }, max_results: max, cancel: &cancel, kinds: vec![] };
        let on_hit = |hit: &swrec::search::Hit| {
            let mut v = serde_json::to_value(hit).unwrap();
            v["ts_disp"] = disp(&hit.ts, &tz);
            v["start_disp"] = disp(&hit.start, &tz);
            v.as_object_mut().unwrap().remove("path");
            if tx.blocking_send(Event::default().event("hit").data(v.to_string())).is_err() {
                cancel.store(true, Ordering::Relaxed);
            }
        };
        let on_progress = |p: &swrec::search::Progress| {
            if tx.blocking_send(Event::default().event("progress").data(serde_json::to_string(p).unwrap())).is_err() {
                cancel.store(true, Ordering::Relaxed);
            }
        };
        let window = q.window.unwrap();
        let r = swrec::search::run(&q, &opts, &on_hit, &on_progress);
        let done = match r {
            Ok(p) => json!({"progress": p, "window": {"start": disp(&fmt_utc_secs(window.start), &tz), "end": disp(&fmt_utc_secs(window.end), &tz)}}),
            Err(e) => json!({"error": e.to_string()}),
        };
        let _ = tx.blocking_send(Event::default().event("done").data(done.to_string()));
    });
    let stream = ReceiverStream::new(rx).map(Ok::<_, Infallible>);
    Sse::new(stream).keep_alive(KeepAlive::default()).into_response()
}

fn sse_error(msg: String) -> Response<Body> {
    let stream: std::pin::Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>> =
        Box::pin(tokio_stream::iter(vec![Ok(Event::default().event("done").data(json!({"error": msg}).to_string()))]));
    Sse::new(stream).into_response()
}

// ---------------------------------------------------------------- serving

fn tls_config(c: &SwrapConfig) -> Result<Arc<rustls::ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(&c.web.tls_cert).with_context(|| c.web.tls_cert.clone())?))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(&c.web.tls_key).with_context(|| c.web.tls_key.clone())?))?
        .context("no private key")?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn app(state: St) -> Router<()> {
    Router::new()
        .route("/", get(index))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/play/{id}", get(play_page))
        .route("/api/search", get(api_search))
        .route("/api/rec/{id}/meta", get(rec_meta))
        .route("/api/rec/{id}/cast", get(rec_cast))
        .route("/api/rec/{id}/text", get(rec_text))
        .route("/api/rec/{id}/live", get(rec_live))
        .route("/assets/{name}", get(asset))
        .layer(axum::middleware::from_fn_with_state(state.clone(), allowlist))
        .with_state(state)
}

async fn serve_tls(addr: SocketAddr, state: St) -> Result<()> {
    let c = cfg(&state);
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config(&c)?);
    let l = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("bind {addr}"))?;
    eprintln!("swrap-web: listening on https://{addr}");
    let router = app(state.clone());
    loop {
        let (tcp, peer) = l.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        let st = state.clone();
        tokio::spawn(async move {
            // Drop non-allow-listed sources before the TLS handshake (defence in depth; nft does it first).
            if !allowed(&st, peer.ip()) {
                return;
            }
            let Ok(tls) = acceptor.accept(tcp).await else { return };
            let ip = ClientIp(peer.ip());
            let svc = tower::ServiceExt::map_request(router, move |mut r: Request<hyper::body::Incoming>| {
                r.extensions_mut().insert(ip);
                r
            });
            let svc = hyper_util::service::TowerToHyperService::new(svc);
            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                .await;
        });
    }
}

/// Relay from edge (spec 13.3): `SWRAP-RELAY/1 {json}\n` then raw TLS bytes. Edge already applied
/// the allow-list; we re-check the reported source address before the handshake.
async fn serve_ingress(state: St) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let p = state.paths.ingress_web_sock();
    let _ = std::fs::remove_file(&p);
    let l = tokio::net::UnixListener::bind(&p).with_context(|| format!("bind {}", p.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config(&cfg(&state))?);
    let router = app(state.clone());
    loop {
        let (mut u, _) = l.accept().await?;
        let (acceptor, router, st) = (acceptor.clone(), router.clone(), state.clone());
        tokio::spawn(async move {
            let mut line = vec![];
            let mut b = [0u8; 1];
            while line.len() < 1024 {
                if u.read_exact(&mut b).await.is_err() {
                    return;
                }
                if b[0] == b'\n' {
                    break;
                }
                line.push(b[0]);
            }
            let line = String::from_utf8_lossy(&line).to_string();
            let Some(js) = line.strip_prefix("SWRAP-RELAY/1 ") else { return };
            let Ok(v) = serde_json::from_str::<Value>(js) else { return };
            let Some(ip) = v["src"].as_str().and_then(|s| s.parse::<IpAddr>().ok()) else { return };
            if !allowed(&st, ip) {
                audit("web.relay", "refused", json!({"src": ip.to_string()}));
                return;
            }
            let Ok(tls) = acceptor.accept(u).await else { return };
            let cip = ClientIp(ip);
            let svc = tower::ServiceExt::map_request(router, move |mut r: Request<hyper::body::Incoming>| {
                r.extensions_mut().insert(cip);
                r
            });
            let svc = hyper_util::service::TowerToHyperService::new(svc);
            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                .await;
        });
    }
}

fn main() -> Result<()> {
    let paths = Paths::from_env();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build()?;
    rt.block_on(async move {
        let state = Arc::new(AppState { paths, sessions: Mutex::new(HashMap::new()), fails: Mutex::new(HashMap::new()) });
        let c = cfg(&state);
        let mut tasks = vec![];
        for b in &c.web.bind {
            if b.starts_with("unix:") {
                // Relayed traffic from edge (PROXY v2 via swrap-ingress) arrives with the edge node.
                continue;
            }
            let addr: SocketAddr = b.parse().with_context(|| format!("bad web.bind {b}"))?;
            tasks.push(tokio::spawn(serve_tls(addr, state.clone())));
        }
        tasks.push(tokio::spawn(serve_ingress(state.clone())));
        // Expire sessions.
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                st.sessions.lock().unwrap().retain(|_, s| s.expires > Instant::now());
            }
        });
        // Any listener failing is fatal (systemd restarts us and the journal shows why).
        let (r, _, _) = futures_util::future::select_all(tasks).await;
        r??;
        Ok(())
    })
}
