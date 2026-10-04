// swrap web UI. All times arrive from the server as {utc, local} ISO 8601 pairs.
(function () {
  "use strict";
  const $ = (s, r) => (r || document).querySelector(s);
  // UTC (Z) unless the "local time" box is ticked (remembered per browser).
  const localBox = $("#local");
  let utc = true;
  try { utc = localStorage.getItem("swrap-local") !== "1"; } catch (e) {}
  if (localBox) {
    localBox.checked = !utc;
    localBox.addEventListener("change", () => {
      utc = !localBox.checked;
      try { localStorage.setItem("swrap-local", utc ? "0" : "1"); } catch (e) {}
      document.querySelectorAll("time[data-utc]").forEach(renderTime);
      document.dispatchEvent(new CustomEvent("swrap-tz"));
    });
  }
  function renderTime(el) { el.textContent = utc ? el.dataset.utc : el.dataset.local; }
  function timeEl(t) {
    const el = document.createElement("time");
    el.dataset.utc = t.utc; el.dataset.local = t.local; el.dateTime = t.utc;
    renderTime(el); return el;
  }
  // Exact byte count; the thin grouping only aids reading, the tooltip has the raw number.
  function bytesTd(h) {
    const c = td(String(h.bytes).replace(/\B(?=(\d{3})+(?!\d))/g, "\u202f") + (h.gz ? " gz" : ""), "num");
    c.title = h.bytes + " bytes on disk" + (h.gz ? " (gzip-compressed record)" : "");
    return c;
  }
  function td(text, cls) { const c = document.createElement("td"); if (cls) c.className = cls; if (text instanceof Node) c.appendChild(text); else c.textContent = text; return c; }

  // ------------------------------------------------------------ search
  if (document.body.querySelector("[data-page=search]")) {
    const form = $("#sf"), tbody = $("#hits tbody"), prog = $("#progress"), cancel = $("#cancel"), qline = $("#qline");
    let es = null;
    document.querySelectorAll("[data-w]").forEach(b => b.addEventListener("click", () => { $("#window").value = b.dataset.w; }));
    function quote(v) { return /\s/.test(v) && !/^["\/]/.test(v) ? '"' + v.replace(/"/g, '\\"') + '"' : v; }
    function buildQuery() {
      const parts = ["window:" + $("#window").value.trim()];
      document.querySelectorAll("[data-f]").forEach(i => {
        const v = i.value.trim(); if (!v) return;
        const neg = v.startsWith("-") && v.length > 1;
        parts.push((neg ? "-" : "") + i.dataset.f + ":" + quote(neg ? v.slice(1) : v));
      });
      const free = $("#free").value.trim(); if (free) parts.push(free);
      return parts.join(" ");
    }
    function stop() { if (es) { es.close(); es = null; } cancel.disabled = true; $("#go").disabled = false; }
    cancel.addEventListener("click", () => { stop(); prog.textContent += " — cancelled"; });
    form.addEventListener("submit", ev => {
      ev.preventDefault(); stop(); tbody.textContent = "";
      const q = buildQuery(); qline.textContent = q; prog.textContent = "searching…";
      $("#go").disabled = true; cancel.disabled = false;
      es = new EventSource("/api/search?q=" + encodeURIComponent(q));
      let n = 0;
      es.addEventListener("hit", e => {
        const h = JSON.parse(e.data); n++;
        const tr = document.createElement("tr");
        const target = h.kind === "sw" ? h.ruser + "@" + h.label : (h.label || h.exec);
        tr.append(td(timeEl(h.ts_disp), "t"), td(h.kind), td(h.user), td(target), td(h.origin + (h.exec && h.exec !== h.origin ? "→" + h.exec : "")), td(h.field), bytesTd(h), td(h.snippet, "snip"));
        tr.addEventListener("click", () => { window.location = "/play/" + encodeURIComponent(h.id) + "?at=" + encodeURIComponent(h.ts); });
        tbody.appendChild(tr);
      });
      es.addEventListener("progress", e => {
        const p = JSON.parse(e.data);
        prog.textContent = `${p.files_scanned}/${p.files_total} files, ${(p.bytes_scanned / 1048576).toFixed(1)} MiB scanned, ${p.hits} hits`;
      });
      es.addEventListener("done", e => {
        const d = JSON.parse(e.data); stop();
        if (d.error) { prog.textContent = "error: " + d.error; return; }
        const p = d.progress;
        prog.textContent = `${p.hits} hits · ${p.files_scanned}/${p.files_total} files · ${(p.bytes_scanned / 1048576).toFixed(1)} MiB` + (p.hits >= 1000 ? " (capped at 1000)" : "");
      });
      es.onerror = () => { if (es) { prog.textContent += " — connection lost"; stop(); } };
    });
  }

  // ------------------------------------------------------------ player
  const pl = document.body.querySelector("[data-page=player]");
  if (pl) {
    const id = pl.dataset.id;
    const at = new URLSearchParams(location.search).get("at") || "";
    let player = null, meta = null, font = 14, textLoaded = "";
    try { font = parseInt(localStorage.getItem("swrap-font") || "14", 10) || 14; } catch (e) {}
    const keysBox = $("#keys"), speedSel = $("#speed");
    function build(startAt) {
      const el = $("#term"); el.textContent = "";
      if (player) { try { player.dispose(); } catch (e) {} player = null; }
      const h = meta.header;
      // The terminal size recorded for this session (header), so the player looks like the original window.
      const cols = Math.max(20, Math.min(400, h.cols || 80)), rows = Math.max(5, Math.min(200, h.rows || 24));
      const src = meta.live ? { url: `/api/rec/${id}/live`, driver: "eventsource" } : `/api/rec/${id}/cast` + (keysBox.checked ? "?keys=1" : "");
      player = AsciinemaPlayer.create(src, el, {
        cols, rows, fit: false, terminalFontSize: font + "px",
        terminalFontFamily: "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace",
        idleTimeLimit: 2, speed: parseFloat(speedSel.value) || 1,
        startAt: meta.live ? undefined : startAt, autoPlay: true, preload: true, controls: true,
        markers: meta.commands.map(c => [c.t, c.cmd]),
      });
      $("#sizeinfo").textContent = `recorded terminal ${cols}×${rows} · text ${font}px · drag the corner to resize the frame`;
    }
    function now() { try { return player ? player.getCurrentTime() : 0; } catch (e) { return 0; } }
    async function load() {
      meta = await (await fetch(`/api/rec/${id}/meta` + (at ? "?at=" + encodeURIComponent(at) : ""))).json();
      renderMeta(meta);
      $("#livebadge").hidden = !meta.live;
      build(meta.start_at);
      if (meta.header.kind === "ai") {
        $("#tab-chat").hidden = false;
        if (new URLSearchParams(location.search).get("view") !== "player") await show("chat");
      }
    }
    function setFont(d) {
      font = Math.max(8, Math.min(28, font + d));
      try { localStorage.setItem("swrap-font", String(font)); } catch (e) {}
      if (meta) build(now());
    }
    $("#font-dn").addEventListener("click", () => setFont(-1));
    $("#font-up").addEventListener("click", () => setFont(+1));
    speedSel.addEventListener("change", () => meta && build(now()));
    keysBox.addEventListener("change", () => { if (meta) build(now()); if (!$("#text").hidden) showText(true); });
    document.addEventListener("swrap-tz", () => { if (!$("#text").hidden) showText(true); });
    async function showText(reload) {
      const want = (keysBox.checked ? "k" : "-") + (utc ? "u" : "l");
      if (reload || textLoaded !== want) {
        const qs = [];
        if (keysBox.checked) qs.push("keys=1");
        if (!utc) qs.push("local=1");
        $("#text").textContent = await (await fetch(`/api/rec/${id}/text` + (qs.length ? "?" + qs.join("&") : ""))).text();
        textLoaded = want;
      }
    }
    // Tabs: chat (swai sessions), player, transcript.
    const views = { chat: "#chatbox", play: "#termbox", text: "#text" };
    async function show(v) {
      Object.keys(views).forEach(k => { $("#tab-" + k).classList.toggle("on", k === v); $(views[k]).hidden = k !== v; });
      if (v === "text") await showText(false);
      if (v === "chat") await loadChat(false);
    }
    Object.keys(views).forEach(k => $("#tab-" + k).addEventListener("click", () => show(k)));

    // ---------------------------------------------------------- swai chat (spec 24.9)
    let chat = null, chatTimer = null;
    const scrub = $("#scrub"), scrubT = $("#scrubt");
    const num = n => String(n || 0).replace(/\B(?=(\d{3})+(?!\d))/g, "\u202f");
    function isoAt(sec) {
      if (!chat || !chat.start) return "";
      const d = new Date(Date.parse(chat.start) + sec * 1000);
      if (utc) return d.toISOString().replace(/\.\d{3}Z$/, "Z");
      const p = n => String(n).padStart(2, "0"), off = -d.getTimezoneOffset();
      return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}${off >= 0 ? "+" : "-"}${p(Math.floor(Math.abs(off) / 60))}:${p(Math.abs(off) % 60)}`;
    }
    function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
    function pre(text) { const p = el("pre"); p.textContent = text; return p; }
    function det(summary, body, cls) { const d = el("details", cls); const s = el("summary"); if (summary instanceof Node) s.appendChild(summary); else s.textContent = summary; d.append(s); [].concat(body).forEach(b => d.append(b)); return d; }
    function head(it, who) {
      const h = el("div", "head"); const t = timeEl(it.ts_disp || { utc: it.ts, local: it.ts });
      t.title = "move the time line here"; t.addEventListener("click", () => setScrub(it.t, true));
      h.append(t, el("span", "who", who)); return h;
    }
    function usageLine(u, it) {
      const parts = [`in ${num(u.in)}` + (u.cache_read || u.cache_write ? ` (cache read ${num(u.cache_read)}, write ${num(u.cache_write)})` : ""), `out ${num(u.out)}`];
      if (it.ttft) parts.push("first token " + it.ttft);
      if (it.latency) parts.push(it.latency);
      if (it.stop) parts.push("stop " + it.stop);
      return el("div", "meta", parts.join(" · "));
    }
    function toolEl(name, input, x) {
      const s = el("span");
      const what = x ? (x.args && (x.args.command || x.args.path || x.args.query || x.args.id)) : (input && (input.command || input.path || input.query));
      s.append("⚙ " + (x ? x.tool : name) + (x && x.target ? ` ${x.ruser}@${x.target}` : "") + (what ? ": " + String(what).split("\n")[0].slice(0, 160) : ""));
      if (x) {
        const r = x.error ? el("span", "bad", "  → error") : el("span", x.exit === 0 || x.exit === undefined || x.exit === null ? "ok" : "bad", x.exit === undefined || x.exit === null ? "  → ok" : `  → exit ${x.exit}`);
        s.append(r, ` (${x.duration})`);
      } else s.append(el("span", "bad", "  → no result recorded"));
      const body = [el("div", "meta", "arguments"), pre(JSON.stringify(x ? x.args : input, null, 2))];
      if (x) {
        body.push(el("div", "meta", "result" + (x.cut ? " (first 64 KiB; the full output is in the recording)" : "") + ` · ${num(x.out_bytes)} bytes out, ${num(x.err_bytes)} err`), pre(x.result || ""));
        const b = el("button", "link", "▶ terminal at " + isoAt(x.started_t)); b.type = "button";
        b.addEventListener("click", async () => { await show("play"); if (player) { player.seek(Math.max(0, x.started_t - 0.5)); player.play(); } });
        body.push(b);
      }
      return det(s, body, "tool");
    }
    function renderChat() {
      const box = $("#chat"), atEnd = box.scrollTop + box.clientHeight >= box.scrollHeight - 20;
      box.textContent = "";
      chat.items.forEach(it => {
        let d;
        if (it.type === "prompt") {
          d = el("div", "item user"); d.append(head(it, "▶ " + (meta.header.aaa_user || "user")));
          if (it.text) d.append(el("div", "txt", it.text + (it.cut ? "\n…" : "")));
          if (it.context && it.context.length) d.append(det(`context the harness added (${it.context.length})`, it.context.map(pre), "ctx"));
        } else if (it.type === "reply") {
          d = el("div", "item ai"); d.append(head(it, "◀ " + (it.model || "model") + " #" + it.n));
          (it.thinking || []).forEach(t => d.append(t ? det("thinking", pre(t), "ctx") : el("div", "meta", "thinking (not shown by the API)")));
          if (it.text) d.append(el("div", "txt", it.text + (it.cut ? "\n…" : "")));
          (it.tools || []).forEach(u => d.append(toolEl(u.name, u.input, u.exec)));
          d.append(usageLine(it.usage || {}, it));
        } else if (it.type === "tool") {
          d = el("div", "item"); d.append(head(it, "tool call"), toolEl(it.exec.tool, it.exec.args, it.exec));
        } else if (it.type === "error") {
          d = el("div", "item err"); d.append(head(it, "✗ inference error" + (it.status && it.status !== 200 ? " (HTTP " + it.status + ")" : "") + (it.cancelled ? " (cancelled)" : "")), el("div", "txt", it.error || ""));
        } else if (it.type === "helper") {
          d = el("div", "item dim"); d.append(head(it, `helper request #${it.n} (${it.model || "model"}: title, compaction…)`), usageLine(it.usage || {}, it));
        } else {
          d = el("div", "item dim"); d.append(head(it, "note"), el("div", "txt", it.msg || ""));
        }
        d.dataset.t = it.t; box.appendChild(d);
      });
      if (chat.end && chat.end.ts) { const d = el("div", "item dim"); d.append(head(chat.end, `end: ${chat.end.reason}` + (chat.end.exit_code !== undefined && chat.end.exit_code !== null ? ` (exit code ${chat.end.exit_code})` : ""))); d.dataset.t = chat.end.t; box.appendChild(d); }
      const t = chat.totals || {};
      $("#chattotals").textContent = `${t.requests} requests, ${t.tool_calls} tool calls, ${t.errors} errors · in ${num(t.in)} · out ${num(t.out)}` + (t.helper_requests ? ` · ${t.helper_requests} helper requests` : "");
      const last = chat.end && chat.end.t ? chat.end.t : (chat.items.length ? chat.items[chat.items.length - 1].t : 0);
      scrub.max = String(Math.max(0, last));
      if (chat.live && atEnd) { box.scrollTop = box.scrollHeight; setScrub(last, false); } else scrubT.textContent = isoAt(parseFloat(scrub.value));
    }
    function setScrub(sec, move) {
      scrub.value = String(sec); scrubT.textContent = isoAt(sec);
      const items = [...$("#chat").children];
      let cur = null; items.forEach(e => { e.classList.remove("at"); if (parseFloat(e.dataset.t) <= sec + 0.001) cur = e; });
      if (cur) { cur.classList.add("at"); if (move) cur.scrollIntoView({ block: "center" }); }
    }
    scrub.addEventListener("input", () => setScrub(parseFloat(scrub.value), true));
    document.addEventListener("swrap-tz", () => { if (chat) scrubT.textContent = isoAt(parseFloat(scrub.value)); });
    async function loadChat(reload) {
      if (chat && !reload) return;
      chat = await (await fetch(`/api/rec/${id}/chat`)).json();
      renderChat();
      if (!reload) {
        // Opened from a search hit: start at that moment.
        const t0 = Date.parse(chat.start), a = Date.parse(at);
        if (at && t0 && a) setScrub(Math.max(0, (a - t0) / 1000), true);
      }
      if (chat.live && !chatTimer) chatTimer = setInterval(() => { if (!$("#chatbox").hidden) loadChat(true); }, 5000);
      if (!chat.live && chatTimer) { clearInterval(chatTimer); chatTimer = null; }
    }
    function renderMeta(m) {
      const dl = $("#meta"); dl.textContent = "";
      const h = m.header;
      const add = (k, v) => { if (v === undefined || v === null || v === "") return; const dt = document.createElement("dt"); dt.textContent = k; const dd = document.createElement("dd"); if (v instanceof Node) dd.appendChild(v); else dd.textContent = String(v); dl.append(dt, dd); };
      add("id", m.id); add("kind", h.kind); add("user", h.aaa_user);
      add("target", h.kind === "sw" ? `${h.ruser}@${h.label} (${h.addr}:${h.port})` : h.kind === "ai" ? (h.mode === "aaa" ? "aaa (all AI hosts)" : `${h.ruser}@${h.label}`) : h.label);
      if (h.kind === "ai") { add("inference", `${h.backend} · ${h.model}`); add("effort", h.effort || "default"); add("harness", h.harness); }
      add("start", timeEl(m.start)); if (m.end) { add("end", timeEl(m.end.ts)); add("duration", m.end.duration); add("reason", m.end.reason); add("exit code", m.end.exit_code); }
      add("origin", h.origin); add("exec", h.exec); add("delegated", h.delegated); add("client", h.client_addr); add("terminal", h.cols ? `${h.cols}×${h.rows} ${h.term || ""}` : "");
      if (m.crypto && m.crypto.kex) { add("kex", m.crypto.kex); add("host key", m.crypto.server_key); add("cipher", m.crypto.cipher_s2c); add("hostbound", m.crypto.hostbound); }
      else add("hostbound", h.hostbound);
      add("profile", h.profile); add("ssh", h.ssh_version); add("config rev", h.config_rev);
      const v = m.verify, vd = $("#verify"); vd.textContent = "";
      const st = document.createElement("div"); st.className = /^ok|live/.test(v.status) ? "st-ok" : "st-bad";
      st.textContent = v.status + (v.signature === true ? ` · signed by ${v.signer}` : v.signature === false ? " · BAD SIGNATURE" : "") + ` · ${v.records} records · ${v.segments_ok} segments ok`;
      vd.appendChild(st);
      [...v.damaged.map(x => "damaged: " + x), ...v.gaps.map(g => `gap: s=${g[0]}..${g[1]}`), ...v.notes].forEach(t => { const d = document.createElement("div"); d.className = "small st-bad"; d.textContent = t; vd.appendChild(d); });
      const ol = $("#cmds"); ol.textContent = "";
      m.commands.forEach(c => { const li = document.createElement("li"); li.append(timeEl(c.ts), " ", c.cmd + (c.exit !== undefined && c.exit !== null ? `  [${c.exit}]` : "") + (c.src === "heuristic" ? "  (heuristic)" : "")); li.addEventListener("click", () => { if (player) { player.seek(Math.max(0, c.t - 0.5)); player.play(); } }); ol.appendChild(li); });
      const ul = $("#links"); ul.textContent = "";
      m.links.filter(l => l.phase === "start").forEach(l => { const li = document.createElement("li"); const a = document.createElement("a"); a.href = "/play/" + encodeURIComponent(l.sw); a.textContent = l.sw; li.append(timeEl(l.ts), " ", a); ul.appendChild(li); });
      const nl = $("#notes"); nl.textContent = "";
      m.notes.forEach(n => { const li = document.createElement("li"); li.append(timeEl(n.ts), " ", n.msg); nl.appendChild(li); });
    }
    load().catch(e => { $("#term").textContent = "failed to load: " + e; });
  }
})();
