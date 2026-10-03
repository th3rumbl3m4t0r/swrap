// swrap web UI. All times arrive from the server as {utc, local} ISO 8601 pairs.
(function () {
  "use strict";
  const $ = (s, r) => (r || document).querySelector(s);
  const utcBox = $("#utc");
  let utc = false;
  try { utc = localStorage.getItem("swrap-utc") === "1"; } catch (e) {}
  if (utcBox) {
    utcBox.checked = utc;
    utcBox.addEventListener("change", () => {
      utc = utcBox.checked;
      try { localStorage.setItem("swrap-utc", utc ? "1" : "0"); } catch (e) {}
      document.querySelectorAll("time[data-utc]").forEach(renderTime);
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
    async function showText(reload) {
      const want = keysBox.checked ? "1" : "0";
      if (reload || textLoaded !== want) {
        $("#text").textContent = await (await fetch(`/api/rec/${id}/text` + (want === "1" ? "?keys=1" : ""))).text();
        textLoaded = want;
      }
    }
    $("#tab-play").addEventListener("click", () => { $("#tab-play").classList.add("on"); $("#tab-text").classList.remove("on"); $("#termbox").hidden = false; $("#text").hidden = true; });
    $("#tab-text").addEventListener("click", async () => { $("#tab-text").classList.add("on"); $("#tab-play").classList.remove("on"); $("#termbox").hidden = true; $("#text").hidden = false; await showText(false); });
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
