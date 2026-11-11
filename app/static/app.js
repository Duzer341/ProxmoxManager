/* Shared helpers for all pages. No framework, no external dependencies. */
(function () {
  "use strict";

  const PM = (window.PM = {});

  // ---------- formatting ----------
  PM.bytes = function (n) {
    if (!n) return "0 B";
    const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let i = 0;
    n = Number(n);
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(n >= 100 ? 0 : 1)) + " " + units[i];
  };

  PM.uptime = function (s) {
    if (!s) return "-";
    s = Math.floor(s);
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d) return d + "d " + h + "h";
    if (h) return h + "h " + m + "m";
    return m + "m";
  };

  PM.duration = function (s) {
    s = Math.round(s || 0);
    if (s < 120) return s + "s";
    return PM.uptime(s);
  };

  // Copy text; navigator.clipboard needs HTTPS, so fall back to execCommand on plain http.
  PM.copy = function (text, label) {
    function legacy() {
      const ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.top = "-1000px";
      document.body.appendChild(ta); ta.select();
      let ok = false; try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      document.body.removeChild(ta); return ok;
    }
    const done = function () { PM.toast((label || "Text") + " copied", "ok"); };
    const fail = function () { PM.toast("Could not copy automatically; select the text and press Ctrl+C.", "bad"); };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, function () { legacy() ? done() : fail(); });
    else legacy() ? done() : fail();
  };

  PM.ago = function (iso) {
    if (!iso) return "never";
    const diff = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (diff < 5) return "just now";
    if (diff < 60) return Math.floor(diff) + "s ago";
    if (diff < 3600) return Math.floor(diff / 60) + "m ago";
    if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
    return Math.floor(diff / 86400) + "d ago";
  };

  PM.when = function (iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    return d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
  };

  // when a host can't be reached, when it last answered (the figures shown are from then)
  PM.lastUp = function (h) {
    if (!h.last_ok_at) return "Not reached since it was added.";
    return "Last up " + PM.ago(h.last_ok_at) + " (" + PM.when(h.last_ok_at) + ")" + (h.summary ? ". Figures shown are from then." : ".");
  };

  // footer text: a host that answered shows when; a failing host shows the last attempt, so it's clear it's still being tried
  PM.pollText = function (h) {
    if (!h.enabled) return h.last_ok_at ? "polled " + PM.ago(h.last_ok_at) + " · polling disabled" : "polling disabled";
    if (h.last_error && h.last_poll_at) return "last tried " + PM.ago(h.last_poll_at);
    return h.last_ok_at ? "polled " + PM.ago(h.last_ok_at) : "never polled";
  };

  PM.pollTitle = function (h) {
    return "Last attempt: " + PM.when(h.last_poll_at) + "\nLast success: " + PM.when(h.last_ok_at);
  };

  PM.pct = function (v) { return (v == null ? "-" : Number(v).toFixed(1) + "%"); };

  PM.level = function (pct, warn, bad) {
    warn = warn == null ? 75 : warn; bad = bad == null ? 90 : bad;
    if (pct >= bad) return "bad";
    if (pct >= warn) return "warn";
    return "";
  };

  PM.esc = function (s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  };

  PM.meter = function (label, pct, right, avg, warn, bad) {
    const lvl = PM.level(pct, warn, bad);
    const marker = avg != null ? '<b style="left:' + Math.min(100, Math.max(0, avg)) + '%" title="Avg ' + PM.pct(avg) + '"></b>' : "";
    return '<div class="meter"><span class="k">' + label + '</span>' +
      '<span class="bar"><i class="' + lvl + '" style="width:' + Math.min(100, Math.max(0, pct || 0)) + '%"></i>' + marker + '</span>' +
      '<span class="v">' + right + '</span></div>';
  };

  PM.mini = function (pct, warn, bad) {
    return '<span class="mini"><i class="' + PM.level(pct, warn, bad) + '" style="width:' + Math.min(100, pct || 0) + '%"></i></span>';
  };

  // ---------- HTTP ----------
  PM.api = async function (method, url, body) {
    const opts = { method: method, headers: { "Accept": "application/json" }, credentials: "same-origin" };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    if (res.status === 401) { window.location.href = "/login?next=" + encodeURIComponent(location.pathname + location.search); throw new Error("Not logged in"); }
    if (res.status === 204) return null;
    let data = null;
    const text = await res.text();
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = { detail: text }; }
    if (!res.ok) {
      let msg = (data && data.detail) || res.statusText;
      if (Array.isArray(msg)) msg = msg.map(function (m) { return (m.loc ? m.loc.slice(1).join(".") + ": " : "") + m.msg; }).join("; ");
      const err = new Error(msg); err.status = res.status; err.data = data;
      throw err;
    }
    return data;
  };

  // ---------- Console re-auth window ----------
  // Shared by the header badge and the host page. The server is the authority: the console
  // endpoints refuse without a valid window; this only avoids a pointless round trip.
  PM.stepup = {
    state: null,
    loadedAt: 0,
    load: async function () {
      try { PM.stepup.set(await PM.api("GET", "/api/stepup")); } catch (e) { /* not allowed consoles */ }
      return PM.stepup.state;
    },
    set: function (st) { PM.stepup.state = st; PM.stepup.loadedAt = Date.now(); PM.stepup.render(); },
    remaining: function () {
      const st = PM.stepup.state;
      if (!st || !st.active) return 0;
      return Math.max(0, st.remaining - (Date.now() - PM.stepup.loadedAt) / 1000);
    },
    active: function () { return PM.stepup.remaining() > 3; },
    render: function () {
      const el = document.getElementById("stepup-badge");
      if (!el) return;
      const r = PM.stepup.remaining();
      if (r <= 0) { el.style.display = "none"; return; }
      el.style.display = "";
      el.querySelector(".t").textContent = r >= 60 ? Math.ceil(r / 60) + " min" : Math.ceil(r) + " s";
    },
    drop: async function () {
      await PM.api("POST", "/api/stepup/drop");
      PM.stepup.set(Object.assign({}, PM.stepup.state || {}, { active: false, remaining: 0 }));
      PM.toast("Console access ended for this browser. You'll be asked to verify again.", "ok");
    }
  };
  (function () {
    const el = document.getElementById("stepup-badge");
    if (!el) return;
    PM.stepup.load();
    setInterval(PM.stepup.render, 5000);
    const b = document.getElementById("stepup-drop");
    if (b) b.addEventListener("click", function () { PM.stepup.drop().catch(function (e) { PM.toast(e.message, "bad"); }); });
  })();

  // ---------- UI bits ----------
  let toastTimer = null;
  PM.toast = function (msg, kind) {
    let el = document.getElementById("toast");
    if (!el) { el = document.createElement("div"); el.id = "toast"; document.body.appendChild(el); }
    el.className = "toast " + (kind || "");
    el.textContent = msg;
    el.style.display = "block";
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.style.display = "none"; }, kind === "bad" ? 7000 : 3500);
  };

  // The modal opened last is on top (e.g. the root password or re-auth dialog opened from the Set up updates window).
  let modalZ = 50;
  PM.openModal = function (id) {
    const m = document.getElementById(id);
    const others = document.querySelectorAll(".modal-bg.open").length - (m.classList.contains("open") ? 1 : 0);
    modalZ = others > 0 ? modalZ + 1 : 50;
    m.style.zIndex = String(modalZ);
    m.classList.add("open");
  };
  PM.closeModal = function (id) { document.getElementById(id).classList.remove("open"); };
  document.addEventListener("click", function (e) {
    if (e.target.classList && e.target.classList.contains("modal-bg")) e.target.classList.remove("open");
    const closer = e.target.closest && e.target.closest("[data-close]");
    if (closer) PM.closeModal(closer.getAttribute("data-close"));
  });
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    let top = null;   // close only the top dialog (one opened over another goes first)
    document.querySelectorAll(".modal-bg.open").forEach(function (m) { if (!top || (+m.style.zIndex || 50) >= (+top.style.zIndex || 50)) top = m; });
    if (top) top.classList.remove("open");
  });

  PM.busy = function (btn, on, label) {
    if (!btn) return;
    if (on) { btn.dataset.label = btn.innerHTML; btn.disabled = true; btn.innerHTML = '<span class="spin"></span> ' + (label || "Working"); }
    else { btn.disabled = false; btn.innerHTML = btn.dataset.label || btn.innerHTML; }
  };

  // Tiny SVG sparkline: values 0-100.
  // ---------- host tags ----------
  // A stable hue per tag (same tag = same colour everywhere), light/dark lightness from CSS.
  PM.tagHue = function (t) {
    let h = 0;
    t = String(t).toLowerCase();
    for (let i = 0; i < t.length; i++) h = (h * 31 + t.charCodeAt(i)) % 360;
    return h;
  };
  PM.tagChip = function (t, opts) {
    opts = opts || {};
    const attrs = ' class="tag' + (opts.active ? " active" : "") + (opts.click ? " clickable" : "") + '" style="--tag-h:' + PM.tagHue(t) + '"' +
      (opts.click ? ' data-tag="' + PM.esc(t) + '" role="button" tabindex="0" title="Show hosts tagged ' + PM.esc(t) + '"' : "");
    return '<span' + attrs + '>' + PM.esc(t) +
      (opts.remove ? '<button type="button" class="tag-x" data-tag-remove="' + PM.esc(t) + '" aria-label="Remove tag ' + PM.esc(t) + '">×</button>' : "") + '</span>';
  };
  PM.tagChips = function (tags, opts) {
    return (tags || []).map(function (t) { return PM.tagChip(t, opts); }).join("");
  };
  // Tag editor: chips + a text box. Enter, comma or Tab adds what is typed; Backspace in an empty box
  // removes the last tag; x removes one; suggestions come from a datalist. get()/set(list)/suggest(list).
  PM.tagInput = function (box, opts) {
    opts = opts || {};
    const max = opts.max || 20, maxLen = opts.maxLen || 40;
    let tags = [];
    const listId = box.id + "-list";
    box.classList.add("tag-input");
    box.innerHTML = '<span class="tag-chips"></span><input type="text" autocomplete="off" list="' + listId + '" maxlength="' + maxLen +
      '" placeholder="' + PM.esc(opts.placeholder || "Add a tag…") + '"><datalist id="' + listId + '"></datalist>';
    const chips = box.querySelector(".tag-chips"), input = box.querySelector("input"), dl = box.querySelector("datalist");
    function draw() {
      chips.innerHTML = PM.tagChips(tags, { remove: true });
      input.placeholder = tags.length >= max ? "Tag limit reached" : (opts.placeholder || "Add a tag…");
      input.disabled = tags.length >= max;
    }
    function add(raw) {
      let added = false;
      String(raw).split(",").forEach(function (part) {
        const t = part.replace(/[<>\u0000-\u001f]/g, "").split(/\s+/).filter(Boolean).join(" ").slice(0, maxLen);
        if (!t || tags.length >= max) return;
        if (tags.some(function (x) { return x.toLowerCase() === t.toLowerCase(); })) return;
        tags.push(t); added = true;
      });
      draw();
      return added;
    }
    input.addEventListener("keydown", function (e) {
      if ((e.key === "Enter" || e.key === "," || (e.key === "Tab" && input.value.trim())) && !e.isComposing) {
        if (input.value.trim() || e.key !== "Tab") e.preventDefault();
        add(input.value); input.value = "";
      } else if (e.key === "Backspace" && !input.value && tags.length) {
        tags.pop(); draw();
      }
    });
    // A pick from the suggestion list adds at once. (Not on "change": that also fires when the box
    // loses focus, and the chips re-flowing under the pointer would make a click on Save miss.)
    input.addEventListener("input", function (e) {
      if (e.inputType === "insertReplacementText" || e.inputType === undefined) {
        const v = input.value.trim().toLowerCase();
        const hit = v && Array.prototype.find.call(dl.options, function (o) { return o.value.toLowerCase() === v; });
        if (hit) { add(hit.value); input.value = ""; }   // the existing spelling
      }
    });
    // No add-on-blur: the chips re-flowing under the pointer would make a click on Save miss.
    // Text left in the box is still saved (get()).
    box.addEventListener("click", function (e) {
      const x = e.target.closest("[data-tag-remove]");
      if (x) {
        const t = x.getAttribute("data-tag-remove");
        tags = tags.filter(function (v) { return v !== t; }); draw(); input.focus();
      } else if (e.target === box || e.target === chips) input.focus();
    });
    draw();
    return {
      get: function () { if (input.value.trim()) { add(input.value); input.value = ""; } return tags.slice(); },
      set: function (list) { tags = []; input.value = ""; add((list || []).join(",")); },
      suggest: function (list) {
        dl.innerHTML = (list || []).map(function (t) { return '<option value="' + PM.esc(t) + '">'; }).join("");
      },
      input: input,
    };
  };

  // ---------- update notes ----------
  // PM.updateNotes(hostId, hostName, [{node, label, updates_list}]): a dialog listing the pending packages with
  // cliff notes from their changelogs (fetched through the node), CVE IDs, and a CVE / keyword lookup.
  const KERNEL_RE = /^(proxmox|pve)-kernel/;
  PM.cveUrl = function (c) { return "https://security-tracker.debian.org/tracker/" + encodeURIComponent(c); };
  function cveChip(c, cls) {
    return '<a class="badge ' + (cls || "bad") + ' cve" href="' + PM.cveUrl(c) + '" target="_blank" rel="noopener noreferrer" title="Open ' + PM.esc(c) + ' in the Debian security tracker">' + PM.esc(c) + '</a>';
  }
  PM.updateNotes = function (hostId, hostName, nodes) {
    let modal = document.getElementById("upd-modal");
    if (!modal) {
      modal = document.createElement("div");
      modal.className = "modal-bg";
      modal.id = "upd-modal";
      modal.innerHTML = '<div class="modal wide upd-modal"><h2 id="upd-title"></h2>' +
        '<div class="upd-search"><input type="text" id="upd-q" placeholder="Check a CVE (e.g. CVE-2025-1234) or a word, e.g. openssh" autocomplete="off" spellcheck="false">' +
        '<div id="upd-answer" class="upd-answer"></div></div>' +
        '<div class="muted upd-progress" id="upd-progress"></div><div id="upd-body"></div>' +
        '<p class="muted upd-foot">Notes come from each package\'s changelog (downloaded by the node from its repository), ' +
        'between the installed and the new version. Kernel changelogs name the Ubuntu kernel they are based on rather than ' +
        'individual CVEs; only pending packages are checked.</p>' +
        '<div class="foot"><button class="btn" type="button" id="upd-close">Close</button></div></div>';
      document.body.appendChild(modal);
      modal.querySelector("#upd-close").addEventListener("click", function () { modal.classList.remove("open"); });
      modal.querySelector("#upd-q").addEventListener("input", function () { answer(); });
    }
    const state = { pkgs: [], gen: (modal._gen || 0) + 1 };
    modal._gen = state.gen;
    modal._state = state;
    const body = modal.querySelector("#upd-body");
    modal.querySelector("#upd-title").textContent = "Pending updates · " + hostName;
    modal.querySelector("#upd-q").value = "";
    let html = "";
    nodes.forEach(function (n) {
      const list = (n.updates_list || []).slice().sort(function (a, b) { return a.package.localeCompare(b.package); });
      if (!list.length) return;
      html += '<div class="upd-node"><div class="upd-node-title">' + PM.esc(n.node) + (n.label ? ' <span class="muted">(' + PM.esc(n.label) + ')</span>' : "") +
        ' <span class="muted">· ' + list.length + ' package' + (list.length === 1 ? "" : "s") + '</span></div>';
      list.forEach(function (u) {
        const i = state.pkgs.length;
        state.pkgs.push({ node: n.node, u: u, notes: null, i: i });
        html += '<details class="upd-pkg" id="upd-pkg-' + i + '"><summary>' +
          '<span class="upd-name mono">' + PM.esc(u.package) + '</span>' +
          '<span class="upd-ver mono">' + (u.old ? PM.esc(u.old) + ' → ' : 'new: ') + '<b>' + PM.esc(u.new) + '</b></span>' +
          (u.origin ? '<span class="badge">' + PM.esc(u.origin) + '</span>' : "") +
          (KERNEL_RE.test(u.package) ? '<span class="badge warn">kernel · reboot</span>' : "") +
          '<span class="upd-flags" id="upd-flags-' + i + '"><span class="muted">reading changelog…</span></span>' +
          '</summary><div class="upd-notes" id="upd-notes-' + i + '"><span class="muted">Loading…</span></div></details>';
      });
      html += '</div>';
    });
    body.innerHTML = html || '<div class="empty">No pending updates on this host.</div>';
    modal.querySelector("#upd-answer").innerHTML = "";
    PM.openModal("upd-modal");
    setTimeout(function () { modal.querySelector("#upd-q").focus(); }, 50);
    progress();

    let next = 0;
    async function worker() {
      while (next < state.pkgs.length && modal._gen === state.gen) {
        const p = state.pkgs[next++];
        let r;
        try {
          r = await PM.api("GET", "/api/hosts/" + hostId + "/nodes/" + encodeURIComponent(p.node) + "/updates/notes?name=" +
                          encodeURIComponent(p.u.package) + "&version=" + encodeURIComponent(p.u.new));
        } catch (e) { r = { ok: false, error: e.message }; }
        if (modal._gen !== state.gen) return;
        p.notes = r;
        draw(p);
        progress();
        answer();
      }
    }
    for (let k = 0; k < 4; k++) worker();

    function draw(p) {
      const r = p.notes, flags = document.getElementById("upd-flags-" + p.i), box = document.getElementById("upd-notes-" + p.i);
      if (!flags || !box) return;
      if (!r.ok) {
        flags.innerHTML = '<span class="muted">no changelog</span>';
        box.innerHTML = '<div class="muted">' + PM.esc(r.error || "No changelog available.") + '</div>';
        return;
      }
      flags.innerHTML = (r.security ? '<span class="badge bad">security</span>' : "") +
        (r.cves || []).slice(0, 4).map(function (c) { return '<span class="badge bad cve-mini">' + PM.esc(c) + '</span>'; }).join("") +
        ((r.cves || []).length > 4 ? '<span class="muted">+' + (r.cves.length - 4) + '</span>' : "") +
        (!r.security && r.entries.length ? '<span class="muted">' + r.entries.length + ' change' + (r.entries.length === 1 ? "" : "s") + '</span>' : "");
      if (!r.entries.length) {
        box.innerHTML = '<div class="muted">The changelog has no entries between the installed and the new version (often a rebuild).</div>';
        return;
      }
      box.innerHTML = r.entries.map(function (e) {
        return '<div class="upd-entry"><div class="upd-entry-head"><b class="mono">' + PM.esc(e.version) + '</b>' +
          (e.urgency && e.urgency !== "medium" && e.urgency !== "low" ? ' <span class="badge warn">urgency ' + PM.esc(e.urgency) + '</span>' : "") +
          (e.dist.indexOf("security") !== -1 ? ' <span class="badge bad">' + PM.esc(e.dist) + '</span>' : "") +
          (e.date ? ' <span class="muted">' + PM.esc(e.date) + '</span>' : "") + '</div>' +
          '<ul>' + e.items.map(function (t) {
            return t.indexOf("\u2013 ") === 0 ? '<li class="sub">' + PM.esc(t.slice(2)) + '</li>' : '<li>' + PM.esc(t) + '</li>';
          }).join("") +
          (e.more_items ? '<li class="muted">… ' + e.more_items + ' more</li>' : "") + '</ul>' +
          (e.cves.length ? '<div class="upd-cves">' + e.cves.map(function (c) { return cveChip(c); }).join(" ") + '</div>' : "") + '</div>';
      }).join("") + (r.more_entries ? '<div class="muted">… ' + r.more_entries + ' older entries in this update not shown</div>' : "") +
        (r.installed_found ? "" : '<div class="muted">The installed version isn\'t in this changelog, so the list may include older changes.</div>');
    }
    function progress() {
      const done = state.pkgs.filter(function (p) { return p.notes; });
      const sec = done.filter(function (p) { return p.notes.ok && p.notes.security; }).length;
      const cves = {};
      done.forEach(function (p) { ((p.notes.ok && p.notes.cves) || []).forEach(function (c) { cves[c] = 1; }); });
      modal.querySelector("#upd-progress").innerHTML = state.pkgs.length + " package" + (state.pkgs.length === 1 ? "" : "s") +
        (done.length < state.pkgs.length ? " · reading changelogs " + done.length + "/" + state.pkgs.length : "") +
        (sec ? ' · <span class="bad-text">' + sec + " with security fixes</span>" : "") +
        (Object.keys(cves).length ? " · " + Object.keys(cves).length + " CVE" + (Object.keys(cves).length === 1 ? "" : "s") + " fixed" : "");
    }
    function answer() {
      const st = modal._state; if (!st) return;
      const raw = modal.querySelector("#upd-q").value.trim();
      const out = modal.querySelector("#upd-answer");
      if (!raw) { out.innerHTML = ""; return; }
      const m = raw.match(/CVE-?(\d{4})-?(\d{4,7})/i);
      const cve = m ? "CVE-" + m[1] + "-" + m[2] : null;
      const done = st.pkgs.filter(function (p) { return p.notes && p.notes.ok; });
      const waiting = st.pkgs.length - st.pkgs.filter(function (p) { return p.notes; }).length;
      const fixes = [], already = [];
      done.forEach(function (p) {
        const r = p.notes;
        if (cve) {
          const e = r.entries.filter(function (x) { return x.cves.indexOf(cve) !== -1; });
          if (e.length) fixes.push({ p: p, ver: e[e.length - 1].version });
          else if (r.fixed_in_installed && r.fixed_in_installed[cve]) already.push({ p: p, ver: r.fixed_in_installed[cve] });
        } else if ((r.search_text || "").toLowerCase().indexOf(raw.toLowerCase()) !== -1 || p.u.package.indexOf(raw.toLowerCase()) !== -1) {
          fixes.push({ p: p, ver: null });
        }
      });
      const pkgLink = function (x) { return '<a href="#" data-upd-open="' + x.p.i + '" class="mono">' + PM.esc(x.p.u.package) + '</a> on ' + PM.esc(x.p.node); };
      let h = "";
      if (cve && fixes.length) {
        h += '<div class="ok-text"><b>' + PM.esc(cve) + ' is fixed by the pending update' + (fixes.length === 1 ? "" : "s") + ':</b> ' +
          fixes.map(function (x) { return pkgLink(x) + ' → ' + PM.esc(x.p.u.new) + ' <span class="muted">(fix in ' + PM.esc(x.ver) + ')</span>'; }).join("; ") + '</div>';
      }
      if (cve && already.length) {
        h += '<div><b>Already fixed in what is installed:</b> ' +
          already.map(function (x) { return pkgLink(x) + ' <span class="muted">(fixed in ' + PM.esc(x.ver) + ', installed ' + PM.esc(x.p.u.old) + ')</span>'; }).join("; ") + '</div>';
      }
      if (!cve && fixes.length) {
        h += '<div>Mentioned in: ' + fixes.map(pkgLink).join("; ") + '</div>';
      }
      if (!fixes.length && !already.length) {
        h += '<div class="warn-text">' + (cve ? PM.esc(cve) + " isn't mentioned" : "Nothing matches") + ' in the changelogs of the pending updates' +
          (waiting ? " read so far (" + waiting + " still loading)" : "") + '.</div>';
        if (cve) h += '<div class="muted">That doesn\'t prove the host isn\'t affected: it may be fixed in a package that has no pending update, ' +
          'or not named in the changelog' + (st.pkgs.some(function (p) { return KERNEL_RE.test(p.u.package); }) ? " (kernel updates list the Ubuntu kernel version, not CVEs)" : "") +
          '. <a href="' + PM.cveUrl(cve) + '" target="_blank" rel="noopener noreferrer">Look it up in the Debian security tracker</a>.</div>';
      } else if (waiting) {
        h += '<div class="muted">' + waiting + ' changelog' + (waiting === 1 ? "" : "s") + ' still loading.</div>';
      }
      out.innerHTML = h;
    }
    modal._answer = answer;
    if (!modal._openBound) {
      modal._openBound = true;
      modal.addEventListener("click", function (e) {
        const a = e.target.closest("[data-upd-open]");
        if (!a) return;
        e.preventDefault();
        const d = document.getElementById("upd-pkg-" + a.getAttribute("data-upd-open"));
        if (d) { d.open = true; d.scrollIntoView({ block: "nearest" }); }
      });
    }
  };

  PM.sparkline = function (points, color) {
    const w = 300, h = 56, pad = 2;
    if (!points || points.length < 2) {
      return '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none"><text x="4" y="30" style="fill:var(--muted)" font-size="11">Not enough samples yet</text></svg>';
    }
    const n = points.length;
    const xs = function (i) { return pad + (i / (n - 1)) * (w - pad * 2); };
    const ys = function (v) { return h - pad - (Math.min(100, Math.max(0, v)) / 100) * (h - pad * 2); };
    let d = "M" + xs(0) + " " + ys(points[0]);
    for (let i = 1; i < n; i++) d += " L" + xs(i) + " " + ys(points[i]);
    const area = d + " L" + xs(n - 1) + " " + (h - pad) + " L" + xs(0) + " " + (h - pad) + " Z";
    return '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
      '<line x1="0" y1="' + ys(50) + '" x2="' + w + '" y2="' + ys(50) + '" style="stroke:var(--border)" stroke-dasharray="3 3"/>' +
      '<path d="' + area + '" style="fill:' + color + '" opacity="0.15"/>' +
      '<path d="' + d + '" fill="none" style="stroke:' + color + '" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>';
  };
})();
