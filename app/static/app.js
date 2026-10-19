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
      const err = new Error(msg); err.status = res.status;
      throw err;
    }
    return data;
  };

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

  PM.openModal = function (id) { document.getElementById(id).classList.add("open"); };
  PM.closeModal = function (id) { document.getElementById(id).classList.remove("open"); };
  document.addEventListener("click", function (e) {
    if (e.target.classList && e.target.classList.contains("modal-bg")) e.target.classList.remove("open");
    const closer = e.target.closest && e.target.closest("[data-close]");
    if (closer) PM.closeModal(closer.getAttribute("data-close"));
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") document.querySelectorAll(".modal-bg.open").forEach(function (m) { m.classList.remove("open"); });
  });

  PM.busy = function (btn, on, label) {
    if (!btn) return;
    if (on) { btn.dataset.label = btn.innerHTML; btn.disabled = true; btn.innerHTML = '<span class="spin"></span> ' + (label || "Working"); }
    else { btn.disabled = false; btn.innerHTML = btn.dataset.label || btn.innerHTML; }
  };

  // Tiny SVG sparkline: values 0-100.
  PM.sparkline = function (points, color) {
    const w = 300, h = 56, pad = 2;
    if (!points || points.length < 2) {
      return '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none"><text x="4" y="30" fill="#8b98a9" font-size="11">Not enough samples yet</text></svg>';
    }
    const n = points.length;
    const xs = function (i) { return pad + (i / (n - 1)) * (w - pad * 2); };
    const ys = function (v) { return h - pad - (Math.min(100, Math.max(0, v)) / 100) * (h - pad * 2); };
    let d = "M" + xs(0) + " " + ys(points[0]);
    for (let i = 1; i < n; i++) d += " L" + xs(i) + " " + ys(points[i]);
    const area = d + " L" + xs(n - 1) + " " + (h - pad) + " L" + xs(0) + " " + (h - pad) + " Z";
    return '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
      '<line x1="0" y1="' + ys(50) + '" x2="' + w + '" y2="' + ys(50) + '" stroke="#283241" stroke-dasharray="3 3"/>' +
      '<path d="' + area + '" fill="' + color + '" opacity="0.15"/>' +
      '<path d="' + d + '" fill="none" stroke="' + color + '" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>';
  };
})();
