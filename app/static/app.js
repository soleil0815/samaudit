/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* SAMAUDIT – small helpers, no external libraries (CSP: 'self' only). */
(function () {
  "use strict";
  var root = document.documentElement;

  // Appearance: like the system (default), light or dark – a convenience of this browser, may fail
  function getPref() {
    try { var v = localStorage.getItem("samaudit-theme"); return v === "light" || v === "dark" ? v : "system"; }
    catch (e) { return "system"; }
  }
  var media = window.matchMedia ? matchMedia("(prefers-color-scheme: dark)") : null;
  function applyTheme(pref) {
    var dark = pref === "dark" || (pref === "system" && media && media.matches);
    root.setAttribute("data-theme", dark ? "dark" : "light");
    document.querySelectorAll("[data-theme-set]").forEach(function (b) {
      b.setAttribute("aria-pressed", b.getAttribute("data-theme-set") === pref ? "true" : "false");
    });
  }
  document.addEventListener("DOMContentLoaded", function () { applyTheme(getPref()); });
  applyTheme(getPref());
  if (media && media.addEventListener) media.addEventListener("change", function () { applyTheme(getPref()); });
  document.addEventListener("click", function (ev) {
    var b = ev.target.closest("[data-theme-set]");
    if (!b) return;
    var pref = b.getAttribute("data-theme-set");
    try { localStorage.setItem("samaudit-theme", pref); } catch (e) { /* ignore */ }
    applyTheme(pref);
  });

  // Copy code
  document.addEventListener("click", function (ev) {
    var b = ev.target.closest("[data-copy]");
    if (!b) return;
    var pre = b.parentElement.querySelector("pre");
    if (!pre || !navigator.clipboard) return;
    navigator.clipboard.writeText(pre.textContent).then(function () {
      var old = b.textContent; b.textContent = b.getAttribute("data-done") || "✓";
      setTimeout(function () { b.textContent = old; }, 1400);
    });
  });

  // Filter tables
  document.addEventListener("input", function (ev) {
    var inp = ev.target.closest("[data-filter]");
    if (!inp) return;
    var q = inp.value.trim().toLowerCase();
    var tbl = document.getElementById(inp.getAttribute("data-filter"));
    if (!tbl) return;
    tbl.querySelectorAll("tbody tr").forEach(function (tr) {
      tr.hidden = q && tr.textContent.toLowerCase().indexOf(q) === -1;
    });
  });

  // Confirmation prompt
  document.addEventListener("submit", function (ev) {
    var f = ev.target;
    var msg = f.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) { ev.preventDefault(); return; }
    var btn = f.querySelector("[data-busy]");
    if (btn) { btn.disabled = true; btn.textContent = btn.getAttribute("data-busy"); }
  });

  // Tooltips in the trend chart
  var tip = null;
  document.addEventListener("mouseover", function (ev) {
    var g = ev.target.closest && ev.target.closest(".pt[data-tip]");
    if (!g) { if (tip) tip.hidden = true; return; }
    if (!tip) { tip = document.createElement("div"); tip.className = "tip"; document.body.appendChild(tip); }
    var r = g.querySelector(".dot").getBoundingClientRect();
    tip.textContent = g.getAttribute("data-tip");
    tip.style.left = (r.left + r.width / 2) + "px";
    tip.style.top = r.top + "px";
    tip.hidden = false;
  });

  // Anchor in the report: expand the finding automatically
  function openHash() {
    if (!location.hash) return;
    var el = document.getElementById(location.hash.slice(1));
    if (el && el.tagName === "DETAILS") { el.open = true; el.scrollIntoView({ block: "start" }); }
  }
  window.addEventListener("hashchange", openHash);
  openHash();

  // Scan progress
  var prog = document.querySelector("[data-scan-status]");
  if (prog) {
    var url = prog.getAttribute("data-scan-status");
    var bar = prog.querySelector(".progress-bar i");
    var phase = prog.querySelector(".phase");
    var pct = prog.querySelector("[data-pct]");
    var err = prog.querySelector("[data-error]");
    var poll = function () {
      fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" })
        .then(function (r) { if (r.status === 401) { location.href = "/login?e=session"; } return r.json(); })
        .then(function (d) {
          if (!d) return;
          bar.style.width = d.progress + "%";
          pct.textContent = d.progress + " %";
          phase.textContent = d.phase;
          if (d.status === "done") { location.href = prog.getAttribute("data-report"); return; }
          if (d.status === "error") { err.hidden = false; err.querySelector("span").textContent = d.error || ""; return; }
          setTimeout(poll, 900);
        })
        .catch(function () { setTimeout(poll, 2500); });
    };
    poll();
  }
})();
