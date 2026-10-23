/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* SAMAUDIT – kleine Helfer, ohne externe Bibliotheken (CSP: nur 'self'). */
(function () {
  "use strict";
  var root = document.documentElement;

  // Darstellung: dunkel (Standard) oder hell – nur Komfort, darf fehlschlagen
  function getTheme() { try { return localStorage.getItem("samaudit-theme") === "light" ? "light" : "dark"; } catch (e) { return "dark"; } }
  function applyTheme(v) {
    if (v === "light") root.setAttribute("data-theme", "light"); else root.removeAttribute("data-theme");
    document.querySelectorAll("[data-theme-btn]").forEach(function (b) {
      b.textContent = b.getAttribute("data-label-" + v) || v;
    });
  }
  applyTheme(getTheme());
  document.addEventListener("click", function (ev) {
    var b = ev.target.closest("[data-theme-btn]");
    if (!b) return;
    var next = getTheme() === "light" ? "dark" : "light";
    try { localStorage.setItem("samaudit-theme", next); } catch (e) { /* ignorieren */ }
    applyTheme(next);
  });

  // Code kopieren
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

  // Tabellen filtern
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

  // Sicherheitsabfrage
  document.addEventListener("submit", function (ev) {
    var f = ev.target;
    var msg = f.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) { ev.preventDefault(); return; }
    var btn = f.querySelector("[data-busy]");
    if (btn) { btn.disabled = true; btn.textContent = btn.getAttribute("data-busy"); }
  });

  // Tooltips im Verlaufsdiagramm
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

  // Anker im Bericht: Befund automatisch aufklappen
  function openHash() {
    if (!location.hash) return;
    var el = document.getElementById(location.hash.slice(1));
    if (el && el.tagName === "DETAILS") { el.open = true; el.scrollIntoView({ block: "start" }); }
  }
  window.addEventListener("hashchange", openHash);
  openHash();

  // Scan-Fortschritt
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
