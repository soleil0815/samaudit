/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Light or dark before the first paint: the choice in this browser ("system", "light", "dark"), default system. */
(function () {
  var pref = "system";
  try { pref = localStorage.getItem("samaudit-theme") || "system"; } catch (e) { /* storage blocked */ }
  var dark = pref === "dark" || (pref !== "light" && window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
})();
