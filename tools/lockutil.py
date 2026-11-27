# SPDX-License-Identifier: AGPL-3.0-or-later
"""Helpers for pinned builds and security updates (standard library only, unit-tested).

Policy (see README, "Security updates and versions"):
- The base image stays in the same Python series and the same Debian release
  (tag "<series>.<patch>-slim-<codename>", always with digest).
- Every Python package stays within its major version (before 1.0: within its minor version).
  Calendar versions (e.g. tzdata, certifi) have no upper limit.
- Security updates are published as "<program version>-s<counter>"; a new program version
  starts the counter again. "latest" only ever points to the highest version.

Command line (used by tools/update-locks.sh and the GitHub workflows):
  lockutil.py constraints REQUIREMENTS_TXT          -> pip constraints that keep every locked package in bounds
  lockutil.py pick-base LIBRARY_FILE SERIES CODENAME -> newest matching python tag, e.g. 3.13.17-slim-trixie
  lockutil.py next-version APP_VERSION TAG...        -> e.g. 1.9.7-s2
  lockutil.py is-highest CANDIDATE TAG...            -> exit 0 if CANDIDATE is the highest version
  lockutil.py diff OLD_DIR NEW_DIR                   -> Markdown table of changed packages ("" if none)
  lockutil.py add-news OLD_DIR NEW_DIR VERSION DATE NEWS_JSON -> short entry for the security update in the
                                                        program's news (app/docs/news.json), newest first
  lockutil.py eol PRODUCT NAME DATE_JSON [TODAY]     -> ok / notice / fail for an end-of-life date
  lockutil.py select REQUIREMENTS_TXT NAME...        -> only the blocks (with hashes) of these packages
  lockutil.py without REQUIREMENTS_TXT NAME...       -> the lock file without these packages
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
from pathlib import Path

CALVER_PACKAGES = {"tzdata", "certifi"}           # versions are dates, not compatibility promises
NOTICE_DAYS = 365                                  # end of support within 12 months: hint
FAIL_DAYS = 183                                    # within 6 months: red run


# --------------------------------------------------------------------------- versions
def release_tuple(version: str) -> tuple[int, ...]:
    """'3.13.17' -> (3, 13, 17); stops at the first non-numeric part (e.g. '1.2.0rc1' -> (1, 2, 0))."""
    out = []
    for part in version.split("."):
        m = re.match(r"\d+", part)
        if not m:
            break
        out.append(int(m.group()))
        if m.end() != len(part):
            break
    return tuple(out)


def is_calver(name: str, version: str) -> bool:
    rel = release_tuple(version)
    return name.lower() in CALVER_PACKAGES or (bool(rel) and rel[0] >= 1990)


def upper_bound(name: str, version: str) -> str | None:
    """Exclusive upper limit that keeps NAME within its major (0.x: minor) version; None = no limit."""
    if is_calver(name, version):
        return None
    rel = release_tuple(version) + (0, 0)
    if rel[0] == 0:
        return f"0.{rel[1] + 1}"
    return f"{rel[0] + 1}"


def parse_lock(text: str) -> dict[str, str]:
    """name==version lines of a pip lock file (hashes, comments and markers are ignored)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;\\]+)", line.strip())
        if m:
            out[normalize(m.group(1))] = m.group(2)
    return out


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def constraints(lock_text: str) -> str:
    """Constraints for an update within bounds: never older than today, never a new major version."""
    lines = []
    for name, ver in sorted(parse_lock(lock_text).items()):
        ub = upper_bound(name, ver)
        lines.append(f"{name}>={ver},<{ub}" if ub else f"{name}>={ver}")
    return "\n".join(lines) + ("\n" if lines else "")


SOURCE_BUILT = ("gssapi", "krb5")                 # no Linux wheels: built in the Dockerfile stage "kerberos"


def blocks(lock_text: str, names: list[str], keep: bool) -> str:
    """Split a pip-compile lock file into its package blocks (requirement line, hashes, "via" comments) and keep
    only the named packages (keep=True) or all others (keep=False). Header comments stay with keep=False."""
    wanted = {normalize(n) for n in names}
    out = []
    for block in re.split(r"\n(?=[A-Za-z0-9])", lock_text):
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==", block)
        if m is None:
            if not keep:
                out.append(block.rstrip("\n"))
            continue
        if (normalize(m.group(1)) in wanted) == keep:
            out.append(block.rstrip("\n"))
    return "\n".join(out) + ("\n" if out else "")


def within_bounds(old: dict[str, str], new: dict[str, str]) -> list[str]:
    """Violations of the policy between two locks (empty list = ok)."""
    bad = []
    for name, ver in new.items():
        if name not in old:
            continue                                  # new sub-dependency: no previous version to compare
        o = old[name]
        if release_tuple(ver) < release_tuple(o):
            bad.append(f"{name}: {o} -> {ver} (older)")
            continue
        ub = upper_bound(name, o)
        if ub and release_tuple(ver) >= release_tuple(ub):
            bad.append(f"{name}: {o} -> {ver} (outside {name}<{ub})")
    return bad


# --------------------------------------------------------------------------- base image
def uploaded_on_pypi(name: str, version: str) -> dt.datetime | None:
    """Earliest upload time of a release on PyPI (None if unknown or not reachable)."""
    import urllib.request
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=20) as r:  # noqa: S310 – fixed https URL
            data = json.load(r)
    except Exception:  # noqa: BLE001
        return None
    times = [u.get("upload_time_iso_8601") for u in data.get("urls") or [] if u.get("upload_time_iso_8601")]
    if not times:
        return None
    return min(dt.datetime.fromisoformat(t.replace("Z", "+00:00")) for t in times)


def too_young(old: dict[str, str], new: dict[str, str], days: int, uploaded=uploaded_on_pypi,
              now: dt.datetime | None = None) -> list[str]:
    """Cooldown: constraints that hold back every changed or new package released less than `days` ago.
    A hijacked release is usually withdrawn within a few days – it never reaches the image this way.
    Unknown upload times count as too young (fail safe)."""
    if days <= 0:
        return []
    now = now or dt.datetime.now(dt.timezone.utc)
    out = []
    for name, ver in sorted(new.items()):
        if old.get(name) == ver:
            continue
        t = uploaded(name, ver)
        if t is None or (now - t).days < days:
            out.append(f"{name}=={old[name]}" if name in old else f"{name}<{ver}")
    return out


def pick_base(library_text: str, series: str, codename: str) -> str:
    """Newest 'X.Y.Z-slim-<codename>' tag of the Python series from docker-library's 'library/python'."""
    pat = re.compile(rf"^{re.escape(series)}\.(\d+)-slim-{re.escape(codename)}$")
    best = None
    for line in library_text.splitlines():
        if not line.startswith("Tags:"):
            continue
        for tag in (t.strip() for t in line[5:].split(",")):
            m = pat.match(tag)
            if m and (best is None or int(m.group(1)) > best[0]):
                best = (int(m.group(1)), tag)
    if best is None:
        raise ValueError(f"no tag {series}.N-slim-{codename} found")
    return best[1]


# --------------------------------------------------------------------------- release numbers
_VER = re.compile(r"^v?(\d+(?:\.\d+)*)(?:-s(\d+))?$")


def version_key(tag: str) -> tuple[tuple[int, ...], int] | None:
    """'v1.9.7-s2' -> ((1, 9, 7), 2); '1.9.7' -> ((1, 9, 7), 0); anything else -> None."""
    m = _VER.match(tag.strip())
    if not m:
        return None
    return release_tuple(m.group(1)), int(m.group(2) or 0)


def next_version(app_version: str, tags: list[str]) -> str:
    app = release_tuple(app_version)
    counters = [k[1] for k in (version_key(t) for t in tags) if k and k[0] == app]
    return f"{app_version}-s{max(counters, default=0) + 1}"


def is_highest(candidate: str, tags: list[str]) -> bool:
    ck = version_key(candidate)
    if ck is None:
        return False
    keys = [k for k in (version_key(t) for t in tags) if k]
    return all(ck >= k for k in keys)


# --------------------------------------------------------------------------- change log
def parse_os(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and not line.startswith("#"):
            out[parts[0]] = parts[1]
    return out


def base_of(dockerfile: str) -> str:
    m = re.search(r"^ARG PYTHON_IMAGE=(\S+)", dockerfile, re.M)
    return m.group(1) if m else ""


def changed_packages(old_dir: Path, new_dir: Path) -> list[tuple[str, str, str, str]]:
    """(area, package, before, now) for every changed package between two checkouts."""
    rows = []
    ob, nb = base_of(_read(old_dir / "Dockerfile")), base_of(_read(new_dir / "Dockerfile"))
    if ob != nb:
        rows.append(("Base image", "python", _short(ob), _short(nb)))
    for area, fname, parser in (("Debian", "locks/os-packages.txt", parse_os),
                                ("Python", "requirements.txt", parse_lock)):
        o, n = parser(_read(old_dir / fname)), parser(_read(new_dir / fname))
        for name in sorted(set(o) | set(n)):
            if o.get(name) != n.get(name):
                rows.append((area, name, o.get(name, "–"), n.get(name, "–")))
    return rows


def diff(old_dir: Path, new_dir: Path) -> str:
    """Markdown table of changed packages between two checkouts (empty string: nothing changed)."""
    rows = changed_packages(old_dir, new_dir)
    if not rows:
        return ""
    lines = ["| Area | Package | before | now |", "|---|---|---|---|"]
    lines += [f"| {a} | {p} | {o} | {n} |" for a, p, o, n in rows]
    return "\n".join(lines) + "\n"


NEWS_MAX_NAMES = 8


def news_entry(rows: list[tuple[str, str, str, str]], version: str, date: str) -> dict:
    """Entry for app/docs/news.json: what a security update changed, in one short line per language."""
    app = version.split("-s", 1)[0]
    groups: dict[str, list[str]] = {}
    for area, name, _old, new in rows:
        if area == "Base image":
            groups.setdefault(area, []).append(f"Python {new.split('-', 1)[0]}")
        else:
            groups.setdefault(area, []).append(name)

    def names(lang: str) -> str:
        label = {"Base image": ("Basisimage", "base image"), "Debian": ("Debian", "Debian"),
                 "Python": ("Python-Pakete", "Python packages")}
        parts = []
        for area in ("Base image", "Debian", "Python"):
            items = sorted(set(groups.get(area, [])))
            if not items:
                continue
            shown, rest = items[:NEWS_MAX_NAMES], len(items) - NEWS_MAX_NAMES
            more = (f" und {rest} weitere" if lang == "de" else f" and {rest} more") if rest > 0 else ""
            parts.append(f"{label[area][0 if lang == 'de' else 1]}: {', '.join(shown)}{more}")
        return "; ".join(parts)

    return {"version": version, "date": date, "items": [{
        "type": "security",
        "de": f"Sicherheitsupdate: gleiches Programm ({app}), neuere Pakete – {names('de')}. "
              "Die einzelnen Versionen stehen in CHANGELOG-SECURITY.md.",
        "en": f"Security update: same program ({app}), newer packages – {names('en')}. "
              "The exact versions are listed in CHANGELOG-SECURITY.md.",
    }]}


def add_news(news_path: Path, entry: dict) -> None:
    """Put the entry at the top of news.json (once per version)."""
    data = json.loads(news_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("news.json must be a list")
    data = [e for e in data if e.get("version") != entry["version"]]
    news_path.write_text(json.dumps([entry] + data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _short(image: str) -> str:
    """python:3.13.17-slim-trixie@sha256:abcdef… -> 3.13.17-slim-trixie (sha256:abcdef123456)"""
    if not image:
        return "–"
    name, _, digest = image.partition("@")
    tag = name.split(":", 1)[-1]
    return f"{tag} ({digest[:19]})" if digest else tag


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""


# --------------------------------------------------------------------------- end of life
def eol_date(data: dict) -> str | None:
    """End of security support from endoflife.date (API v1 'result' or the classic format)."""
    d = data.get("result", data)
    for key in ("eolFrom", "eol"):
        v = d.get(key)
        if isinstance(v, str) and re.match(r"\d{4}-\d{2}-\d{2}$", v):
            return v
    return None


def eol_status(eol: str, today: dt.date) -> tuple[str, int]:
    days = (dt.date.fromisoformat(eol) - today).days
    if days <= FAIL_DAYS:
        return "fail", days
    if days <= NOTICE_DAYS:
        return "notice", days
    return "ok", days


# --------------------------------------------------------------------------- CLI
def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    cmd, args = argv[0], argv[1:]
    if cmd == "constraints":
        sys.stdout.write(constraints(Path(args[0]).read_text(encoding="utf-8")))
    elif cmd == "pick-base":
        print(pick_base(Path(args[0]).read_text(encoding="utf-8"), args[1], args[2]))
    elif cmd == "next-version":
        print(next_version(args[0], args[1:]))
    elif cmd == "is-highest":
        return 0 if is_highest(args[0], args[1:]) else 1
    elif cmd == "check-bounds":
        bad = within_bounds(parse_lock(Path(args[0]).read_text(encoding="utf-8")),
                            parse_lock(Path(args[1]).read_text(encoding="utf-8")))
        for b in bad:
            print(b)
        return 1 if bad else 0
    elif cmd == "too-young":
        for line in too_young(parse_lock(Path(args[0]).read_text(encoding="utf-8")),
                              parse_lock(Path(args[1]).read_text(encoding="utf-8")), int(args[2])):
            print(line)
    elif cmd == "diff":
        sys.stdout.write(diff(Path(args[0]), Path(args[1])))
    elif cmd == "add-news":
        rows = changed_packages(Path(args[0]), Path(args[1]))
        if not rows:
            print("no changed packages", file=sys.stderr)
            return 1
        add_news(Path(args[4]), news_entry(rows, args[2], args[3]))
    elif cmd in ("select", "without"):
        text = blocks(Path(args[0]).read_text(encoding="utf-8"), args[1:], keep=cmd == "select")
        if cmd == "select" and len(parse_lock(text)) != len(args[1:]):
            print(f"not all of {args[1:]} found in {args[0]}", file=sys.stderr)
            return 1
        sys.stdout.write(text)
    elif cmd == "eol":
        product, name, path = args[0], args[1], args[2]
        today = dt.date.fromisoformat(args[3]) if len(args) > 3 else dt.date.today()
        try:
            eol = eol_date(json.loads(Path(path).read_text(encoding="utf-8")))
        except (OSError, ValueError):
            eol = None
        if not eol:
            print(f"::error title=Base check::{product} {name}: end of support not determinable (endoflife.date)")
            return 1
        state, days = eol_status(eol, today)
        msg = f"{product} {name}: security updates until {eol} ({days} days left)"
        if state == "fail":
            print(f"::error title=Lift the base::{msg} – less than 6 months. Lift the base deliberately.")
            return 1
        if state == "notice":
            print(f"::warning title=Lift the base soon::{msg} – less than 12 months.")
        else:
            print(msg)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
