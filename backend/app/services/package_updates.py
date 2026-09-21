"""Cross-check grype's "fixed" verdicts against the target's own package manager.

A distro scanner decides by version number. Distributions backport security fixes without
bumping the upstream version, so the classic false positive is "openssl 3.0.2 is vulnerable"
when Ubuntu's 3.0.2-0ubuntu1.18 already carries the fix. Grype avoids most of that by using
the distribution's own fixed *package* versions, but the DB and the mirror can disagree.
So after an OS scan the worker asks the server what apt/dnf would actually upgrade and, per
CVE, records whether the fix is really waiting in the repository:

    UPDATE_AVAILABLE  the repository offers a version at or above the fixed version
    UPDATE_BELOW_FIX  an update exists but is still below the fixed version
    NO_UPDATE_FOUND   nothing to upgrade: the DB is ahead of the mirror or the finding is a false positive
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Optional

UPDATE_AVAILABLE = "UPDATE_AVAILABLE"
UPDATE_BELOW_FIX = "UPDATE_BELOW_FIX"
NO_UPDATE_FOUND = "NO_UPDATE_FOUND"

# Read-only except for refreshing the package index (what unattended-upgrades does daily); needs no root otherwise.
REMOTE_COMMAND = (
    "if command -v apt-get >/dev/null 2>&1; then "
    "  echo MANAGER=apt; "
    "  if sudo -n apt-get update -qq >/dev/null 2>&1; then echo REFRESHED=yes; else echo REFRESHED=no; fi; "
    "  apt list --upgradable 2>/dev/null; "
    "elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then "
    "  echo MANAGER=rpm; echo REFRESHED=yes; "
    "  (dnf -q check-update 2>/dev/null || yum -q check-update 2>/dev/null); "
    "else echo MANAGER=none; fi; true"
)
APT_LINE = re.compile(r"^([^/\s]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:\s*([^\]]+)\]")
RPM_LINE = re.compile(r"^(\S+?)\.(?:x86_64|aarch64|noarch|i686|s390x|ppc64le)\s+(\S+)\s+\S+$")


def parse_updates(text: str) -> dict[str, Any]:
    manager, refreshed, packages = None, False, {}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("MANAGER="):
            manager = line[8:] if line[8:] in {"apt", "rpm"} else None
        elif line.startswith("REFRESHED="):
            refreshed = line[10:] == "yes"
        elif manager == "apt":
            match = APT_LINE.match(line)
            if match:
                packages[match.group(1)] = {"candidate": match.group(2), "installed": match.group(3).strip()}
        elif manager == "rpm":
            match = RPM_LINE.match(line)
            if match:
                packages[match.group(1)] = {"candidate": match.group(2), "installed": None}
    return {"manager": manager, "refreshed": refreshed, "packages": packages,
            "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


# ---- Debian version comparison (dpkg --compare-versions semantics) ----

def _order(char: str) -> int:
    if char == "~":
        return -1
    if char == "" or char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_fragment(a: str, b: str) -> int:
    while a or b:
        # non-digit run
        while (a and not a[0].isdigit()) or (b and not b[0].isdigit()):
            ac = _order(a[0]) if a and not a[0].isdigit() else _order("")
            bc = _order(b[0]) if b and not b[0].isdigit() else _order("")
            if ac != bc:
                return -1 if ac < bc else 1
            if a and not a[0].isdigit():
                a = a[1:]
            if b and not b[0].isdigit():
                b = b[1:]
        # digit run
        na = re.match(r"\d*", a).group(0)
        nb = re.match(r"\d*", b).group(0)
        a, b = a[len(na):], b[len(nb):]
        ia, ib = int(na or 0), int(nb or 0)
        if ia != ib:
            return -1 if ia < ib else 1
    return 0


def _split(version: str) -> tuple[int, str, str]:
    epoch, _, rest = version.partition(":") if ":" in version else ("0", "", version)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch) if epoch.isdigit() else 0, upstream, revision


def compare_versions(a: str, b: str) -> int:
    """-1, 0 or 1 like dpkg --compare-versions; also a fair approximation of rpm's label compare."""
    ea, ua, ra = _split(a.strip())
    eb, ub, rb = _split(b.strip())
    if ea != eb:
        return -1 if ea < eb else 1
    result = _compare_fragment(ua, ub)
    return result if result else _compare_fragment(ra, rb)


def fix_check(component_name: str, fixed_versions: list[str], updates: Optional[dict[str, Any]]) -> Optional[str]:
    """What the package manager says about the fix grype expects for this component."""
    if not updates or not updates.get("manager") or not fixed_versions:
        return None
    update = (updates.get("packages") or {}).get(component_name)
    if not update:
        return NO_UPDATE_FOUND
    candidate = update.get("candidate") or ""
    if any(compare_versions(candidate, str(version)) >= 0 for version in fixed_versions):
        return UPDATE_AVAILABLE
    return UPDATE_BELOW_FIX
