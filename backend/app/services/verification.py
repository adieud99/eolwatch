"""Second-opinion verification of scan findings against public, authoritative sources.

Two questions a practitioner asks about a finding that the scanner alone cannot answer:

1. *What does the distribution itself say?* Ubuntu publishes per-CVE, per-release status
   (``released <version>``, ``pending <version>``, ``needed``, ``deferred``, ``ignored``,
   ``not-affected``, ``DNE``). Grype only knows ``released`` fixes, so everything else shows as
   "no fix". Storing the tracker status turns "수정판 없음" into "다음 커널에서 수정 예정",
   "업스트림만 수정", or "이미 수정됨 (DB 지연)".

2. *Does this kernel CVE touch code this machine runs?* The kernel CNA publishes, for every
   kernel CVE, the affected source files. Compared with the machine's architecture, loaded
   modules (``lsmod``) and mounted filesystems, a CVE in ``drivers/gpu/drm`` on a headless
   cloud VM without that module loaded is "미로드 드라이버". The heuristic is documented in
   ``classify_files``; built-in (=y) code cannot be told apart without the kernel config, so
   "확인 필요" and the AI review stay in the loop.

Both lookups are cached in the database (``tracker_cache``, ``kernel_cve_files``) and run
after import in the worker, or on demand through ``POST /api/analyses/{run_id}/verify``.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import logging
import re
import time
from typing import Any, Iterable, Optional
from urllib.parse import parse_qsl, urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from .cve_breakdown import is_kernel_package

logger = logging.getLogger(__name__)

UBUNTU_CVE_URL = "https://ubuntu.com/security/cves/{cve}.json"
KERNEL_CVE_URL = "https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/{year}/{cve}.json"
USER_AGENT = "EOLWatch-verification/1.0 (+https://github.com/adieud99)"
CACHE_TTL = timedelta(hours=24)
THREADS = 8
TIMEOUT = 20.0

# Ubuntu release codenames for VERSION_IDs the tracker knows; the scan stores VERSION_CODENAME when the server has it.
UBUNTU_CODENAMES = {"20.04": "focal", "22.04": "jammy", "24.04": "noble", "24.10": "oracular", "25.04": "plucky",
                    "25.10": "questing", "26.04": "resolute"}
TRACKER_OPEN = ("needed", "pending", "deferred", "needs-triage")
TRACKER_CLOSED = ("not-affected", "DNE", "ignored")

# host_relevance values
CORE = "CORE"                      # code every running kernel executes (mm, sched, core networking, root filesystem...)
LOADED_MODULE = "LOADED_MODULE"    # a module named in lsmod contains the affected file
UNLOADED_MODULE = "UNLOADED_MODULE"  # driver / subsystem code that is only built as a module and is not loaded here
OTHER_ARCH = "OTHER_ARCH"          # arch/<something else>
FS_NOT_USED = "FS_NOT_USED"        # a filesystem driver this machine neither mounts nor has loaded
UNKNOWN = "UNKNOWN"
NOT_APPLICABLE_KINDS = (UNLOADED_MODULE, OTHER_ARCH, FS_NOT_USED)

ARCH_DIRS = {"x86_64": "x86", "amd64": "x86", "aarch64": "arm64", "arm64": "arm64", "armv7l": "arm", "riscv64": "riscv",
             "ppc64le": "powerpc", "s390x": "s390"}
CORE_TOP = ("kernel", "mm", "lib", "block", "security", "crypto", "include", "init", "virt", "io_uring", "ipc", "certs", "rust")
CORE_NET = ("core", "ipv4", "ipv6", "netfilter", "sched", "unix", "netlink", "ethtool", "xfrm", "key", "packet", "bridge", "8021q", "llc")
MODULAR_NET = {"sctp", "tipc", "rds", "dccp", "batman-adv", "can", "bluetooth", "wireless", "mac80211", "nfc", "ax25", "netrom",
               "rose", "x25", "appletalk", "9p", "ceph", "rxrpc", "smc", "mctp", "qrtr", "vmw_vsock", "hsr", "l2tp", "mpls",
               "openvswitch", "ieee802154", "6lowpan", "atm", "phonet", "nsh", "bpfilter", "caif", "dsa", "hsr", "kcm", "lapb",
               "mptcp", "ncsi", "psample", "strparser", "tls", "vmw_vsock", "wimax", "xdp", "handshake"}
NET_MODULE_NAMES = {"wireless": ("cfg80211",), "mac80211": ("mac80211",), "bluetooth": ("bluetooth",), "vmw_vsock": ("vsock",),
                    "batman-adv": ("batman_adv",), "openvswitch": ("openvswitch",), "mptcp": ("mptcp_diag",), "tls": ("tls",)}


# ---------------------------------------------------------------- HTTP with cache

def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True)


def _source_package(component: models.Component) -> str:
    """Ubuntu tracks CVEs per *source* package; the PURL's upstream qualifier names it for binaries."""
    if component.purl:
        try:
            for key, value in parse_qsl(urlsplit(component.purl).query):
                if key == "upstream" and value:
                    return value.split("@", 1)[0]
        except ValueError:
            pass
    return component.name


def fetch_ubuntu(client: httpx.Client, cve: str) -> Optional[dict[str, Any]]:
    try:
        response = client.get(UBUNTU_CVE_URL.format(cve=cve))
    except httpx.HTTPError as error:
        logger.debug("ubuntu tracker %s: %s", cve, error)
        return None
    if response.status_code == 404:
        return {"missing": True}
    if response.status_code != 200:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def fetch_kernel(client: httpx.Client, cve: str) -> Optional[dict[str, Any]]:
    year = cve.split("-")[1]
    try:
        response = client.get(KERNEL_CVE_URL.format(year=year, cve=cve))
    except httpx.HTTPError:
        return None
    if response.status_code == 404:
        return {"missing": True}
    if response.status_code != 200:
        return None
    try:
        data = response.json()
        cna = data["containers"]["cna"]
        affected = cna.get("affected") or []
        files = sorted({f for entry in affected for f in (entry.get("programFiles") or [])})
        fixed = sorted({str(v.get("lessThanOrEqual") or v.get("lessThan")) for entry in affected for v in (entry.get("versions") or [])
                        if v.get("versionType") != "git" and v.get("status") == "affected" and (v.get("lessThanOrEqual") or v.get("lessThan"))})
        return {"title": str(cna.get("title") or "")[:160], "files": files[:40], "fixed": fixed[:10]}
    except (KeyError, TypeError, ValueError):
        return {"missing": True}


# ---------------------------------------------------------------- host relevance

def _tokens(path: str) -> set[str]:
    parts = path.split("/")
    stem = parts[-1].rsplit(".", 1)[0]
    tokens = {p.replace("-", "_") for p in parts[1:-1]} | {stem.replace("-", "_")}
    return {t for t in tokens if t and t not in ("core", "common", "main", "lib", "src")}


def _module_loaded(tokens: set[str], modules: set[str]) -> bool:
    """A file belongs to a loaded module when a path token names it, or a loaded module shares the file's family prefix
    (dm-mpath.c -> dm_multipath, snd-hda-*.c -> snd_hda_*). Erring towards 'loaded' keeps a real CVE from being dismissed."""
    if tokens & modules:
        return True
    prefixes = {t.split("_", 1)[0] + "_" for t in tokens if "_" in t}
    return any(m.startswith(prefix) for prefix in prefixes for m in modules)


def classify_files(files: Iterable[str], host: dict[str, Any]) -> str:
    """Where in the kernel the CVE lives, against what this machine runs. See the module docstring for the caveats."""
    files = [f for f in files if f]
    if not files or not host:
        return UNKNOWN
    modules = {m.replace("-", "_") for m in host.get("modules") or []}
    filesystems = set(host.get("filesystems") or []) | ({host["rootfs"]} if host.get("rootfs") else set())
    arch_dir = ARCH_DIRS.get(str(host.get("arch") or ""))
    verdicts = []
    for path in files:
        parts = path.split("/")
        top = parts[0]
        if top == "arch":
            verdicts.append(CORE if len(parts) > 1 and parts[1] == arch_dir else OTHER_ARCH)
            continue
        if top in CORE_TOP:
            verdicts.append(CORE)
            continue
        tokens = _tokens(path)
        if top == "fs":
            name = parts[1] if len(parts) > 2 else ""
            if not name or name in ("proc", "sysfs", "kernfs", "notify", "iomap", "netfs", "quota", "nls", "crypto", "verity", "cachefiles", "overlayfs", "exportfs", "dlm"):
                verdicts.append(CORE)
            elif name in filesystems or name in modules or _module_loaded(tokens, modules):
                verdicts.append(CORE if name in filesystems else LOADED_MODULE)
            else:
                verdicts.append(FS_NOT_USED)
            continue
        if top == "net":
            sub = parts[1] if len(parts) > 2 else ""
            if not sub or sub in CORE_NET:
                verdicts.append(CORE)
            elif sub in MODULAR_NET:
                names = set(NET_MODULE_NAMES.get(sub, ())) | {sub.replace("-", "_")}
                verdicts.append(LOADED_MODULE if names & modules or _module_loaded(tokens, modules) else UNLOADED_MODULE)
            else:
                verdicts.append(LOADED_MODULE if _module_loaded(tokens, modules) else UNKNOWN)
            continue
        if top in ("drivers", "sound"):
            verdicts.append(LOADED_MODULE if _module_loaded(tokens, modules) else UNLOADED_MODULE)
            continue
        verdicts.append(UNKNOWN)
    # One reachable file makes the CVE reachable; only when every file is out of reach is it "not here".
    for kind in (CORE, LOADED_MODULE):
        if kind in verdicts:
            return kind
    if UNKNOWN in verdicts:
        return UNKNOWN
    if all(v == OTHER_ARCH for v in verdicts):
        return OTHER_ARCH
    if all(v in (FS_NOT_USED, OTHER_ARCH) for v in verdicts):
        return FS_NOT_USED
    return UNLOADED_MODULE


# ---------------------------------------------------------------- tracker status

def _tracker_status(data: dict[str, Any], package: str, codename: Optional[str]) -> tuple[str, Optional[str], Optional[str]]:
    """(status, fixed version or pending version, priority) for one source package on one release."""
    if not data or data.get("missing"):
        return "unknown", None, None
    priority = data.get("priority")
    for entry in data.get("packages") or []:
        if entry.get("name") != package:
            continue
        for status in entry.get("statuses") or []:
            if codename and status.get("release_codename") != codename:
                continue
            state = str(status.get("status") or "unknown")
            note = str(status.get("description") or "").strip() or None
            return state, note, priority
    return "not-listed", None, priority


def _compare_deb(a: str, b: str) -> int:
    from .package_updates import compare_versions
    return compare_versions(a, b)


# ---------------------------------------------------------------- main entry

def verify_run(db: Session, run_id: int, *, budget_seconds: float = 600.0) -> dict[str, Any]:
    """Fill tracker_status / host_relevance for the run's findings; returns the counts it stored."""
    started = time.monotonic()
    run = db.get(models.AnalysisRun, run_id)
    if not run:
        raise ValueError("analysis run not found")
    info = run.database_info if isinstance(run.database_info, dict) else {}
    distro = info.get("distro") or {}
    host = info.get("host") or {}
    distro_id = str(distro.get("id") or "")
    codename = distro.get("codename") or UBUNTU_CODENAMES.get(str(distro.get("versionID") or ""))
    rows = db.execute(select(models.ComponentVulnerability, models.Component, models.Vulnerability)
                      .join(models.Component, models.ComponentVulnerability.component_id == models.Component.id)
                      .join(models.Vulnerability, models.ComponentVulnerability.vulnerability_id == models.Vulnerability.id)
                      .where(models.ComponentVulnerability.analysis_run_id == run_id)).all()
    counts: dict[str, Any] = {"tracker": {}, "host": {}, "checked_cves": 0, "partial": False, "distro": distro_id, "codename": codename}

    # ---- 1. distribution tracker (Ubuntu only for now)
    if distro_id == "ubuntu" and codename:
        wanted: dict[tuple[str, str], list[models.ComponentVulnerability]] = {}
        for link, component, vuln in rows:
            wanted.setdefault((vuln.osv_id, _source_package(component)), []).append(link)
        cached = {(c.cve, c.package): c for c in db.scalars(select(models.TrackerCache).where(
            models.TrackerCache.distro_id == distro_id, models.TrackerCache.release == codename,
            models.TrackerCache.cve.in_({cve for cve, _ in wanted})))}
        fresh_after = models.utcnow() - CACHE_TTL
        to_fetch = sorted({cve for (cve, package) in wanted if not (cached.get((cve, package)) and cached[(cve, package)].checked_at.replace(tzinfo=None) > fresh_after.replace(tzinfo=None))})
        fetched: dict[str, Optional[dict[str, Any]]] = {}
        if to_fetch:
            with _client() as client, ThreadPoolExecutor(THREADS) as pool:
                futures = {cve: pool.submit(fetch_ubuntu, client, cve) for cve in to_fetch}
                for cve, future in futures.items():
                    if time.monotonic() - started > budget_seconds:
                        counts["partial"] = True
                        break
                    fetched[cve] = future.result()
        for (cve, package), links in wanted.items():
            entry = cached.get((cve, package))
            if cve in fetched:
                data = fetched[cve]
                if data is None:
                    continue  # transient error: keep whatever was cached
                status, note, priority = _tracker_status(data, package, codename)
                if entry is None:
                    entry = models.TrackerCache(cve=cve, distro_id=distro_id, release=codename, package=package)
                    db.add(entry)
                entry.status, entry.fix, entry.priority, entry.checked_at = status, note, priority, models.utcnow()
            if entry is None:
                continue
            for link in links:
                link.tracker_status = entry.status
                link.tracker_fix = entry.fix
            counts["checked_cves"] += 1
        db.flush()
        tally: dict[str, int] = {}
        fixed_already = 0
        seen = set()
        for link, component, vuln in rows:
            if vuln.osv_id in seen or not link.tracker_status:
                continue
            seen.add(vuln.osv_id)
            tally[link.tracker_status] = tally.get(link.tracker_status, 0) + 1
            # Grype says no fix, Ubuntu says released at or below the installed version: the DB is behind (or the finding is wrong).
            if link.tracker_status == "released" and not link.fixed_versions and link.tracker_fix and component.version:
                try:
                    if _compare_deb(component.version, link.tracker_fix) >= 0:
                        fixed_already += 1
                except Exception:
                    pass
        counts["tracker"] = tally
        counts["fixed_already"] = fixed_already

    # ---- 2. kernel CVE source files vs this host
    kernel_rows = [(link, component, vuln) for link, component, vuln in rows if is_kernel_package(component.name, component.purl)]
    if kernel_rows:
        cves = sorted({vuln.osv_id for _, _, vuln in kernel_rows})
        cached_files = {c.cve: c for c in db.scalars(select(models.KernelCveFiles).where(models.KernelCveFiles.cve.in_(cves)))}
        to_fetch = [cve for cve in cves if cve not in cached_files]
        if to_fetch and time.monotonic() - started < budget_seconds:
            with _client() as client, ThreadPoolExecutor(THREADS) as pool:
                futures = {cve: pool.submit(fetch_kernel, client, cve) for cve in to_fetch}
                for cve, future in futures.items():
                    if time.monotonic() - started > budget_seconds:
                        counts["partial"] = True
                        break
                    data = future.result()
                    if data is None:
                        continue
                    record = models.KernelCveFiles(cve=cve, files=data.get("files") or [], fixed_versions=data.get("fixed") or [],
                                                   title=data.get("title"), missing=bool(data.get("missing")), fetched_at=models.utcnow())
                    db.add(record)
                    cached_files[cve] = record
            db.flush()
        tally = {}
        seen = set()
        for link, component, vuln in kernel_rows:
            record = cached_files.get(vuln.osv_id)
            if record is None:
                continue
            relevance = classify_files(record.files, host) if not record.missing else UNKNOWN
            link.host_relevance = relevance
            link.kernel_files = list(record.files[:5])
            if vuln.osv_id not in seen:
                seen.add(vuln.osv_id)
                tally[relevance] = tally.get(relevance, 0) + 1
        counts["host"] = tally
    counts["checked_at"] = models.utcnow().isoformat()
    counts["seconds"] = round(time.monotonic() - started, 1)
    run.database_info = {**info, "verification": counts}
    db.commit()
    return counts
