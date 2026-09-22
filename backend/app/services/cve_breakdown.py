"""Which CVEs a reviewer can act on: the ones with a fixed package, and the kernel bucket.

An Ubuntu host reports every CVE the distribution tracks for each installed source package,
including thousands the maintainers have not fixed (or will not), and the kernel source
package alone carries most of them. Counting all of that as one number hides the handful of
packages an `apt upgrade` would actually change, so runs and lists expose the split.
"""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import String, and_, case, cast, func, or_, select
from sqlalchemy.orm import Session

from .. import models

link = models.ComponentVulnerability
component = models.Component

# EPSS probability at or above this is worth a human look (1%: roughly the top 10% of all CVEs).
EPSS_ATTENTION = 0.01
# fixed_versions is a JSON list; a link with any fixed version is actionable.
HAS_FIX = and_(link.fixed_versions.isnot(None), cast(link.fixed_versions, String).notin_(("[]", "null", "")))
# Ubuntu/Debian binary packages built from the kernel source carry upstream=linux… in their PURL.
IS_KERNEL = or_(component.purl.like("%upstream=linux%"), component.name.like("linux-image%"), component.name.like("linux-modules%"),
                component.name.like("linux-headers%"), component.name == "bpftool")


def is_kernel_package(name: str, purl: Optional[str]) -> bool:
    """Python twin of IS_KERNEL for the importer."""
    return bool((purl and "upstream=linux" in purl) or name.startswith(("linux-image", "linux-modules", "linux-headers")) or name == "bpftool")


def breakdown(db: Session, run_ids: list[int]) -> dict[int, dict[str, int]]:
    """Per analysis run: distinct CVEs with a fix, on kernel packages, and both.

    Grouped by the run's own links (not the SBOM) so OSV cross-check findings on the same SBOM do not leak in.
    """
    empty = lambda: {"fixable_cve_count": 0, "kernel_cve_count": 0, "kernel_fixable_cve_count": 0, "verified_fixable_cve_count": 0, "suspect_cve_count": 0,
                     "kev_cve_count": 0, "epss_cve_count": 0}
    result = {run_id: empty() for run_id in run_ids}
    if not run_ids:
        return result
    rows = db.execute(
        # max() over 1/0 rather than booleans: PostgreSQL has no max(boolean).
        select(link.analysis_run_id, link.vulnerability_id, func.max(case((HAS_FIX, 1), else_=0)), func.max(case((IS_KERNEL, 1), else_=0)),
               func.max(case((link.fix_check == "UPDATE_AVAILABLE", 1), else_=0)), func.max(case((link.fix_check == "NO_UPDATE_FOUND", 1), else_=0)),
               func.max(case((link.kev.is_(True), 1), else_=0)), func.max(case((link.epss >= EPSS_ATTENTION, 1), else_=0)))
        .join(component, link.component_id == component.id)
        .where(link.analysis_run_id.in_(run_ids))
        .group_by(link.analysis_run_id, link.vulnerability_id)
    ).all()
    for run_id, _vulnerability_id, fixed, kernel, verified, suspect, kev, epss in rows:
        counts = result.setdefault(run_id, empty())
        if kev:
            counts["kev_cve_count"] += 1
        if epss:
            counts["epss_cve_count"] += 1
        if verified:
            counts["verified_fixable_cve_count"] += 1
        if suspect:
            counts["suspect_cve_count"] += 1
        if fixed:
            counts["fixable_cve_count"] += 1
        if kernel:
            counts["kernel_cve_count"] += 1
            if fixed:
                counts["kernel_fixable_cve_count"] += 1
    return result


NOT_HERE = ("UNLOADED_MODULE", "OTHER_ARCH", "FS_NOT_USED")
# 'actionable': something can be done now (a fix exists, or exploitation evidence); 'relevant': also kernel code this host runs.
ACTIONABLE = or_(HAS_FIX, link.kev.is_(True), link.epss >= EPSS_ATTENTION)


def filters(fix: str, kernel: bool, relevance: str = "all") -> list[Any]:
    """WHERE clauses for a link query joined to Component: fix in ALL/FIXED/UNFIXED, kernel True keeps kernel packages,
    relevance actionable/relevant/all narrows to what a practitioner should look at first."""
    clauses = []
    if relevance == "actionable":
        clauses.append(ACTIONABLE)
    elif relevance == "relevant":
        clauses.append(or_(ACTIONABLE, ~IS_KERNEL, link.host_relevance.is_(None), link.host_relevance.notin_(NOT_HERE)))
    if fix == "FIXED":
        clauses.append(HAS_FIX)
    elif fix == "UNFIXED":
        clauses.append(~HAS_FIX)
    if not kernel:
        clauses.append(~IS_KERNEL)
    return clauses
