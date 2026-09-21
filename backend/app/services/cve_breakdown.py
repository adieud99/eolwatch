"""Which CVEs a reviewer can act on: the ones with a fixed package, and the kernel bucket.

An Ubuntu host reports every CVE the distribution tracks for each installed source package,
including thousands the maintainers have not fixed (or will not), and the kernel source
package alone carries most of them. Counting all of that as one number hides the handful of
packages an `apt upgrade` would actually change, so runs and lists expose the split.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import String, and_, case, cast, func, or_, select
from sqlalchemy.orm import Session

from .. import models

link = models.ComponentVulnerability
component = models.Component

# fixed_versions is a JSON list; a link with any fixed version is actionable.
HAS_FIX = and_(link.fixed_versions.isnot(None), cast(link.fixed_versions, String).notin_(("[]", "null", "")))
# Ubuntu/Debian binary packages built from the kernel source carry upstream=linux… in their PURL.
IS_KERNEL = or_(component.purl.like("%upstream=linux%"), component.name.like("linux-image%"), component.name.like("linux-modules%"),
                component.name.like("linux-headers%"), component.name == "bpftool")


def breakdown(db: Session, run_ids: list[int]) -> dict[int, dict[str, int]]:
    """Per analysis run: distinct CVEs with a fix, on kernel packages, and both.

    Grouped by the run's own links (not the SBOM) so OSV cross-check findings on the same SBOM do not leak in.
    """
    empty = lambda: {"fixable_cve_count": 0, "kernel_cve_count": 0, "kernel_fixable_cve_count": 0, "verified_fixable_cve_count": 0, "suspect_cve_count": 0}
    result = {run_id: empty() for run_id in run_ids}
    if not run_ids:
        return result
    rows = db.execute(
        # max() over 1/0 rather than booleans: PostgreSQL has no max(boolean).
        select(link.analysis_run_id, link.vulnerability_id, func.max(case((HAS_FIX, 1), else_=0)), func.max(case((IS_KERNEL, 1), else_=0)),
               func.max(case((link.fix_check == "UPDATE_AVAILABLE", 1), else_=0)), func.max(case((link.fix_check == "NO_UPDATE_FOUND", 1), else_=0)))
        .join(component, link.component_id == component.id)
        .where(link.analysis_run_id.in_(run_ids))
        .group_by(link.analysis_run_id, link.vulnerability_id)
    ).all()
    for run_id, _vulnerability_id, fixed, kernel, verified, suspect in rows:
        counts = result.setdefault(run_id, empty())
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


def filters(fix: str, kernel: bool) -> list[Any]:
    """WHERE clauses for a link query joined to Component: fix in ALL/FIXED/UNFIXED, kernel True keeps kernel packages."""
    clauses = []
    if fix == "FIXED":
        clauses.append(HAS_FIX)
    elif fix == "UNFIXED":
        clauses.append(~HAS_FIX)
    if not kernel:
        clauses.append(~IS_KERNEL)
    return clauses
