from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings


def _timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _severity(item: dict[str, Any]) -> str:
    database_value = (item.get("database_specific") or {}).get("severity")
    if isinstance(database_value, str):
        value = database_value.upper()
        if value in {"LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"}:
            return "MEDIUM" if value == "MODERATE" else value
    if item.get("severity"):
        return "KNOWN"
    return "UNKNOWN"


def query_osv(queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not queries:
        return []
    settings = get_settings()
    with httpx.Client(timeout=30) as client:
        response = client.post(settings.osv_api_url, json={"queries": queries})
        response.raise_for_status()
        results = response.json().get("results") or []
        detail_base = settings.osv_api_url.rsplit("/querybatch", 1)[0] + "/vulns/"
        cache: dict[str, dict[str, Any]] = {}
        for result in results:
            detailed = []
            for summary in result.get("vulns") or []:
                osv_id = summary.get("id")
                if not osv_id:
                    continue
                if osv_id not in cache:
                    detail_response = client.get(detail_base + quote(osv_id, safe=""))
                    detail_response.raise_for_status()
                    cache[osv_id] = detail_response.json()
                detailed.append(cache[osv_id])
            result["vulns"] = detailed
        return results


def scan_sbom(db: Session, sbom_id: int) -> dict[str, int]:
    components = db.scalars(
        select(models.Component).where(models.Component.sbom_id == sbom_id, models.Component.purl.is_not(None))
    ).all()
    queries = []
    for item in components:
        query: dict[str, Any] = {"package": {"purl": item.purl}}
        if "@" not in item.purl and item.version:
            query["version"] = item.version
        queries.append(query)
    results: list[dict[str, Any]] = []
    for start in range(0, len(queries), 1000):
        results.extend(query_osv(queries[start : start + 1000]))

    link_count = 0
    osv_ids: set[str] = set()
    for component, result in zip(components, results):
        for raw in result.get("vulns") or []:
            osv_id = raw.get("id")
            if not osv_id:
                continue
            osv_ids.add(osv_id)
            vulnerability = db.scalar(select(models.Vulnerability).where(models.Vulnerability.osv_id == osv_id))
            if not vulnerability:
                vulnerability = models.Vulnerability(osv_id=osv_id)
                db.add(vulnerability)
                db.flush()
            vulnerability.summary = raw.get("summary")
            vulnerability.details = raw.get("details")
            vulnerability.severity = _severity(raw)
            vulnerability.aliases = raw.get("aliases") or []
            vulnerability.references = raw.get("references") or []
            vulnerability.published_at = _timestamp(raw.get("published"))
            vulnerability.modified_at = _timestamp(raw.get("modified"))
            link = db.scalar(
                select(models.ComponentVulnerability).where(
                    models.ComponentVulnerability.component_id == component.id,
                    models.ComponentVulnerability.vulnerability_id == vulnerability.id,
                )
            )
            if not link:
                db.add(
                    models.ComponentVulnerability(
                        component_id=component.id,
                        vulnerability_id=vulnerability.id,
                        vex_status="AFFECTED",
                    )
                )
            link_count += 1
    db.commit()
    return {
        "sbom_id": sbom_id,
        "queried_components": len(components),
        "vulnerability_links": link_count,
        "unique_vulnerabilities": len(osv_ids),
    }
