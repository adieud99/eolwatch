from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any
from urllib.parse import quote

import httpx
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from .osv_matching import (
    SEVERITY_RANK, match_advisory, maximum_severity, osv_query, package_context, parse_timestamp,
    safe_fixed_versions, severity, validate_advisory,
)


def _timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # Database values may be naive; actual OSV values are validated RFC3339.
        parsed = parse_timestamp(value) if value.endswith("Z") or re.search(r"[+-]\d\d:\d\d$", value) else datetime.fromisoformat(value)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except (ValueError, AttributeError):
        return None


def _severity(item: dict[str, Any]) -> str:
    return severity(item)


def _cve_ids(item: dict[str, Any]) -> list[str]:
    values = [item.get("id"), *(item.get("aliases") or [])]
    return sorted({value.upper() for value in values if isinstance(value, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", value.upper())})


def _fixed_version(item: dict[str, Any], component: Any = None) -> str | None:
    """Compatibility helper: a fix cannot be inferred without package/version."""
    if component is None:
        return None
    versions = match_advisory(package_context(component), validate_advisory(item)).fixed_versions
    return versions[0] if versions else None


def _result_list(payload: Any, expected_count: int) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("OSV batch 응답의 results 목록이 없습니다")
    results = payload["results"]
    if len(results) != expected_count:
        raise ValueError(f"OSV 응답 개수가 요청과 다릅니다 ({expected_count}개 요청, {len(results)}개 응답); 결과를 저장하지 않았습니다")
    for result in results:
        if not isinstance(result, dict) or "error" in result:
            raise ValueError("OSV 개별 조회 응답에 오류가 있습니다")
        if not isinstance(result.get("vulns", []), list):
            raise ValueError("OSV vulns 목록 형식이 올바르지 않습니다")
        token = result.get("next_page_token", "")
        if not isinstance(token, str):
            raise ValueError("OSV 페이지 토큰 형식이 올바르지 않습니다")
    return results


def query_osv(queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fetch every batch page, then every full advisory, preserving input order."""
    if not queries:
        return []
    settings = get_settings()
    results: list[dict[str, Any]] = [{"vulns": []} for _ in queries]
    pending = [(index, dict(query)) for index, query in enumerate(queries)]
    seen_tokens: list[set[str]] = [set() for _ in queries]
    seen_ids: list[set[str]] = [set() for _ in queries]
    detail_base = settings.osv_api_url.rsplit("/querybatch", 1)[0] + "/vulns/"
    with httpx.Client(timeout=30) as client:
        for _page in range(100):
            response = client.post(settings.osv_api_url, json={"queries": [query for _index, query in pending]})
            response.raise_for_status()
            page_results = _result_list(response.json(), len(pending))
            next_pending = []
            for (index, query), result in zip(pending, page_results):
                for summary in result.get("vulns", []):
                    if not isinstance(summary, dict) or not isinstance(summary.get("id"), str) or not summary["id"].strip():
                        raise ValueError("OSV batch 취약점 id가 없습니다")
                    if summary["id"] not in seen_ids[index]:
                        results[index]["vulns"].append(summary["id"])
                        seen_ids[index].add(summary["id"])
                token = result.get("next_page_token")
                if token:
                    if token in seen_tokens[index]:
                        raise ValueError("OSV 페이지 토큰이 반복되어 전체 결과를 확인할 수 없습니다")
                    seen_tokens[index].add(token)
                    next_pending.append((index, {**query, "page_token": token}))
            pending = next_pending
            if not pending:
                break
        if pending:
            raise ValueError("OSV 페이지 제한을 초과했습니다; 일부 결과를 저장하지 않았습니다")
        cache: dict[str, dict[str, Any]] = {}
        for result in results:
            detailed = []
            for osv_id in result["vulns"]:
                if osv_id not in cache:
                    detail_response = client.get(detail_base + quote(osv_id, safe=""))
                    detail_response.raise_for_status()
                    cache[osv_id] = validate_advisory(detail_response.json(), expected_id=osv_id)
                detailed.append(cache[osv_id])
            result["vulns"] = detailed
    return results


def _merge_metadata(vulnerability: models.Vulnerability, advisories: list[dict[str, Any]]) -> None:
    """Keep strongest evidence and all source identifiers across advisory aliases."""
    ranked = sorted(advisories, key=lambda raw: (SEVERITY_RANK[_severity(raw)], raw.get("modified", ""), raw["id"]), reverse=True)
    incoming_severity = maximum_severity([_severity(raw) for raw in advisories])
    if SEVERITY_RANK.get(incoming_severity, 0) >= SEVERITY_RANK.get(vulnerability.severity, 0):
        vulnerability.summary = next((raw["summary"] for raw in ranked if raw.get("summary")), vulnerability.summary)
        vulnerability.details = next((raw["details"] for raw in ranked if raw.get("details")), vulnerability.details)
    vulnerability.severity = maximum_severity([vulnerability.severity, incoming_severity])
    aliases = {value for value in (vulnerability.aliases or []) if isinstance(value, str)}
    references = {json.dumps(value, sort_keys=True): value for value in (vulnerability.references or [])}
    published = [_timestamp(vulnerability.published_at.isoformat())] if vulnerability.published_at else []
    modified = [_timestamp(vulnerability.modified_at.isoformat())] if vulnerability.modified_at else []
    for raw in advisories:
        aliases.update([raw["id"], *raw.get("aliases", [])])
        references.update({json.dumps(value, sort_keys=True): value for value in raw.get("references", [])})
        published.append(_timestamp(raw.get("published")))
        modified.append(_timestamp(raw.get("modified")))
    vulnerability.aliases = sorted(aliases)
    vulnerability.references = [references[key] for key in sorted(references)]
    vulnerability.published_at = min((value for value in published if value), default=None)
    vulnerability.modified_at = max((value for value in modified if value), default=None)


def scan_sbom(db: Session, sbom_id: int) -> dict[str, int]:
    all_components = db.scalars(select(models.Component).where(models.Component.sbom_id == sbom_id)).all()
    components = []
    queries = []
    contexts = {}
    skipped_components = 0
    for component in all_components:
        if not component.purl:
            skipped_components += 1
            continue
        context = package_context(component)
        query = osv_query(context)
        if query is None:
            skipped_components += 1
            continue
        components.append(component)
        contexts[component.id] = context
        queries.append(query)
    results: list[dict[str, Any]] = []
    for start in range(0, len(queries), 1000):
        batch = query_osv(queries[start:start + 1000])
        # Also defend the service boundary if a different OSV client is injected.
        results.extend(_result_list({"results": batch}, len(queries[start:start + 1000])))

    grouped: dict[tuple[int, str], list[dict[str, Any]]] = {}
    ignored_non_cve = ignored_withdrawn = ignored_unaffected = 0
    for component, result in zip(components, results):
        if result.get("next_page_token"):
            raise ValueError("OSV의 남은 페이지가 처리되지 않았습니다")
        for raw in result.get("vulns", []):
            validate_advisory(raw)
            if raw.get("withdrawn"):
                ignored_withdrawn += 1
                continue
            identifiers = _cve_ids(raw)
            if not identifiers:
                ignored_non_cve += 1
                continue
            matched = match_advisory(contexts[component.id], raw)
            if matched.affected is False:
                ignored_unaffected += 1
                continue
            for cve_id in identifiers:
                grouped.setdefault((component.id, cve_id), []).append({
                    "raw": raw, "fixed_versions": matched.fixed_versions,
                    "severity": severity(raw, matched.entries),
                })

    # All network responses and recommendations have been validated before the
    # first write. The router rolls back on any error; review fields are untouched.
    cve_ids = {cve_id for _component_id, cve_id in grouped}
    advisory_groups: dict[str, list[dict[str, Any]]] = {}
    for (_component_id, cve_id), entries in grouped.items():
        advisory_groups.setdefault(cve_id, []).extend(entry["raw"] for entry in entries)
    vulnerabilities = {}
    protected = set()
    for cve_id in sorted(cve_ids):
        vulnerability = db.scalar(select(models.Vulnerability).where(models.Vulnerability.osv_id == cve_id))
        if not vulnerability:
            vulnerability = models.Vulnerability(osv_id=cve_id, severity="UNKNOWN")
            db.add(vulnerability)
            db.flush()
        vulnerabilities[cve_id] = vulnerability
        if db.scalar(select(models.ComponentVulnerability.id).where(
            models.ComponentVulnerability.vulnerability_id == vulnerability.id,
            or_(models.ComponentVulnerability.analysis_run_id.is_not(None),
                models.ComponentVulnerability.finding_source == "GRYPE"),
        ).limit(1)):
            protected.add(cve_id)
        if cve_id not in protected:
            _merge_metadata(vulnerability, advisory_groups[cve_id])

    for (component_id, cve_id), entries in grouped.items():
        vulnerability = vulnerabilities[cve_id]
        link = db.scalar(select(models.ComponentVulnerability).where(
            models.ComponentVulnerability.component_id == component_id,
            models.ComponentVulnerability.vulnerability_id == vulnerability.id,
        ))
        if link and (link.analysis_run_id is not None or link.finding_source == "GRYPE"):
            # A saved Grype baseline and its human review are immutable to OSV.
            continue
        if not link:
            link = models.ComponentVulnerability(component_id=component_id, vulnerability_id=vulnerability.id, vex_status="AFFECTED")
            db.add(link)
        versions = safe_fixed_versions(contexts[component_id],
                                       [version for entry in entries for version in entry["fixed_versions"]],
                                       [entry["raw"] for entry in entries])
        link.fixed_version = versions[0] if versions else None
        link.fixed_versions = versions
        link.finding_source = "OSV"
        link.finding_severity = maximum_severity([entry["severity"] for entry in entries])
        link.analysis_run_id = None
    db.commit()
    return {
        "sbom_id": sbom_id, "queried_components": len(components),
        "vulnerability_links": len(grouped), "unique_vulnerabilities": len(cve_ids),
        "ignored_non_cve": ignored_non_cve, "skipped_components": skipped_components,
        "ignored_withdrawn": ignored_withdrawn, "ignored_unaffected": ignored_unaffected,
    }
