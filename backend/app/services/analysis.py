"""Import an SPDX + Grype bundle atomically and retain the original evidence."""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import re
from typing import Any, Optional
from urllib.parse import parse_qsl, unquote, urlsplit

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from .sbom import import_spdx, validate_spdx_schema


class ReportObject(BaseModel):
    model_config = ConfigDict(extra="allow")


class Fix(ReportObject):
    versions: list[str] = Field(default_factory=list)
    state: str = "unknown"


class Finding(ReportObject):
    id: str = Field(min_length=1, max_length=120)
    severity: str = "Unknown"
    description: Optional[str] = None
    dataSource: Optional[str] = None
    urls: list[str] = Field(default_factory=list)
    fix: Fix = Field(default_factory=Fix)


class Artifact(ReportObject):
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    purl: Optional[str] = None


class Related(ReportObject):
    id: str


class Match(ReportObject):
    artifact: Artifact
    vulnerability: Finding
    relatedVulnerabilities: list[Related] = Field(default_factory=list)


class Descriptor(ReportObject):
    name: str
    version: str = Field(min_length=1, max_length=80)
    db: dict[str, Any] = Field(default_factory=dict)


class Report(ReportObject):
    descriptor: Descriptor
    source: dict[str, Any]
    matches: list[Match]


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def purl_key(value: str) -> tuple:
    parsed = urlsplit(value)
    return unquote(parsed.path), tuple(sorted(parse_qsl(parsed.query))), unquote(parsed.fragment)


def import_analysis(db: Session, payload: schemas.AnalysisImport, *, commit: bool = True) -> models.AnalysisRun:
    try:
        report = Report.model_validate(payload.report)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="Grype JSON 보고서의 필수 필드가 없거나 형식이 올바르지 않습니다") from exc
    # Grype retains the original directory/image source even when its input is an SPDX file.
    if report.descriptor.name.lower() != 'grype' or report.source.get('type') not in {'sbom', 'sbom-file', 'directory', 'image', 'file'}:
        raise HTTPException(status_code=422, detail="지원하는 원본 유형의 Grype JSON 보고서가 필요합니다")
    if payload.sbom.get('spdxVersion') != 'SPDX-2.3':
        raise HTTPException(status_code=422, detail="분석 묶음에는 SPDX 2.3 JSON이 필요합니다")
    validate_spdx_schema(payload.sbom)
    if not payload.sbom.get('packages'):
        raise HTTPException(status_code=422, detail="구성요소가 없는 SBOM은 분석 결과로 등록할 수 없습니다")
    if not db.get(models.Asset, payload.asset_id):
        raise HTTPException(status_code=404, detail="연결할 자산이 없습니다")
    fingerprint = digest({'asset_id': payload.asset_id, 'sbom': payload.sbom, 'report': payload.report})
    previous = db.scalar(select(models.AnalysisRun).where(models.AnalysisRun.report_sha256 == fingerprint))
    if previous:
        return previous
    sbom = db.scalar(select(models.SbomDocument).where(
        models.SbomDocument.serial_number == payload.sbom['documentNamespace'],
        models.SbomDocument.document_version == 1,
    ))
    if sbom and (sbom.asset_id != payload.asset_id or digest(sbom.raw_document) != digest(payload.sbom)):
        raise HTTPException(status_code=409, detail="같은 SBOM 식별자가 다른 자산 또는 다른 원본에 사용되고 있습니다")
    if not sbom:
        sbom = import_spdx(db, payload.sbom, payload.asset_id, commit=False)
    components = db.scalars(select(models.Component).where(models.Component.sbom_id == sbom.id)).all()
    by_purl, by_identity = defaultdict(list), defaultdict(list)
    for component in components:
        if component.purl:
            by_purl[purl_key(component.purl)].append(component)
        by_identity[(component.name, component.version)].append(component)

    creators = payload.sbom.get('creationInfo', {}).get('creators', [])
    run = models.AnalysisRun(
        sbom_id=sbom.id, report_sha256=fingerprint, sbom_sha256=digest(payload.sbom),
        scanner='Grype', scanner_version=report.descriptor.version,
        generator=', '.join(c for c in creators if c.startswith('Tool:'))[:160] or 'unknown',
        scan_scope=payload.scan_scope, match_count=len(report.matches), cve_count=0,
        link_count=0, ignored_non_cve=0, database_info=report.descriptor.db,
        raw_report=payload.report,
    )
    db.add(run)
    db.flush()
    seen, cves = set(), set()
    rank = {'UNKNOWN': 0, 'NEGLIGIBLE': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 4, 'CRITICAL': 5}
    links = {}
    all_cves = {identifier for match in report.matches
                for identifier in [match.vulnerability.id, *(r.id for r in match.relatedVulnerabilities)]
                if re.fullmatch(r'CVE-\d{4}-\d{4,}', identifier)}
    vulnerabilities = {}
    cve_list = sorted(all_cves)
    for start in range(0, len(cve_list), 500):
        vulnerabilities.update({v.osv_id: v for v in db.scalars(select(models.Vulnerability).where(
            models.Vulnerability.osv_id.in_(cve_list[start:start + 500])))})
    existing_links = {(link.component_id, cve): link for link, cve in db.execute(
        select(models.ComponentVulnerability, models.Vulnerability.osv_id)
        .join(models.Vulnerability)
        .join(models.Component)
        .where(models.Component.sbom_id == sbom.id))}
    for match in report.matches:
        # Match all rows, including non-CVE rows, to reject a report paired with the wrong SBOM.
        candidates = by_purl[purl_key(match.artifact.purl)] if match.artifact.purl else by_identity[(match.artifact.name, match.artifact.version)]
        candidates = [c for c in candidates if c.name == match.artifact.name and c.version == match.artifact.version]
        if not candidates or (not match.artifact.purl and len(candidates) != 1):
            raise HTTPException(status_code=422, detail=f"보고서 구성요소가 SBOM과 일치하지 않거나 모호합니다: {match.artifact.name}")
        identifiers = {match.vulnerability.id, *(r.id for r in match.relatedVulnerabilities)}
        ids = sorted(i for i in identifiers if re.fullmatch(r'CVE-\d{4}-\d{4,}', i))
        if not ids:
            run.ignored_non_cve += 1
            continue
        severity = match.vulnerability.severity.upper()
        severity = severity if severity in rank else 'UNKNOWN'
        versions = sorted(set(match.vulnerability.fix.versions)) if match.vulnerability.fix.state == 'fixed' else []
        if any(len(v) > 160 for v in versions):
            raise HTTPException(status_code=422, detail="수정 버전 문자열이 너무 깁니다")
        for cve in ids:
            vulnerability = vulnerabilities.get(cve)
            if not vulnerability:
                vulnerability = models.Vulnerability(
                    osv_id=cve, summary=match.vulnerability.description, details=match.vulnerability.description,
                    severity=severity, aliases=sorted(identifiers), references=[{'url': u} for u in match.vulnerability.urls],
                )
                db.add(vulnerability)
                vulnerabilities[cve] = vulnerability
            cves.add(cve)
            for component in candidates:
                key = (component.id, cve)
                if key not in links:
                    link = existing_links.get(key)
                    if not link:
                        link = models.ComponentVulnerability(component_id=component.id, vulnerability=vulnerability, vex_status='AFFECTED')
                        db.add(link)
                    link.analysis_run_id = run.id
                    link.finding_source = 'Grype'
                    link.finding_severity = severity
                    link.fixed_versions = []
                    links[key] = link
                link = links[key]
                if rank[severity] > rank[link.finding_severity]:
                    link.finding_severity = severity
                link.fixed_versions = sorted(set(link.fixed_versions) | set(versions))
                # Multiple fixed branches are alternatives, not a single recommended upgrade.
                link.fixed_version = link.fixed_versions[0] if len(link.fixed_versions) == 1 else None
                seen.add(key)
    run.cve_count, run.link_count = len(cves), len(seen)
    if commit:
        db.commit()
        db.refresh(run)
    else:
        db.flush()
    return run
