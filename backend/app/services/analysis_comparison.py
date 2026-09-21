"""Read-only detection deltas from each run's original SBOM and Grype evidence."""
from __future__ import annotations

from collections import defaultdict
from datetime import timezone
import json
import re
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .. import models
from .analysis import Report
from .sbom import validate_spdx_schema


SEVERITY = {'UNKNOWN': 0, 'NEGLIGIBLE': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 4, 'CRITICAL': 5}
CVE = re.compile(r'CVE-\d{4}-\d{4,}')


def scanner_db(run) -> dict:
    """The grype DB descriptor only; run.database_info also carries EOLWatch bookkeeping (counts, package_updates)."""
    info = run.database_info if isinstance(run.database_info, dict) else {}
    return {k: v for k, v in info.items() if k not in ("counts", "package_updates")}


def _invalid(message: str):
    raise HTTPException(status_code=422, detail=f'분석 비교 원본을 확인하세요: {message}')


def _python_name(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower()


def _purl(value: str) -> tuple[str, str | None, str]:
    """Keep ecosystem/namespace/qualifiers/subpath, removing only the version.

    Decode individual path segments before re-encoding, so an encoded slash in a
    package name cannot silently turn into a namespace separator.
    """
    if not isinstance(value, str) or not value:
        _invalid('비어 있거나 잘못된 패키지 PURL입니다.')
    try:
        parsed = urlsplit(value)
    except ValueError:
        _invalid('패키지 PURL을 해석할 수 없습니다.')
    kind, separator, package_path = parsed.path.partition('/')
    if parsed.scheme != 'pkg' or parsed.netloc or not separator or not kind or not package_path:
        _invalid('패키지 PURL 형식이 올바르지 않습니다.')
    kind = kind.lower()
    version = None
    if package_path.rfind('@') > package_path.rfind('/'):
        package_path, version = package_path.rsplit('@', 1)
        version = unquote(version)
        if not version:
            _invalid('PURL 버전이 비어 있습니다.')
    parts = [unquote(part) for part in package_path.split('/')]
    if not all(parts):
        _invalid('PURL 패키지 이름이 비어 있습니다.')
    if kind == 'pypi':
        parts[-1] = _python_name(parts[-1])
    identity = f"pkg:{kind}/" + '/'.join(quote(part, safe='._-~') for part in parts)
    qualifiers = [(key.lower(), val) for key, val in parse_qsl(parsed.query, keep_blank_values=True)]
    if any(not key or not val for key, val in qualifiers) or len({key for key, _ in qualifiers}) != len(qualifiers):
        _invalid('PURL 한정자(배포판·아키텍처 등)가 비어 있거나 중복됐습니다.')
    if qualifiers:
        identity += '?' + urlencode(sorted(qualifiers), quote_via=quote)
    if parsed.fragment:
        identity += '#' + '/'.join(quote(unquote(part), safe='._-~') for part in parsed.fragment.split('/'))
    return identity, version, kind


def _evidence(run: models.AnalysisRun) -> dict:
    document = run.sbom.raw_document
    if not isinstance(document, dict) or document.get('spdxVersion') != 'SPDX-2.3':
        _invalid('SPDX 2.3 SBOM이 필요합니다.')
    validate_spdx_schema(document)
    packages = document.get('packages')
    if not isinstance(packages, list) or not packages:
        _invalid('구성요소 목록이 없거나 비어 있습니다.')
    try:
        report = Report.model_validate(run.raw_report)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail='필수 필드가 없는 Grype 원본은 비교할 수 없습니다.') from exc
    if report.descriptor.name.lower() != 'grype' or report.source.get('type') not in {'sbom', 'directory', 'image', 'file'}:
        _invalid('지원되는 Grype 보고서 원본이 아닙니다.')

    inventory, names = defaultdict(set), {}
    by_purl, by_name = defaultdict(list), defaultdict(list)
    identifiers = set()
    weak_identity = False
    for package in packages:
        spdx_id = package.get('SPDXID')
        if spdx_id in identifiers:
            _invalid('SBOM 구성요소 식별자가 중복됐습니다.')
        identifiers.add(spdx_id)
        name = package['name']
        if not name.strip():
            _invalid('SBOM 구성요소 이름이 비어 있습니다.')
        version = package.get('versionInfo')
        if version is not None and (not isinstance(version, str) or not version.strip()):
            _invalid('SBOM 구성요소 버전이 올바르지 않습니다.')
        purls = {ref['referenceLocator'] for ref in package.get('externalRefs', [])
                 if ref.get('referenceType', '').lower() == 'purl'}
        if len(purls) > 1:
            _invalid('한 구성요소에 여러 PURL이 있어 식별할 수 없습니다.')
        ecosystem = None
        if purls:
            identity, purl_version, ecosystem = _purl(next(iter(purls)))
            if version and purl_version and version != purl_version:
                _invalid('SBOM 버전과 PURL 버전이 일치하지 않습니다.')
            version = version or purl_version
        else:
            # No ecosystem can be inferred safely from a bare display name.
            identity = 'unidentified:' + json.dumps([
                name, package.get('supplier'), package.get('primaryPackagePurpose'),
            ], ensure_ascii=False, separators=(',', ':'))
            # A target inventory losing a package's PURL must not be trusted as
            # evidence of removal, even if the target has no CVE matches at all.
            weak_identity |= bool(version)
        inventory[identity].update([version] if version else [])
        names[identity] = name
        item = {'identity': identity, 'name': name, 'version': version, 'ecosystem': ecosystem}
        by_name[(name, version)].append(item)
        if purls:
            by_purl[(identity, version)].append(item)

    findings = {}
    for match in report.matches:
        artifact = match.artifact
        if artifact.purl is not None:
            identity, purl_version, ecosystem = _purl(artifact.purl)
            if purl_version and purl_version != artifact.version:
                _invalid('보고서 구성요소 버전과 PURL 버전이 일치하지 않습니다.')
            candidates = by_purl[(identity, artifact.version)]
            normalize = _python_name if ecosystem == 'pypi' else lambda value: value
            candidates = [item for item in candidates if normalize(item['name']) == normalize(artifact.name)]
        else:
            candidates = by_name[(artifact.name, artifact.version)]
            if len(candidates) != 1:
                _invalid('PURL이 없는 보고서 구성요소를 유일하게 식별할 수 없습니다.')
        if not candidates:
            _invalid('보고서 구성요소가 해당 SBOM의 이름·버전·PURL과 일치하지 않습니다.')
        # Validate non-CVE matches too, so a mismatched report cannot look clean.
        cves = {value for value in [match.vulnerability.id, *(related.id for related in match.relatedVulnerabilities)]
                if CVE.fullmatch(value)}
        severity = match.vulnerability.severity.upper()
        severity = severity if severity in SEVERITY else 'UNKNOWN'
        fixed = set(match.vulnerability.fix.versions) if match.vulnerability.fix.state == 'fixed' else set()
        for item in candidates:
            for cve in cves:
                identity = item['identity']
                weak_identity |= identity.startswith('unidentified:')
                finding = findings.setdefault((identity, cve), {'severity': 'UNKNOWN', 'fixed_versions': set()})
                if SEVERITY[severity] > SEVERITY[finding['severity']]:
                    finding['severity'] = severity
                finding['fixed_versions'].update(fixed)
    return {'inventory': inventory, 'names': names, 'findings': findings, 'report': report,
            'weak_identity': weak_identity}


def _metadata(run: models.AnalysisRun) -> dict:
    return {'id': run.id, 'sbom_id': run.sbom_id, 'asset_id': run.sbom.asset_id,
            'asset_tag': run.sbom.asset.asset_tag if run.sbom.asset else None,
            'scan_scope': run.scan_scope, 'imported_at': run.imported_at}


def _timestamp(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def compare_analyses(db: Session, base_id: int, target_id: int) -> dict:
    runs = {run.id: run for run in db.scalars(select(models.AnalysisRun).options(
        joinedload(models.AnalysisRun.sbom).joinedload(models.SbomDocument.asset),
    ).where(models.AnalysisRun.id.in_([base_id, target_id])))}
    if base_id not in runs or target_id not in runs:
        raise HTTPException(status_code=404, detail='비교할 분석 이력이 없습니다.')
    base, target = runs[base_id], runs[target_id]
    if base_id == target_id or (_timestamp(target.imported_at), target.id) <= (_timestamp(base.imported_at), base.id):
        raise HTTPException(status_code=409, detail='이전 분석과 그 이후의 다른 분석을 선택하세요.')
    if not base.sbom or not target.sbom:
        _invalid('연결된 SBOM이 없습니다.')
    if not base.sbom.asset_id or base.sbom.asset_id != target.sbom.asset_id:
        raise HTTPException(status_code=409, detail='동일한 자산의 분석만 비교할 수 있습니다.')
    if not base.scan_scope or not base.scan_scope.strip() or base.scan_scope != target.scan_scope:
        raise HTTPException(status_code=409, detail='수집 범위가 같고 명시된 분석만 비교할 수 있습니다.')
    before, after = _evidence(base), _evidence(target)
    warnings = []
    verified = set(db.scalars(select(models.AnalysisJob.analysis_run_id).where(
        models.AnalysisJob.analysis_run_id.in_([base_id, target_id]),
        models.AnalysisJob.status == 'SUCCESS', models.AnalysisJob.asset_id == base.sbom.asset_id,
    )))
    if verified != {base_id, target_id}:
        warnings.append('수동 반입 또는 성공한 웹 분석 작업과 연결되지 않은 원본이 포함되어 수집 완료를 확인할 수 없습니다.')
    old_report, new_report = before['report'], after['report']
    if (base.scanner.lower(), base.scanner_version, old_report.descriptor.name.lower(), old_report.descriptor.version) != (
            target.scanner.lower(), target.scanner_version, new_report.descriptor.name.lower(), new_report.descriptor.version):
        warnings.append('분석 도구 또는 버전이 달라 탐지 결과의 차이에 영향을 줄 수 있습니다.')
    if old_report.descriptor.db != new_report.descriptor.db or scanner_db(base) != scanner_db(target):
        warnings.append('취약점 데이터베이스 정보가 달라 탐지 결과의 차이에 영향을 줄 수 있습니다.')
    if not old_report.descriptor.db or not new_report.descriptor.db:
        warnings.append('취약점 데이터베이스 식별 정보가 없어 동일한 분석 기준인지 확인할 수 없습니다.')
    if before['weak_identity'] or after['weak_identity']:
        warnings.append('일부 버전이 있는 구성요소에 PURL이 없어 생태계·패키지 식별을 확정할 수 없습니다.')

    summary = {'persistent': 0, 'new': 0, 'no_longer_detected': 0, 'component_removed': 0}
    findings = []
    for key in sorted(before['findings'].keys() | after['findings'].keys()):
        identity, cve = key
        previous, current = before['findings'].get(key), after['findings'].get(key)
        if previous and current:
            status = 'PERSISTENT'
        elif current:
            status = 'NEW'
        elif identity in after['inventory']:
            status = 'NO_LONGER_DETECTED'
        else:
            status = 'COMPONENT_REMOVED'
        summary[status.lower()] += 1
        evidence = current or previous
        findings.append({
            'cve_id': cve, 'component_identity': identity,
            'component_name': after['names'].get(identity, before['names'].get(identity)),
            'status': status,
            'before_versions': sorted(before['inventory'].get(identity, set())),
            'after_versions': sorted(after['inventory'].get(identity, set())),
            'fixed_versions': sorted(evidence['fixed_versions']), 'severity': evidence['severity'],
        })
    return {'base': _metadata(base), 'target': _metadata(target), 'summary': summary,
            'findings': findings, 'warnings': warnings, 'comparable': not warnings}
