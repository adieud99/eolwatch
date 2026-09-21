"""Build a read-only, self-contained report from validated analysis evidence."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .. import models
from .analysis import digest
from .analysis_comparison import compare_analyses


LIMITATIONS = [
    '보고서는 선택한 두 분석의 수집 범위에 한정됩니다. 서버 전체 또는 앱 전체의 안전성을 인증하지 않습니다.',
    '재분석 미검출은 이후 보고서에 같은 CVE가 없다는 관측입니다. 악용 가능성이나 조치 완료를 자동 판정하지 않습니다.',
    '수정 버전은 분석 도구가 제시한 정보입니다. 실제 적용 버전과 호환성·서비스 정상 여부는 운영자가 확인해야 합니다.',
    '구성요소 제거와 재분석 미검출을 구분하며, 수동 VEX 조치 상태를 변경하거나 완료 승인으로 간주하지 않습니다.',
    '전후 요약의 단위는 구성요소 식별자와 CVE의 조합입니다. 고유 CVE 수 또는 악용 가능한 취약점 수와 다를 수 있습니다.',
    '원본 SHA-256은 저장된 JSON의 내용 일치를 확인하는 값이며, 외부 작성자의 서명이나 수집 사실의 암호학적 인증이 아닙니다.',
]


def _iso(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _database_info(report: dict) -> dict:
    database = report.get('descriptor', {}).get('db', {})
    status = database.get('status')
    source = status if isinstance(status, dict) else database
    return {'status': {
        key: value if isinstance(value, (str, int, float, bool)) else None
        for key in ('built', 'schemaVersion', 'valid') for value in [source.get(key)]
    }}


def _run_metadata(db: Session, run: models.AnalysisRun) -> dict:
    document, report = run.sbom.raw_document, run.raw_report
    sbom_hash = digest(document)
    bundle_hash = digest({'asset_id': run.sbom.asset_id, 'sbom': document, 'report': report})
    if sbom_hash != run.sbom_sha256 or bundle_hash != run.report_sha256:
        raise HTTPException(status_code=409, detail='저장된 원본과 분석 시점의 SHA-256이 다릅니다. 원본 확인 후 보고서를 생성하세요.')
    jobs = db.scalars(select(models.AnalysisJob).where(
        models.AnalysisJob.analysis_run_id == run.id,
        models.AnalysisJob.asset_id == run.sbom.asset_id,
        models.AnalysisJob.status == 'SUCCESS',
    ).order_by(models.AnalysisJob.id)).all()
    snapshot = jobs[0].asset_snapshot if jobs else {}
    asset = run.sbom.asset
    # SSH credentials, worker leases and arbitrary snapshot fields are never exported.
    return {
        'id': run.id, 'sbom_id': run.sbom_id, 'asset_id': run.sbom.asset_id,
        'asset_tag': snapshot.get('asset_tag') or (asset.asset_tag if asset else None),
        'asset_name': snapshot.get('name') or (asset.name if asset else None),
        'asset_identity_source': 'job_snapshot' if snapshot.get('asset_tag') and snapshot.get('name') else 'current_asset_record',
        'scan_scope': run.scan_scope, 'imported_at': _iso(run.imported_at),
        'scanner': run.scanner, 'scanner_version': run.scanner_version, 'generator': run.generator,
        'component_count': run.sbom.component_count, 'cve_count': run.cve_count, 'link_count': run.link_count,
        'sbom_sha256': sbom_hash, 'bundle_sha256': bundle_hash,
        # Explicit fields keep reports small and avoid copying arbitrary scanner configuration.
        'database_info': _database_info(report),
        'jobs': [{
            'id': job.id, 'status': job.status,
            'requested_at': _iso(job.requested_at), 'started_at': _iso(job.started_at), 'finished_at': _iso(job.finished_at),
            'asset_tag': job.asset_snapshot.get('asset_tag'), 'asset_name': job.asset_snapshot.get('name'),
        } for job in jobs],
    }


def build_comparison_report(db: Session, base_id: int, target_id: int) -> dict:
    comparison = compare_analyses(db, base_id, target_id)
    runs = {run.id: run for run in db.scalars(select(models.AnalysisRun).options(
        joinedload(models.AnalysisRun.sbom).joinedload(models.SbomDocument.asset),
    ).where(models.AnalysisRun.id.in_([base_id, target_id])))}
    if base_id not in runs or target_id not in runs:
        raise HTTPException(status_code=404, detail='비교할 분석 이력이 없습니다.')
    base, target = _run_metadata(db, runs[base_id]), _run_metadata(db, runs[target_id])
    return {
        'report_version': 1, 'generated_at': _iso(datetime.now(timezone.utc)),
        'title': 'EOLWatch 분석 전후 검증 보고서',
        'base': base, 'target': target,
        'summary': comparison['summary'], 'findings': comparison['findings'],
        'comparable': comparison['comparable'], 'warnings': comparison['warnings'],
        'limitations': list(LIMITATIONS),
        'raw_evidence': {
            'base_bundle_path': f'/api/analyses/{base_id}/bundle',
            'target_bundle_path': f'/api/analyses/{target_id}/bundle',
        },
        'hash_format': {
            'algorithm': 'SHA-256', 'encoding': 'UTF-8',
            'canonical_json': {'sort_keys': True, 'ensure_ascii': False, 'separators': [',', ':']},
            'sbom_value': 'sbom', 'bundle_fields': ['asset_id', 'sbom', 'report'],
            'findings_value': 'findings',
        },
        'findings_sha256': digest(comparison['findings']),
    }
