from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from textwrap import wrap

from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfgen import canvas
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .. import models
from .lifecycle_overview import build_lifecycle_overview
from .risk import lifecycle_risk


FONT_NAME = "HYSMyeongJo-Medium"


def _new_document(title: str) -> tuple[BytesIO, canvas.Canvas, float]:
    pdfmetrics.registerFont(UnicodeCIDFont(FONT_NAME))
    buffer = BytesIO()
    document = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    document.setTitle(title)
    document.setFont(FONT_NAME, 17)
    document.drawString(42, height - 48, title)
    document.setFont(FONT_NAME, 8)
    document.drawRightString(width - 42, height - 46, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    document.line(42, height - 58, width - 42, height - 58)
    return buffer, document, height - 82


def _line(document: canvas.Canvas, y: float, text: str, size: int = 9) -> float:
    _, height = A4
    document.setFont(FONT_NAME, size)
    for part in wrap(text, width=78, break_long_words=True, replace_whitespace=False) or [""]:
        if y < 52:
            document.showPage()
            document.setFont(FONT_NAME, size)
            y = height - 48
        document.drawString(44, y, part)
        y -= size + 5
    return y


def _finish(buffer: BytesIO, document: canvas.Canvas) -> bytes:
    document.save()
    buffer.seek(0)
    return buffer.read()


def lifecycle_report(db: Session) -> bytes:
    buffer, document, y = _new_document("EOLWatch 지원종료 위험 보고서")
    overview = build_lifecycle_overview(db)
    y = _line(document, y, '집계: ' + overview['aggregation_basis']['lifecycle'])
    y = _line(document, y, '기준일: ' + overview['aggregation_basis']['as_of_date'] + ' · ' + overview['aggregation_basis']['timezone'])
    for item in overview['items']:
        location = (' | ' + item['asset_tag']) if item.get('asset_tag') else ''
        source = (' | SBOM #' + str(item['sbom_id'])) if item.get('sbom_id') else ''
        y = _line(document, y, f"[{item['risk_level']}] {item['kind']} {item['name']} {item['version'] or ''}{location}{source} | 종료일 {item['end_date'] or '미입력'} | {item['days_left'] if item['days_left'] is not None else '-'}일")
    if not overview['items']:
        _line(document, y, "등록된 자산과 소프트웨어가 없습니다.")
    return _finish(buffer, document)


def daily_check_report(db: Session) -> bytes:
    buffer, document, y = _new_document("EOLWatch 인프라 점검 보고서")
    jobs = db.scalars(
        select(models.CollectionJob)
        .options(joinedload(models.CollectionJob.asset), joinedload(models.CollectionJob.result))
        .order_by(models.CollectionJob.started_at.desc())
        .limit(100)
    ).unique().all()
    for job in jobs:
        when = job.started_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M") if job.started_at else "-"
        if job.result:
            result = job.result
            detail = f"CPU {result.cpu_percent}% | 메모리 {result.memory_percent}% | 디스크 {result.max_disk_percent}% | {result.health_level}"
        else:
            detail = f"{job.failure_stage or '-'} | {job.failure_message or '결과 없음'}"
        y = _line(document, y, f"{when} | {job.asset.asset_tag} {job.asset.name} | {job.status} | {detail}")
    if not jobs:
        _line(document, y, "저장된 점검 이력이 없습니다.")
    return _finish(buffer, document)


def asset_report(db: Session, asset_id: int) -> bytes | None:
    asset = db.scalar(select(models.Asset).where(models.Asset.id == asset_id))
    if not asset:
        return None
    buffer, document, y = _new_document(f"EOLWatch 자산 보고서 · {asset.name}")
    model_end = None
    if asset.model_release:
        model_end = asset.model_release.security_end_date or asset.model_release.support_end_date or asset.model_release.eol_date
    risk_level, days_left = lifecycle_risk(model_end or asset.support_end_date)
    y = _line(document, y, f"자산번호: {asset.asset_tag} | 자산명: {asset.name} | 유형: {asset.asset_type}")
    y = _line(document, y, f"제조사/모델: {asset.manufacturer or '-'} / {asset.model or '-'} | 시리얼: {asset.serial_number or '-'}")
    y = _line(document, y, f"위치: {asset.site or '-'} {asset.building or ''} {asset.floor or ''}층 {asset.room or ''} {asset.rack or ''} {asset.rack_position or ''}")
    y = _line(document, y, f"운영 상태: {asset.operational_status} | 서비스 중요도: {asset.service_criticality} | 담당자: {asset.owner_name or '-'}")
    y = _line(document, y, f"구매일: {asset.purchase_date or '-'} | 구매가격: {asset.purchase_price or '-'}원 | 전력: {asset.power_watts or '-'}W")
    y = _line(document, y, f"지원 상태: {risk_level} | 지원 종료까지: {days_left if days_left is not None else '-'}일 | 보증 종료: {asset.warranty_end_date or '-'}")
    y = _line(document, y, f"내부 위험도: {getattr(asset, 'service_criticality', 'STANDARD')} 기준으로 산정된 자산 우선순위 요약")
    y = _line(document, y, "설치 소프트웨어", 11)
    deployments = db.scalars(select(models.Deployment).where(models.Deployment.asset_id == asset_id).options(joinedload(models.Deployment.software_product))).all()
    for deployment in deployments:
        product = deployment.software_product
        y = _line(document, y, f"- {product.name} {product.version} | {product.vendor or '-'} | {deployment.environment}")
    if not deployments:
        y = _line(document, y, "- 등록된 설치 소프트웨어 없음")
    y = _line(document, y, "SBOM", 11)
    sboms = db.scalars(select(models.SbomDocument).where(models.SbomDocument.asset_id == asset_id).order_by(models.SbomDocument.imported_at.desc())).all()
    for sbom in sboms[:10]:
        y = _line(document, y, f"- SBOM #{sbom.id} {sbom.bom_format} {sbom.spec_version} | 구성요소 {sbom.component_count}개 | 의존관계 {sbom.dependency_count}개")
    if not sboms:
        y = _line(document, y, "- 연결된 SBOM 없음")
    y = _line(document, y, "유지보수 계약", 11)
    contract_links = db.scalars(select(models.ContractAsset).where(models.ContractAsset.asset_id == asset_id)).all()
    for link in contract_links:
        contract = db.get(models.Contract, link.contract_id)
        if contract:
            y = _line(document, y, f"- {contract.contract_no} | {contract.provider} | {contract.start_date} ~ {contract.end_date} | {contract.annual_cost or '-'}원")
    if not contract_links:
        y = _line(document, y, "- 연결된 유지보수 계약 없음")
    y = _line(document, y, "최근 자산 이력", 11)
    jobs = db.scalars(select(models.AnalysisJob).where(models.AnalysisJob.asset_id == asset_id).order_by(models.AnalysisJob.requested_at.desc()).limit(10)).all()
    for job in jobs:
        y = _line(document, y, f"- 분석 작업 #{job.id} | {job.status} | {job.requested_at}")
    if not jobs:
        y = _line(document, y, "- 분석 이력 없음")
    y = _line(document, y, "본 보고서의 취약점·지원 종료 결과는 저장된 분석과 등록된 일정 기준이며, 자동 패치나 실제 공격 가능성의 판정이 아닙니다.", 8)
    return _finish(buffer, document)
