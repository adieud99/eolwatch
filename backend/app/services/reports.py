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
from .risk import RISK_ORDER, lifecycle_risk


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
    if y < 52:
        document.showPage()
        document.setFont(FONT_NAME, 9)
        y = height - 48
    document.setFont(FONT_NAME, size)
    for part in wrap(text, width=78, break_long_words=True, replace_whitespace=False) or [""]:
        document.drawString(44, y, part)
        y -= size + 5
    return y


def _finish(buffer: BytesIO, document: canvas.Canvas) -> bytes:
    document.save()
    buffer.seek(0)
    return buffer.read()


def lifecycle_report(db: Session) -> bytes:
    buffer, document, y = _new_document("EOLWatch 지원종료 위험 보고서")
    rows: list[tuple[int, str]] = []
    for asset in db.scalars(select(models.Asset).order_by(models.Asset.asset_tag)).all():
        end_date = asset.support_end_date
        if asset.model_release:
            end_date = asset.model_release.security_end_date or asset.model_release.support_end_date or asset.model_release.eol_date or end_date
        risk, days = lifecycle_risk(end_date)
        rows.append((RISK_ORDER[risk], f"[{risk}] 자산 {asset.asset_tag} | {asset.name} | 종료일 {end_date or '미입력'} | {days if days is not None else '-'}일"))
    for item in db.scalars(
        select(models.ProductRelease)
        .where(models.ProductRelease.product_type != "HARDWARE_MODEL")
        .order_by(models.ProductRelease.name)
    ).all():
        end_date = item.security_end_date or item.support_end_date or item.eol_date
        risk, days = lifecycle_risk(end_date)
        rows.append((RISK_ORDER[risk], f"[{risk}] 소프트웨어 {item.name} {item.version} | 종료일 {end_date or '미입력'} | {days if days is not None else '-'}일"))
    for _, text in sorted(rows, key=lambda value: (value[0], value[1])):
        y = _line(document, y, text)
    if not rows:
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
