"""Searchable scan and job history, project summaries and comparison report downloads."""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from io import BytesIO
from typing import Optional, Literal
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import func, literal, or_, select, union
from sqlalchemy.orm import Session, defer, joinedload

from .. import models, schemas
from ..config import get_settings
from ..db import get_db
from ..services.comparison_report_pdf import render_comparison_pdf
from ..services.comparison_reports import build_comparison_report
from .analyses import read, read_job

router = APIRouter(prefix='/analyses', tags=['analysis history'])
# 검사 기록의 전후 비교 보고서 내려받기. 기존 프런트 경로(/api/reports/analyses/...)를 유지한다.
reports_router = APIRouter(prefix='/reports', tags=['analysis history'])
JobStatus = Literal['ALL', 'QUEUED', 'COLLECTING', 'SCANNING', 'IMPORTING', 'CANCEL_REQUESTED', 'CANCELLED', 'SUCCESS', 'FAILED']


def runs_query():
    return select(models.AnalysisRun).join(models.SbomDocument).outerjoin(models.Asset).options(
        defer(models.AnalysisRun.raw_report),
        joinedload(models.AnalysisRun.sbom).defer(models.SbomDocument.raw_document).joinedload(models.SbomDocument.asset))


def jobs_query():
    return select(models.AnalysisJob).join(models.Asset).options(
        joinedload(models.AnalysisJob.analysis_run).load_only(models.AnalysisRun.sbom_id))


def job_scope():
    return func.coalesce(models.AnalysisJob.asset_snapshot['scan_scope'].as_string(), 'ubuntu-dpkg-installed')


def filtered(query, asset_column, scope_column, time_column, asset_id, scan_scope, q, date_from, date_to):
    if asset_id is not None:
        query = query.where(asset_column == asset_id)
    if scan_scope is not None:
        query = query.where(scope_column == scan_scope)
    if q:
        query = query.where(or_(*(col.icontains(q, autoescape=True) for col in
                                  (models.Asset.asset_tag, models.Asset.name, scope_column))))
    if date_from and date_to and date_from > date_to:
        raise HTTPException(status_code=422, detail='조회 시작일은 종료일보다 늦을 수 없습니다.')
    zone = ZoneInfo(get_settings().scheduler_timezone)
    try:
        if date_from:
            query = query.where(time_column >= datetime.combine(date_from, time.min, zone).astimezone(timezone.utc))
        if date_to:
            # Exclusive next midnight also covers timestamp fractional seconds.
            query = query.where(time_column < datetime.combine(date_to + timedelta(days=1), time.min, zone).astimezone(timezone.utc))
    except OverflowError as error:
        raise HTTPException(status_code=422, detail='조회 날짜가 설정된 시간대의 지원 범위를 벗어났습니다.') from error
    return query


def page(db, query, limit, offset, reader):
    total = count_rows(db, query)
    return {'items': [reader(row) for row in db.scalars(query.limit(limit).offset(offset)).all()],
            'total': total, 'limit': limit, 'offset': offset}


def count_rows(db, query):
    return db.scalar(select(func.count()).select_from(query.order_by(None)
        .with_only_columns(literal(1), maintain_column_froms=True).subquery())) or 0


@router.get('/history')
def history(asset_id: Optional[int] = Query(None, gt=0), scan_scope: Optional[str] = Query(None, max_length=300),
            q: Optional[str] = Query(None, max_length=100), date_from: Optional[date] = None, date_to: Optional[date] = None,
            limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    query = filtered(runs_query(), models.SbomDocument.asset_id, models.AnalysisRun.scan_scope,
                     models.AnalysisRun.imported_at, asset_id, scan_scope, q, date_from, date_to)
    return page(db, query.order_by(models.AnalysisRun.imported_at.desc(), models.AnalysisRun.id.desc()), limit, offset, read)


@router.get('/job-history')
def job_history(asset_id: Optional[int] = Query(None, gt=0), scan_scope: Optional[str] = Query(None, max_length=300),
                status: JobStatus = 'ALL', q: Optional[str] = Query(None, max_length=100),
                date_from: Optional[date] = None, date_to: Optional[date] = None,
                limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    query = filtered(jobs_query(), models.AnalysisJob.asset_id, job_scope(), models.AnalysisJob.requested_at,
                     asset_id, scan_scope, q, date_from, date_to)
    if status != 'ALL':
        query = query.where(models.AnalysisJob.status == status)
    return page(db, query.order_by(models.AnalysisJob.requested_at.desc(), models.AnalysisJob.id.desc()), limit, offset, read_job)


@router.get('/jobs/{job_id}', response_model=schemas.AnalysisJobRead)
def get_job(job_id: int, db: Session = Depends(get_db)):
    job = db.scalar(jobs_query().where(models.AnalysisJob.id == job_id))
    if not job:
        raise HTTPException(status_code=404, detail='분석 작업이 없습니다.')
    return read_job(job)


def get_run(db, run_id):
    run = db.scalar(runs_query().where(models.AnalysisRun.id == run_id))
    if not run:
        raise HTTPException(status_code=404, detail='분석 이력이 없습니다.')
    return run


@router.get('/runs/{run_id}', response_model=schemas.AnalysisRead)
def run_detail(run_id: int, db: Session = Depends(get_db)):
    return read(get_run(db, run_id))


@router.get('/projects')
def projects(asset_id: Optional[int] = Query(None, gt=0), q: Optional[str] = Query(None, max_length=100),
             scan_scope: Optional[str] = Query(None, max_length=300),
             limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    scopes = union(
        select(models.SbomDocument.asset_id.label('asset_id'), models.AnalysisRun.scan_scope.label('scan_scope'))
            .join(models.AnalysisRun, models.AnalysisRun.sbom_id == models.SbomDocument.id),
        select(models.AnalysisJob.asset_id, job_scope()),
        select(models.AnalysisUpload.asset_id, literal('source-zip:') + models.AnalysisUpload.project_name)).subquery()
    query = select(scopes.c.asset_id, scopes.c.scan_scope, models.Asset.asset_tag, models.Asset.name).join(
        models.Asset, models.Asset.id == scopes.c.asset_id)
    if asset_id is not None:
        query = query.where(scopes.c.asset_id == asset_id)
    if scan_scope is not None:
        query = query.where(scopes.c.scan_scope == scan_scope)
    if q:
        query = query.where(or_(*(column.icontains(q, autoescape=True) for column in
                                (models.Asset.asset_tag, models.Asset.name, scopes.c.scan_scope))))
    total = count_rows(db, query)
    items = []
    for row in db.execute(query.order_by(models.Asset.asset_tag, scopes.c.scan_scope, scopes.c.asset_id).limit(limit).offset(offset)):
        aid, scope = row.asset_id, row.scan_scope
        run_q = runs_query().where(models.SbomDocument.asset_id == aid, models.AnalysisRun.scan_scope == scope)
        job_q = jobs_query().where(models.AnalysisJob.asset_id == aid, job_scope() == scope)
        latest_run = db.scalar(run_q.order_by(models.AnalysisRun.imported_at.desc(), models.AnalysisRun.id.desc()).limit(1))
        latest_job = db.scalar(job_q.order_by(models.AnalysisJob.requested_at.desc(), models.AnalysisJob.id.desc()).limit(1))
        project_name = scope.split(':', 1)[1] if scope.startswith(('source-zip:', 'source-git:')) else None
        items.append({'asset_id': aid, 'asset_tag': row.asset_tag, 'asset_name': row.name, 'scan_scope': scope,
            'project_name': project_name, 'analysis_count': count_rows(db, run_q), 'job_count': count_rows(db, job_q),
            'latest_analysis': read(latest_run) if latest_run else None, 'latest_job': read_job(latest_job) if latest_job else None})
    return {'items': items, 'total': total, 'limit': limit, 'offset': offset}


@reports_router.get('/analyses/{base_id}/compare/{target_id}.json')
def download_comparison_json(base_id: int, target_id: int, db: Session = Depends(get_db)):
    report = build_comparison_report(db, base_id, target_id)
    return JSONResponse(report, headers={
        'Content-Disposition': f'attachment; filename="eolwatch-analysis-{base_id}-{target_id}.json"',
        'Cache-Control': 'no-store',
    })


@reports_router.get('/analyses/{base_id}/compare/{target_id}.pdf')
def download_comparison_pdf(base_id: int, target_id: int, db: Session = Depends(get_db)):
    report = build_comparison_report(db, base_id, target_id)
    return StreamingResponse(
        BytesIO(render_comparison_pdf(report)),
        media_type='application/pdf',
        headers={'Content-Disposition': f'attachment; filename="eolwatch-analysis-{base_id}-{target_id}.pdf"',
                 'Cache-Control': 'no-store'},
    )
