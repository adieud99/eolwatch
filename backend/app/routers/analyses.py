from typing import Optional

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, defer, joinedload
from starlette.concurrency import run_in_threadpool

from .. import models, schemas
from ..db import get_db
from ..config import get_settings
from ..services.analysis import import_analysis
from ..services.cve_breakdown import breakdown
from ..services.analysis_jobs import enqueue_analysis
from ..services.analysis_comparison import compare_analyses
from ..services.analysis_uploads import save_upload

router = APIRouter(prefix='/analyses', tags=['SBOM analysis tools'])


def read_job(job: models.AnalysisJob) -> schemas.AnalysisJobRead:
    return schemas.AnalysisJobRead(
        id=job.id, asset_id=job.asset_id,
        asset_tag=job.asset_snapshot['asset_tag'], asset_name=job.asset_snapshot['name'],
        scan_scope=job.asset_snapshot.get('scan_scope', 'ubuntu-dpkg-installed'),
        status=job.status, requested_at=job.requested_at, started_at=job.started_at,
        finished_at=job.finished_at, error_code=job.error_code, error_message=job.error_message,
        analysis_run_id=job.analysis_run_id,
        sbom_id=job.analysis_run.sbom_id if job.analysis_run else None, retry_of_id=job.retry_of_id,
        profile=job.asset_snapshot.get('profile', job.asset_snapshot.get('scan_scope', 'ubuntu-dpkg-installed')),
        input_type=job.asset_snapshot.get('input_type', 'ssh'),
        upload_id=job.asset_snapshot.get('upload_id'), upload_sha256=job.asset_snapshot.get('upload_sha256'),
        upload_filename=job.asset_snapshot.get('upload_filename'), project_name=job.asset_snapshot.get('project_name'),
        git_url=job.asset_snapshot.get('git_url'), git_ref=job.asset_snapshot.get('git_ref'), git_commit=job.asset_snapshot.get('git_commit'),
    )


@router.get('/jobs', response_model=list[schemas.AnalysisJobRead])
def list_jobs(db: Session = Depends(get_db)):
    jobs = db.scalars(select(models.AnalysisJob).options(
        joinedload(models.AnalysisJob.analysis_run).load_only(models.AnalysisRun.sbom_id)
    ).order_by(models.AnalysisJob.id.desc()).limit(100)).all()
    return [read_job(job) for job in jobs]


@router.post('/assets/{asset_id}/jobs', response_model=schemas.AnalysisJobRead, status_code=202)
def create_job(asset_id: int, payload: Optional[schemas.AnalysisJobRequest] = Body(default=None),
               db: Session = Depends(get_db)):
    request = payload or schemas.AnalysisJobRequest()
    return read_job(enqueue_analysis(db, asset_id, scan_scope=request.scan_scope))


@router.post('/assets/{asset_id}/uploads', response_model=schemas.AnalysisJobRead, status_code=202)
async def upload_source(asset_id: int, file: UploadFile = File(), project_name: str = Form(..., min_length=1, max_length=80),
                        db: Session = Depends(get_db)):
    try:
        upload = await save_upload(db, asset_id, file, project_name, get_settings())
        # save_upload has already committed the reusable source and released
        # its asset lock. Queueing and lazy result reads run off the event loop.
        try:
            return await run_in_threadpool(_queue_upload, db, asset_id, upload.id)
        except HTTPException as error:
            if error.status_code == 409:
                raise HTTPException(status_code=409, detail='이 대상의 다른 검사가 진행 중입니다. 검사가 끝나면 같은 파일을 다시 올리세요.') from error
            raise
    except HTTPException:
        await run_in_threadpool(db.rollback)
        raise
    except IntegrityError as error:
        await run_in_threadpool(db.rollback)
        raise HTTPException(status_code=409, detail='동시에 요청된 분석이 있습니다. 작업 목록을 확인하세요.') from error


@router.post('/assets/{asset_id}/git', response_model=schemas.AnalysisJobRead, status_code=202)
def scan_repository(asset_id: int, payload: schemas.AnalysisGitRequest, db: Session = Depends(get_db)):
    """Queue a read-only shallow clone of a Git repository for dependency scanning."""
    return read_job(enqueue_analysis(db, asset_id, scan_scope='source-git', git=payload.model_dump()))


def _queue_upload(db, asset_id, upload_id):
    return read_job(enqueue_analysis(db, asset_id, scan_scope='source-zip', upload_id=upload_id))


@router.post('/jobs/{job_id}/retry', response_model=schemas.AnalysisJobRead, status_code=202)
def retry_job(job_id: int, payload: Optional[schemas.AnalysisJobRequest] = Body(default=None),
              db: Session = Depends(get_db)):
    previous = db.get(models.AnalysisJob, job_id)
    if not previous:
        raise HTTPException(status_code=404, detail='재시도할 작업이 없습니다')
    return read_job(enqueue_analysis(db, previous.asset_id, retry_of_id=job_id))


def read(run: models.AnalysisRun, counts: Optional[dict[str, int]] = None) -> schemas.AnalysisRead:
    asset = run.sbom.asset
    if counts is None and isinstance(run.database_info, dict) and run.database_info.get('counts'):
        # Single-run and history responses used to drop the frozen fixable/kernel split and report zeros.
        counts = run.database_info['counts']
    return schemas.AnalysisRead(**(counts or {}), package_updates=(run.database_info or {}).get('package_updates') if isinstance(run.database_info, dict) else None,
        id=run.id, sbom_id=run.sbom_id, asset_id=run.sbom.asset_id,
        asset_tag=asset.asset_tag if asset else None, asset_name=asset.name if asset else None,
        scanner=run.scanner, scanner_version=run.scanner_version,
        generator=run.generator, scan_scope=run.scan_scope,
        component_count=run.sbom.component_count, match_count=run.match_count,
        cve_count=run.cve_count, link_count=run.link_count, ignored_non_cve=run.ignored_non_cve,
        # database_info stays the scanner DB descriptor; our own bookkeeping (counts, package_updates) lives beside it
        database_info={k: v for k, v in (run.database_info or {}).items() if k not in ('counts', 'package_updates', 'verification', 'host', 'distro')} if isinstance(run.database_info, dict) else run.database_info,
        verification=(run.database_info or {}).get('verification') if isinstance(run.database_info, dict) else None,
        host=({**(run.database_info or {}).get('host', {}), 'modules': len((run.database_info or {}).get('host', {}).get('modules') or [])} if isinstance(run.database_info, dict) and (run.database_info or {}).get('host') else None),
        imported_at=run.imported_at,
    )


@router.get('', response_model=list[schemas.AnalysisRead])
def list_analyses(db: Session = Depends(get_db)):
    runs = db.scalars(select(models.AnalysisRun).options(
        defer(models.AnalysisRun.raw_report),
        joinedload(models.AnalysisRun.sbom).defer(models.SbomDocument.raw_document).joinedload(models.SbomDocument.asset)
    ).order_by(models.AnalysisRun.id.desc()).limit(100)).all()
    stored = {run.id: run.database_info['counts'] for run in runs if isinstance(run.database_info, dict) and run.database_info.get('counts')}
    counts = {**breakdown(db, [run.id for run in runs if run.id not in stored]), **stored}  # older runs: live query
    return [read(run, counts.get(run.id)) for run in runs]


@router.post('/import', response_model=schemas.AnalysisRead)
def import_bundle(payload: schemas.AnalysisImport, db: Session = Depends(get_db)):
    try:
        run = import_analysis(db, payload)
        return read(run, (run.database_info or {}).get('counts') or breakdown(db, [run.id])[run.id])
    except HTTPException:
        db.rollback()
        raise
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail='기존 데이터와 식별자가 충돌합니다. 분석 원본을 확인하세요.') from exc


@router.post('/{run_id}/verify', response_model=schemas.AnalysisRead)
def verify_run_endpoint(run_id: int, budget: int = Query(120, ge=10, le=900), db: Session = Depends(get_db)):
    """Second opinion for one scan: Ubuntu tracker status and kernel source-file relevance. Cached lookups make repeats fast."""
    from ..services.verification import verify_run
    if not db.get(models.AnalysisRun, run_id):
        raise HTTPException(status_code=404, detail='분석 이력이 없습니다')
    try:
        verify_run(db, run_id, budget_seconds=budget)
    except Exception as error:
        db.rollback()
        raise HTTPException(status_code=502, detail=f'2차 검증 중 외부 조회에 실패했습니다: {type(error).__name__}') from error
    run = db.scalar(select(models.AnalysisRun).options(defer(models.AnalysisRun.raw_report),
                    joinedload(models.AnalysisRun.sbom).defer(models.SbomDocument.raw_document).joinedload(models.SbomDocument.asset))
                    .where(models.AnalysisRun.id == run_id))
    return read(run, (run.database_info or {}).get('counts') or breakdown(db, [run.id])[run.id])


@router.get('/{base_id}/compare/{target_id}')
def compare_runs(base_id: int, target_id: int, db: Session = Depends(get_db)):
    return compare_analyses(db, base_id, target_id)


@router.get('/{run_id}/bundle')
def get_bundle(run_id: int, db: Session = Depends(get_db)):
    run = db.get(models.AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail='분석 이력이 없습니다')
    return {'asset_id': run.sbom.asset_id, 'scan_scope': run.scan_scope, 'sbom': run.sbom.raw_document, 'report': run.raw_report}
