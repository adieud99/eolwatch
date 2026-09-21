from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .. import models, schemas
from ..db import get_db
from ..services.collector import CollectionFailure, packages_to_spdx, run_collection
from ..services.sbom import import_spdx


router = APIRouter(prefix="/checks", tags=["infrastructure checks"])


def _read(job: models.CollectionJob) -> schemas.CollectionJobRead:
    result = job.result
    return schemas.CollectionJobRead(
        id=job.id,
        asset_id=job.asset_id,
        asset_tag=job.asset.asset_tag,
        asset_name=job.asset.name,
        trigger_type=job.trigger_type,
        status=job.status,
        failure_stage=job.failure_stage,
        failure_code=job.failure_code,
        failure_message=job.failure_message,
        started_at=job.started_at,
        finished_at=job.finished_at,
        retry_count=job.retry_count,
        health_level=result.health_level if result else None,
        cpu_percent=result.cpu_percent if result else None,
        memory_percent=result.memory_percent if result else None,
        max_disk_percent=result.max_disk_percent if result else None,
        uptime_seconds=result.uptime_seconds if result else None,
        server_info=(result.raw_metrics or {}).get("server_info") if result else None,
    )


@router.get("", response_model=list[schemas.CollectionJobRead])
def list_checks(asset_id: Optional[int] = None, limit: int = Query(default=50, ge=1, le=500), db: Session = Depends(get_db)):
    query = (
        select(models.CollectionJob)
        .options(joinedload(models.CollectionJob.asset), joinedload(models.CollectionJob.result))
        .order_by(models.CollectionJob.started_at.desc())
        .limit(limit)
    )
    if asset_id:
        query = query.where(models.CollectionJob.asset_id == asset_id)
    return [_read(job) for job in db.scalars(query).unique().all()]


@router.post("/assets/{asset_id}/run", response_model=schemas.CollectionJobRead)
def run_check(asset_id: int, db: Session = Depends(get_db)):
    if not db.get(models.Asset, asset_id):
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    try:
        job = run_collection(db, asset_id)
    except CollectionFailure as failure:
        raise HTTPException(status_code=422, detail=failure.message)
    query = (
        select(models.CollectionJob)
        .where(models.CollectionJob.id == job.id)
        .options(joinedload(models.CollectionJob.asset), joinedload(models.CollectionJob.result))
    )
    return _read(db.scalar(query))


@router.get("/{job_id}/result", response_model=schemas.CheckResultRead)
def get_result(job_id: int, db: Session = Depends(get_db)):
    job = db.get(models.CollectionJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="점검 작업이 없습니다")
    if not job.result:
        raise HTTPException(status_code=404, detail="성공한 점검 결과가 없습니다")
    return job.result


@router.post("/{job_id}/sbom", response_model=schemas.SbomRead)
def generate_sbom_from_check(job_id: int, db: Session = Depends(get_db)):
    query = (
        select(models.CollectionJob)
        .where(models.CollectionJob.id == job_id)
        .options(joinedload(models.CollectionJob.asset), joinedload(models.CollectionJob.result))
    )
    job = db.scalar(query)
    if not job:
        raise HTTPException(status_code=404, detail="점검 작업이 없습니다")
    if not job.result or job.status != "SUCCESS":
        raise HTTPException(status_code=422, detail="성공한 점검 결과에서만 SBOM을 생성할 수 있습니다")
    packages = job.result.raw_metrics.get("packages") or []
    if not packages:
        raise HTTPException(status_code=422, detail="수집된 패키지 목록이 없습니다")
    document = packages_to_spdx(
        job.asset,
        packages,
        job.finished_at or job.started_at,
        job.result.raw_metrics.get("package_context") or {},
    )
    sbom = import_spdx(db, document, asset_id=job.asset_id)
    sbom.collection_job_id = job.id
    db.commit()
    db.refresh(sbom)
    return sbom
