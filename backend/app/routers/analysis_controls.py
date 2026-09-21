"""Analysis controls registered before the historical analysis routes."""
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .. import models, schemas
from ..db import get_db
from ..services.analysis_jobs import ACTIVE, cancel_analysis
from .analyses import read_job

router = APIRouter(prefix='/analyses', tags=['Analysis controls'])


@router.get('/jobs/active', response_model=list[schemas.AnalysisJobRead])
def active_jobs(db: Session = Depends(get_db)):
    # Tracking is independent of historical list pagination. At most one
    # active row exists for each asset; never silently truncate that set.
    jobs = db.scalars(select(models.AnalysisJob).where(models.AnalysisJob.status.in_(ACTIVE))
        .options(joinedload(models.AnalysisJob.analysis_run).load_only(models.AnalysisRun.sbom_id))
        .order_by(models.AnalysisJob.id)).all()
    return [read_job(job) for job in jobs]


@router.post('/jobs/{job_id}/cancel', response_model=schemas.AnalysisJobRead)
def cancel_job(job_id: int, db: Session = Depends(get_db)):
    # Global authentication/audit middleware enforces ADMIN for this mutation
    # and records the actor, method, path and successful response status.
    return read_job(cancel_analysis(db, job_id))
