from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session, joinedload

from .. import models, schemas
from ..config import get_settings
from ..db import get_db
from ..services import ai_advisor


router = APIRouter(prefix="/ai", tags=["ai advisor"])


def _read(record: models.AiSummary) -> schemas.AiSummaryRead:
    return schemas.AiSummaryRead(id=record.id, kind=record.kind, target_id=record.target_id, provider=record.provider, model=record.model,
                                 summary=record.summary, prompt_chars=record.prompt_chars, input_tokens=record.input_tokens,
                                 output_tokens=record.output_tokens, generated_at=record.generated_at, generated_by=record.generated_by)


def _username(request: Request):
    user = getattr(request.state, "audit_user", None) or {}
    return user.get("username")


@router.get("/status", response_model=schemas.AiStatus)
def status():
    return schemas.AiStatus(enabled=ai_advisor.ai_available(), provider=ai_advisor.provider_name(), model=ai_advisor.current_model())


@router.get("/analyses/{run_id}", response_model=Optional[schemas.AiSummaryRead])
def read_analysis_summary(run_id: int, db: Session = Depends(get_db)):
    if not db.get(models.AnalysisRun, run_id):
        raise HTTPException(status_code=404, detail="검사 결과가 없습니다.")
    record = ai_advisor.latest_summary(db, "analysis", run_id)
    return _read(record) if record else None


@router.post("/analyses/{run_id}", response_model=schemas.AiSummaryRead)
def summarize_analysis(run_id: int, request: Request, force: bool = False, db: Session = Depends(get_db)):
    run = db.get(models.AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="검사 결과가 없습니다.")
    context = ai_advisor.analysis_context(db, run)
    return _read(ai_advisor.generate_summary(db, "analysis", run_id, context, _username(request), force=force))


@router.get("/checks/{job_id}", response_model=Optional[schemas.AiSummaryRead])
def read_check_summary(job_id: int, db: Session = Depends(get_db)):
    if not db.get(models.CollectionJob, job_id):
        raise HTTPException(status_code=404, detail="점검 결과가 없습니다.")
    record = ai_advisor.latest_summary(db, "check", job_id)
    return _read(record) if record else None


@router.post("/checks/{job_id}", response_model=schemas.AiSummaryRead)
def summarize_check(job_id: int, request: Request, force: bool = False, db: Session = Depends(get_db)):
    job = db.get(models.CollectionJob, job_id, options=[joinedload(models.CollectionJob.result), joinedload(models.CollectionJob.asset)])
    if not job:
        raise HTTPException(status_code=404, detail="점검 결과가 없습니다.")
    context = ai_advisor.check_context(job)
    return _read(ai_advisor.generate_summary(db, "check", job_id, context, _username(request), force=force))
