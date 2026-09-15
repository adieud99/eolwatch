from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..services.notifications import send_risk_summary, send_teams


router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("", response_model=list[schemas.NotificationRead])
def list_deliveries(limit: int = 100, db: Session = Depends(get_db)):
    safe_limit = max(1, min(limit, 500))
    return db.scalars(
        select(models.NotificationDelivery).order_by(models.NotificationDelivery.created_at.desc()).limit(safe_limit)
    ).all()


@router.post("/test", response_model=schemas.NotificationRead)
def test_notification(db: Session = Depends(get_db)):
    return send_teams(db, "TEST", "EOLWatch 연결 시험", ["Teams Workflow 알림 연결 시험입니다."])


@router.post("/risk-summary", response_model=schemas.NotificationRead)
def risk_summary_notification(db: Session = Depends(get_db)):
    return send_risk_summary(db)
