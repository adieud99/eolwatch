from __future__ import annotations

from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..services.risk import RISK_ORDER, lifecycle_risk


router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=schemas.DashboardSummary)
def summary(db: Session = Depends(get_db)):
    risk_counts: Counter[str] = Counter({key: 0 for key in RISK_ORDER})
    urgent: list[dict[str, Any]] = []

    for asset in db.scalars(select(models.Asset)).all():
        model_end_date = None
        if asset.model_release:
            model_end_date = asset.model_release.security_end_date or asset.model_release.support_end_date or asset.model_release.eol_date
        risk, days = lifecycle_risk(model_end_date or asset.support_end_date)
        risk_counts[risk] += 1
        if risk in {"EXPIRED", "CRITICAL", "WARN"}:
            urgent.append({"kind": "자산", "name": asset.name, "version": asset.model, "risk_level": risk, "days_left": days})
    for item in db.scalars(select(models.SoftwareProduct).where(models.SoftwareProduct.product_type != "HARDWARE_MODEL")).all():
        risk, days = lifecycle_risk(item.support_end_date)
        risk_counts[risk] += 1
        if risk in {"EXPIRED", "CRITICAL", "WARN"}:
            urgent.append({"kind": "소프트웨어", "name": item.name, "version": item.version, "risk_level": risk, "days_left": days})
    for item in db.scalars(select(models.Component).where(models.Component.support_end_date.is_not(None))).all():
        risk, days = lifecycle_risk(item.support_end_date)
        risk_counts[risk] += 1
        if risk in {"EXPIRED", "CRITICAL", "WARN"}:
            urgent.append({"kind": "구성요소", "name": item.name, "version": item.version, "risk_level": risk, "days_left": days})

    sbom_count = db.scalar(select(func.count(models.SbomDocument.id))) or 0
    average_quality = db.scalar(select(func.avg(models.SbomDocument.quality_score))) or 0
    low_quality = db.scalar(select(func.count(models.SbomDocument.id)).where(models.SbomDocument.quality_score < 70)) or 0
    urgent.sort(key=lambda item: (RISK_ORDER[item["risk_level"]], item["days_left"] or 0))

    return schemas.DashboardSummary(
        assets=db.scalar(select(func.count(models.Asset.id))) or 0,
        software_products=db.scalar(select(func.count(models.SoftwareProduct.id)).where(models.SoftwareProduct.product_type != "HARDWARE_MODEL")) or 0,
        sbom_documents=sbom_count,
        components=db.scalar(select(func.count(models.Component.id))) or 0,
        dependencies=db.scalar(select(func.count(models.DependencyEdge.id))) or 0,
        lifecycle_risk=dict(risk_counts),
        sbom_quality={"average_score": round(float(average_quality), 1), "below_70": low_quality},
        urgent_items=urgent[:20],
    )
