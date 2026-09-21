from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..services.lifecycle_overview import build_lifecycle_overview
from ..models import utcnow


router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def latest_analysis_overview(db: Session) -> list[schemas.DashboardLatestAnalysis]:
    # Project immutable run counts only; avoid loading SBOMs or large raw reports.
    runs = select(
        models.SbomDocument.asset_id.label("asset_id"),
        models.Asset.asset_tag, models.Asset.name.label("asset_name"),
        models.AnalysisRun.scan_scope,
        models.AnalysisRun.id.label("analysis_run_id"),
        models.AnalysisRun.sbom_id, models.AnalysisRun.cve_count,
        models.AnalysisRun.imported_at.label("last_success_at"),
        func.row_number().over(
            partition_by=(models.SbomDocument.asset_id, models.AnalysisRun.scan_scope),
            order_by=(models.AnalysisRun.imported_at.desc(), models.AnalysisRun.id.desc()),
        ).label("position"),
    ).select_from(models.AnalysisRun).join(models.SbomDocument, models.AnalysisRun.sbom_id == models.SbomDocument.id).join(
        models.Asset, models.SbomDocument.asset_id == models.Asset.id
    ).subquery()
    latest = {}
    for row in db.execute(select(runs).where(runs.c.position == 1)).mappings():
        values = {key: value for key, value in row.items() if key != "position"}
        latest[(row["asset_id"], row["scan_scope"])] = schemas.DashboardLatestAnalysis(**values)

    scope = func.coalesce(models.AnalysisJob.asset_snapshot["scan_scope"].as_string(), "ubuntu-dpkg-installed")
    attempts = select(
        models.AnalysisJob.asset_id, models.Asset.asset_tag, models.Asset.name.label("asset_name"),
        scope.label("scan_scope"), models.AnalysisJob.id.label("latest_attempt_id"),
        models.AnalysisJob.status.label("latest_attempt_status"),
        models.AnalysisJob.requested_at.label("latest_attempt_requested_at"),
        models.AnalysisJob.finished_at.label("latest_attempt_finished_at"),
        func.row_number().over(
            partition_by=(models.AnalysisJob.asset_id, scope),
            order_by=(models.AnalysisJob.requested_at.desc(), models.AnalysisJob.id.desc()),
        ).label("position"),
    ).select_from(models.AnalysisJob).join(models.Asset, models.AnalysisJob.asset_id == models.Asset.id).subquery()
    for row in db.execute(select(attempts).where(attempts.c.position == 1)).mappings():
        key = (row["asset_id"], row["scan_scope"])
        if key not in latest:
            latest[key] = schemas.DashboardLatestAnalysis(**{name: row[name] for name in ("asset_id", "asset_tag", "asset_name", "scan_scope")})
        item = latest[key]
        for name in ("latest_attempt_id", "latest_attempt_status", "latest_attempt_requested_at", "latest_attempt_finished_at"):
            setattr(item, name, row[name])
        item.latest_attempt_is_newer = item.last_success_at is None or row["latest_attempt_requested_at"] > item.last_success_at
    return sorted(latest.values(), key=lambda item: (item.asset_tag, item.asset_id, item.scan_scope))


@router.get("/summary", response_model=schemas.DashboardSummary)
def summary(db: Session = Depends(get_db)):
    overview = build_lifecycle_overview(db)
    urgent = [item for item in overview['items'] if item['risk_level'] in {'EXPIRED', 'CRITICAL', 'WARN'}]

    sbom_count = db.scalar(select(func.count(models.SbomDocument.id))) or 0
    average_quality = db.scalar(select(func.avg(models.SbomDocument.quality_score))) or 0
    low_quality = db.scalar(select(func.count(models.SbomDocument.id)).where(models.SbomDocument.quality_score < 70)) or 0
    open_statuses = {"AFFECTED", "UNDER_INVESTIGATION"}
    open_cves = db.scalar(
        select(func.count(func.distinct(models.ComponentVulnerability.vulnerability_id))).where(
            models.ComponentVulnerability.vex_status.in_(open_statuses)
        )
    ) or 0
    affected_assets = db.scalar(
        select(func.count(func.distinct(models.SbomDocument.asset_id)))
        .join(models.Component, models.Component.sbom_id == models.SbomDocument.id)
        .join(models.ComponentVulnerability, models.ComponentVulnerability.component_id == models.Component.id)
        .where(
            models.ComponentVulnerability.vex_status.in_(open_statuses),
            models.SbomDocument.asset_id.is_not(None),
        )
    ) or 0
    failed_checks_24h = db.scalar(
        select(func.count(models.CollectionJob.id)).where(
            models.CollectionJob.status == "FAILED",
            models.CollectionJob.started_at >= utcnow() - timedelta(hours=24),
        )
    ) or 0

    return schemas.DashboardSummary(
        assets=db.scalar(select(func.count(models.Asset.id))) or 0,
        software_products=db.scalar(select(func.count(models.SoftwareProduct.id)).where(models.SoftwareProduct.product_type != "HARDWARE_MODEL")) or 0,
        sbom_documents=sbom_count,
        components=db.scalar(select(func.count(models.Component.id))) or 0,
        dependencies=db.scalar(select(func.count(models.DependencyEdge.id))) or 0,
        open_cves=open_cves,
        affected_assets=affected_assets,
        failed_checks_24h=failed_checks_24h,
        lifecycle_risk=overview['risk_counts'],
        sbom_quality={"average_score": round(float(average_quality), 1), "below_70": low_quality},
        urgent_items=urgent[:20],
        latest_analyses=latest_analysis_overview(db),
        current_inventory=overview['current_inventory'], aggregation_basis=overview['aggregation_basis'],
    )
