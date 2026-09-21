"""Current inventory selection and one lifecycle calculation for UI, PDF and Teams."""
from __future__ import annotations

from collections import Counter
from datetime import date
from typing import Optional

from sqlalchemy import case, func, or_, select, union
from sqlalchemy.orm import Session, joinedload

from .. import models
from ..config import get_settings
from .business_date import business_today
from .component_lifecycle import effective_component_lifecycle
from .risk import RISK_ORDER, lifecycle_risk


def current_sbom_ids():
    """Latest successful run per asset/scope plus a latest manual-import slot.

    Unassigned documents cannot be assumed to be the same project, so each
    document remains independent. A failed/new pending job never replaces a run.
    """
    document = models.SbomDocument
    unassigned = case((document.asset_id.is_(None), document.id), else_=0)
    runs = select(models.AnalysisRun.sbom_id.label('sbom_id'), func.row_number().over(
        partition_by=(document.asset_id, unassigned, models.AnalysisRun.scan_scope),
        order_by=(models.AnalysisRun.imported_at.desc(), models.AnalysisRun.id.desc()),
    ).label('position')).join(document, models.AnalysisRun.sbom_id == document.id).subquery()
    has_run = select(models.AnalysisRun.id).where(models.AnalysisRun.sbom_id == document.id).exists()
    manual = select(document.id.label('sbom_id'), func.row_number().over(
        partition_by=(document.asset_id, unassigned),
        order_by=(document.imported_at.desc(), document.id.desc()),
    ).label('position')).where(~has_run).subquery()
    return union(select(runs.c.sbom_id).where(runs.c.position == 1),
                 select(manual.c.sbom_id).where(manual.c.position == 1))


def build_lifecycle_overview(db: Session, today: Optional[date] = None) -> dict:
    today = business_today() if today is None else today
    selected = current_sbom_ids()
    items = []
    counts = Counter({key: 0 for key in RISK_ORDER})

    def add(kind, name, version, end_date, **extra):
        risk, days = lifecycle_risk(end_date, today)
        counts[risk] += 1
        items.append(dict(kind=kind, name=name, version=version, risk_level=risk, days_left=days,
                          end_date=end_date.isoformat() if end_date else None, **extra))

    for asset in db.scalars(select(models.Asset).options(joinedload(models.Asset.model_release))).all():
        release = asset.model_release
        inherited = (release.security_end_date or release.support_end_date or release.eol_date) if release else None
        add('자산', asset.name, asset.model, inherited or asset.support_end_date,
            asset_id=asset.id, asset_tag=asset.asset_tag, date_source='product' if inherited else 'asset')

    components = db.scalars(select(models.Component).where(models.Component.sbom_id.in_(selected)).options(
        joinedload(models.Component.product_release),
        joinedload(models.Component.sbom).load_only(models.SbomDocument.id, models.SbomDocument.asset_id)
            .joinedload(models.SbomDocument.asset).load_only(models.Asset.id, models.Asset.asset_tag),
    )).all()
    represented_products = {item.product_release_id for item in components if item.product_release_id is not None}
    for item in components:
        end_date, source_url, source_kind = effective_component_lifecycle(item)
        asset = item.sbom.asset
        add('구성요소', item.name, item.version, end_date, component_id=item.id, sbom_id=item.sbom_id,
            product_release_id=item.product_release_id, asset_id=item.sbom.asset_id,
            asset_tag=asset.asset_tag if asset else None, source_url=source_url, date_source=source_kind)

    has_component_history = select(models.Component.id).where(
        models.Component.product_release_id == models.ProductRelease.id).exists()
    has_deployment = select(models.Deployment.id).where(
        models.Deployment.software_product_id == models.ProductRelease.id).exists()
    for product in db.scalars(select(models.ProductRelease).where(
            models.ProductRelease.product_type != 'HARDWARE_MODEL',
            or_(~has_component_history, has_deployment))).all():
        # The catalog supplies dates for its occurrences; it is not an additional
        # deployed occurrence when those components already represent the product.
        if product.id not in represented_products:
            add('소프트웨어', product.name, product.version,
                product.security_end_date or product.support_end_date or product.eol_date,
                product_release_id=product.id, asset_id=None, source_url=product.lifecycle_source_url,
                date_source='product')

    open_links = select(models.ComponentVulnerability.vulnerability_id).join(
        models.Component, models.ComponentVulnerability.component_id == models.Component.id
    ).where(models.Component.sbom_id.in_(selected),
            models.ComponentVulnerability.vex_status.in_({'AFFECTED', 'UNDER_INVESTIGATION'}))
    current = {
        'sbom_documents': db.scalar(select(func.count()).select_from(selected.subquery())) or 0,
        'components': len(components),
        'dependencies': db.scalar(select(func.count(models.DependencyEdge.id)).where(models.DependencyEdge.sbom_id.in_(selected))) or 0,
        'assets': db.scalar(select(func.count(func.distinct(models.SbomDocument.asset_id))).where(models.SbomDocument.id.in_(selected))) or 0,
        'open_cves': db.scalar(select(func.count()).select_from(open_links.distinct().subquery())) or 0,
        'affected_assets': db.scalar(select(func.count(func.distinct(models.SbomDocument.asset_id)))
            .join(models.Component, models.Component.sbom_id == models.SbomDocument.id)
            .join(models.ComponentVulnerability, models.ComponentVulnerability.component_id == models.Component.id)
            .where(models.SbomDocument.id.in_(selected),
                   models.ComponentVulnerability.vex_status.in_({'AFFECTED', 'UNDER_INVESTIGATION'}))) or 0,
        'lifecycle_items': len(items),
    }
    items.sort(key=lambda item: (RISK_ORDER[item['risk_level']], item['days_left'] or 0,
                               item['kind'], item['name'], item.get('component_id') or 0))
    return {'items': items, 'risk_counts': dict(counts), 'current_inventory': current,
            'aggregation_basis': {
                'historical_inventory': '기존 문서·구성요소·CVE 지표는 전체 보관 이력 기준',
                'current_inventory': '자산·분석 범위별 최신 성공 SBOM + 자산별 최신 수동 import SBOM; 미연결 문서는 각각 별도',
                'lifecycle': '관리 자산 + 현재 SBOM의 구성요소 사용 위치 + 현재 구성요소로 표현되지 않은 등록 소프트웨어',
                'catalog': '과거 SBOM에만 등장하는 제품은 제외; 명시적 배포가 있거나 구성요소 이력이 없는 등록 제품은 포함',
                'component_dates': '구성요소 개별 종료일 우선, 없으면 제품 보안지원→일반지원→EOL 순서로 상속',
                'as_of_date': today.isoformat(), 'timezone': get_settings().scheduler_timezone,
            }}
