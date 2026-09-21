from datetime import date

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app import models, schemas
from app.db import Base
from app.routers.sboms import component_page, dependency_page, get_component, raw_sbom, sbom_detail, update_component_lifecycle
from app.routers.dashboard import summary


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        asset = models.Asset(asset_tag="EXPLORER-1", name="실제 앱 서버", asset_type="server")
        product = models.ProductRelease(name="shared", version="1.0", support_end_date=date(2000, 1, 1), lifecycle_source_url="https://example.com/support")
        document = models.SbomDocument(serial_number="explorer-1", spec_version="2.3", bom_format="SPDX", asset=asset, component_count=3, dependency_count=3, raw_document={"original": "unchanged"}, quality_details={"checks": {"component_names": True}})
        other = models.SbomDocument(serial_number="explorer-2", spec_version="2.3", raw_document={})
        session.add_all([document, other, product]); session.flush()
        session.add_all([
            models.Component(id=1, sbom=document, bom_ref="root", name="service", version="1", licenses=["MIT"], hashes=[{"algorithm": "SHA256", "checksumValue": "a" * 64}]),
            models.Component(id=2, sbom=document, bom_ref="dep", name="pkg_100%", version="1.0", purl="pkg:pypi/shared@1.0", product_release=product, licenses=["BSD-3-Clause"]),
            models.Component(id=3, sbom=document, bom_ref="other", name="pkg_100x", version="2"),
            models.Component(id=4, sbom=other, bom_ref="dep", name="wrong document", version="1"),
            models.DependencyEdge(sbom=document, source_ref="root", target_ref="dep"),
            models.DependencyEdge(sbom=document, source_ref="dep", target_ref="unknown-ref"),
            models.DependencyEdge(sbom=document, source_ref="dep", target_ref="dep"),
        ])
        session.commit()
        yield session, document.id, other.id, engine
    engine.dispose()


def test_detail_and_pages_exclude_raw_and_support_literal_search(db):
    session, sbom_id, _, engine = db
    session.expunge_all()
    statements = []
    def capture(_conn, _cursor, statement, _parameters, _context, _many): statements.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        metadata = sbom_detail(sbom_id, session)
        page = component_page(sbom_id, "100%", 1, 0, session)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert metadata["asset"]["asset_tag"] == "EXPLORER-1"
    assert "raw_document" not in metadata
    assert page["total"] == 1 and page["items"][0].name == "pkg_100%"
    assert not any("raw_document" in statement for statement in statements)
    first, second = component_page(sbom_id, "", 2, 0, session), component_page(sbom_id, "", 2, 2, session)
    assert first["total"] == 3 and len(first["items"]) == 2 and len(second["items"]) == 1
    assert not {item.id for item in first["items"]} & {item.id for item in second["items"]}


def test_dependency_direction_preserves_missing_refs_and_cycles_without_cross_sbom_join(db):
    session, sbom_id, other_id, _ = db
    outgoing = dependency_page(sbom_id, 2, "outgoing", 20, 0, session)
    incoming = dependency_page(sbom_id, 2, "incoming", 20, 0, session)
    assert outgoing["total"] == 2 and incoming["total"] == 2
    assert outgoing["items"][0]["target"] == {"id": None, "ref": "unknown-ref", "name": "unknown-ref", "version": None, "purl": None}
    assert incoming["items"][0]["target"]["name"] == "pkg_100%"
    with pytest.raises(HTTPException) as error: dependency_page(sbom_id, 4, "both", 20, 0, session)
    assert error.value.status_code == 404
    with pytest.raises(HTTPException): get_component(other_id, 2, session)


def test_component_lifecycle_inherits_product_and_override_does_not_change_product_or_raw(db):
    session, sbom_id, _, _ = db
    inherited = get_component(sbom_id, 2, session)
    assert inherited.lifecycle_origin == "product" and inherited.risk_level == "EXPIRED"
    updated = update_component_lifecycle(2, schemas.ComponentLifecycleUpdate(support_end_date="2099-01-01", lifecycle_source_url="https://example.com/component"), session)
    assert updated.lifecycle_origin == "component" and updated.risk_level == "SAFE"
    assert summary(session).lifecycle_risk["EXPIRED"] == 0
    assert session.get(models.Component, 2).product_release.support_end_date == date(2000, 1, 1)
    assert session.get(models.SbomDocument, sbom_id).raw_document == {"original": "unchanged"}
    restored = update_component_lifecycle(2, schemas.ComponentLifecycleUpdate(support_end_date=None, lifecycle_source_url=None), session)
    assert restored.lifecycle_origin == "product" and restored.support_end_date == date(2000, 1, 1)
    dashboard = summary(session)
    assert dashboard.lifecycle_risk["EXPIRED"] == 1
    urgent = next(item for item in dashboard.urgent_items if item.get("component_id") == 2)
    assert urgent["date_source"] == "product" and urgent["end_date"] == "2000-01-01"
    assert urgent["sbom_id"] == sbom_id


def test_component_details_preserve_license_hashes_and_original_download(db):
    session, sbom_id, _, _ = db
    item = get_component(sbom_id, 1, session)
    assert item.licenses == ["MIT"] and item.hashes[0]["checksumValue"] == "a" * 64
    response = raw_sbom(sbom_id, session)
    assert response.body == b'{"original":"unchanged"}'
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"] == f'attachment; filename="eolwatch-sbom-{sbom_id}.json"'
    with pytest.raises(HTTPException) as error: sbom_detail(999, session)
    assert error.value.status_code == 404
