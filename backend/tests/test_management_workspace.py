"""Management changes use an isolated database; no running lab data is touched."""
from datetime import date
import os

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/eolwatch-test.db")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import models
from app.db import Base, get_db
from app.routers import assets, contracts, products


@pytest.fixture
def workspace():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([models.Customer(id=i, customer_code=f"C{i}", name=f"고객 {i}") for i in (1, 2)])
        db.flush()
        db.add_all([models.Site(id=i, customer_id=i, site_code=f"S{i}", name=f"사이트 {i}") for i in (1, 2)])
        db.flush()
        db.add_all([models.Asset(id=i, site_id=i if i < 3 else None, asset_tag=f"A-{i}", name=f"자산 {i}", asset_type="vm") for i in (1, 2, 3)])
        db.add_all([models.ProductRelease(id=i, product_type="HARDWARE_MODEL" if i == 1 else "LIBRARY", vendor="Vendor", name=f"제품 {i:02}", version="1.0", purl=f"pkg:generic/product-{i}@1.0") for i in range(1, 25)])
        db.commit()
        application = FastAPI()
        for router in (assets.router, contracts.router, products.router):
            application.include_router(router, prefix="/api")
        application.dependency_overrides[get_db] = lambda: db
        with TestClient(application) as client:
            yield client, db
    engine.dispose()


def contract_payload(**overrides):
    return {"customer_id": 1, "contract_no": "MA-01", "provider": "유지보수사", "start_date": "2026-01-01", "end_date": "2026-12-31", "annual_cost": 12000, "asset_ids": [1], **overrides}


def test_products_sql_pagination_search_and_model_impact(workspace):
    client, db = workspace
    first = client.get("/api/products", params={"q": "Vendor", "limit": 20, "offset": 0}).json()
    second = client.get("/api/products", params={"q": "Vendor", "limit": 20, "offset": 20}).json()
    assert len(first) == 20 and len(second) == 4
    assert not {item["id"] for item in first} & {item["id"] for item in second}
    assert len(client.get("/api/products").json()) == 24
    assert client.get("/api/products", params={"limit": 201}).status_code == 422
    assert client.get("/api/products", params={"product_type": "INVALID"}).status_code == 422
    db.get(models.Asset, 1).model_release_id = 1
    db.add(models.Deployment(asset_id=1, software_product_id=1))
    db.commit()
    impact = client.get("/api/products/1/impact").json()
    assert impact["asset_count"] == 1
    assert impact["affected_assets"][0]["asset_tag"] == "A-1"


def test_product_dates_validate_source_and_preserve_component_overrides(workspace):
    client, db = workspace
    sbom = models.SbomDocument(serial_number="immutable", spec_version="2.3", asset_id=1, raw_document={"evidence": "original"})
    db.add(sbom); db.flush()
    inherited = models.Component(sbom_id=sbom.id, product_release_id=1, bom_ref="inherited", name="product")
    override = models.Component(sbom_id=sbom.id, product_release_id=1, bom_ref="override", name="product", support_end_date=date(2031, 1, 1), lifecycle_source_url="https://example.com/override")
    db.add_all([inherited, override]); db.commit()
    assert client.patch("/api/products/1", json={"security_end_date": "2027-01-01"}).status_code == 422
    assert client.patch("/api/products/1", json={"security_end_date": "2027-01-01", "lifecycle_source_url": "javascript:alert(1)"}).status_code == 422
    response = client.patch("/api/products/1", json={"security_end_date": "2027-01-01", "support_end_date": "2026-01-01", "lifecycle_source_url": "https://example.com/product"})
    assert response.status_code == 200, response.text
    assert response.json()["verified_at"]
    from app.services.component_lifecycle import effective_component_lifecycle
    assert effective_component_lifecycle(inherited) == (date(2027, 1, 1), "https://example.com/product", "product")
    assert effective_component_lifecycle(override) == (date(2031, 1, 1), "https://example.com/override", "component")
    assert inherited.support_end_date is None
    assert sbom.raw_document == {"evidence": "original"}
    assert client.patch("/api/products/1", json={"lifecycle_source_url": None}).status_code == 422
    assert client.get("/api/products/1").json()["lifecycle_source_url"] == "https://example.com/product"
    assert client.patch("/api/products/1", json={"name": None}).status_code == 422
    assert client.patch("/api/products/1", json={"purl": "pkg:generic/product-2@1.0"}).status_code == 409


def test_contract_create_edit_search_and_customer_validation(workspace):
    client, _ = workspace
    for changes in ({"end_date": "2025-12-31"}, {"asset_ids": [2]}, {"asset_ids": [3]}, {"annual_cost": -1}):
        assert client.post("/api/contracts", json=contract_payload(**changes)).status_code == 422
    assert client.post("/api/contracts", json=contract_payload(asset_ids=[999])).status_code == 404
    created = client.post("/api/contracts", json=contract_payload(asset_ids=[1, 1]))
    assert created.status_code == 201, created.text
    identity = created.json()["id"]
    assert created.json()["asset_ids"] == [1]
    assert client.post("/api/contracts", json=contract_payload()).status_code == 409
    assert client.patch(f"/api/contracts/{identity}", json={"customer_id": 2}).status_code == 422
    assert client.patch(f"/api/contracts/{identity}", json={"start_date": "2027-01-01"}).status_code == 422
    assert client.patch(f"/api/contracts/{identity}", json={"provider": None}).status_code == 422
    response = client.patch(f"/api/contracts/{identity}", json={"customer_id": 2, "asset_ids": [2], "provider": "새 유지보수사", "annual_cost": None})
    assert response.status_code == 200, response.text
    assert response.json()["asset_ids"] == [2] and response.json()["customer_name"] == "고객 2"
    assert response.json()["annual_cost"] is None
    assert client.get("/api/contracts", params={"q": "새 유지보수사", "customer_id": 2, "limit": 1}).json()[0]["id"] == identity
    assert client.get("/api/contracts", params={"customer_id": 1}).json() == []
    assert client.patch(f"/api/contracts/{identity}", json={"asset_ids": []}).json()["asset_ids"] == []


def test_asset_edit_links_ports_sources_and_contract_site_constraint(workspace):
    client, _ = workspace
    assert client.patch("/api/assets/1", json={"name": None}).status_code == 422
    assert client.patch("/api/assets/1", json={"name": "  "}).status_code == 422
    assert client.patch("/api/assets/1", json={"ssh_port": 65536}).status_code == 422
    assert client.patch("/api/assets/1", json={"support_end_date": "2027-01-01"}).status_code == 422
    assert client.patch("/api/assets/1", json={"model_release_id": 999}).status_code == 404
    assert client.patch("/api/assets/1", json={"asset_tag": "A-2"}).status_code == 409
    response = client.patch("/api/assets/1", json={"ssh_port": 2222, "ssh_username": "collector", "model_release_id": 1, "monitored": True, "lifecycle_source_url": "https://example.com/asset", "support_end_date": "2027-01-01"})
    assert response.status_code == 200, response.text
    assert response.json()["ssh_port"] == 2222 and response.json()["model_release_id"] == 1
    assert client.post("/api/contracts", json=contract_payload()).status_code == 201
    assert client.patch("/api/assets/1", json={"site_id": 2}).status_code == 409
    assert client.patch("/api/assets/1", json={"site_id": None}).status_code == 409
    assert client.get("/api/assets/1").json()["site_id"] == 1


@pytest.mark.parametrize("kind", ["analysis", "collection", "sbom", "deployment", "contract"])
def test_asset_delete_preserves_all_history_and_connections(workspace, kind):
    client, db = workspace
    if kind == "analysis":
        db.add(models.AnalysisJob(asset_id=1, asset_snapshot={}, status="FAILED"))
    elif kind == "collection":
        db.add(models.CollectionJob(asset_id=1, status="SUCCESS"))
    elif kind == "sbom":
        db.add(models.SbomDocument(asset_id=1, serial_number="keep", spec_version="2.3", raw_document={"keep": True}))
    elif kind == "deployment":
        db.add(models.Deployment(asset_id=1, software_product_id=1))
    else:
        assert client.post("/api/contracts", json=contract_payload()).status_code == 201
    db.commit()
    assert client.delete("/api/assets/1").status_code == 409
    assert client.get("/api/assets/1").status_code == 200
    assert client.delete("/api/assets/3").status_code == 204
    assert client.get("/api/assets/3").status_code == 404


def test_active_analysis_blocks_connection_edits_and_delete(workspace):
    client, db = workspace
    db.add(models.AnalysisJob(asset_id=1, active_asset_id=1, asset_snapshot={}, status="QUEUED")); db.commit()
    assert client.patch("/api/assets/1", json={"ip_address": "10.0.0.2"}).status_code == 409
    assert client.patch("/api/assets/1", json={"name": "Changed"}).status_code == 409
    assert client.patch("/api/assets/1", json={"site": "새 설치 위치"}).status_code == 200
    assert client.delete("/api/assets/1").status_code == 409
