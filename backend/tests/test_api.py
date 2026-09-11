import json
import os
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:////tmp/eolwatch-test.db"

from fastapi.testclient import TestClient

from app.db import Base, engine
from app.main import app


def setup_module():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def teardown_module():
    Base.metadata.drop_all(bind=engine)


def test_asset_sbom_and_dashboard_flow():
    with TestClient(app) as client:
        customer_response = client.post("/api/customers", json={"customer_code": "CUST-01", "name": "테스트 고객사"})
        assert customer_response.status_code == 201
        site_response = client.post(
            "/api/sites",
            json={"customer_id": customer_response.json()["id"], "site_code": "SEOUL", "name": "서울 전산실"},
        )
        assert site_response.status_code == 201

        asset_response = client.post(
            "/api/assets",
            json={
                "asset_tag": "TEST-SRV-001",
                "name": "테스트 서버",
                "asset_type": "server",
                "site_id": site_response.json()["id"],
                "support_end_date": "2026-12-31",
                "lifecycle_source_url": "https://example.com/lifecycle",
                "monitored": True,
            },
        )
        assert asset_response.status_code == 201
        asset = asset_response.json()
        assert asset["risk_level"] in {"CRITICAL", "WARN", "EXPIRED"}

        contract_response = client.post(
            "/api/contracts",
            json={
                "customer_id": customer_response.json()["id"],
                "contract_no": "MA-2026-001",
                "provider": "테스트 유지보수사",
                "start_date": "2026-01-01",
                "end_date": "2026-12-31",
                "annual_cost": 12000000,
                "service_level": "24x7",
                "asset_ids": [asset["id"]],
            },
        )
        assert contract_response.status_code == 201, contract_response.text
        assert contract_response.json()["asset_ids"] == [asset["id"]]

        software_response = client.post(
            "/api/software",
            json={
                "name": "Ubuntu Server",
                "vendor": "Canonical",
                "version": "22.04",
                "purl": "pkg:generic/ubuntu@22.04",
                "support_end_date": "2027-04-30",
                "lifecycle_source_url": "https://example.com/ubuntu-lifecycle",
                "asset_id": asset["id"],
                "environment": "production",
            },
        )
        assert software_response.status_code == 201, software_response.text
        assert software_response.json()["asset_ids"] == [asset["id"]]

        sample_path = Path(__file__).parents[2] / "samples" / "cyclonedx-example.json"
        document = json.loads(sample_path.read_text(encoding="utf-8"))
        sbom_response = client.post(f"/api/sboms/import?asset_id={asset['id']}", json=document)
        assert sbom_response.status_code == 201, sbom_response.text
        sbom = sbom_response.json()
        assert sbom["component_count"] == 2
        assert sbom["dependency_count"] == 2
        assert sbom["quality_score"] == 100.0

        components = client.get(f"/api/sboms/{sbom['id']}/components")
        assert components.status_code == 200
        assert {item["name"] for item in components.json()} == {"Ubuntu Server", "PostgreSQL"}

        summary = client.get("/api/dashboard/summary")
        assert summary.status_code == 200
        assert summary.json()["assets"] == 1
        assert summary.json()["software_products"] == 2
        assert summary.json()["components"] == 2

        products = client.get("/api/products?q=PostgreSQL")
        assert products.status_code == 200
        assert len(products.json()) == 1
        impact = client.get(f"/api/products/{products.json()[0]['id']}/impact")
        assert impact.status_code == 200
        assert impact.json()["asset_count"] == 1


def test_reject_non_cyclonedx_document():
    with TestClient(app) as client:
        response = client.post("/api/sboms/import", json={"spdxVersion": "SPDX-2.3"})
        assert response.status_code == 422


def test_reject_invalid_cyclonedx_schema():
    with TestClient(app) as client:
        response = client.post(
            "/api/sboms/import",
            json={"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": [{"type": "library"}]},
        )
        assert response.status_code == 422
        assert response.json()["detail"]["message"].startswith("CycloneDX")
