"""AI advisor: prompt building from stored data, endpoint behaviour with a mocked model call."""
from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/eolwatch-test.db")

from app import models  # noqa: E402
from app.db import Base, engine, SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.services import ai_advisor  # noqa: E402


@pytest.fixture
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        token = test_client.post("/api/auth/login", json={"username": "admin", "password": "Eolwatch!2026"}).json()["access_token"]
        test_client.headers.update({"Authorization": f"Bearer {token}"})
        yield test_client
    Base.metadata.drop_all(bind=engine)


def _import_run(client) -> int:
    asset = client.post("/api/assets", json={"asset_tag": "AI-01", "name": "AI 대상", "asset_type": "other"}).json()
    document = json.loads((Path(__file__).parents[2] / "samples" / "spdx-2.3-blackduck-compatible.json").read_text())
    document["documentNamespace"] = "https://eolwatch.test/ai/" + str(uuid4())
    report = {"descriptor": {"name": "grype", "version": "0.118.0", "db": {}}, "source": {"type": "sbom"}, "matches": [{
        "vulnerability": {"id": "CVE-2025-27516", "severity": "High", "fix": {"versions": ["3.1.6"], "state": "fixed"}, "dataSource": "https://osv.dev"},
        "artifact": {"name": document["packages"][0]["name"], "version": document["packages"][0].get("versionInfo", "1.0"), "type": "python"},
        "matchDetails": [], "relatedVulnerabilities": []}]}
    response = client.post("/api/analyses/import", json={"asset_id": asset["id"], "sbom": document, "report": report, "scan_scope": "source-zip:ai-demo"})
    assert response.status_code == 200, response.text
    return response.json()["id"]


def test_prompt_is_built_from_stored_findings_only(client, monkeypatch):
    run_id = _import_run(client)
    with SessionLocal() as db:
        run = db.get(models.AnalysisRun, run_id)
        context = ai_advisor.analysis_context(db, run)
    assert context["kind"] == "analysis" and context["scan_scope"] == "source-zip:ai-demo"
    assert context["cve_count"] == len(context["findings"]) == 1
    finding = context["findings"][0]
    assert finding["cve"] == "CVE-2025-27516" and finding["severity"] == "HIGH" and finding["fixed_versions"] == ["3.1.6"]
    prompt = ai_advisor.build_prompt(context)
    assert "CVE-2025-27516" in prompt and "findings에 없는 항목은 언급하지 마라" in prompt
    assert json.loads(prompt.split("데이터(JSON):\n", 1)[1])["target"]["tag"] == "AI-01"


def test_summary_endpoint_stores_and_returns_latest(client, monkeypatch):
    run_id = _import_run(client)
    assert client.get(f"/api/ai/analyses/{run_id}").json() is None
    calls = []
    def fake_complete(prompt):
        calls.append(prompt)
        return "위험 수준은 높음이다.\n- Jinja2를 3.1.6으로 올린다.", "claude-opus-5"
    monkeypatch.setattr(ai_advisor, "complete", fake_complete)
    created = client.post(f"/api/ai/analyses/{run_id}")
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["kind"] == "analysis" and body["target_id"] == run_id and body["model"] == "claude-opus-5"
    assert body["summary"].startswith("위험 수준은 높음") and body["generated_by"] == "admin"
    assert len(calls) == 1 and "CVE-2025-27516" in calls[0]
    latest = client.get(f"/api/ai/analyses/{run_id}").json()
    assert latest["id"] == body["id"]
    assert client.get("/api/ai/analyses/9999").status_code == 404


def test_summary_requires_configuration_and_admin(client, monkeypatch):
    run_id = _import_run(client)
    monkeypatch.setattr(ai_advisor, "ai_available", lambda: False)
    assert client.get("/api/ai/status").json()["enabled"] is False
    response = client.post(f"/api/ai/analyses/{run_id}")
    assert response.status_code == 503 and "ANTHROPIC_API_KEY" in response.json()["detail"]
    client.post("/api/auth/users", json={"username": "viewer-ai", "password": "ViewerOnly!2026", "role": "VIEWER"})
    token = client.post("/api/auth/login", json={"username": "viewer-ai", "password": "ViewerOnly!2026"}).json()["access_token"]
    viewer = client.post(f"/api/ai/analyses/{run_id}", headers={"Authorization": f"Bearer {token}"})
    assert viewer.status_code == 403
    assert client.get(f"/api/ai/analyses/{run_id}", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_check_context_covers_server_info_and_failures():
    asset = models.Asset(asset_tag="SRV-1", name="서버", asset_type="server", ip_address="10.0.0.5")
    job = models.CollectionJob(id=7, asset=asset, status="FAILED", failure_stage="CONNECT", failure_code="TIMEOUTERROR", failure_message="timed out")
    context = ai_advisor.check_context(job)
    assert context["kind"] == "check" and context["failure"]["code"] == "TIMEOUTERROR" and context["usage"] is None
    assert "점검이 실패했다면" in ai_advisor.build_prompt(context)
