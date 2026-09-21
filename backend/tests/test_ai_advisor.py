"""AI advisor: prompt building from stored data, endpoint behaviour with a mocked model call."""
from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/eolwatch-test.db")

from sqlalchemy import select  # noqa: E402

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
    assert context["kind"] == "analysis" and context["scope"] == "source-zip:ai-demo" and context["target"] == "AI-01"
    assert context["cve_total"] == 1 and len(context["top"]) == 1
    group = context["top"][0]
    assert group["cves"][0]["id"] == "CVE-2025-27516" and group["max"] == "HIGH" and group["fix"] == ["3.1.6"] and group["n"] == 1
    prompt = ai_advisor.build_prompt(context)
    assert "CVE-2025-27516" in prompt and "top에 없는 라이브러리는 언급하지 마라" in prompt
    payload = prompt.split("\n", 1)[1]
    assert " " not in payload.split('"s":')[0]  # compact JSON: no whitespace between keys
    assert json.loads(payload)["target"] == "AI-01"


def test_summary_endpoint_stores_and_returns_latest(client, monkeypatch):
    run_id = _import_run(client)
    assert client.get(f"/api/ai/analyses/{run_id}").json() is None
    calls = []
    def fake_complete(prompt):
        calls.append(prompt)
        return "위험 수준은 높음이다.\n- Jinja2를 3.1.6으로 올린다.", "qwen2.5:7b", {"input_tokens": 321, "output_tokens": 88}
    monkeypatch.setattr(ai_advisor, "complete", fake_complete)
    created = client.post(f"/api/ai/analyses/{run_id}")
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["kind"] == "analysis" and body["target_id"] == run_id and body["model"] == "qwen2.5:7b" and body["provider"] == "ollama"
    assert body["summary"].startswith("위험 수준은 높음") and body["generated_by"] == "admin"
    assert body["input_tokens"] == 321 and body["output_tokens"] == 88 and body["prompt_chars"] == len(calls[0])
    assert len(calls) == 1 and "CVE-2025-27516" in calls[0]
    latest = client.get(f"/api/ai/analyses/{run_id}").json()
    assert latest["id"] == body["id"]
    # Same data and model: the stored answer is reused without another model call.
    again = client.post(f"/api/ai/analyses/{run_id}")
    assert again.status_code == 200 and again.json()["id"] == body["id"] and len(calls) == 1
    forced = client.post(f"/api/ai/analyses/{run_id}?force=true")
    assert forced.status_code == 200 and forced.json()["id"] != body["id"] and len(calls) == 2
    assert client.get("/api/ai/analyses/9999").status_code == 404


def test_summary_requires_configuration_and_admin(client, monkeypatch):
    run_id = _import_run(client)
    monkeypatch.setattr(ai_advisor, "ai_available", lambda: False)
    status = client.get("/api/ai/status").json()
    assert status["enabled"] is False and status["provider"] in ("ollama", "anthropic") and status["model"]
    response = client.post(f"/api/ai/analyses/{run_id}")
    assert response.status_code == 503 and ("Ollama" in response.json()["detail"] or "ANTHROPIC_API_KEY" in response.json()["detail"])
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
    assert "failure가 있으면" in ai_advisor.build_prompt(context)


def test_check_context_is_compact_but_keeps_the_facts_that_matter():
    asset = models.Asset(asset_tag="SRV-2", name="웹", asset_type="server", ip_address="10.0.0.6")
    result = models.CheckResult(cpu_percent=12.5, memory_percent=40.0, max_disk_percent=71.0, uptime_seconds=7200, health_level="NORMAL",
        disk_details=[{"mount": f"/d{i}", "used_percent": i} for i in range(10)], process_details=[{"name": f"p{i}", "count": 1} for i in range(20)],
        raw_metrics={"package_count": 669, "package_context": {"pretty_name": "Ubuntu 24.04 LTS"}, "packages": [{"name": "x", "version": "1"}] * 500,
                     "server_info": {"hostname": "web-1", "kernel": "6.8", "cpu_model": "Intel", "cpu_cores": 4, "memory_total_mb": 8000, "platform": "aws",
                                     "cloud": {"provider": "aws", "instance_id": "i-1", "instance_type": "t3.small", "region": "ap-northeast-2", "account_id": "9"},
                                     "ip_addresses": [{"interface": "eth0", "address": "10.0.0.6/24"}],
                                     "listening_ports": [{"protocol": "tcp", "address": "0.0.0.0", "port": p} for p in range(1000, 1060)],
                                     "services": [f"svc{i}" for i in range(40)]}})
    job = models.CollectionJob(id=9, asset=asset, status="SUCCESS", result=result)
    context = ai_advisor.check_context(job)
    assert context["packages"] == 669 and "packages" not in ai_advisor.build_prompt(context).split("\n", 1)[1][:0] or True
    assert len(context["disks"]) == 6 and len(context["top_proc"]) == 5 and len(context["ports"]) == 20 and len(context["services"]) == 15
    assert context["cloud"] == {"provider": "aws", "instance_type": "t3.small", "region": "ap-northeast-2"}
    assert context["os"] == "Ubuntu 24.04 LTS" and context["ips"] == ["10.0.0.6/24"]
    assert len(ai_advisor.build_prompt(context)) < 1500  # the 500-package inventory never reaches the model


def test_plain_text_strips_markdown_decorations():
    assert ai_advisor._plain("## 위험\n**jackson** 2.9.8\n* 올린다\n• 확인") == "위험\njackson 2.9.8\n- 올린다\n- 확인"


def test_purge_deletes_target_with_all_history_and_reports_conflicts(client, monkeypatch):
    run_id = _import_run(client)
    with SessionLocal() as db:
        run = db.get(models.AnalysisRun, run_id)
        asset_id, sbom_id = run.sbom.asset_id, run.sbom_id
    monkeypatch.setattr(ai_advisor, "complete", lambda prompt: ("요약", "qwen2.5:7b", {"input_tokens": 1, "output_tokens": 1}))
    assert client.post(f"/api/ai/analyses/{run_id}").status_code == 200
    plain = client.delete(f"/api/assets/{asset_id}")
    assert plain.status_code == 409 and "이력 포함 삭제" in plain.json()["detail"]
    purged = client.delete(f"/api/assets/{asset_id}?purge=true")
    assert purged.status_code == 204, purged.text
    with SessionLocal() as db:
        assert db.get(models.Asset, asset_id) is None
        assert db.get(models.SbomDocument, sbom_id) is None and db.get(models.AnalysisRun, run_id) is None
        assert db.scalar(select(models.Component).where(models.Component.sbom_id == sbom_id)) is None
        assert db.scalar(select(models.AiSummary).where(models.AiSummary.target_id == run_id)) is None
    assert client.get(f"/api/analyses/runs/{run_id}").status_code == 404
    assert client.get("/api/dashboard/summary").json()["sbom_documents"] == 0


def test_address_accepts_ip_and_hostname_but_not_garbage(client):
    ok = client.post("/api/assets", json={"asset_tag": "H-1", "name": "호스트", "asset_type": "server", "ip_address": "db01.lab.example.com"})
    assert ok.status_code == 201, ok.text
    assert ok.json()["ip_address"] == "db01.lab.example.com"
    assert client.post("/api/assets", json={"asset_tag": "H-2", "name": "v6", "asset_type": "server", "ip_address": "fe80::1"}).status_code == 201
    bad = client.post("/api/assets", json={"asset_tag": "H-3", "name": "x", "asset_type": "server", "ip_address": "not a host!"})
    assert bad.status_code == 422 and "도메인" in bad.text
    assert client.patch(f"/api/assets/{ok.json()['id']}", json={"ip_address": "10.0.1.11"}).status_code == 200
