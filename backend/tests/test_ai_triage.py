"""AI triage/advice: candidate selection, output validation, endpoints with a mocked model, data minimisation."""
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
from app.config import get_settings  # noqa: E402
from app.db import Base, engine, SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.services import ai_advisor, ai_triage  # noqa: E402


@pytest.fixture
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        token = test_client.post("/api/auth/login", json={"username": "admin", "password": "Eolwatch!2026"}).json()["access_token"]
        test_client.headers.update({"Authorization": f"Bearer {token}"})
        yield test_client
    Base.metadata.drop_all(bind=engine)


def _import_run(client) -> tuple[int, int]:
    asset = client.post("/api/assets", json={"asset_tag": "TRI-01", "name": "선별 대상", "asset_type": "server", "ip_address": "10.9.9.9", "ssh_username": "ops", "monitored": True}).json()
    document = json.loads((Path(__file__).parents[2] / "samples" / "spdx-2.3-blackduck-compatible.json").read_text())
    document["documentNamespace"] = "https://eolwatch.test/triage/" + str(uuid4())
    package = document["packages"][0]
    artifact = {"name": package["name"], "version": package.get("versionInfo", "1.0"), "type": "python"}
    report = {"descriptor": {"name": "grype", "version": "0.118.0", "db": {}}, "source": {"type": "sbom"}, "matches": [
        {"vulnerability": {"id": "CVE-2026-40001", "severity": "High", "fix": {"versions": ["3.1.6"], "state": "fixed"},
                           "knownExploited": [{"cve": "CVE-2026-40001"}], "epss": [{"cve": "CVE-2026-40001", "epss": 0.3, "percentile": 0.9}]},
         "artifact": artifact, "matchDetails": [], "relatedVulnerabilities": []},
        {"vulnerability": {"id": "CVE-2026-40002", "severity": "Low", "fix": {"versions": [], "state": "not-fixed"},
                           "epss": [{"cve": "CVE-2026-40002", "epss": 0.0002, "percentile": 0.05}]},
         "artifact": artifact, "matchDetails": [], "relatedVulnerabilities": []},
    ]}
    run = client.post("/api/analyses/import", json={"asset_id": asset["id"], "scan_scope": "ubuntu-dpkg-installed", "sbom": document, "report": report})
    assert run.status_code == 200, run.text
    return run.json()["id"], asset["id"]


def test_candidates_pick_only_findings_worth_a_look_and_hide_identifiers(client):
    run_id, asset_id = _import_run(client)
    with SessionLocal() as db:
        # a successful check with server facts, including things the model must never see
        job = models.CollectionJob(asset_id=asset_id, status="SUCCESS")
        db.add(job); db.flush()
        db.add(models.CheckResult(collection_job_id=job.id, health_level="NORMAL", raw_metrics={"package_context": {"pretty_name": "Ubuntu 26.04 LTS"},
                                  "server_info": {"hostname": "secret-host", "kernel": "7.0.0-1012-aws", "architecture": "x86_64", "platform": "aws",
                                                  "cloud": {"instance_id": "i-secret", "account_id": "123", "instance_type": "t3.micro"},
                                                  "ip_addresses": [{"interface": "eth0", "address": "10.9.9.9/24"}],
                                                  "listening_ports": [{"protocol": "tcp", "address": "*", "port": 22}], "services": ["ssh"]}}))
        db.commit()
        run = db.get(models.AnalysisRun, run_id)
        context = ai_triage.triage_context(db, run)
    assert [c["cve"] for c in context["candidates"]] == ["CVE-2026-40001"]     # the low, unfixed, unexploited one is not sent
    assert context["candidates"][0]["kev"] is True and context["candidates"][0]["epss"] == 0.3
    text = ai_triage.triage_prompt(context)
    for secret in ("secret-host", "i-secret", "10.9.9.9", "123"):
        assert secret not in text
    assert "7.0.0-1012-aws" in text and "t3.micro" in text


def test_validate_triage_keeps_only_candidate_cves_and_known_verdicts():
    context = {"candidates": [{"cve": "CVE-1", "pkg": "a", "ver": "1", "fix": [], "sev": "HIGH", "epss": 0.5, "kev": True, "apt": None, "kernel": False}],
               "eligible": 1, "sent": 1, "cve_total": 10}
    answer = {"items": [{"cve": "CVE-1", "verdict": "해당", "reason": "r", "action": "a"}, {"cve": "CVE-2", "verdict": "해당", "reason": "made up"},
                        {"cve": "CVE-1", "verdict": "확인 필요"}, {"cve": "CVE-1", "verdict": "위험"}], "note": "n"}
    result = ai_triage.validate_triage(answer, context)
    assert [i["cve"] for i in result["items"]] == ["CVE-1"] and result["items"][0]["verdict"] == "해당"
    assert result["counts"] == {"해당": 1, "확인 필요": 0, "해당 없음 가능성": 0}
    with pytest.raises(Exception):
        ai_triage.validate_triage({"items": [{"cve": "CVE-9", "verdict": "해당"}]}, context)


def test_triage_and_advice_endpoints_store_validated_answers(client, monkeypatch):
    run_id, _ = _import_run(client)
    calls = []

    def fake_complete(prompt, *, system=ai_advisor.SYSTEM_PROMPT, json_mode=False, max_tokens=700):
        calls.append((json_mode, max_tokens))
        if json_mode:
            return json.dumps({"items": [{"cve": "CVE-2026-40001", "verdict": "해당", "reason": "악용 확인", "action": "apt upgrade"},
                                         {"cve": "CVE-2026-99999", "verdict": "해당", "reason": "없는 CVE"}], "note": "한 건"}), "gpt-5-mini", {"input_tokens": 10, "output_tokens": 5}
        return "1) 해당됨\n- sudo apt install --only-upgrade pkg", "gpt-5-mini", {"input_tokens": 8, "output_tokens": 4}
    monkeypatch.setattr(ai_advisor, "complete", fake_complete)
    monkeypatch.setattr(ai_advisor, "ai_available", lambda: True)

    assert client.get(f"/api/ai/analyses/{run_id}/triage").json() is None
    preview = client.get(f"/api/ai/analyses/{run_id}/triage/context").json()
    assert preview["context"]["sent"] == 1 and "CVE-2026-40001" in preview["prompt"]
    first = client.post(f"/api/ai/analyses/{run_id}/triage")
    assert first.status_code == 200, first.text
    body = json.loads(first.json()["summary"])
    assert [i["cve"] for i in body["items"]] == ["CVE-2026-40001"] and body["counts"]["해당"] == 1 and body["cve_total"] == 2
    assert first.json()["kind"] == "triage"
    again = client.post(f"/api/ai/analyses/{run_id}/triage")
    assert again.json()["id"] == first.json()["id"] and len([c for c in calls if c[0]]) == 1   # same prompt: cached, no second call
    assert client.get(f"/api/ai/analyses/{run_id}/triage").json()["id"] == first.json()["id"]

    link_id = client.get("/api/vulnerability-work", params={"status": "ALL"}).json()["items"][0]["link_id"]
    assert client.get(f"/api/ai/vulnerabilities/{link_id}/advice").json() is None
    advice = client.post(f"/api/ai/vulnerabilities/{link_id}/advice")
    assert advice.status_code == 200 and advice.json()["kind"] == "advice" and "apt install" in advice.json()["summary"]
    assert client.get("/api/ai/vulnerabilities/999999/advice").status_code == 404


def test_check_context_never_carries_addresses_or_host_names():
    class Result:
        cpu_percent = 1.0; memory_percent = 2.0; max_disk_percent = 3.0; uptime_seconds = 60; health_level = "NORMAL"; disk_details = []; process_details = []
        raw_metrics = {"package_count": 5, "server_info": {"hostname": "db-01", "ip_addresses": [{"interface": "eth0", "address": "192.168.0.5/24"}],
                                                          "cloud": {"provider": "aws", "instance_id": "i-1", "account_id": "9", "instance_type": "t3.micro", "region": "ap-northeast-2"}}}
    class Asset:
        asset_tag = "SRV"; ip_address = "192.168.0.5"
    class Job:
        id = 1; status = "SUCCESS"; result = Result(); asset = Asset(); failure_stage = failure_code = failure_message = None
    text = ai_advisor._dumps(ai_advisor.check_context(Job()))
    for secret in ("db-01", "192.168.0.5", "i-1", '"9"'):
        assert secret not in text
    assert "t3.micro" in text


def test_secret_settings_can_come_from_files(tmp_path, monkeypatch):
    secret = tmp_path / "jwt"; secret.write_text("from-a-file\n")
    monkeypatch.setenv("JWT_SECRET_FILE", str(secret)); monkeypatch.setenv("JWT_SECRET", "from-env")
    get_settings.cache_clear()
    try:
        assert get_settings().jwt_secret == "from-a-file"
        monkeypatch.setenv("JWT_SECRET_FILE", str(tmp_path / "missing"))
        get_settings.cache_clear()
        with pytest.raises(RuntimeError):
            get_settings()
    finally:
        monkeypatch.delenv("JWT_SECRET_FILE"); get_settings.cache_clear(); get_settings()


def test_collector_commands_fall_back_when_a_tool_is_missing():
    from app.services import collector
    assert "/proc/stat" in collector.COMMANDS["cpu"] and "apk info" in collector.COMMANDS["packages"]
    assert "netstat" in collector.SERVER_INFO_COMMANDS["listening_ports"] and "hostname -I" in collector.SERVER_INFO_COMMANDS["ip_addresses"]
    assert "rc-status" in collector.SERVER_INFO_COMMANDS["services"] and "/proc/cpuinfo" in collector.SERVER_INFO_COMMANDS["cpu_cores"]


def test_openai_error_bodies_wrapped_in_a_list_are_reported_not_crashed(monkeypatch):
    """Gemini's OpenAI-compatible endpoint answers 429 with a JSON list; that used to raise AttributeError (HTTP 500)."""
    import httpx
    from fastapi import HTTPException
    from app.services import ai_advisor
    calls = {"n": 0}
    def post(self, url, json=None, headers=None):
        calls["n"] += 1
        return httpx.Response(429, json=[{"error": {"message": "Quota exceeded for quota metric 'free_tier_requests' PerDay", "code": 429}}])
    monkeypatch.setattr(httpx.Client, "post", post)
    monkeypatch.setattr(ai_advisor.time, "sleep", lambda *_: None)
    monkeypatch.setattr(ai_advisor, "ai_available", lambda: True)
    with pytest.raises(HTTPException) as caught:
        ai_advisor._complete_openai("p", "s", False, 100)
    assert caught.value.status_code == 429 and "하루 요청 한도" in caught.value.detail and calls["n"] == ai_advisor.OPENAI_ATTEMPTS
