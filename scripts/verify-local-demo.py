#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


BASE_URL = os.environ.get("EOLWATCH_URL", "http://127.0.0.1:18080").rstrip("/")
USERNAME = os.environ.get("EOLWATCH_USERNAME", "admin")
PASSWORD = os.environ.get("EOLWATCH_PASSWORD", "Eolwatch!2026")


def request(path: str, method: str = "GET", body=None, token: str | None = None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urlopen(Request(BASE_URL + path, data=data, headers=headers, method=method), timeout=90) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        raw = error.read()
        try:
            content = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            content = {"detail": raw.decode("utf-8", errors="replace") or error.reason}
        return error.code, content


status, login = request("/api/auth/login", "POST", {"username": USERNAME, "password": PASSWORD})
assert status == 200, login
token = login["access_token"]

status, assets = request("/api/assets", token=token)
assert status == 200, assets
targets = [item for item in assets if item["monitored"] and item["ip_address"]]
assert len(targets) >= 2, f"점검 대상 VM이 부족합니다: {len(targets)}"

created_sboms = []
for asset in targets[:2]:
    status, job = request(f"/api/checks/assets/{asset['id']}/run", "POST", token=token)
    assert status == 200 and job["status"] == "SUCCESS", job
    status, sbom = request(f"/api/checks/{job['id']}/sbom", "POST", token=token)
    assert status == 200 and sbom["bom_format"] == "SPDX", sbom
    created_sboms.append(
        {"asset": asset["asset_tag"], "job": job["id"], "sbom": sbom["id"], "components": sbom["component_count"]}
    )

sample_path = Path(__file__).parents[1] / "samples" / "spdx-2.3-blackduck-compatible.json"
sample = json.loads(sample_path.read_text(encoding="utf-8"))
status, imported = request(f"/api/sboms/import?asset_id={targets[0]['id']}", "POST", sample, token)
if status == 409:
    _, sboms = request("/api/sboms", token=token)
    imported = next(item for item in sboms if item["serial_number"] == sample["documentNamespace"])
else:
    assert status == 201, imported

status, scan = request(f"/api/vulnerabilities/scan/sbom/{imported['id']}", "POST", token=token)
assert status == 200, scan
status, findings = request(f"/api/vulnerabilities?sbom_id={imported['id']}", token=token)
assert status == 200, findings
assert all(item["cve_id"].startswith("CVE-") for item in findings), findings

print(json.dumps({"health": "ok", "targets": created_sboms, "cve_scan": scan, "cves": findings[:5]}, ensure_ascii=False, indent=2))
