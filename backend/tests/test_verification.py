"""Second-opinion verification: kernel file relevance heuristic, tracker status parsing, run-level counts with mocked lookups."""
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
from app.services import verification  # noqa: E402

HOST = {"arch": "x86_64", "modules": ["ena", "nf_conntrack", "cfg80211", "vsock", "dm_multipath"], "filesystems": ["ext4", "vfat", "squashfs"], "rootfs": "ext4"}


@pytest.mark.parametrize("files,expected", [
    (["drivers/net/wireless/mediatek/mt76/mt7925/mac.c"], verification.UNLOADED_MODULE),
    (["drivers/net/ethernet/amazon/ena/ena_netdev.c"], verification.LOADED_MODULE),
    (["drivers/gpu/drm/amd/amdgpu/amdgpu_vm.c"], verification.UNLOADED_MODULE),
    (["fs/ntfs3/xattr.c"], verification.FS_NOT_USED),
    (["fs/ext4/inode.c"], verification.CORE),
    (["fs/namei.c"], verification.CORE),
    (["net/sctp/socket.c"], verification.UNLOADED_MODULE),
    (["net/wireless/nl80211.c"], verification.LOADED_MODULE),
    (["net/ipv4/tcp_input.c"], verification.CORE),
    (["mm/memory.c", "drivers/gpu/drm/i915/i915_gem.c"], verification.CORE),
    (["arch/arm64/kernel/entry.S"], verification.OTHER_ARCH),
    (["arch/x86/kvm/vmx/vmx.c"], verification.CORE),
    (["sound/soc/codecs/wm8994.c"], verification.UNLOADED_MODULE),
    (["drivers/md/dm-mpath.c"], verification.LOADED_MODULE),
    ([], verification.UNKNOWN),
    (["tools/perf/util/evsel.c"], verification.UNKNOWN),
])
def test_kernel_files_are_classified_against_the_hosts_modules_and_filesystems(files, expected):
    assert verification.classify_files(files, HOST) == expected


def test_tracker_status_reads_the_release_row_of_the_source_package():
    data = {"priority": "medium", "packages": [
        {"name": "linux-aws", "statuses": [{"release_codename": "noble", "status": "needed", "description": ""},
                                            {"release_codename": "resolute", "status": "pending", "description": "7.0.0-1014.14"}]},
        {"name": "linux", "statuses": [{"release_codename": "resolute", "status": "released", "description": "7.0.0-38.38"}]}]}
    assert verification._tracker_status(data, "linux-aws", "resolute") == ("pending", "7.0.0-1014.14", "medium")
    assert verification._tracker_status(data, "linux", "resolute") == ("released", "7.0.0-38.38", "medium")
    assert verification._tracker_status(data, "expat", "resolute") == ("not-listed", None, "medium")
    assert verification._tracker_status({"missing": True}, "linux", "resolute") == ("unknown", None, None)


@pytest.fixture
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        token = test_client.post("/api/auth/login", json={"username": "admin", "password": "Eolwatch!2026"}).json()["access_token"]
        test_client.headers.update({"Authorization": f"Bearer {token}"})
        yield test_client
    Base.metadata.drop_all(bind=engine)


def test_verify_run_fills_tracker_and_host_relevance_from_cached_lookups(client, monkeypatch):
    asset = client.post("/api/assets", json={"asset_tag": "VER-01", "name": "검증 대상", "asset_type": "server"}).json()
    document = json.loads((Path(__file__).parents[2] / "samples" / "spdx-2.3-blackduck-compatible.json").read_text())
    document["documentNamespace"] = "https://eolwatch.test/verify/" + str(uuid4())
    kernel = dict(document["packages"][0], SPDXID="SPDXRef-Package-kernel", name="linux-modules-7.0.0-1012-aws", versionInfo="7.0.0-1012.12",
                  externalRefs=[{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                 "referenceLocator": "pkg:deb/ubuntu/linux-modules-7.0.0-1012-aws@7.0.0-1012.12?arch=amd64&distro=ubuntu-26.04&upstream=linux-aws"}])
    expat = dict(document["packages"][0], SPDXID="SPDXRef-Package-expat", name="libexpat1", versionInfo="2.7.4-1ubuntu0.1",
                 externalRefs=[{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                "referenceLocator": "pkg:deb/ubuntu/libexpat1@2.7.4-1ubuntu0.1?arch=amd64&distro=ubuntu-26.04&upstream=expat"}])
    document["packages"] += [kernel, expat]
    document["relationships"] += [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": p["SPDXID"]} for p in (kernel, expat)]
    art = lambda p: {"name": p["name"], "version": p["versionInfo"], "purl": p["externalRefs"][0]["referenceLocator"]}
    report = {"descriptor": {"name": "grype", "version": "0.119.0", "db": {}}, "source": {"type": "sbom"}, "matches": [
        {"artifact": art(kernel), "vulnerability": {"id": "CVE-2026-68193", "severity": "Medium", "fix": {"state": "not-fixed", "versions": []}}, "matchDetails": [], "relatedVulnerabilities": []},
        {"artifact": art(kernel), "vulnerability": {"id": "CVE-2026-89779", "severity": "Medium", "fix": {"state": "not-fixed", "versions": []}}, "matchDetails": [], "relatedVulnerabilities": []},
        {"artifact": art(expat), "vulnerability": {"id": "CVE-2026-50219", "severity": "Medium", "fix": {"state": "not-fixed", "versions": []}}, "matchDetails": [], "relatedVulnerabilities": []},
    ]}
    imported = client.post("/api/analyses/import", json={"asset_id": asset["id"], "scan_scope": "ubuntu-dpkg-installed", "sbom": document, "report": report,
                                                          "distro": {"id": "ubuntu", "versionID": "26.04", "codename": "resolute"}, "host": HOST})
    assert imported.status_code == 200, imported.text
    run_id = imported.json()["id"]
    assert imported.json()["host"]["modules"] == len(HOST["modules"]) and imported.json()["verification"] is None

    ubuntu = {"CVE-2026-68193": {"priority": "medium", "packages": [{"name": "linux-aws", "statuses": [{"release_codename": "resolute", "status": "pending", "description": "7.0.0-1014.14"}]}]},
              "CVE-2026-89779": {"priority": "medium", "packages": [{"name": "linux-aws", "statuses": [{"release_codename": "resolute", "status": "needed", "description": ""}]}]},
              "CVE-2026-50219": {"priority": "medium", "packages": [{"name": "expat", "statuses": [{"release_codename": "resolute", "status": "released", "description": "2.7.4-1ubuntu0.1"}]}]}}
    kernel_files = {"CVE-2026-68193": {"files": ["drivers/net/wireless/mediatek/mt76/mt7925/mac.c"], "fixed": [], "title": "wifi: mt76"},
                    "CVE-2026-89779": {"files": ["fs/ntfs3/xattr.c"], "fixed": ["6.1.188"], "title": "fs/ntfs3"}}
    calls = {"ubuntu": 0, "kernel": 0}
    def fake_ubuntu(_client, cve):
        calls["ubuntu"] += 1; return ubuntu[cve]
    def fake_kernel(_client, cve):
        calls["kernel"] += 1; return kernel_files.get(cve, {"missing": True})
    monkeypatch.setattr(verification, "fetch_ubuntu", fake_ubuntu)
    monkeypatch.setattr(verification, "fetch_kernel", fake_kernel)

    verified = client.post(f"/api/analyses/{run_id}/verify")
    assert verified.status_code == 200, verified.text
    v = verified.json()["verification"]
    assert v["tracker"] == {"pending": 1, "needed": 1, "released": 1} and v["fixed_already"] == 1   # expat: DB lag, already fixed on the box
    assert v["host"] == {"UNLOADED_MODULE": 1, "FS_NOT_USED": 1} and v["checked_cves"] == 3 and v["partial"] is False
    rows = {r["cve_id"]: r for r in client.get("/api/vulnerabilities", params={"sbom_id": imported.json()["sbom_id"]}).json()}
    assert rows["CVE-2026-68193"]["tracker_status"] == "pending" and rows["CVE-2026-68193"]["tracker_fix"] == "7.0.0-1014.14"
    assert rows["CVE-2026-68193"]["host_relevance"] == "UNLOADED_MODULE" and rows["CVE-2026-68193"]["kernel_files"] == ["drivers/net/wireless/mediatek/mt76/mt7925/mac.c"]
    assert rows["CVE-2026-89779"]["host_relevance"] == "FS_NOT_USED" and rows["CVE-2026-50219"]["tracker_status"] == "released"
    # Second run: everything comes from the caches, no lookups.
    client.post(f"/api/analyses/{run_id}/verify")
    assert calls == {"ubuntu": 3, "kernel": 2}
    with SessionLocal() as db:
        assert db.scalar(select(models.TrackerCache).where(models.TrackerCache.cve == "CVE-2026-68193")).status == "pending"
        assert db.scalar(select(models.KernelCveFiles).where(models.KernelCveFiles.cve == "CVE-2026-89779")).files == ["fs/ntfs3/xattr.c"]
    # relevance filter: the practitioner default hides what is not actionable, 'relevant' hides what this host cannot reach.
    sbom_id = imported.json()["sbom_id"]
    assert client.get("/api/vulnerability-work/cves", params={"sbom_id": sbom_id, "relevance": "actionable"}).json()["total"] == 0
    assert client.get("/api/vulnerability-work/cves", params={"sbom_id": sbom_id, "relevance": "relevant"}).json()["total"] == 1   # expat only (not kernel)
    assert client.get("/api/vulnerability-work/cves", params={"sbom_id": sbom_id, "relevance": "all"}).json()["total"] == 3
