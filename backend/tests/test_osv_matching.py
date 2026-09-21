"""OSV package/range, CVSS, pagination and persistence regression coverage."""
from copy import deepcopy
from datetime import date
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app import models
from app.db import Base
from app.services.osv_matching import (
    match_advisory, osv_query, package_context, parse_timestamp, severity, validate_advisory,
)
from app.services.vulnerabilities import query_osv, scan_sbom


CVE = "CVE-2026-12345"


def component(purl="pkg:pypi/demo@1.0", version="1.0"):
    return SimpleNamespace(id=7, purl=purl, version=version)


def entry(name="demo", ecosystem="PyPI", events=None, kind="ECOSYSTEM", **extra):
    return {"package": {"name": name, "ecosystem": ecosystem},
            "ranges": [{"type": kind, "events": events or [{"introduced": "0"}, {"fixed": "2.0"}]}], **extra}


def advisory(*entries, id=CVE, **extra):
    return {"id": id, "affected": list(entries) or [entry()], **extra}


def match(item, c=None):
    return match_advisory(package_context(c or component()), validate_advisory(item))


def test_fix_uses_package_identity_instead_of_first_affected_record():
    item = advisory(entry(name="other", events=[{"introduced": "0"}, {"fixed": "999"}]), entry())
    assert match(item).fixed_versions == ["2.0"]
    assert match(advisory(entry(name="other"))).affected is False
    assert match(advisory(entry(name="demo", ecosystem="npm", kind="SEMVER"))).affected is False


def test_pypi_name_normalization_and_namespace_identity():
    assert match(advisory(entry(name="Demo.Foo")), component("pkg:pypi/demo_foo@1.0")).fixed_versions == ["2.0"]
    scoped = component("pkg:npm/%40one/demo@1.0.0", "1.0.0")
    item = advisory(entry("@two/demo", "npm", [{"introduced": "0"}, {"fixed": "9.0.0"}], "SEMVER"),
                    entry("@one/demo", "npm", [{"introduced": "0"}, {"fixed": "1.1.0"}], "SEMVER"))
    assert match(item, scoped).fixed_versions == ["1.1.0"]


def test_advisory_purl_qualifiers_are_constraints_not_discarded():
    e = entry()
    e["package"]["purl"] = "pkg:pypi/demo?arch=arm64"
    assert match(advisory(e), component("pkg:pypi/demo@1.0?arch=x86_64")).affected is False
    assert match(advisory(e), component("pkg:pypi/demo@1.0?arch=arm64")).fixed_versions == ["2.0"]
    e["package"]["purl"] = "pkg:pypi/demo@2.0"
    with pytest.raises(ValueError, match="버전"):
        match(advisory(e))


def test_only_interval_containing_installed_branch_contributes_fix():
    events = [{"introduced": "0"}, {"fixed": "1.1"}, {"introduced": "2.0"}, {"fixed": "2.3"}]
    item = advisory(entry(events=events))
    assert match(item).fixed_versions == ["1.1"]
    assert match(item, component("pkg:pypi/demo@2.1", "2.1")).fixed_versions == ["2.3"]
    assert match(item, component("pkg:pypi/demo@1.5", "1.5")).affected is False


def test_unsorted_events_follow_version_order_and_fixed_boundary_is_excluded():
    item = advisory(entry(events=[{"fixed": "1.2"}, {"introduced": "0"}]))
    assert match(item).fixed_versions == ["1.2"]
    assert match(item, component("pkg:pypi/demo@1.2", "1.2")).affected is False


def test_overlapping_range_cannot_recommend_still_affected_candidate():
    item = advisory(entry(events=[{"introduced": "0"}, {"fixed": "1.1"}]),
                    entry(events=[{"introduced": "0"}, {"fixed": "1.2"}]))
    assert match(item).fixed_versions == ["1.2"]


@pytest.mark.parametrize("events,version,state", [
    ([{"introduced": "0"}, {"last_affected": "1.0"}], "1.0", True),
    ([{"introduced": "0"}, {"last_affected": "1.0"}], "1.1", False),
    ([{"introduced": "0"}, {"limit": "1.0"}], "1.0", False),
    ([{"introduced": "0"}, {"limit": "2.0"}], "1.0", True),
    ([{"introduced": "0"}, {"limit": "*"}], "1.0", True),
])
def test_last_affected_and_limit_are_not_fixed_versions(events, version, state):
    result = match(advisory(entry(events=events)), component(f"pkg:pypi/demo@{version}", version))
    assert result.affected is state
    assert result.fixed_versions == []


def test_pep440_prerelease_epoch_postrelease_and_local_versions():
    for installed, fixed in [("1.0rc1", "1.0"), ("1!1.0", "1!1.0.post1"), ("1.0+local", "1.0.post1")]:
        assert match(advisory(entry(events=[{"introduced": "0"}, {"fixed": fixed}])),
                     component(f"pkg:pypi/demo@{installed}", installed)).fixed_versions == [fixed]


@pytest.mark.parametrize("purl,ecosystem,name,installed,fixed", [
    ("npm", "npm", "demo", "1.0.0-beta.1", "1.0.0"),
    ("cargo", "crates.io", "demo", "1.0.0", "1.1.0"),
    ("golang", "Go", "example.com/demo", "v1.0.0", "1.1.0"),
])
def test_supported_semver_ecosystems(purl, ecosystem, name, installed, fixed):
    item = advisory(entry(name, ecosystem, [{"introduced": "0"}, {"fixed": fixed}], "ECOSYSTEM"))
    assert match(item, component(f"pkg:{purl}/{name}@{installed}", installed)).fixed_versions == [fixed]


def test_semver_build_metadata_does_not_change_fixed_boundary():
    item = advisory(entry("demo", "npm", [{"introduced": "0"}, {"fixed": "1.0.0+one"}], "SEMVER"))
    assert match(item, component("pkg:npm/demo@1.0.0+two", "1.0.0+two")).affected is False


@pytest.mark.parametrize("purl,ecosystem,name,kind,installed,fixed", [
    ("maven/org.example/demo", "Maven", "org.example:demo", "ECOSYSTEM", "1.0", "2.0"),
    ("deb/debian/demo?distro=debian-12", "Debian:12", "demo", "ECOSYSTEM", "1.0-1", "1.0-2"),
    ("pypi/demo", "PyPI", "demo", "GIT", "abcdef", "fedcba"),
    ("npm/demo", "npm", "demo", "ECOSYSTEM", "1.0", "2.0"),
])
def test_unsupported_or_invalid_order_returns_unknown_without_invented_fix(purl, ecosystem, name, kind, installed, fixed):
    item = advisory(entry(name, ecosystem, [{"introduced": "0"}, {"fixed": fixed}], kind))
    result = match(item, component(f"pkg:{purl}", installed))
    assert result.affected is None
    assert result.fixed_versions == []


def test_explicit_versions_can_match_unsupported_git_but_cannot_invent_fixed_release():
    item = advisory(entry(kind="GIT", events=[{"introduced": "0"}, {"fixed": "a" * 40}], versions=["1.0"]))
    result = match(item)
    assert result.affected is True
    assert result.fixed_versions == []


def test_ambiguous_equal_boundaries_do_not_propose_a_fix():
    result = match(advisory(entry(events=[{"introduced": "0"}, {"introduced": "1.0"}, {"fixed": "1.0.0"}])))
    assert result.affected is None
    assert result.fixed_versions == []


def test_versionless_npm_scope_is_not_mistaken_for_version_separator():
    assert osv_query(package_context(component("pkg:npm/@scope/demo", "1.2.3"))) == {
        "package": {"purl": "pkg:npm/%40scope/demo"}, "version": "1.2.3"}
    assert osv_query(package_context(component("pkg:npm/%40scope/demo@1.2.3", "1.2.3"))) == {
        "package": {"purl": "pkg:npm/%40scope/demo@1.2.3"}}
    assert osv_query(package_context(component("pkg:pypi/demo", None))) is None


def test_purl_version_conflict_fails_instead_of_querying_wrong_installation():
    with pytest.raises(ValueError, match="설치 버전이 다릅니다"):
        package_context(component("pkg:pypi/demo@1.0", "2.0"))
    assert package_context(component("pkg:pypi/demo@1.0", "1.0.0")).version == "1.0.0"
    with pytest.raises(ValueError, match="PURL"):
        package_context(component("not-a-package", "1.0"))


def test_distribution_qualifier_prevents_cross_release_matches():
    result = match(advisory(entry("demo", "Debian:11")),
                   component("pkg:deb/debian/demo@1.0?distro=debian-12"))
    assert result.affected is False


def test_explicit_semver_range_can_be_checked_without_guessing_ecosystem_order():
    result = match(advisory(entry("org.example:demo", "Maven", [{"introduced": "0"}, {"fixed": "1.1.0"}], "SEMVER")),
                   component("pkg:maven/org.example/demo@1.0.0", "1.0.0"))
    assert result.fixed_versions == ["1.1.0"]


@pytest.mark.parametrize("kind,vector,expected", [
    ("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL"),
    ("CVSS_V3", "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "HIGH"),
    ("CVSS_V3", "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "LOW"),
    ("CVSS_V2", "AV:N/AC:L/Au:N/C:C/I:C/A:C", "HIGH"),
    ("CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N", "CRITICAL"),
    ("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "NONE"),
    ("CVSS_V3", "9.8", "UNKNOWN"),
    ("CVSS_V3", "CVSS:3.1/AV:N/AC:invalid", "UNKNOWN"),
    ("CVSS_V4", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "UNKNOWN"),
])
def test_cvss_is_calculated_with_validated_version_specific_library(kind, vector, expected):
    assert severity({"severity": [{"type": kind, "score": vector}]}) == expected


def test_package_severity_and_multiple_vectors_take_highest_valid_rating():
    item = {"database_specific": {"severity": "moderate"}, "severity": [{"type": "CVSS_V3", "score": "bad"}]}
    assert severity(item) == "MEDIUM"
    assert severity(item, [{"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]) == "CRITICAL"
    assert severity({}) == "UNKNOWN"


def mock_osv(monkeypatch, handler):
    original = httpx.Client
    monkeypatch.setattr("app.services.vulnerabilities.httpx.Client", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    monkeypatch.setattr("app.services.vulnerabilities.get_settings", lambda: SimpleNamespace(osv_api_url="https://osv.test/v1/querybatch"))


def test_batch_pagination_preserves_order_and_deduplicates_detail_requests(monkeypatch):
    import json
    requests = []
    def handler(request):
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=advisory(id=request.url.path.split("/")[-1]))
        queries = json.loads(request.content)["queries"]
        if len(queries) == 2:
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "A"}], "next_page_token": "page2"}, {"vulns": [{"id": "B"}]}]})
        assert queries == [{"package": {"purl": "pkg:pypi/one@1"}, "page_token": "page2"}]
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "A"}, {"id": "C"}]}]})
    mock_osv(monkeypatch, handler)
    results = query_osv([{"package": {"purl": "pkg:pypi/one@1"}}, {"package": {"purl": "pkg:pypi/two@1"}}])
    assert [[raw["id"] for raw in result["vulns"]] for result in results] == [["A", "C"], ["B"]]
    assert len([request for request in requests if request.method == "GET"]) == 3


@pytest.mark.parametrize("payload", [[], {}, {"results": []}, {"results": [{}, {}]}, {"results": [{"vulns": None}]},
                                     {"results": [{"vulns": [{}]}]}, {"results": [{"error": "unavailable"}]}])
def test_malformed_or_partial_batch_is_failure_not_a_clean_scan(monkeypatch, payload):
    mock_osv(monkeypatch, lambda _request: httpx.Response(200, json=payload))
    with pytest.raises(ValueError):
        query_osv([{"package": {"purl": "pkg:pypi/demo@1"}}])


def test_repeated_pagination_token_fails(monkeypatch):
    mock_osv(monkeypatch, lambda _request: httpx.Response(200, json={"results": [{"next_page_token": "loop"}]}))
    with pytest.raises(ValueError, match="반복"):
        query_osv([{"package": {"purl": "pkg:pypi/demo@1"}}])


def test_detail_id_mismatch_fails(monkeypatch):
    mock_osv(monkeypatch, lambda request: httpx.Response(200, json={"results": [{"vulns": [{"id": "A"}]}]} if request.method == "POST" else advisory(id="B")))
    with pytest.raises(ValueError, match="id가 요청"):
        query_osv([{"package": {"purl": "pkg:pypi/demo@1"}}])


@pytest.mark.parametrize("bad", [
    {"id": CVE}, {"id": CVE, "affected": [None]}, advisory({"ranges": []}),
    advisory(entry(events=[{"introduced": "0", "fixed": "1.0"}])),
    advisory(entry(events=[{"fixed": "2.0"}])),
    advisory(entry(events=[{"introduced": "0"}, {"fixed": "2.0"}, {"last_affected": "1.0"}])),
    advisory(aliases=[{}]), advisory(references="url"),
])
def test_malformed_advisory_is_rejected(bad):
    with pytest.raises(ValueError):
        validate_advisory(bad)


def test_osv_nanosecond_timestamp_is_accepted_on_python39():
    timestamp = "2026-09-10T03:49:48.526758681Z"
    assert parse_timestamp(timestamp).microsecond == 526758
    validate_advisory(advisory(modified=timestamp))
    for value in ("not-a-time", "2026-09-10", "2026-09-10T03:49:48", "2026-99-10T03:49:48Z"):
        with pytest.raises(ValueError, match="날짜"):
            validate_advisory(advisory(withdrawn=value))


@pytest.fixture
def osv_db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'osv.db'}")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        sbom = models.SbomDocument(serial_number="osv-tests", bom_format="SPDX", spec_version="2.3", component_count=1, raw_document={})
        db.add(sbom); db.flush()
        installed = models.Component(sbom_id=sbom.id, bom_ref="demo", name="demo", version="1.0", purl="pkg:pypi/demo@1.0")
        db.add(installed); db.commit()
        yield db, sbom, installed
    engine.dispose()


def test_advisory_aliases_aggregate_fixes_severity_and_references_without_resetting_review(osv_db, monkeypatch):
    db, sbom, installed = osv_db
    first = advisory(id="GHSA-first", aliases=[CVE], database_specific={"severity": "CRITICAL"},
                     summary="Most severe", references=[{"type": "ADVISORY", "url": "https://example.test/one"}])
    second = advisory(entry(events=[{"introduced": "0"}, {"fixed": "3.0"}]), id="PYSEC-second", aliases=[CVE],
                      database_specific={"severity": "LOW"}, summary="Less severe",
                      references=[{"type": "ADVISORY", "url": "https://example.test/two"}])
    monkeypatch.setattr("app.services.vulnerabilities.query_osv", lambda _: [{"vulns": [first, second]}])
    result = scan_sbom(db, sbom.id)
    link = db.scalar(select(models.ComponentVulnerability))
    assert result["vulnerability_links"] == 1
    # 2.0 is still affected according to the second advisory for the same CVE.
    assert link.fixed_versions == ["3.0"]
    assert link.finding_severity == "CRITICAL"
    assert link.vulnerability.summary == "Most severe"
    assert link.vulnerability.aliases == [CVE, "GHSA-first", "PYSEC-second"]
    assert len(link.vulnerability.references) == 2
    link.vex_status = "UNDER_INVESTIGATION"; link.detail = "보안 검토"; link.review_revision = 2; link.due_date = date(2026, 10, 1)
    db.commit()
    monkeypatch.setattr("app.services.vulnerabilities.query_osv", lambda _: [{"vulns": [second, first]}])
    scan_sbom(db, sbom.id)
    assert link.fixed_versions == ["3.0"]
    assert (link.vex_status, link.detail, link.review_revision, link.due_date) == ("UNDER_INVESTIGATION", "보안 검토", 2, date(2026, 10, 1))


def test_scan_skips_unversioned_and_withdrawn_and_already_fixed(osv_db, monkeypatch):
    db, sbom, installed = osv_db
    db.add_all([models.Component(sbom_id=sbom.id, bom_ref="versionless", name="unknown", purl="pkg:npm/@scope/unknown"),
                models.Component(sbom_id=sbom.id, bom_ref="no-purl", name="root", version="1")])
    db.commit()
    def query(queries):
        assert len(queries) == 1
        return [{"vulns": [advisory(withdrawn="2026-01-01T00:00:00Z"),
                           advisory(entry(events=[{"introduced": "0"}, {"fixed": "1.0"}]))]}]
    monkeypatch.setattr("app.services.vulnerabilities.query_osv", query)
    result = scan_sbom(db, sbom.id)
    assert result["queried_components"] == 1
    assert result["skipped_components"] == 2
    assert result["ignored_withdrawn"] == 1
    assert result["ignored_unaffected"] == 1
    assert db.scalar(select(models.ComponentVulnerability)) is None


def test_invalid_later_advisory_cannot_leave_partial_new_findings(osv_db, monkeypatch):
    db, sbom, _installed = osv_db
    monkeypatch.setattr("app.services.vulnerabilities.query_osv", lambda _: [{"vulns": [advisory(), {"id": CVE}]}])
    with pytest.raises(ValueError):
        scan_sbom(db, sbom.id)
    assert db.scalar(select(models.Vulnerability)) is None
    assert db.scalar(select(models.ComponentVulnerability)) is None


def test_package_specific_severity_does_not_use_another_package_rating(osv_db, monkeypatch):
    db, sbom, _installed = osv_db
    raw = advisory(entry("other", severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]),
                   entry(severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]))
    monkeypatch.setattr("app.services.vulnerabilities.query_osv", lambda _: [{"vulns": [raw]}])
    scan_sbom(db, sbom.id)
    assert db.scalar(select(models.ComponentVulnerability)).finding_severity == "LOW"


def test_withdrawal_does_not_delete_or_automatically_change_saved_human_review(osv_db, monkeypatch):
    db, sbom, _installed = osv_db
    monkeypatch.setattr("app.services.vulnerabilities.query_osv", lambda _: [{"vulns": [advisory()]}])
    scan_sbom(db, sbom.id)
    link = db.scalar(select(models.ComponentVulnerability))
    link.vex_status = "NOT_AFFECTED"; link.detail = "이전 담당자 판단"; link.review_revision = 4
    db.commit()
    columns = list(models.ComponentVulnerability.__table__.columns)
    before = deepcopy(dict(db.execute(select(*columns)).mappings().one()))
    monkeypatch.setattr("app.services.vulnerabilities.query_osv", lambda _: [{"vulns": [advisory(withdrawn="2026-09-01T00:00:00Z")]}])
    assert scan_sbom(db, sbom.id)["ignored_withdrawn"] == 1
    assert dict(db.execute(select(*columns)).mappings().one()) == before


def test_injected_client_with_short_result_fails_before_writes(osv_db, monkeypatch):
    db, sbom, _installed = osv_db
    monkeypatch.setattr("app.services.vulnerabilities.query_osv", lambda _: [])
    with pytest.raises(ValueError, match="응답 개수"):
        scan_sbom(db, sbom.id)
    assert db.scalar(select(models.Vulnerability)) is None
