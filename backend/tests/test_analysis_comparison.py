"""Comparison uses immutable run evidence and never marks disappearance as fixed."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

os.environ["DATABASE_URL"] = "sqlite:////tmp/eolwatch-test.db"

from fastapi import HTTPException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app import models, schemas
from app.db import Base
from app.services.analysis import import_analysis
from app.services.analysis_comparison import compare_analyses


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'comparison.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as session:
        yield session
    engine.dispose()


@pytest.fixture
def asset(db):
    value = models.Asset(asset_tag='COMPARE-01', name='비교 서버', asset_type='server')
    db.add(value)
    db.commit()
    return value


def package(name='demo-lib', version='1.0', purl=None):
    return {'name': name, 'version': version, 'purl': purl or f'pkg:pypi/{name}@{version}'}


def match(item, cve='CVE-2026-12345', *, aliases=(), severity='High', fixed=('2.0',)):
    return {
        'artifact': {'name': item['name'], 'version': item['version'], 'purl': item['purl']},
        'vulnerability': {'id': cve, 'severity': severity,
                          'fix': {'state': 'fixed', 'versions': list(fixed)}},
        'relatedVulnerabilities': [{'id': value} for value in aliases],
    }


def add_run(db, asset, packages, matches, *, verified=True, scope='dpkg + /opt/demo', scanner_version='1.0', database=None):
    sample = Path(__file__).parents[2] / 'samples' / 'spdx-2.3-blackduck-compatible.json'
    document = json.loads(sample.read_text(encoding='utf-8'))
    document['documentNamespace'] = f'https://eolwatch.test/compare/{uuid4()}'
    document['creationInfo']['creators'] = ['Tool: syft-test-fixture']
    template = document['packages'][0]
    document['packages'] = []
    for index, item in enumerate(packages):
        entry = deepcopy(template)
        entry.update(SPDXID=f'SPDXRef-Package-{index}', name=item['name'], versionInfo=item['version'])
        # Keep the imported product identity unique for equal names in different ecosystems.
        entry['supplier'] = 'Organization: ' + item['purl'].split('@')[0] + item['purl'].partition('?')[2]
        entry['externalRefs'][0]['referenceLocator'] = item['purl']
        document['packages'].append(entry)
    document['documentDescribes'] = [entry['SPDXID'] for entry in document['packages']]
    document['relationships'] = [
        {'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': entry['SPDXID']}
        for entry in document['packages']
    ]
    report = {
        'descriptor': {'name': 'grype', 'version': scanner_version,
                       'db': database if database is not None else {'built': '2026-09-15T00:00:00Z', 'schemaVersion': 6}},
        'source': {'type': 'sbom', 'target': 'fixture.spdx.json'},
        'matches': deepcopy(matches),
    }
    run = import_analysis(db, schemas.AnalysisImport(asset_id=asset.id, sbom=document, report=report, scan_scope=scope))
    run.imported_at = datetime(2026, 9, 15, tzinfo=timezone.utc) + timedelta(seconds=run.id)
    if verified:
        db.add(models.AnalysisJob(asset_id=asset.id, asset_snapshot={'asset_tag': asset.asset_tag, 'name': asset.name},
                                  status='SUCCESS', analysis_run_id=run.id, finished_at=run.imported_at))
    db.commit()
    return run


def test_delta_distinguishes_update_disappearance_removal_and_new_findings(db, asset):
    keep, update, removed, added = package('keep'), package('update'), package('removed'), package('added')
    updated = package('update', '2.0')
    base = add_run(db, asset, [keep, update, removed], [match(keep), match(update, 'CVE-2026-12346'), match(removed, 'CVE-2026-12347')])
    target = add_run(db, asset, [keep, updated, added], [match(keep), match(added, 'CVE-2026-12348')])
    result = compare_analyses(db, base.id, target.id)
    assert result['comparable'] is True
    assert result['warnings'] == []
    assert result['base']['asset_id'] == result['target']['asset_id'] == asset.id
    assert result['base']['id'] == base.id
    assert result['target']['sbom_id'] == target.sbom_id
    assert result['summary'] == {'persistent': 1, 'new': 1, 'no_longer_detected': 1, 'component_removed': 1}
    findings = {item['component_name']: item for item in result['findings']}
    assert findings['keep']['status'] == 'PERSISTENT'
    assert findings['added']['status'] == 'NEW'
    assert findings['added']['before_versions'] == []
    assert findings['update']['status'] == 'NO_LONGER_DETECTED'
    assert findings['update']['before_versions'] == ['1.0']
    assert findings['update']['after_versions'] == ['2.0']
    assert findings['update']['fixed_versions'] == ['2.0']
    assert findings['removed']['status'] == 'COMPONENT_REMOVED'
    assert findings['removed']['after_versions'] == []


def test_simultaneous_versions_remain_visible_and_a_remaining_vulnerable_version_is_persistent(db, asset):
    old, fixed = package(), package(version='2.0')
    base = add_run(db, asset, [old, fixed], [match(old)])
    unchanged = add_run(db, asset, [old, fixed], [match(old)])
    updated = add_run(db, asset, [fixed], [])
    still_affected = compare_analyses(db, base.id, unchanged.id)['findings'][0]
    assert still_affected['status'] == 'PERSISTENT'
    assert still_affected['before_versions'] == still_affected['after_versions'] == ['1.0', '2.0']
    no_detection = compare_analyses(db, base.id, updated.id)['findings'][0]
    assert no_detection['status'] == 'NO_LONGER_DETECTED'
    assert no_detection['before_versions'] == ['1.0', '2.0']
    assert no_detection['after_versions'] == ['2.0']


def test_canonical_identity_preserves_ecosystem_namespace_architecture_and_subpath(db, asset):
    pypi = package('library')
    npm = package('library', purl='pkg:npm/%40one/library@1.0#dist/server')
    deb = package('library', purl='pkg:deb/ubuntu/library@1.0?arch=amd64&distro=ubuntu-24.04')
    npm_other = package('library', purl='pkg:npm/%40two/library@1.0#dist/server')
    deb_other = package('library', purl='pkg:deb/ubuntu/library@1.0?distro=ubuntu-24.04&arch=arm64')
    base = add_run(db, asset, [pypi, npm, deb], [match(item) for item in [pypi, npm, deb]])
    target = add_run(db, asset, [pypi, npm_other, deb_other], [match(item) for item in [pypi, npm_other, deb_other]])
    result = compare_analyses(db, base.id, target.id)
    assert result['summary'] == {'persistent': 1, 'new': 2, 'no_longer_detected': 0, 'component_removed': 2}
    assert len({item['component_identity'] for item in result['findings']}) == 5


def test_purl_qualifier_order_and_python_name_normalization_do_not_create_false_removals(db, asset):
    old = package('Demo_Lib', purl='pkg:pypi/Demo_Lib@1.0?arch=any&repository_url=https%3A%2F%2Fexample.test')
    new = package('demo-lib', '2.0', purl='pkg:pypi/demo-lib@2.0?repository_url=https%3A%2F%2Fexample.test&arch=any')
    base = add_run(db, asset, [old], [match(old)])
    target = add_run(db, asset, [new], [])
    result = compare_analyses(db, base.id, target.id)
    assert result['summary']['no_longer_detected'] == 1
    assert result['summary']['component_removed'] == 0
    assert result['findings'][0]['after_versions'] == ['2.0']


def test_alias_and_duplicate_matches_aggregate_cve_severity_and_fixed_branches(db, asset):
    item = package()
    alias = match(item, 'GHSA-test-fixture-only', aliases=['CVE-2026-12345', 'CVE-2026-12345'], severity='Low', fixed=['2.0'])
    duplicate = match(item, severity='Critical', fixed=['2.0', '3.0'])
    unrelated = match(item, 'GHSA-other-fixture-only')
    base = add_run(db, asset, [item], [alias, duplicate, unrelated])
    target = add_run(db, asset, [package(version='3.0')], [])
    result = compare_analyses(db, base.id, target.id)
    assert len(result['findings']) == 1
    assert result['findings'][0]['severity'] == 'CRITICAL'
    assert result['findings'][0]['fixed_versions'] == ['2.0', '3.0']
    assert result['findings'][0]['cve_id'] == 'CVE-2026-12345'


def test_comparison_is_unchanged_by_mutable_vex_and_does_not_write_remediation(db, asset):
    item = package()
    base = add_run(db, asset, [item], [match(item)])
    target = add_run(db, asset, [package(version='2.0')], [])
    original = compare_analyses(db, base.id, target.id)
    link = db.scalar(select(models.ComponentVulnerability))
    link.vex_status = 'NOT_AFFECTED'
    link.fixed_versions = ['untrusted-manual-edit']
    link.finding_severity = 'LOW'
    link.analysis_run_id = None
    db.commit()
    assert compare_analyses(db, base.id, target.id) == original
    db.refresh(link)
    assert link.vex_status == 'NOT_AFFECTED'
    assert link.fixed_versions == ['untrusted-manual-edit']
    assert db.scalar(select(func.count()).select_from(models.AnalysisRun)) == 2
    assert not db.new and not db.dirty and not db.deleted


@pytest.mark.parametrize('problem', ['same_run', 'reverse_order', 'other_asset', 'missing_asset', 'scope', 'blank_scope'])
def test_unrelated_or_out_of_order_runs_are_rejected(db, asset, problem):
    item = package()
    base = add_run(db, asset, [item], [match(item)])
    target = add_run(db, asset, [package(version='2.0')], [])
    target_id = target.id
    if problem == 'same_run':
        target_id = base.id
    elif problem == 'reverse_order':
        base, target = target, base
        target_id = target.id
    elif problem == 'other_asset':
        other = models.Asset(asset_tag='OTHER', name='다른 서버', asset_type='server')
        db.add(other)
        db.flush()
        target.sbom.asset_id = other.id
    elif problem == 'missing_asset':
        base.sbom.asset_id = target.sbom.asset_id = None
    elif problem == 'scope':
        target.scan_scope = '/different/path'
    else:
        base.scan_scope = target.scan_scope = '  '
    db.commit()
    with pytest.raises(HTTPException) as error:
        compare_analyses(db, base.id, target_id)
    assert error.value.status_code == 409


def test_unknown_run_is_not_found(db, asset):
    item = package()
    base = add_run(db, asset, [item], [match(item)])
    with pytest.raises(HTTPException) as error:
        compare_analyses(db, base.id, 999999)
    assert error.value.status_code == 404


@pytest.mark.parametrize('difference', ['manual_import', 'scanner_version', 'database', 'missing_database'])
def test_unverified_or_changed_analysis_basis_warns_and_cannot_claim_comparable_remediation(db, asset, difference):
    item = package()
    base = add_run(db, asset, [item], [match(item)])
    kwargs = {}
    if difference == 'manual_import':
        kwargs['verified'] = False
    elif difference == 'scanner_version':
        kwargs['scanner_version'] = '2.0'
    elif difference == 'database':
        kwargs['database'] = {'built': '2026-09-16T00:00:00Z', 'schemaVersion': 6}
    else:
        kwargs['database'] = {}
    target = add_run(db, asset, [package(version='2.0')], [], **kwargs)
    result = compare_analyses(db, base.id, target.id)
    assert result['comparable'] is False
    assert result['warnings']
    assert result['findings'][0]['status'] == 'NO_LONGER_DETECTED'


@pytest.mark.parametrize('corruption', ['missing_matches', 'null_matches', 'missing_inventory', 'empty_inventory', 'mismatched_artifact', 'non_cve_mismatch', 'purl_version'])
def test_malformed_or_mismatched_original_evidence_is_rejected_instead_of_read_as_zero(db, asset, corruption):
    item = package()
    base = add_run(db, asset, [item], [match(item)])
    target = add_run(db, asset, [package(version='2.0')], [])
    report, document = deepcopy(target.raw_report), deepcopy(target.sbom.raw_document)
    if corruption == 'missing_matches':
        del report['matches']
    elif corruption == 'null_matches':
        report['matches'] = None
    elif corruption == 'missing_inventory':
        del document['packages']
    elif corruption == 'empty_inventory':
        document['packages'] = []
    elif corruption in {'mismatched_artifact', 'non_cve_mismatch'}:
        report['matches'] = [match(item, 'GHSA-test-mismatch' if corruption == 'non_cve_mismatch' else 'CVE-2026-12345')]
    else:
        document['packages'][0]['externalRefs'][0]['referenceLocator'] = 'pkg:pypi/demo-lib@9.0'
    target.raw_report, target.sbom.raw_document = report, document
    db.commit()
    with pytest.raises(HTTPException) as error:
        compare_analyses(db, base.id, target.id)
    assert error.value.status_code == 422


def test_explicit_empty_matches_with_valid_inventory_is_a_legitimate_clean_comparison(db, asset):
    base = add_run(db, asset, [package()], [])
    target = add_run(db, asset, [package(version='2.0')], [])
    result = compare_analyses(db, base.id, target.id)
    assert result['comparable'] is True
    assert result['findings'] == []
    assert all(value == 0 for value in result['summary'].values())


def test_lost_purl_in_clean_target_inventory_does_not_make_removal_trustworthy(db, asset):
    item = package()
    base = add_run(db, asset, [item], [match(item)])
    target = add_run(db, asset, [package(version='2.0')], [])
    document = deepcopy(target.sbom.raw_document)
    document['packages'][0]['externalRefs'] = []
    target.sbom.raw_document = document
    db.commit()
    result = compare_analyses(db, base.id, target.id)
    assert result['comparable'] is False
    assert any('PURL' in warning for warning in result['warnings'])
    assert result['findings'][0]['status'] == 'COMPONENT_REMOVED'
