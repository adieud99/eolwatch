"""Current lifecycle risk stays consistent across dashboard, PDF and Teams content."""
from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session

from app import models
from app.db import Base
from app.routers.dashboard import summary
from app.services import lifecycle_overview as overview, notifications, reports


TODAY = date(2026, 9, 16)
NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)


@pytest.fixture
def db(monkeypatch):
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    monkeypatch.setattr(overview, 'business_today', lambda: TODAY)
    with Session(engine) as session:
        session.add_all([models.Asset(id=i, asset_tag=f'CURRENT-{i}', name=f'Asset {i}', asset_type='server') for i in (1, 2)])
        session.commit()
        yield session
    engine.dispose()


def document(db, identity, asset_id=1, scope='app', minutes=0, scanned=True):
    sbom = models.SbomDocument(id=identity, serial_number=f'overview-{identity}', spec_version='2.3',
        asset_id=asset_id, imported_at=NOW + timedelta(minutes=minutes), component_count=1,
        raw_document={'private-source': 'never needed by overview'})
    db.add(sbom); db.flush()
    if scanned:
        db.add(models.AnalysisRun(id=identity, sbom_id=identity, report_sha256=f'{identity:064x}',
            sbom_sha256='a' * 64, scanner='grype', scanner_version='test', generator='syft', scan_scope=scope,
            match_count=0, cve_count=0, link_count=0, ignored_non_cve=0,
            raw_report={'private-report': 'never needed by overview'}, imported_at=sbom.imported_at))
        db.flush()
    return sbom


def component(db, sbom, name, product=None, end_date=None):
    item = models.Component(sbom_id=sbom.id, bom_ref=name, name=name, version='1.0',
                            product_release=product, support_end_date=end_date)
    db.add(item); db.flush()
    return item


def finding(db, item, vulnerability=None):
    if vulnerability is None:
        vulnerability = models.Vulnerability(osv_id='CVE-2099-' + str(item.id))
        db.add(vulnerability); db.flush()
    db.add(models.ComponentVulnerability(component_id=item.id, vulnerability_id=vulnerability.id, vex_status='AFFECTED'))
    db.flush()
    return vulnerability


def test_current_components_override_and_inherit_dates_without_catalog_or_history_inflation(db):
    product = models.ProductRelease(name='Shared package', version='1.0', product_type='LIBRARY',
        eol_date=TODAY - timedelta(days=300), support_end_date=TODAY - timedelta(days=200),
        security_end_date=TODAY - timedelta(days=10), lifecycle_source_url='https://example.test/lifecycle')
    db.add(product); db.flush()
    old = component(db, document(db, 1), 'obsolete component', product, TODAY - timedelta(days=500))
    current = component(db, document(db, 2, minutes=1), 'current override', product, TODAY + timedelta(days=800))
    inherited = component(db, document(db, 3, asset_id=2), 'current inherited', product)
    db.commit()
    result = overview.build_lifecycle_overview(db)
    assert result['current_inventory']['components'] == 2
    assert result['current_inventory']['sbom_documents'] == 2
    assert result['current_inventory']['assets'] == 2
    assert result['current_inventory']['lifecycle_items'] == 4  # two assets and two package occurrences
    assert result['risk_counts'] == {'EXPIRED': 1, 'CRITICAL': 0, 'WARN': 0, 'SAFE': 1, 'UNKNOWN': 2}
    package_rows = {item['component_id']: item for item in result['items'] if item['kind'] == '구성요소'}
    assert set(package_rows) == {current.id, inherited.id}
    assert package_rows[current.id]['date_source'] == 'component'
    assert package_rows[inherited.id]['date_source'] == 'product'
    assert package_rows[inherited.id]['days_left'] == -10
    assert package_rows[inherited.id]['source_url'] == product.lifecycle_source_url
    assert db.get(models.Component, old.id).support_end_date == TODAY - timedelta(days=500)
    assert db.scalar(select(func.count()).select_from(models.Component)) == 3
    current.support_end_date = None; db.commit()
    assert overview.build_lifecycle_overview(db)['risk_counts']['EXPIRED'] == 2


def test_current_selection_keeps_scopes_manual_slot_and_unassigned_documents(db):
    document(db, 1, scope='app', minutes=1)
    document(db, 2, scope='app', minutes=2)
    document(db, 3, scope='os', minutes=0)
    document(db, 4, scanned=False, minutes=0)
    document(db, 5, scanned=False, minutes=1)
    document(db, 6, asset_id=None, scanned=False)
    document(db, 7, asset_id=None, scanned=False)
    document(db, 8, asset_id=None)
    document(db, 9, asset_id=None)
    document(db, 10, scope='app', minutes=2)  # equal timestamp uses the larger run ID
    db.add(models.AnalysisJob(asset_id=1, asset_snapshot={'scan_scope': 'app'}, status='FAILED', requested_at=NOW + timedelta(days=1)))
    db.commit()
    assert set(db.scalars(overview.current_sbom_ids())) == {3, 5, 6, 7, 8, 9, 10}


def test_legacy_cve_counts_remain_historical_while_current_counts_deduplicate_assets_and_cves(db):
    old = component(db, document(db, 1), 'old-only-vulnerable')
    finding(db, old)
    new = component(db, document(db, 2, minutes=1), 'current-vulnerable')
    cve = finding(db, new)
    other_scope = component(db, document(db, 3, scope='os'), 'same-cve-other-scope')
    finding(db, other_scope, cve)
    other_asset = component(db, document(db, 4, asset_id=2), 'same-cve-other-asset')
    finding(db, other_asset, cve)
    db.commit()
    result = summary(db)
    assert result.open_cves == 2 and result.components == 4 and result.sbom_documents == 4
    assert result.current_inventory['open_cves'] == 1
    assert result.current_inventory['affected_assets'] == 2
    assert result.current_inventory['components'] == 3
    assert result.current_inventory['sbom_documents'] == 3
    assert result.aggregation_basis['as_of_date'] == TODAY.isoformat()


def test_zero_findings_latest_snapshot_removes_historical_risk_from_current_only(db):
    historical = component(db, document(db, 1), 'historical-vulnerable', end_date=TODAY - timedelta(days=1))
    finding(db, historical)
    component(db, document(db, 2, minutes=1), 'current-safe', end_date=TODAY + timedelta(days=700))
    db.commit()
    result = summary(db)
    assert result.open_cves == 1 and result.affected_assets == 1
    assert result.current_inventory['open_cves'] == 0 and result.current_inventory['affected_assets'] == 0
    assert result.lifecycle_risk['EXPIRED'] == 0
    assert not any(item['name'] == 'historical-vulnerable' for item in result.urgent_items)


def test_unrepresented_catalog_product_remains_in_lifecycle_inventory(db):
    db.add(models.ProductRelease(name='Catalog only', version='1', product_type='LIBRARY', support_end_date=TODAY + timedelta(days=30)))
    db.commit()
    result = overview.build_lifecycle_overview(db)
    assert result['risk_counts']['CRITICAL'] == 1
    assert result['current_inventory']['components'] == 0
    assert any(item['name'] == 'Catalog only' and item['kind'] == '소프트웨어' for item in result['items'])


@pytest.mark.parametrize('explicit_deployment', [False, True])
def test_historical_only_product_does_not_return_as_current_catalog_risk(db, explicit_deployment):
    obsolete = models.ProductRelease(name='Service package', version='1', product_type='LIBRARY',
                                     support_end_date=TODAY - timedelta(days=20))
    current = models.ProductRelease(name='Service package', version='2', product_type='LIBRARY',
                                    support_end_date=TODAY + timedelta(days=700))
    db.add_all([obsolete, current]); db.flush()
    old = component(db, document(db, 1), 'old-version', obsolete)
    component(db, document(db, 2, minutes=1), 'new-version', current)
    if explicit_deployment:
        db.add(models.Deployment(asset_id=1, software_product_id=obsolete.id))
    db.commit()
    result = overview.build_lifecycle_overview(db)
    assert result['risk_counts']['EXPIRED'] == int(explicit_deployment)
    assert result['risk_counts']['SAFE'] == 1
    assert sum(item['kind'] == '소프트웨어' and item['product_release_id'] == obsolete.id for item in result['items']) == int(explicit_deployment)
    assert db.get(models.Component, old.id).product_release_id == obsolete.id
    assert db.get(models.SbomDocument, 1).raw_document == {'private-source': 'never needed by overview'}


def test_dashboard_pdf_and_teams_content_share_effective_current_risks_without_sending(db, monkeypatch):
    old = component(db, document(db, 1), 'obsolete-for-report', end_date=TODAY - timedelta(days=50))
    product = models.ProductRelease(name='Report package', version='1', product_type='LIBRARY',
                                    support_end_date=TODAY - timedelta(days=50))
    db.add(product); db.flush()
    current = component(db, document(db, 2, minutes=1), 'current-for-report', product, TODAY + timedelta(days=90))
    db.commit()
    result = summary(db)
    rendered = []
    actual_line = reports._line

    def capture_line(pdf, y, text, size=9):
        rendered.append(text)
        return actual_line(pdf, y, text, size)

    monkeypatch.setattr(reports, '_line', capture_line)
    assert reports.lifecycle_report(db).startswith(b'%PDF')
    assert any('current-for-report' in text for text in rendered)
    current_line = next(text for text in rendered if 'current-for-report' in text)
    assert '[CRITICAL]' in current_line and (TODAY + timedelta(days=90)).isoformat() in current_line
    assert not any('obsolete-for-report' in text for text in rendered)
    sent_content = []
    monkeypatch.setattr(notifications, 'send_teams', lambda db, event, title, lines: sent_content.append(lines))
    notifications.send_risk_summary(db)
    assert sent_content and f"긴급: {result.lifecycle_risk['CRITICAL']}건" in sent_content[0]
    assert '지원종료: 0건' in sent_content[0]
    assert db.scalar(select(func.count()).select_from(models.NotificationDelivery)) == 0
    assert db.get(models.Component, old.id) and db.get(models.Component, current.id)


def test_current_overview_does_not_read_raw_sbom_or_scanner_report(db):
    component(db, document(db, 1), 'current')
    db.commit(); db.expire_all()
    statements = []

    def track(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(db.bind, 'before_cursor_execute', track)
    try:
        assert overview.build_lifecycle_overview(db)['current_inventory']['components'] == 1
    finally:
        event.remove(db.bind, 'before_cursor_execute', track)
    assert statements and all('raw_report' not in sql and 'raw_document' not in sql for sql in statements)


def test_pdf_wrapped_row_breaks_page_before_clipping_and_restores_font():
    class Document:
        page = 1
        font = None

        def __init__(self):
            self.lines = []

        def showPage(self):
            self.page += 1
            self.font = None

        def setFont(self, font, size):
            self.font = (font, size)

        def drawString(self, x, y, text):
            self.lines.append((self.page, y, text, self.font))

    document = Document()
    reports._line(document, 60, 'long package name ' * 40, size=12)
    assert len(document.lines) > 3
    assert document.lines[0][0] == 1 and document.lines[1][0] == 2
    assert all(y >= 52 and font == (reports.FONT_NAME, 12) for _, y, _, font in document.lines)
