from datetime import date, datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app import models
from app.db import Base
from app.routers.vulnerability_work import list_work
from app.services import business_date, risk


@pytest.mark.parametrize(("zone", "instant", "expected"), [
    ("Asia/Seoul", "2026-09-15T23:30:00+00:00", date(2026, 9, 16)),
    ("UTC", "2026-09-15T23:30:00+00:00", date(2026, 9, 15)),
    ("Asia/Seoul", "2026-09-15T14:59:59+00:00", date(2026, 9, 15)),
    ("Asia/Seoul", "2026-09-15T15:00:00+00:00", date(2026, 9, 16)),
    ("America/Los_Angeles", "2026-09-16T00:30:00+00:00", date(2026, 9, 15)),
])
def test_business_date_uses_configured_timezone_at_calendar_boundaries(monkeypatch, zone, instant, expected):
    monkeypatch.setattr(business_date, "get_settings", lambda: SimpleNamespace(scheduler_timezone=zone))
    assert business_date.business_today(datetime.fromisoformat(instant)) == expected


def freeze(monkeypatch, instant):
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            assert tz is timezone.utc
            return instant
    monkeypatch.setattr(business_date, "datetime", FrozenDatetime)


def test_lifecycle_default_uses_business_date_and_explicit_today_has_priority(monkeypatch):
    freeze(monkeypatch, datetime(2026, 9, 15, 23, 30, tzinfo=timezone.utc))
    monkeypatch.setattr(business_date, "get_settings", lambda: SimpleNamespace(scheduler_timezone="Asia/Seoul"))
    assert risk.lifecycle_risk(date(2026, 9, 15)) == ("EXPIRED", -1)
    assert risk.lifecycle_risk(date(2026, 9, 16)) == ("CRITICAL", 0)
    def must_not_read_clock():
        raise AssertionError("An explicit date must not consult the business clock")
    monkeypatch.setattr(risk, "business_today", must_not_read_clock)
    assert risk.lifecycle_risk(date(2026, 9, 15), today=date(2026, 9, 15)) == ("CRITICAL", 0)
    assert risk.lifecycle_risk(None) == ("UNKNOWN", None)


def test_naive_timestamp_does_not_silently_use_the_host_timezone():
    with pytest.raises(ValueError, match="timezone-aware"):
        business_date.business_today(datetime(2026, 9, 15, 23, 30))


def test_work_as_of_overdue_query_and_lifecycle_use_one_business_date(monkeypatch):
    freeze(monkeypatch, datetime(2026, 9, 15, 23, 30, tzinfo=timezone.utc))
    settings = SimpleNamespace(scheduler_timezone="Asia/Seoul")
    monkeypatch.setattr(business_date, "get_settings", lambda: settings)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            product = models.ProductRelease(name="timezone-boundary", version="1", security_end_date=date(2026, 9, 15))
            document = models.SbomDocument(serial_number="timezone-boundary", spec_version="2.3", raw_document={})
            component = models.Component(sbom=document, product_release=product, bom_ref="pkg", name="timezone-boundary", version="1")
            vulnerability = models.Vulnerability(osv_id="CVE-2026-12345", severity="HIGH", aliases=[], references=[])
            finding = models.ComponentVulnerability(component=component, vulnerability=vulnerability, vex_status="AFFECTED", due_date=date(2026, 9, 15))
            db.add(finding); db.commit()
            def page(overdue):
                return list_work(q="", asset_id=None, sbom_id=None, status="ALL", severity=None, assignee_id=None,
                                 unassigned=False, overdue=overdue, limit=25, offset=0, db=db)
            korean = page(True)
            assert korean.as_of == date(2026, 9, 16)
            assert korean.total == 1 and korean.items[0].overdue is True
            assert korean.items[0].lifecycle_risk == "EXPIRED"
            assert korean.items[0].lifecycle_days_left == -1
            settings.scheduler_timezone = "UTC"
            assert page(True).total == 0
            utc = page(False)
            assert utc.as_of == date(2026, 9, 15)
            assert utc.total == 1 and utc.items[0].overdue is False
            assert utc.items[0].lifecycle_risk == "CRITICAL"
            assert utc.items[0].lifecycle_days_left == 0
    finally:
        engine.dispose()
