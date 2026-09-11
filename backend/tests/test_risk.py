from datetime import date, timedelta

from app.services.risk import lifecycle_risk


def test_lifecycle_risk_boundaries():
    today = date(2026, 9, 11)
    assert lifecycle_risk(today - timedelta(days=1), today) == ("EXPIRED", -1)
    assert lifecycle_risk(today, today) == ("CRITICAL", 0)
    assert lifecycle_risk(today + timedelta(days=180), today) == ("CRITICAL", 180)
    assert lifecycle_risk(today + timedelta(days=181), today) == ("WARN", 181)
    assert lifecycle_risk(today + timedelta(days=365), today) == ("WARN", 365)
    assert lifecycle_risk(today + timedelta(days=366), today) == ("SAFE", 366)
    assert lifecycle_risk(None, today) == ("UNKNOWN", None)
