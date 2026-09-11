from __future__ import annotations

from datetime import date
from typing import Optional


RISK_ORDER = {"EXPIRED": 0, "CRITICAL": 1, "WARN": 2, "SAFE": 3, "UNKNOWN": 4}


def lifecycle_risk(end_date: Optional[date], today: Optional[date] = None) -> tuple[str, Optional[int]]:
    if end_date is None:
        return "UNKNOWN", None
    remaining = (end_date - (today or date.today())).days
    if remaining < 0:
        return "EXPIRED", remaining
    if remaining <= 180:
        return "CRITICAL", remaining
    if remaining <= 365:
        return "WARN", remaining
    return "SAFE", remaining
