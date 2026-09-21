"""Calendar dates follow the configured business timezone, not the server clock zone."""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo

from ..config import get_settings


def business_today(now: Optional[datetime] = None) -> date:
    instant = datetime.now(timezone.utc) if now is None else now
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("Business date requires a timezone-aware timestamp")
    return instant.astimezone(ZoneInfo(get_settings().scheduler_timezone)).date()
