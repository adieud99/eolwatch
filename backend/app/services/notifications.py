from __future__ import annotations

import httpx
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from .lifecycle_overview import build_lifecycle_overview


def _card(title: str, lines: list[str]) -> dict:
    body = [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": title}]
    body.extend({"type": "TextBlock", "wrap": True, "text": line} for line in lines)
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                },
            }
        ],
    }


def send_teams(db: Session, event_type: str, title: str, lines: list[str]) -> models.NotificationDelivery:
    settings = get_settings()
    delivery = models.NotificationDelivery(
        channel="TEAMS",
        event_type=event_type,
        status="PENDING",
        recipient_label=settings.teams_recipient_label,
        payload_summary={"title": title, "lines": lines[:20]},
    )
    db.add(delivery)
    db.flush()
    if not settings.teams_webhook_url:
        delivery.status = "SKIPPED"
        delivery.error_message = "TEAMS_WEBHOOK_URL이 설정되지 않았습니다"
        db.commit()
        db.refresh(delivery)
        return delivery
    try:
        with httpx.Client(timeout=15) as client:
            response = client.post(settings.teams_webhook_url, json=_card(title, lines))
            delivery.response_code = response.status_code
            response.raise_for_status()
        delivery.status = "SUCCESS"
    except httpx.HTTPError as exc:
        delivery.status = "FAILED"
        delivery.error_message = str(exc)[:2000]
    db.commit()
    db.refresh(delivery)
    return delivery


def send_risk_summary(db: Session) -> models.NotificationDelivery:
    overview = build_lifecycle_overview(db)
    counts = overview['risk_counts']
    lines = [
        f"지원종료: {counts['EXPIRED']}건",
        f"긴급: {counts['CRITICAL']}건",
        f"주의: {counts['WARN']}건",
        f"안전: {counts['SAFE']}건",
        f"미확인: {counts['UNKNOWN']}건",
        '집계: ' + overview['aggregation_basis']['lifecycle'],
        '기준일: ' + overview['aggregation_basis']['as_of_date'] + ' · ' + overview['aggregation_basis']['timezone'],
    ]
    return send_teams(db, "RISK_SUMMARY", "EOLWatch 위험 건수 요약", lines)
