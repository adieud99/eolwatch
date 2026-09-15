from __future__ import annotations

from io import BytesIO

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..services.reports import daily_check_report, lifecycle_report


router = APIRouter(prefix="/reports", tags=["reports"])


def _pdf(content: bytes, filename: str) -> StreamingResponse:
    return StreamingResponse(
        BytesIO(content),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/lifecycle.pdf")
def download_lifecycle_report(db: Session = Depends(get_db)):
    return _pdf(lifecycle_report(db), "eolwatch-lifecycle-report.pdf")


@router.get("/daily-checks.pdf")
def download_daily_check_report(db: Session = Depends(get_db)):
    return _pdf(daily_check_report(db), "eolwatch-daily-checks.pdf")
