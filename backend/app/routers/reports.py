from __future__ import annotations

from io import BytesIO

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..services.reports import asset_report, daily_check_report, lifecycle_report
from ..services.comparison_reports import build_comparison_report


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


@router.get("/assets/{asset_id}.pdf")
def download_asset_report(asset_id: int, db: Session = Depends(get_db)):
    content = asset_report(db, asset_id)
    if content is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    return _pdf(content, f"eolwatch-asset-{asset_id}.pdf")


@router.get('/analyses/{base_id}/compare/{target_id}.json')
def download_comparison_json(base_id: int, target_id: int, db: Session = Depends(get_db)):
    report = build_comparison_report(db, base_id, target_id)
    return JSONResponse(report, headers={
        'Content-Disposition': f'attachment; filename="eolwatch-analysis-{base_id}-{target_id}.json"',
        'Cache-Control': 'no-store',
    })


@router.get('/analyses/{base_id}/compare/{target_id}.pdf')
def download_comparison_pdf(base_id: int, target_id: int, db: Session = Depends(get_db)):
    from ..services.comparison_report_pdf import render_comparison_pdf
    report = build_comparison_report(db, base_id, target_id)
    response = _pdf(render_comparison_pdf(report), f'eolwatch-analysis-{base_id}-{target_id}.pdf')
    response.headers['Cache-Control'] = 'no-store'
    return response
