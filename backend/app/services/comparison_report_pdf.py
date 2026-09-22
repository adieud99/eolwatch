"""Printable Korean analysis evidence. Rendering never fetches URLs or changes state.

Unmodified Nanum Gothic fonts are bundled under SIL OFL 1.1 (resources/fonts/OFL.txt).
Official source: google/fonts, commit 133ccbee9a8b408eb71f31a36ccb9116f5c695ad,
ofl/nanumgothic/{NanumGothic-Regular.ttf,NanumGothic-Bold.ttf}.
SHA256 regular: 76f45ef4a6bcff344c837c95a7dcc26e017e38b5846d5ae0cdcb5b86be2e2d31
SHA256 bold:    f96298f9fb18e364d2370f4c3ce948ac67a2b61af992d7234bc15c42b033c674
"""
from __future__ import annotations

from datetime import datetime
from io import BytesIO
import json
from pathlib import Path
import re
from threading import Lock
import unicodedata
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


_FONT = "EOLWatch-NanumGothic"
_BOLD = "EOLWatch-NanumGothic-Bold"
_FONT_LOCK = Lock()
_NAVY = colors.HexColor("#132D49")
_TEAL = colors.HexColor("#137B83")
_INK = colors.HexColor("#26384B")
_MUTED = colors.HexColor("#617187")
_PALE = colors.HexColor("#F0F4F8")
_LINE = colors.HexColor("#D9E2EA")
_STATUS = {
    "PERSISTENT": "계속 검출", "NEW": "새로 검출",
    "NO_LONGER_DETECTED": "재분석 미검출", "COMPONENT_REMOVED": "구성요소 제거",
}
_SCOPES = {"ubuntu-dpkg-installed": "Ubuntu 설치 패키지"}
_IDENTITY_SOURCES = {"job_snapshot": "분석 요청 시점의 자산 정보", "current_asset_record": "현재 자산 정보 (요청 기록 없음)"}
_BASE_LIMITS = (
    "이 보고서는 저장된 두 분석 원본의 탐지 차이를 보여줍니다. 조치 상태를 자동으로 FIXED로 변경하지 않습니다.",
    "재분석 미검출은 이후 원본에서 같은 구성요소의 CVE가 탐지되지 않았다는 의미입니다. 모든 취약점의 제거 또는 악용 가능성 검증을 뜻하지 않습니다.",
    "구성요소 제거는 이후 SBOM에서 해당 식별자가 없다는 의미입니다. 업데이트 성공이나 취약점 조치 완료로 해석할 수 없습니다.",
    "수정 버전은 분석 도구가 원본에 제공한 정보입니다. 적용 가능한 버전 계열과 서비스 동작은 별도로 확인해야 합니다.",
)


def _fonts() -> None:
    with _FONT_LOCK:
        if _FONT not in pdfmetrics.getRegisteredFontNames():
            root = Path(__file__).resolve().parents[1] / "resources" / "fonts"
            pdfmetrics.registerFont(TTFont(_FONT, str(root / "NanumGothic-Regular.ttf")))
            pdfmetrics.registerFont(TTFont(_BOLD, str(root / "NanumGothic-Bold.ttf")))
            pdfmetrics.registerFontFamily(_FONT, normal=_FONT, bold=_BOLD, italic=_FONT, boldItalic=_BOLD)


def _text(value) -> str:
    if value is None or value == "":
        return "정보 없음"
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return ", ".join(_text(item) for item in value) if value else "없음"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return str(value)


def _safe(value) -> str:
    # Only renderer-owned markup is accepted. Data cannot introduce links, tags,
    # image loads, paragraph directives or external references.
    text = unicodedata.normalize("NFC", _text(value))
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return escape(text).replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br/>")


def _count(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "정보 없음"


def _styles():
    body = ParagraphStyle("ComparisonBody", fontName=_FONT, fontSize=9, leading=14,
                          textColor=_INK, wordWrap="CJK", splitLongWords=True,
                          spaceAfter=5, allowWidows=0, allowOrphans=0)
    return {
        "body": body,
        "small": ParagraphStyle("ComparisonSmall", parent=body, fontSize=7.5, leading=11, textColor=_MUTED, spaceAfter=3),
        "title": ParagraphStyle("ComparisonTitle", parent=body, fontName=_BOLD, fontSize=22, leading=30,
                                textColor=_NAVY, spaceAfter=9),
        "section": ParagraphStyle("ComparisonSection", parent=body, fontName=_BOLD, fontSize=13, leading=19,
                                  textColor=_NAVY, spaceBefore=14, spaceAfter=9, keepWithNext=True),
        "finding": ParagraphStyle("ComparisonFinding", parent=body, fontName=_BOLD, fontSize=10, leading=15,
                                  textColor=_NAVY, spaceBefore=8, keepWithNext=True),
        "label": ParagraphStyle("ComparisonLabel", parent=body, fontName=_BOLD, fontSize=8, leading=12,
                                textColor=_MUTED),
        "metric": ParagraphStyle("ComparisonMetric", parent=body, fontName=_BOLD, fontSize=24, leading=32,
                                 textColor=_NAVY, alignment=TA_CENTER, spaceAfter=0),
        "metric_label": ParagraphStyle("ComparisonMetricLabel", parent=body, fontSize=8, leading=13,
                                       alignment=TA_CENTER, spaceAfter=0),
    }


def _p(value, styles, style="body"):
    return Paragraph(_safe(value), styles[style])


def _label(label, value, styles, style="body"):
    return Paragraph("<b>" + _safe(label) + "</b>  " + _safe(value), styles[style])


def _section(story, number, title, styles):
    story.append(_p(f"{number:02d}  {title}", styles, "section"))


def _flat_metadata(value, prefix=""):
    """Flatten metadata without hiding nested DB identifiers or build values."""
    if isinstance(value, dict) and value:
        for key, nested in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            yield from _flat_metadata(nested, name)
    elif isinstance(value, list) and value:
        for index, nested in enumerate(value):
            yield from _flat_metadata(nested, f"{prefix}[{index}]")
    else:
        yield prefix or "DB 정보", value


def _identity_table(base, target, styles, width):
    rows = [[_p("항목", styles, "label"), _p("이전 분석", styles, "label"), _p("이후 분석", styles, "label")]]
    fields = [
        ("분석 / SBOM", lambda item: f"분석 #{_text(item.get('id'))} / SBOM #{_text(item.get('sbom_id'))}"),
        ("자산", lambda item: f"{_text(item.get('asset_tag'))} · {_text(item.get('asset_name'))}"),
        ("자산 정보 기준", lambda item: _IDENTITY_SOURCES.get(item.get("asset_identity_source"), item.get("asset_identity_source"))),
        ("분석 범위", lambda item: _SCOPES.get(item.get("scan_scope"), item.get("scan_scope"))),
        ("결과 저장 시각", lambda item: item.get("imported_at")),
        ("취약점 분석 도구", lambda item: f"{_text(item.get('scanner'))} {_text(item.get('scanner_version'))}"),
        ("SBOM 생성 도구", lambda item: item.get("generator")),
        ("구성요소 / CVE", lambda item: f"{_count(item.get('component_count'))}개 / {_count(item.get('cve_count'))}개"),
        ("구성요소·CVE 연결", lambda item: _count(item.get("link_count")) + "건"),
    ]
    for label, getter in fields:
        rows.append([_p(label, styles, "label"), _p(getter(base), styles), _p(getter(target), styles)])
    table = Table(rows, colWidths=[88, (width - 88) / 2, (width - 88) / 2], repeatRows=1,
                  splitByRow=True, splitInRow=True, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _PALE), ("BACKGROUND", (0, 1), (0, -1), _PALE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, 0), 0.6, _LINE),
        ("LINEBELOW", (0, 1), (-1, -1), 0.3, _LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return table


def render_comparison_pdf(report: dict) -> bytes:
    """Render all provided findings as A4 PDF with embedded Korean fonts.

    Timestamps retain the source's ISO 8601 offset. Missing metadata is labelled;
    comparisons and vulnerability conclusions are supplied by the caller.
    """
    _fonts()
    styles = _styles()
    buffer = BytesIO()
    title = _text(report.get("title") or "EOLWatch 분석 전후 검증 보고서")
    document = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=40, rightMargin=40,
                                 topMargin=46, bottomMargin=46, title=title,
                                 author="EOLWatch", subject="저장된 분석 원본의 읽기 전용 비교 증거", pageCompression=1)
    base, target = report.get("base") or {}, report.get("target") or {}
    findings = report.get("findings") or []
    summary = report.get("summary") or {}
    story = [_p("EOLWATCH  /  ANALYSIS EVIDENCE", styles, "label"), _p(title, styles, "title"),
             _label("보고서 생성 시각", report.get("generated_at"), styles, "small")]
    condition = "비교 조건 확인됨" if report.get("comparable") else "비교 조건에 주의가 필요합니다"
    story.extend([_p(condition, styles, "finding"), _p(
        "저장된 분석 원본을 기준으로 구성요소와 CVE의 탐지 변화를 비교합니다. 시각은 원본의 ISO 8601 시간대 표기를 유지합니다.", styles, "small")])
    metrics = []
    for key in ("persistent", "new", "no_longer_detected", "component_removed"):
        metrics.append([_p(_count(summary.get(key, 0)), styles, "metric"), _p(_STATUS[key.upper()], styles, "metric_label")])
    metric_table = Table([metrics], colWidths=[document.width / 4] * 4, hAlign="LEFT")
    metric_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _PALE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LINEAFTER", (0, 0), (-2, -1), 1, colors.white),
    ]))
    story.extend([Spacer(1, 7), metric_table, Spacer(1, 6), _p(
        f"집계 단위: CVE × 구성요소 식별자 · 비교 상세 {len(findings):,}건 전체 수록", styles, "small")])
    _section(story, 1, "비교 대상과 분석 기준", styles)
    story.append(_identity_table(base, target, styles, document.width))
    warnings = report.get("warnings") or []
    _section(story, 2, "비교 시 확인할 사항", styles)
    if warnings:
        for index, warning in enumerate(warnings, 1):
            story.append(_label(f"주의 {index}.", warning, styles))
    else:
        story.append(_p("비교 서비스에서 보고한 조건 차이 경고가 없습니다. 이는 취약점 조치 완료의 자동 판정을 의미하지 않습니다.", styles))

    story.append(PageBreak())
    _section(story, 3, "전체 탐지 변화", styles)
    story.append(_p("이전·이후 버전은 각 SBOM의 설치 목록입니다. 구성요소 식별자는 PURL에서 버전을 제외해 비교한 값입니다.", styles, "small"))
    if not findings:
        story.append(_p("두 분석 원본에서 비교할 CVE·구성요소 연결이 없습니다. 이 결과만으로 전체 시스템의 무취약성을 판단할 수 없습니다.", styles))
    for index, finding in enumerate(findings, 1):
        status = _STATUS.get(finding.get("status"), _text(finding.get("status")))
        story.append(_p(f"{index:04d}  {_text(finding.get('cve_id'))}  ·  {status}", styles, "finding"))
        story.append(_label("구성요소", finding.get("component_name"), styles))
        story.append(_label("심각도 / 비교 상태", f"{_text(finding.get('severity'))} / {_text(finding.get('status'))}", styles, "small"))
        story.append(_label("이전 설치 버전", finding.get("before_versions") or [], styles))
        story.append(_label("이후 설치 버전", finding.get("after_versions") or [], styles))
        story.append(_label("분석 도구 제공 수정 버전", finding.get("fixed_versions") or [], styles))
        story.append(_label("구성요소 식별자 (PURL)", finding.get("component_identity"), styles, "small"))
        story.append(HRFlowable(width="100%", thickness=0.4, color=_LINE, spaceBefore=3, spaceAfter=4))
    story.append(_p(f"전체 {len(findings):,}건 수록 완료", styles, "small"))

    story.append(PageBreak())
    _section(story, 4, "원본과 실행 이력", styles)
    story.append(_p("해시는 다운로드 파일의 바이트가 아닌, 아래 규칙으로 정규화한 JSON 값의 SHA-256입니다. 원본 조회에는 서비스 접근 권한이 필요합니다.", styles, "small"))
    story.append(_label("JSON 직렬화 규칙", 'UTF-8 · 키 정렬(sort_keys=true) · 한글 유지(ensure_ascii=false) · 구분자: 쉼표/콜론, 추가 공백 없음', styles, "small"))
    story.append(_label("해시 대상", 'SBOM: sbom 값 / 분석 묶음: {asset_id, sbom, report}만 포함(scan_scope 제외) / 비교 결과: findings 값', styles, "small"))
    story.append(_label("비교 결과 SHA-256", report.get("findings_sha256"), styles, "small"))
    raw_evidence = report.get("raw_evidence") or {}
    for role, metadata in (("base", base), ("target", target)):
        name = "이전 분석" if role == "base" else "이후 분석"
        story.append(_p(f"{name} #{_text(metadata.get('id'))}", styles, "finding"))
        story.append(_label("자산 / 식별자", f"{_text(metadata.get('asset_tag'))} · {_text(metadata.get('asset_name'))} / 자산 #{_text(metadata.get('asset_id'))}", styles))
        story.append(_label("분석 범위 코드", metadata.get("scan_scope"), styles, "small"))
        story.append(_label("SBOM SHA-256", metadata.get("sbom_sha256"), styles, "small"))
        story.append(_label("분석 묶음 SHA-256", metadata.get("bundle_sha256"), styles, "small"))
        story.append(_label("원본 묶음 경로", raw_evidence.get(role + "_bundle_path"), styles, "small"))
        story.append(_p("취약점 데이터베이스 식별 정보", styles, "label"))
        if metadata.get("database_info"):
            for key, value in _flat_metadata(metadata["database_info"]):
                story.append(_label(key, value, styles, "small"))
        else:
            story.append(_p("정보 없음", styles, "small"))
        jobs = metadata.get("jobs") or []
        if not jobs:
            story.append(_p("연결된 웹 분석 작업이 없습니다. 수동 반입 원본의 실제 수집 완료 여부는 이 보고서만으로 확인할 수 없습니다.", styles, "small"))
        for job in jobs:
            story.append(_label(f"웹 분석 작업 #{_text(job.get('id'))}", job.get("status"), styles))
            story.append(_label("작업 대상", f"{_text(job.get('asset_tag'))} · {_text(job.get('asset_name'))}", styles, "small"))
            for label, field in (("요청", "requested_at"), ("시작", "started_at"), ("완료", "finished_at")):
                story.append(_label(label + " 시각", job.get(field), styles, "small"))
        story.append(Spacer(1, 7))

    _section(story, 5, "해석 범위와 한계", styles)
    supplied_limits = report.get("limitations")
    limits = [_text(item) for item in supplied_limits] if supplied_limits is not None else _BASE_LIMITS
    for index, limit in enumerate(limits, 1):
        story.append(_label(f"{index}.", limit, styles))

    def decorate(canvas, _document):
        canvas.saveState()
        canvas.setStrokeColor(_TEAL)
        canvas.setLineWidth(2)
        canvas.line(40, A4[1] - 26, A4[0] - 40, A4[1] - 26)
        canvas.setFont(_FONT, 7)
        canvas.setFillColor(_MUTED)
        canvas.drawString(40, 27, "EOLWatch · 저장된 분석 원본의 비교 보고서 · v" + _count(report.get("report_version", 1)))
        canvas.drawRightString(A4[0] - 40, 27, f"{canvas.getPageNumber()} 페이지")
        canvas.restoreState()

    document.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return buffer.getvalue()
