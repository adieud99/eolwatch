"""AI advisor: turns a scan result or an SSH check into a short Korean assessment with Claude.

The model only ever sees data EOLWatch already stores (CVE ids, components, versions,
server facts). It never receives credentials, tokens or source code. Its output is
advice for a human reviewer; it does not change any scan result or remediation state.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
MAX_FINDINGS = 60

SYSTEM_PROMPT = (
    "당신은 EOLWatch의 보안 검토 보조자다. 개발 소스와 운영 서버의 취약점 검사 결과를 받아 "
    "운영 담당자가 바로 행동할 수 있게 한국어로 정리한다.\n"
    "규칙:\n"
    "- 주어진 데이터에 있는 사실만 쓴다. 데이터에 없는 CVE, 버전, 서버 정보를 지어내지 않는다.\n"
    "- 조치 완료 여부를 단정하지 않는다. 판단은 담당자가 한다.\n"
    "- 형식은 마크다운 없이 짧은 문단과 '- '로 시작하는 목록만 쓴다. 표, 제목 기호(#), 굵게(**)는 쓰지 않는다.\n"
    "- 전체 길이는 한국어 600자 안쪽으로 맞춘다."
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def analysis_context(db: Session, run: models.AnalysisRun) -> dict[str, Any]:
    """Compact, deterministic view of one scan result for the model."""
    rows = db.execute(
        select(models.ComponentVulnerability, models.Component, models.Vulnerability)
        .join(models.Component, models.ComponentVulnerability.component_id == models.Component.id)
        .join(models.Vulnerability, models.ComponentVulnerability.vulnerability_id == models.Vulnerability.id)
        .where(models.Component.sbom_id == run.sbom_id)
    ).all()
    findings = []
    for link, component, vulnerability in rows:
        findings.append({
            "cve": vulnerability.osv_id, "component": component.name, "version": component.version, "summary": (vulnerability.summary or "")[:160],
            "severity": (link.finding_severity or vulnerability.severity or "UNKNOWN").upper(),
            "fixed_versions": list(link.fixed_versions or []) or ([link.fixed_version] if link.fixed_version else []),
            "status": link.vex_status,
        })
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["component"], item["cve"]))
    counts: dict[str, int] = {}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    asset = run.sbom.asset
    return {
        "kind": "analysis", "run_id": run.id, "scan_scope": run.scan_scope,
        "target": {"tag": asset.asset_tag if asset else None, "name": asset.name if asset else None},
        "scanner": f"{run.scanner} {run.scanner_version}", "imported_at": run.imported_at.isoformat() if run.imported_at else None,
        "component_count": run.sbom.component_count, "cve_count": run.cve_count,
        "severity_counts": counts, "findings": findings[:MAX_FINDINGS], "omitted_findings": max(0, len(findings) - MAX_FINDINGS),
    }


def check_context(job: models.CollectionJob) -> dict[str, Any]:
    result = job.result
    info = (result.raw_metrics or {}).get("server_info") if result else None
    return {
        "kind": "check", "job_id": job.id, "status": job.status,
        "target": {"tag": job.asset.asset_tag, "name": job.asset.name, "ip": job.asset.ip_address},
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "usage": {"cpu_percent": result.cpu_percent, "memory_percent": result.memory_percent, "max_disk_percent": result.max_disk_percent,
                  "uptime_seconds": result.uptime_seconds, "health_level": result.health_level} if result else None,
        "disks": result.disk_details if result else [], "top_processes": (result.process_details or [])[:10] if result else [],
        "package_count": (result.raw_metrics or {}).get("package_count") if result else None,
        "os": (result.raw_metrics or {}).get("package_context") if result else None,
        "server_info": info,
        "failure": {"stage": job.failure_stage, "code": job.failure_code, "message": job.failure_message} if job.status != "SUCCESS" else None,
    }


def build_prompt(context: dict[str, Any]) -> str:
    if context["kind"] == "analysis":
        ask = ("아래는 소스 또는 서버 검사 한 건의 결과다. 1) 전체 위험 수준을 한두 문장으로, 2) 먼저 손봐야 할 구성요소 3~5개와 "
               "그 이유·권장 버전을 목록으로, 3) 담당자가 확인할 점을 목록으로 정리하라. findings에 없는 항목은 언급하지 마라.")
    else:
        ask = ("아래는 서버 한 대의 SSH 점검 결과다. 1) 이 서버가 어떤 환경인지(OS, 하드웨어, 가상화·클라우드, 공개 포트) 한두 문장으로, "
               "2) 자원 사용률과 열린 포트·실행 서비스에서 눈여겨볼 점을 목록으로, 3) 다음에 할 일을 목록으로 정리하라. "
               "점검이 실패했다면 원인과 확인할 설정을 정리하라.")
    return ask + "\n\n데이터(JSON):\n" + json.dumps(context, ensure_ascii=False, sort_keys=True, default=str)


def _create_client():
    settings = get_settings()
    try:
        import anthropic  # imported lazily: only the API process needs the SDK
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise HTTPException(status_code=503, detail="AI 요약 기능에 필요한 anthropic 패키지가 설치되지 않았습니다.") from error
    if settings.anthropic_api_key:
        return anthropic.Anthropic(api_key=settings.anthropic_api_key, timeout=120.0)
    return anthropic.Anthropic(timeout=120.0)


def ai_available() -> bool:
    settings = get_settings()
    if settings.anthropic_api_key:
        return True
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    import os
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))


def complete(prompt: str) -> tuple[str, str]:
    """Return (text, model). Raises HTTPException with a user-facing message on failure."""
    settings = get_settings()
    if not ai_available():
        raise HTTPException(status_code=503, detail="AI 요약이 설정되지 않았습니다. ANTHROPIC_API_KEY를 설정하세요.")
    client = _create_client()
    try:
        import anthropic
        response = client.messages.create(
            model=settings.ai_model, max_tokens=4000, system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as error:  # SDK errors are translated for the UI; details go to the log.
        logger.warning("AI summary request failed: %s", error)
        status = getattr(error, "status_code", None)
        if status == 401:
            raise HTTPException(status_code=503, detail="AI 서비스 인증에 실패했습니다. API 키를 확인하세요.") from error
        if status == 429:
            raise HTTPException(status_code=429, detail="AI 서비스 요청 한도를 초과했습니다. 잠시 후 다시 시도하세요.") from error
        raise HTTPException(status_code=502, detail="AI 서비스에 연결하지 못했습니다. 잠시 후 다시 시도하세요.") from error
    if getattr(response, "stop_reason", None) == "refusal":
        raise HTTPException(status_code=502, detail="AI가 이 요청에 답하지 않았습니다.")
    text = "".join(block.text for block in response.content if getattr(block, "type", None) == "text").strip()
    if not text:
        raise HTTPException(status_code=502, detail="AI 응답이 비어 있습니다.")
    return text, getattr(response, "model", settings.ai_model)


def latest_summary(db: Session, kind: str, target_id: int) -> Optional[models.AiSummary]:
    return db.scalar(select(models.AiSummary).where(models.AiSummary.kind == kind, models.AiSummary.target_id == target_id)
                     .order_by(models.AiSummary.generated_at.desc(), models.AiSummary.id.desc()).limit(1))


def generate_summary(db: Session, kind: str, target_id: int, context: dict[str, Any], username: Optional[str]) -> models.AiSummary:
    prompt = build_prompt(context)
    text, model = complete(prompt)
    record = models.AiSummary(kind=kind, target_id=target_id, model=model, prompt_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                              summary=text, generated_at=_now(), generated_by=username)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record
