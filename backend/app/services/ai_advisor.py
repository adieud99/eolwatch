"""AI advisor: turns a scan result or an SSH check into a short Korean assessment.

Two providers: the OpenAI API (default) or the Claude API; both need a key in .env.
``complete`` is also the single door the in-pipeline AI steps use (library reference for lockfile-less
sources, the collection agent that picks OS-appropriate commands); those ask for JSON answers.
The model only ever sees data EOLWatch already stores (CVE ids, components, versions,
server facts) and that data is compacted first ("token diet"): findings are grouped per
component, lists are capped, free text is trimmed and the JSON is sent without whitespace.
Its output is advice for a human reviewer; it never changes a scan result or a remediation state.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from typing import Any, Optional

from fastapi import HTTPException
import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
# Token diet caps: enough for a useful assessment, small enough to keep every call cheap.
MAX_COMPONENTS = 25
MAX_CVES_PER_COMPONENT = 3
MAX_SUMMARY_CHARS = 90
MAX_PORTS = 20
MAX_SERVICES = 15
MAX_PROCESSES = 5
MAX_DISKS = 6
MAX_AGENT_RESULTS = 8
MAX_AGENT_OUTPUT_CHARS = 240
OPENAI_MIN_COMPLETION_TOKENS = 4000

SYSTEM_PROMPT = (
    "너는 EOLWatch의 보안 검토 보조자다. 취약점 검사 결과를 받아 운영 담당자가 바로 행동할 수 있게 한국어로 정리한다. "
    "데이터에 있는 사실만 쓰고 없는 CVE·버전·서버 정보는 지어내지 않는다. 조치 완료를 단정하지 않는다. "
    "마크다운 없이 짧은 문단과 '- ' 목록만 쓰고 600자 안에 끝낸다."
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dumps(value: Any) -> str:
    """Compact JSON: no spaces, stable key order, Korean kept as-is (ASCII escapes cost tokens)."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


# ---------- context builders (token diet applied here) ----------

def analysis_context(db: Session, run: models.AnalysisRun) -> dict[str, Any]:
    rows = db.execute(
        select(models.ComponentVulnerability, models.Component, models.Vulnerability)
        .join(models.Component, models.ComponentVulnerability.component_id == models.Component.id)
        .join(models.Vulnerability, models.ComponentVulnerability.vulnerability_id == models.Vulnerability.id)
        .where(models.Component.sbom_id == run.sbom_id)
    ).all()
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    counts: dict[str, int] = {}
    for link, component, vulnerability in rows:
        severity = (link.finding_severity or vulnerability.severity or "UNKNOWN").upper()
        counts[severity] = counts.get(severity, 0) + 1
        key = (component.name, component.version or "")
        group = groups.setdefault(key, {"lib": component.name, "ver": component.version, "cves": [], "max": severity, "n": 0, "fix": set()})
        group["n"] += 1
        if SEVERITY_ORDER.get(severity, 9) < SEVERITY_ORDER.get(group["max"], 9):
            group["max"] = severity
        group["cves"].append((SEVERITY_ORDER.get(severity, 9), vulnerability.osv_id, (vulnerability.summary or "")[:MAX_SUMMARY_CHARS]))
        for version in list(link.fixed_versions or []) or ([link.fixed_version] if link.fixed_version else []):
            group["fix"].add(str(version))
    components = []
    for group in groups.values():
        cves = sorted(group["cves"])[:MAX_CVES_PER_COMPONENT]
        components.append({"lib": group["lib"], "ver": group["ver"], "n": group["n"], "max": group["max"],
                           "fix": sorted(group["fix"])[:3], "cves": [{"id": cve, "s": summary} for _, cve, summary in cves]})
    components.sort(key=lambda item: (SEVERITY_ORDER.get(item["max"], 9), -item["n"], item["lib"]))
    asset = run.sbom.asset
    return {
        "kind": "analysis", "run": run.id, "scope": run.scan_scope, "target": asset.asset_tag if asset else None,
        "ai_estimated_versions": "AI-Library-Reference" in (run.generator or ""),
        "components_total": run.sbom.component_count, "cve_total": run.cve_count, "by_severity": counts,
        "top": components[:MAX_COMPONENTS], "omitted_components": max(0, len(components) - MAX_COMPONENTS),
    }


def check_context(job: models.CollectionJob) -> dict[str, Any]:
    result = job.result
    raw = (result.raw_metrics or {}) if result else {}
    info = raw.get("server_info") or {}
    ports = info.get("listening_ports") or []
    return {
        "kind": "check", "job": job.id, "status": job.status, "target": job.asset.asset_tag, "ip": job.asset.ip_address,
        "usage": {"cpu": result.cpu_percent, "mem": result.memory_percent, "disk_max": result.max_disk_percent,
                  "uptime_h": round((result.uptime_seconds or 0) / 3600, 1), "health": result.health_level} if result else None,
        "disks": [{"m": d.get("mount"), "used": d.get("used_percent")} for d in (result.disk_details or [])[:MAX_DISKS]] if result else [],
        "top_proc": [p.get("name") for p in (result.process_details or [])[:MAX_PROCESSES]] if result else [],
        "packages": raw.get("package_count"),
        "os": (raw.get("package_context") or {}).get("pretty_name") or info.get("os_name"),
        "host": info.get("hostname"), "kernel": info.get("kernel"), "arch": info.get("architecture"),
        "cpu": {"model": info.get("cpu_model"), "cores": info.get("cpu_cores")}, "mem_mb": info.get("memory_total_mb"),
        "platform": info.get("platform"), "virt": info.get("virtualization"), "dmi": " ".join(filter(None, [info.get("dmi_vendor"), info.get("dmi_product")])) or None,
        "cloud": {k: v for k, v in (info.get("cloud") or {}).items() if k in ("provider", "instance_type", "region")} or None,
        "ips": [a.get("address") for a in (info.get("ip_addresses") or [])],
        "ports": sorted({p.get("port") for p in ports if p.get("port") is not None})[:MAX_PORTS],
        "services": (info.get("services") or [])[:MAX_SERVICES],
        "agent": [{"id": r.get("id"), "out": (r.get("output") or "")[:MAX_AGENT_OUTPUT_CHARS]} for r in ((info.get("ai_collection") or {}).get("results") or [])[:MAX_AGENT_RESULTS]] or None,
        "failure": {"stage": job.failure_stage, "code": job.failure_code, "msg": (job.failure_message or "")[:160]} if job.status != "SUCCESS" else None,
    }


def build_prompt(context: dict[str, Any]) -> str:
    if context["kind"] == "analysis":
        ask = ("검사 결과 하나다. 1) 전체 위험 수준 한두 문장, 2) 먼저 손볼 라이브러리 3~5개와 이유·권장 버전 목록, "
               "3) 담당자가 확인할 점 목록. top에 없는 라이브러리는 언급하지 마라. 키 뜻: lib 라이브러리, ver 현재 버전, n CVE 수, max 최고 심각도, fix 수정 버전, cves 대표 CVE. "
               "ai_estimated_versions가 true면 잠금 파일이 없어 버전을 AI가 추정한 것이니 실제 설치 버전 확인을 첫 할 일로 두어라.")
    else:
        ask = ("서버 한 대의 SSH 점검 결과다. 1) 어떤 환경인지(OS, 하드웨어, 가상화·클라우드, 열린 포트) 한두 문장, "
               "2) 자원 사용률·포트·서비스·agent(수집 에이전트가 실행한 점검 출력)에서 눈여겨볼 점 목록, 3) 다음 할 일 목록. failure가 있으면 원인과 확인할 설정을 정리하라.")
    return ask + "\n" + _dumps(context)


# ---------- providers ----------

def provider_name() -> str:
    return (get_settings().ai_provider or "openai").lower()


def current_model() -> str:
    settings = get_settings()
    return settings.openai_model if provider_name() == "openai" else settings.ai_model


def ai_available() -> bool:
    settings = get_settings()
    if provider_name() == "openai":
        return bool(settings.openai_api_key or os.environ.get("OPENAI_API_KEY"))
    if settings.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        try:
            import anthropic  # noqa: F401
            return True
        except ImportError:
            return False
    return False


def _complete_openai(prompt: str, system: str, json_mode: bool, max_tokens: int) -> tuple[str, str, dict[str, int]]:
    """OpenAI chat completions over plain HTTPS; OPENAI_BASE_URL also lets any OpenAI-compatible server answer."""
    settings = get_settings()
    key = settings.openai_api_key or os.environ.get("OPENAI_API_KEY", "")
    # Reasoning models (gpt-5, gemini-2.5 behind the compatible endpoint) spend hidden thinking tokens from
    # the same budget, so the cap gets headroom; the prompt itself is what keeps the cost down.
    body: dict[str, Any] = {"model": settings.openai_model, "max_completion_tokens": max(max_tokens * 4, OPENAI_MIN_COMPLETION_TOKENS),
                            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    try:
        with httpx.Client(timeout=180) as client:
            response = client.post(settings.openai_base_url.rstrip("/") + "/chat/completions", json=body,
                                   headers={"Authorization": f"Bearer {key}"})
        if response.status_code == 401:
            raise HTTPException(status_code=503, detail="OpenAI 인증에 실패했습니다. OPENAI_API_KEY를 확인하세요.")
        if response.status_code == 429:
            raise HTTPException(status_code=429, detail="OpenAI 요청 한도를 초과했습니다. 잠시 후 다시 시도하세요.")
        if response.status_code in (400, 404):
            try:
                error = (response.json() or {}).get("error") or {}
            except ValueError:
                error = {}
            if response.status_code == 404 or error.get("param") == "model" or "model" in str(error.get("code", "")):
                raise HTTPException(status_code=503, detail=f"OpenAI 모델 '{settings.openai_model}'을(를) 쓸 수 없습니다. OPENAI_MODEL을 확인하세요.")
            raise HTTPException(status_code=502, detail=f"OpenAI가 요청을 거부했습니다: {str(error.get('message') or response.text)[:160]}")
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPError as error:
        logger.warning("OpenAI request failed: %s", error)
        raise HTTPException(status_code=502, detail="OpenAI에 연결하지 못했습니다. 잠시 후 다시 시도하세요.") from error
    choices = data.get("choices") or [{}]
    text = ((choices[0].get("message") or {}).get("content") or "").strip()
    usage = data.get("usage") or {}
    return text, data.get("model") or settings.openai_model, {"input_tokens": int(usage.get("prompt_tokens") or 0), "output_tokens": int(usage.get("completion_tokens") or 0)}


def _complete_anthropic(prompt: str, system: str, json_mode: bool, max_tokens: int) -> tuple[str, str, dict[str, int]]:
    settings = get_settings()
    try:
        import anthropic
    except ImportError as error:  # pragma: no cover - environment dependent
        raise HTTPException(status_code=503, detail="anthropic 패키지가 설치되지 않았습니다.") from error
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key or None, timeout=120.0)
    try:
        response = client.messages.create(model=settings.ai_model, max_tokens=max_tokens, system=system,
                                          messages=[{"role": "user", "content": prompt}])
    except Exception as error:
        logger.warning("Claude request failed: %s", error)
        status = getattr(error, "status_code", None)
        if status == 401:
            raise HTTPException(status_code=503, detail="AI 서비스 인증에 실패했습니다. API 키를 확인하세요.") from error
        if status == 429:
            raise HTTPException(status_code=429, detail="AI 서비스 요청 한도를 초과했습니다. 잠시 후 다시 시도하세요.") from error
        raise HTTPException(status_code=502, detail="AI 서비스에 연결하지 못했습니다. 잠시 후 다시 시도하세요.") from error
    if getattr(response, "stop_reason", None) == "refusal":
        raise HTTPException(status_code=502, detail="AI가 이 요청에 답하지 않았습니다.")
    text = "".join(block.text for block in response.content if getattr(block, "type", None) == "text").strip()
    usage = {"input_tokens": int(getattr(response.usage, "input_tokens", 0) or 0), "output_tokens": int(getattr(response.usage, "output_tokens", 0) or 0)}
    return text, getattr(response, "model", settings.ai_model), usage


def _plain(text: str) -> str:
    """Models ignore the no-markdown rule now and then; strip the usual decorations."""
    lines = []
    for line in text.replace("**", "").replace("__", "").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            stripped = stripped.lstrip("#").strip()
        if stripped.startswith(("* ", "• ")):
            stripped = "- " + stripped[2:]
        lines.append(stripped)
    return "\n".join(lines).strip()


PROVIDERS = {"openai": _complete_openai, "anthropic": _complete_anthropic}


def unavailable_reason() -> str:
    if provider_name() == "openai":
        return "AI가 설정되지 않았습니다. OPENAI_API_KEY를 설정하세요."
    return "AI가 설정되지 않았습니다. ANTHROPIC_API_KEY를 설정하세요."


def complete(prompt: str, *, system: str = SYSTEM_PROMPT, json_mode: bool = False, max_tokens: int = 700) -> tuple[str, str, dict[str, int]]:
    """Return (text, model, usage). Raises HTTPException with a user-facing message on failure.

    json_mode asks the provider for a JSON object and leaves the text untouched; otherwise markdown is stripped.
    """
    if not ai_available():
        raise HTTPException(status_code=503, detail=unavailable_reason())
    provider = PROVIDERS.get(provider_name())
    if provider is None:
        raise HTTPException(status_code=503, detail=f"알 수 없는 AI 제공자 '{provider_name()}'입니다. AI_PROVIDER는 openai 또는 anthropic이어야 합니다.")
    text, model, usage = provider(prompt, system, json_mode, max_tokens)
    if not json_mode:
        text = _plain(text)
    if not text:
        raise HTTPException(status_code=502, detail="AI 응답이 비어 있습니다.")
    return text, model, usage


def complete_json(prompt: str, *, system: str, max_tokens: int = 1500) -> tuple[dict[str, Any], str, dict[str, int]]:
    """complete() for pipeline steps: returns the parsed JSON object, tolerating code fences and stray prose."""
    text, model, usage = complete(prompt, system=system, json_mode=True, max_tokens=max_tokens)
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned[cleaned.find("{"):] if "{" in cleaned else cleaned
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start < 0 or end < start:
        raise HTTPException(status_code=502, detail="AI가 JSON이 아닌 답을 보냈습니다.")
    try:
        data = json.loads(cleaned[start:end + 1])
    except ValueError as error:
        raise HTTPException(status_code=502, detail="AI 답(JSON)을 읽지 못했습니다.") from error
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="AI 답이 JSON 객체가 아닙니다.")
    return data, model, usage


# ---------- persistence ----------

def latest_summary(db: Session, kind: str, target_id: int) -> Optional[models.AiSummary]:
    return db.scalar(select(models.AiSummary).where(models.AiSummary.kind == kind, models.AiSummary.target_id == target_id)
                     .order_by(models.AiSummary.generated_at.desc(), models.AiSummary.id.desc()).limit(1))


def generate_summary(db: Session, kind: str, target_id: int, context: dict[str, Any], username: Optional[str], *, force: bool = False) -> models.AiSummary:
    prompt = build_prompt(context)
    digest = hashlib.sha256((provider_name() + ":" + current_model() + ":" + prompt).encode("utf-8")).hexdigest()
    if not force:
        # Same data, same model: reuse the stored answer instead of spending tokens again.
        cached = db.scalar(select(models.AiSummary).where(models.AiSummary.kind == kind, models.AiSummary.target_id == target_id,
                                                          models.AiSummary.prompt_sha256 == digest).order_by(models.AiSummary.id.desc()).limit(1))
        if cached:
            return cached
    text, model, usage = complete(prompt)
    record = models.AiSummary(kind=kind, target_id=target_id, provider=provider_name(), model=model, prompt_sha256=digest, summary=text,
                              prompt_chars=len(prompt), input_tokens=usage.get("input_tokens"), output_tokens=usage.get("output_tokens"),
                              generated_at=_now(), generated_by=username)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record
