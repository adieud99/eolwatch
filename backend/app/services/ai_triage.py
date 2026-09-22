"""AI triage and remediation advice for scan findings.

Two AI steps a reviewer can ask for after a scan:

* triage: the findings that deserve a look (KEV, EPSS >= 1%, fixable non-kernel, critical/high non-kernel) are sent
  together with a few facts about the machine (OS, running kernel, platform, listening ports, services). The model
  sorts them into 해당 / 확인 필요 / 해당 없음 가능성 with a one-line reason and a concrete action. Output is validated:
  only CVEs from the candidate list, only the three verdicts. It never changes a remediation state.
* advice: for one finding, the exact steps (package command, restart, verification) a Korean operator would run.

Data minimisation applies (see ai_advisor.check_context): no addresses, host names, credentials or identifiers.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .. import models
from . import ai_advisor
from .cve_breakdown import EPSS_ATTENTION, is_kernel_package

MAX_CANDIDATES = 40
VERDICTS = ("해당", "확인 필요", "해당 없음 가능성")

TRIAGE_SYSTEM = (
    "너는 리눅스 서버 취약점 검토 보조자다. 검사 도구가 찾은 CVE 후보 목록과 서버 사실을 받아 담당자가 먼저 볼 것을 고른다. "
    "각 CVE를 '해당'(이 서버에서 실제 위험 가능성이 있어 조치 필요), '확인 필요'(서버 구성·서비스 노출을 봐야 판단 가능), "
    "'해당 없음 가능성'(이 서버 유형에 없는 장치·서브시스템, 실행되지 않는 커널, 이미 고쳐진 정황 등 근거가 있을 때만) 중 하나로 판정한다. "
    "근거 없는 판정을 하지 않고, 확신이 없으면 '확인 필요'로 둔다. 데이터에 없는 CVE·버전·서버 정보는 지어내지 않는다. "
    "키 뜻: cve 번호, pkg 패키지, ver 설치 버전, fix 수정판, sev 심각도, epss 30일 내 악용 확률, kev CISA 악용 확인, "
    "apt 저장소 대조(UPDATE_AVAILABLE 올릴 수 있음/NO_UPDATE_FOUND 올릴 것 없음), kernel 커널 패키지 여부, running 실행 중 커널에 속하는지, "
    "tracker 배포판 추적기 상태(released 정식 배포됨/pending 다음 패키지에서 수정 예정/needed 업스트림만 수정/not-affected 해당 없음), tracker_fix 그 버전, "
    "host 커널 코드 위치 판정(CORE 핵심/LOADED_MODULE 로드된 모듈/UNLOADED_MODULE 미로드 드라이버/OTHER_ARCH 다른 아키텍처/FS_NOT_USED 미사용 파일시스템), files 영향 소스 파일. "
    'JSON 객체 하나만 답한다: {"items":[{"cve":"...","verdict":"해당|확인 필요|해당 없음 가능성","reason":"한 문장","action":"한 문장 (명령 포함 가능)"}],"note":"전체 한 줄 평"}'
)
ADVICE_SYSTEM = (
    "너는 리눅스 서버 운영자를 돕는 보안 조치 보조자다. CVE 하나와 그 서버의 사실을 받아 담당자가 바로 실행할 조치 절차를 한국어로 쓴다. "
    "1) 이 서버에 해당되는지 판단 근거 한두 문장, 2) 조치 명령 순서(패키지 관리자 명령은 실제 배포판 문법으로), 3) 재시작·재부팅 필요 여부, "
    "4) 조치 후 확인 방법(버전 확인 명령, EOLWatch 재검사), 5) 수정판이 없을 때의 완화책. 데이터에 없는 사실은 지어내지 않는다. "
    "마크다운 없이 짧은 문단과 '- ' 목록만 쓰고 700자 안에 끝낸다."
)


def _server_facts(db: Session, asset_id: Optional[int]) -> dict[str, Any]:
    """What the model may know about the machine: OS, running kernel, platform class, ports, services. Nothing that identifies it."""
    if not asset_id:
        return {}
    job = db.scalar(select(models.CollectionJob).where(models.CollectionJob.asset_id == asset_id, models.CollectionJob.status == "SUCCESS")
                    .options(joinedload(models.CollectionJob.result)).order_by(models.CollectionJob.id.desc()).limit(1))
    if not job or not job.result:
        return {}
    raw = job.result.raw_metrics or {}
    info = raw.get("server_info") or {}
    return {"os": (raw.get("package_context") or {}).get("pretty_name") or info.get("os_name"), "kernel_running": info.get("kernel"),
            "arch": info.get("architecture"), "platform": info.get("platform"),
            "instance_type": ((info.get("cloud") or {}).get("instance_type")),
            "ports": sorted({p.get("port") for p in (info.get("listening_ports") or []) if p.get("port") is not None})[:15],
            "services": (info.get("services") or [])[:15]}


def _running_kernel(component_name: str, purl: Optional[str], kernel_running: Optional[str]) -> Optional[bool]:
    if not kernel_running or not is_kernel_package(component_name, purl):
        return None
    # linux-modules-7.0.0-1006-aws belongs to running kernel 7.0.0-1006-aws; meta/tools packages carry no release string.
    version = kernel_running.rsplit("-", 1)[0]
    return version in component_name if any(char.isdigit() for char in component_name) else None


def candidates(db: Session, run: models.AnalysisRun) -> tuple[list[dict[str, Any]], dict[str, int]]:
    link, component, vuln = models.ComponentVulnerability, models.Component, models.Vulnerability
    rows = db.execute(select(link, component, vuln).join(component, link.component_id == component.id).join(vuln, link.vulnerability_id == vuln.id)
                      .where(link.analysis_run_id == run.id, link.vex_status.in_(("AFFECTED", "UNDER_INVESTIGATION")))).all()
    facts = _server_facts(db, run.sbom.asset_id)
    per: dict[str, dict[str, Any]] = {}
    for item, comp, vulnerability in rows:
        kernel = is_kernel_package(comp.name, comp.purl)
        severity = (item.finding_severity or vulnerability.severity or "UNKNOWN").upper()
        fixed = bool(item.fixed_versions)
        reasons = []
        if item.kev:
            reasons.append("kev")
        if (item.epss or 0) >= EPSS_ATTENTION:
            reasons.append("epss")
        if fixed and not kernel:
            reasons.append("fixable")
        if severity in ("CRITICAL", "HIGH") and not kernel:
            reasons.append("severe")
        if not reasons:
            continue
        entry = per.setdefault(vulnerability.osv_id, {"cve": vulnerability.osv_id, "pkg": comp.name, "ver": comp.version, "fix": sorted(item.fixed_versions or [])[:2],
                                                       "sev": severity, "epss": round(item.epss or 0, 4), "kev": bool(item.kev), "apt": item.fix_check,
                                                       "kernel": kernel, "running": _running_kernel(comp.name, comp.purl, facts.get("kernel_running")),
                                                       "sub": (vulnerability.summary or "")[:60] or None, "why": set(), "link_id": item.id,
                                                       "tracker": item.tracker_status, "tracker_fix": item.tracker_fix, "host": item.host_relevance,
                                                       "files": list(item.kernel_files or [])[:3]})
        entry["why"].update(reasons)
        if severity_rank(severity) > severity_rank(entry["sev"]):
            entry["sev"] = severity
    ordered = sorted(per.values(), key=lambda e: (not e["kev"], -e["epss"], -severity_rank(e["sev"]), e["cve"]))
    counts = {"eligible": len(ordered), "sent": min(len(ordered), MAX_CANDIDATES)}
    chosen = ordered[:MAX_CANDIDATES]
    for e in chosen:
        e["why"] = sorted(e["why"])
    return chosen, counts


def severity_rank(value: str) -> int:
    return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NEGLIGIBLE": 1}.get(value, 0)


def triage_context(db: Session, run: models.AnalysisRun) -> dict[str, Any]:
    chosen, counts = candidates(db, run)
    return {"kind": "triage", "run": run.id, "scope": run.scan_scope, "cve_total": run.cve_count, "server": _server_facts(db, run.sbom.asset_id),
            "candidates": [{k: v for k, v in e.items() if k != "link_id"} for e in chosen], **counts}


def triage_prompt(context: dict[str, Any]) -> str:
    ask = (f"검사 결과 CVE {context['cve_total']}건 중 먼저 볼 후보 {context['sent']}건이다(전체 후보 {context['eligible']}건, kev·epss·수정판·심각도 기준으로 고름). "
           "후보마다 판정·이유·조치를 적어라. 후보 밖 CVE는 언급하지 마라.")
    return ask + "\n" + ai_advisor._dumps({"server": context["server"], "candidates": context["candidates"]})


def validate_triage(answer: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    allowed = {e["cve"]: e for e in context["candidates"]}
    items, seen = [], set()
    for row in (answer.get("items") if isinstance(answer, dict) else None) or []:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cve", "")).strip()
        verdict = str(row.get("verdict", "")).strip()
        if cve not in allowed or cve in seen or verdict not in VERDICTS:
            continue
        seen.add(cve)
        base = allowed[cve]
        items.append({"cve": cve, "verdict": verdict, "reason": str(row.get("reason", ""))[:300], "action": str(row.get("action", ""))[:400],
                      "pkg": base["pkg"], "ver": base["ver"], "fix": base["fix"], "sev": base["sev"], "epss": base["epss"], "kev": base["kev"], "apt": base["apt"], "kernel": base["kernel"]})
    if not items:
        raise HTTPException(status_code=502, detail="AI가 후보 목록에 대한 판정을 돌려주지 않았습니다.")
    order = {v: i for i, v in enumerate(VERDICTS)}
    items.sort(key=lambda e: (order[e["verdict"]], not e["kev"], -e["epss"]))
    counts = {v: sum(1 for e in items if e["verdict"] == v) for v in VERDICTS}
    return {"items": items, "note": str((answer or {}).get("note", ""))[:300], "counts": counts,
            "eligible": context["eligible"], "sent": context["sent"], "cve_total": context["cve_total"]}


def generate_triage(db: Session, run: models.AnalysisRun, username: Optional[str], *, force: bool = False) -> models.AiSummary:
    context = triage_context(db, run)
    if not context["candidates"]:
        raise HTTPException(status_code=422, detail="선별할 후보가 없습니다. KEV·EPSS 1% 이상·수정판 있는 일반 패키지·치명/높음 일반 패키지 CVE가 없는 검사입니다.")
    prompt = triage_prompt(context)
    record = ai_advisor.generate_record(db, "triage", run.id, prompt, username, force=force, system=TRIAGE_SYSTEM, json_mode=True, max_tokens=2500)
    try:
        answer = json.loads(record.summary)
        if "items" in answer and "counts" in answer:
            return record          # already validated and stored
    except ValueError:
        answer = None
    if answer is None:
        cleaned = record.summary.strip()
        start, end = cleaned.find("{"), cleaned.rfind("}")
        try:
            answer = json.loads(cleaned[start:end + 1]) if start >= 0 else {}
        except ValueError:
            answer = {}
    record.summary = json.dumps(validate_triage(answer, context), ensure_ascii=False)
    db.commit()
    db.refresh(record)
    return record


def advice_context(db: Session, link: models.ComponentVulnerability) -> dict[str, Any]:
    comp = link.component
    sbom = comp.sbom
    return {"cve": link.vulnerability.osv_id, "summary": (link.vulnerability.summary or "")[:200] or None, "pkg": comp.name, "ver": comp.version,
            "purl": comp.purl, "fix": sorted(link.fixed_versions or [])[:3], "sev": (link.finding_severity or link.vulnerability.severity or "UNKNOWN").upper(),
            "epss": link.epss, "kev": bool(link.kev), "apt": link.fix_check, "status": link.vex_status,
            "kernel": is_kernel_package(comp.name, comp.purl), "tracker": link.tracker_status, "tracker_fix": link.tracker_fix,
            "host": link.host_relevance, "files": list(link.kernel_files or [])[:5], "server": _server_facts(db, sbom.asset_id if sbom else None)}


VERIFY_SYSTEM = (
    "너는 취약점 검사 결과의 2차 검토자다. 도구가 잡은 CVE 하나에 대해, 주어진 근거만으로 이 서버에서 그 판정이 맞는지 평가한다. "
    "근거의 뜻: fix 배포판 수정판(비어 있으면 도구가 수정판을 모름), tracker 배포판 추적기 상태(released/pending/needed/not-affected/DNE), tracker_fix 그 버전, "
    "apt 저장소 대조, kernel 커널 패키지 여부, host 커널 코드 위치(CORE/LOADED_MODULE/UNLOADED_MODULE/OTHER_ARCH/FS_NOT_USED), files 영향 소스 파일, "
    "server 실행 중 커널·플랫폼·포트·서비스, epss 악용 확률, kev 실제 악용 확인. "
    "판정은 '유효'(이 서버에 해당하는 실제 취약점), '오탐 가능성'(추적기가 not-affected/DNE이거나 설치 버전이 이미 수정판 이상), "
    "'해당 없음 가능성'(이 서버에 없는 장치·아키텍처·미사용 파일시스템 코드, 실행되지 않는 커널), '확인 필요'(근거 부족) 중 하나다. "
    "근거 없는 단정은 하지 않는다. "
    'JSON 객체 하나만 답한다: {"verdict":"유효|오탐 가능성|해당 없음 가능성|확인 필요","confidence":"high|medium|low","reason":"두 문장 이내","next":"담당자가 할 일 한 문장"}'
)
VERIFY_VERDICTS = ("유효", "오탐 가능성", "해당 없음 가능성", "확인 필요")


def generate_verify(db: Session, link: models.ComponentVulnerability, username: Optional[str], *, force: bool = False) -> models.AiSummary:
    context = advice_context(db, link)
    prompt = "이 CVE 판정이 이 서버에서 맞는지 2차 검토하라.\n" + ai_advisor._dumps(context)
    record = ai_advisor.generate_record(db, "verify", link.id, prompt, username, force=force, system=VERIFY_SYSTEM, json_mode=True, max_tokens=600)
    try:
        answer = json.loads(record.summary)
    except ValueError:
        cleaned = record.summary.strip(); start, end = cleaned.find("{"), cleaned.rfind("}")
        try:
            answer = json.loads(cleaned[start:end + 1]) if start >= 0 else {}
        except ValueError:
            answer = {}
    verdict = str((answer or {}).get("verdict", "")).strip()
    if verdict not in VERIFY_VERDICTS:
        verdict = "확인 필요"
    confidence = str((answer or {}).get("confidence", "low")).lower()
    result = {"verdict": verdict, "confidence": confidence if confidence in ("high", "medium", "low") else "low",
              "reason": str((answer or {}).get("reason", ""))[:400], "next": str((answer or {}).get("next", ""))[:300],
              "evidence": {k: context[k] for k in ("tracker", "tracker_fix", "host", "apt", "kev", "epss", "fix")}}
    if record.summary != json.dumps(result, ensure_ascii=False):
        record.summary = json.dumps(result, ensure_ascii=False)
        db.commit(); db.refresh(record)
    return record


def generate_advice(db: Session, link: models.ComponentVulnerability, username: Optional[str], *, force: bool = False) -> models.AiSummary:
    context = advice_context(db, link)
    prompt = "이 CVE의 조치 절차를 써라.\n" + ai_advisor._dumps(context)
    return ai_advisor.generate_record(db, "advice", link.id, prompt, username, force=force, system=ADVICE_SYSTEM, max_tokens=900)
