"""AI collection agent for SSH checks: picks OS-appropriate, read-only commands and runs them.

The fixed inventory (collector.COMMANDS / SERVER_INFO_COMMANDS) is the same on every host. After it
has run, this agent shows the AI what kind of machine it is looking at (OS, architecture, platform,
open ports, running services) and a catalog of read-only commands, and asks which of them are worth
running here and why. Only catalog entries can be executed: the AI chooses ids, never command text.
Without an AI (or when it fails) a small OS rule set picks the defaults, so the check still works.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "너는 서버 점검 수집 에이전트다. 서버 정보(os, arch, platform, ports, services)를 보고 catalog에 있는 읽기 전용 명령 중 "
    "이 서버에 맞는 것만 고른다. os 태그가 서버 OS와 맞지 않는 항목은 고르지 않는다. 최대 8개, 이유는 한 문장. "
    'JSON 객체 하나만 답한다: {"commands":[{"id":"catalog의 id","reason":"왜 이 서버에 필요한지"}],"note":"서버에 대한 한 줄 평"}'
)

MAX_COMMANDS = 8
MAX_OUTPUT_CHARS = 4000
COMMAND_TIMEOUT = 20

# id -> purpose (Korean), os tags (empty = any Linux), command. Every command is read-only and must not prompt.
CATALOG: dict[str, dict[str, Any]] = {
    "apt_upgradable": {"purpose": "apt로 미적용 보안 업데이트 확인", "os": ["debian", "ubuntu"],
                       "command": "apt list --upgradable 2>/dev/null | head -60"},
    "apt_auto_upgrades": {"purpose": "자동 보안 업데이트(unattended-upgrades) 설정 확인", "os": ["debian", "ubuntu"],
                          "command": "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; systemctl is-enabled unattended-upgrades 2>/dev/null; true"},
    "reboot_required": {"purpose": "커널·라이브러리 갱신 후 재부팅 대기 여부", "os": ["debian", "ubuntu"],
                        "command": "if [ -f /var/run/reboot-required ]; then cat /var/run/reboot-required; cat /var/run/reboot-required.pkgs 2>/dev/null; else echo '재부팅 대기 없음'; fi"},
    "dnf_updates": {"purpose": "dnf/yum으로 미적용 업데이트 확인", "os": ["rhel", "centos", "rocky", "almalinux", "fedora", "amzn"],
                    "command": "(dnf -q check-update 2>/dev/null || yum -q check-update 2>/dev/null) | head -60; true"},
    "needs_restarting": {"purpose": "갱신 후 재시작이 필요한 서비스·재부팅 여부", "os": ["rhel", "centos", "rocky", "almalinux", "fedora", "amzn"],
                         "command": "needs-restarting -r 2>/dev/null; needs-restarting -s 2>/dev/null | head -20; true"},
    "selinux": {"purpose": "SELinux 적용 상태", "os": ["rhel", "centos", "rocky", "almalinux", "fedora", "amzn"],
                "command": "getenforce 2>/dev/null || echo '확인 불가'"},
    "apk_upgradable": {"purpose": "apk로 미적용 업데이트 확인", "os": ["alpine"],
                       "command": "apk version -l '<' 2>/dev/null | head -60; true"},
    "os_support": {"purpose": "배포판 버전과 지원(EOL) 판단 근거", "os": [],
                   "command": "grep -E '^(PRETTY_NAME|VERSION_ID|VERSION_CODENAME|SUPPORT_END)=' /etc/os-release 2>/dev/null; true"},
    "sshd_policy": {"purpose": "SSH 원격 접속 정책(root 로그인·비밀번호 인증·포트)", "os": [],
                    "command": "sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|port|pubkeyauthentication|maxauthtries) ' || grep -Ei '^(PermitRootLogin|PasswordAuthentication|Port|PubkeyAuthentication)' /etc/ssh/sshd_config 2>/dev/null; true"},
    "firewall": {"purpose": "방화벽 활성 여부와 규칙 요약", "os": [],
                 "command": "ufw status 2>/dev/null || firewall-cmd --state 2>/dev/null || (nft list ruleset 2>/dev/null | head -40) || (iptables -S 2>/dev/null | head -40); true"},
    "runtimes": {"purpose": "설치된 언어 런타임 버전(python·node·java·go·php·ruby)", "os": [],
                 "command": "for c in python3 node java go php ruby; do if command -v $c >/dev/null 2>&1; then printf '%s|' $c; $c --version 2>&1 | head -1; fi; done; true"},
    "web_servers": {"purpose": "웹 서버 소프트웨어 버전(nginx·apache)", "os": [],
                    "command": "nginx -v 2>&1 | head -1; apache2 -v 2>/dev/null | head -1; httpd -v 2>/dev/null | head -1; true"},
    "databases": {"purpose": "DB 서버 클라이언트/서버 버전(postgres·mysql·redis·mongo)", "os": [],
                  "command": "psql --version 2>/dev/null; mysql --version 2>/dev/null; mariadb --version 2>/dev/null; redis-server --version 2>/dev/null; mongod --version 2>/dev/null | head -1; true"},
    "containers": {"purpose": "실행 중인 Docker 컨테이너와 이미지", "os": [],
                   "command": "docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null | head -30; true"},
    "failed_units": {"purpose": "실패한 systemd 서비스", "os": [],
                     "command": "systemctl --failed --no-legend --plain 2>/dev/null | head -20; true"},
    "recent_logins": {"purpose": "최근 로그인 기록", "os": [],
                      "command": "last -n 10 -w 2>/dev/null | head -12; true"},
    "ssh_failures": {"purpose": "최근 하루 SSH 인증 실패 횟수", "os": [],
                     "command": "(journalctl --since '-1 day' --no-pager 2>/dev/null | grep -c 'Failed password') || (grep -c 'Failed password' /var/log/auth.log 2>/dev/null) || echo 0"},
    "cron_jobs": {"purpose": "예약 작업(cron) 목록", "os": [],
                  "command": "ls /etc/cron.d 2>/dev/null; crontab -l 2>/dev/null | grep -v '^#' | head -20; true"},
    "sudo_users": {"purpose": "sudo 권한 그룹 구성원", "os": [],
                   "command": "getent group sudo wheel admin 2>/dev/null; true"},
    "time_sync": {"purpose": "시간 동기화 상태", "os": [],
                  "command": "timedatectl show -p NTPSynchronized -p Timezone 2>/dev/null || date; true"},
    "cloud_agents": {"purpose": "클라우드 에이전트·SSM 상태", "os": [],
                     "command": "systemctl is-active amazon-ssm-agent snap.amazon-ssm-agent.amazon-ssm-agent.service cloud-init google-guest-agent 2>/dev/null; true"},
}

DEBIAN = ("debian", "ubuntu")
RHEL = ("rhel", "centos", "rocky", "almalinux", "fedora", "amzn")
_plan_cache: dict[str, dict[str, Any]] = {}


def catalog_for(os_id: str) -> list[dict[str, str]]:
    """Catalog entries applicable to this OS, compacted for the prompt (id + purpose only)."""
    return [{"id": key, "purpose": entry["purpose"]} for key, entry in CATALOG.items() if not entry["os"] or os_id in entry["os"]]


def rule_plan(context: dict[str, Any]) -> dict[str, Any]:
    """Deterministic fallback when no AI answers: OS family decides the update checks, the rest are universal."""
    os_id = context.get("os_id") or ""
    chosen = []
    if os_id in DEBIAN:
        chosen += [("apt_upgradable", "Debian 계열이라 apt로 미적용 업데이트를 본다"), ("reboot_required", "갱신 후 재부팅 대기 여부")]
    elif os_id in RHEL:
        chosen += [("dnf_updates", "RHEL 계열이라 dnf로 미적용 업데이트를 본다"), ("needs_restarting", "갱신 후 재시작 필요 여부")]
    elif os_id == "alpine":
        chosen += [("apk_upgradable", "Alpine이라 apk로 미적용 업데이트를 본다")]
    chosen += [("os_support", "배포판 지원 종료 여부 판단"), ("sshd_policy", "원격 접속 정책 점검"), ("firewall", "방화벽 상태"),
               ("runtimes", "설치 런타임 버전"), ("failed_units", "실패한 서비스")]
    if any(port in (context.get("ports") or []) for port in (80, 443, 8080)):
        chosen.append(("web_servers", "웹 포트가 열려 있어 웹 서버 버전 확인"))
    return {"source": "rules", "model": None, "note": "AI를 쓰지 못해 OS 규칙으로 골랐습니다.",
            "commands": [{"id": key, "reason": reason} for key, reason in chosen[:MAX_COMMANDS]]}


def build_prompt(context: dict[str, Any]) -> str:
    body = {"server": context, "catalog": catalog_for(context.get("os_id") or "")}
    return "이 서버에 맞는 수집 명령을 catalog에서 고르라.\n" + json.dumps(body, ensure_ascii=False, separators=(",", ":"))


def validate_plan(answer: dict[str, Any], os_id: str) -> list[dict[str, str]]:
    allowed = {entry["id"] for entry in catalog_for(os_id)}
    chosen, seen = [], set()
    for row in (answer.get("commands") if isinstance(answer, dict) else None) or []:
        if not isinstance(row, dict):
            continue
        key = str(row.get("id", "")).strip()
        if key in allowed and key not in seen:
            seen.add(key)
            chosen.append({"id": key, "reason": str(row.get("reason", ""))[:200]})
        if len(chosen) >= MAX_COMMANDS:
            break
    return chosen


def plan(context: dict[str, Any], complete_json: Optional[Callable[..., tuple[dict[str, Any], str, dict[str, int]]]]) -> dict[str, Any]:
    """Ask the AI once per (OS, arch, platform, ports, services) shape; identical servers reuse the answer (token diet)."""
    if complete_json is None:
        return rule_plan(context)
    prompt = build_prompt(context)
    key = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    cached = _plan_cache.get(key)
    if cached:
        return dict(cached, cached=True)
    try:
        answer, model, usage = complete_json(prompt, system=SYSTEM_PROMPT, max_tokens=800)
    except Exception as error:  # the check must not fail because the AI did
        logger.warning("AI collection plan failed, using rules: %s", getattr(error, "detail", error))
        fallback = rule_plan(context)
        fallback["note"] = f"AI를 쓰지 못해 OS 규칙으로 골랐습니다 ({getattr(error, 'detail', None) or type(error).__name__})."
        return fallback
    commands = validate_plan(answer, context.get("os_id") or "")
    if not commands:
        fallback = rule_plan(context)
        fallback["note"] = "AI가 고른 명령이 없어 OS 규칙으로 골랐습니다."
        return fallback
    result = {"source": "ai", "model": model, "note": str(answer.get("note", ""))[:200], "commands": commands,
              "prompt_chars": len(prompt), "input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens")}
    _plan_cache[key] = result
    return result


def context_from(server_info: dict[str, Any], package_context: dict[str, str]) -> dict[str, Any]:
    ports = sorted({p.get("port") for p in (server_info.get("listening_ports") or []) if isinstance(p.get("port"), int)})[:20]
    return {"os_id": (package_context.get("id") or "").lower(), "os": package_context.get("pretty_name") or server_info.get("os_name"),
            "arch": server_info.get("architecture"), "platform": server_info.get("platform"), "ports": ports,
            "services": (server_info.get("services") or [])[:15]}


def run_plan(chosen: dict[str, Any], run_command: Callable[[str], str]) -> list[dict[str, Any]]:
    """Execute the chosen catalog commands (by id) and keep a capped output per command."""
    results = []
    for item in chosen.get("commands") or []:
        entry = CATALOG.get(item["id"])
        if not entry:
            continue
        try:
            output = run_command(entry["command"])
            ok = True
        except Exception as error:  # a failing probe is a finding, not a failed check
            output = str(getattr(error, "message", None) or error)
            ok = False
        text = (output or "").strip()
        results.append({"id": item["id"], "purpose": entry["purpose"], "reason": item.get("reason", ""), "command": entry["command"],
                        "ok": ok, "output": text[:MAX_OUTPUT_CHARS] + ("\n…" if len(text) > MAX_OUTPUT_CHARS else "") or "(출력 없음)"})
    return results


def collect(server_info: dict[str, Any], package_context: dict[str, str], run_command: Callable[[str], str],
            complete_json: Optional[Callable[..., Any]]) -> dict[str, Any]:
    context = context_from(server_info, package_context)
    chosen = plan(context, complete_json)
    return {"source": chosen.get("source"), "model": chosen.get("model"), "note": chosen.get("note"), "cached": chosen.get("cached", False),
            "input_tokens": chosen.get("input_tokens"), "output_tokens": chosen.get("output_tokens"),
            "results": run_plan(chosen, run_command)}
