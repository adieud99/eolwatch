"""AI collection agent: OS-aware command choice, allowlist enforcement, rule fallback, plan reuse."""
from __future__ import annotations

from fastapi import HTTPException
import pytest

from app.services import ai_collection as agent


@pytest.fixture(autouse=True)
def fresh_cache():
    agent._plan_cache.clear()


UBUNTU = {"os_id": "ubuntu", "os": "Ubuntu 22.04.4 LTS", "arch": "x86_64", "platform": "aws", "ports": [22, 80], "services": ["ssh.service", "nginx.service"]}


def test_catalog_is_filtered_by_os_and_every_command_is_read_only():
    ids = {entry["id"] for entry in agent.catalog_for("ubuntu")}
    assert "apt_upgradable" in ids and "dnf_updates" not in ids and "sshd_policy" in ids
    for entry in agent.CATALOG.values():
        assert not any(word in entry["command"] for word in ("rm -", "apt-get install", "systemctl restart", "shutdown", "reboot ", " > /", "chmod", "useradd", "passwd"))


def test_ai_choice_is_validated_against_the_catalog_and_reused_for_the_same_shape():
    calls = []

    def complete_json(prompt, *, system, max_tokens):
        calls.append(prompt)
        assert '"apt_upgradable"' in prompt and '"dnf_updates"' not in prompt and "읽기 전용" in system
        return ({"commands": [{"id": "apt_upgradable", "reason": "Ubuntu라 apt"}, {"id": "dnf_updates", "reason": "잘못된 선택"},
                              {"id": "rm -rf /", "reason": "허용 안 됨"}, {"id": "apt_upgradable", "reason": "중복"}, {"id": "web_servers", "reason": "80 포트"}],
                 "note": "AWS의 Ubuntu 웹 서버"}, "gpt-5-mini", {"input_tokens": 400, "output_tokens": 60})
    first = agent.plan(UBUNTU, complete_json)
    assert first["source"] == "ai" and first["model"] == "gpt-5-mini" and first["note"] == "AWS의 Ubuntu 웹 서버"
    assert [c["id"] for c in first["commands"]] == ["apt_upgradable", "web_servers"]
    second = agent.plan(dict(UBUNTU), complete_json)
    assert second["cached"] is True and len(calls) == 1


def test_rules_take_over_when_the_ai_is_unavailable_or_answers_nothing_useful():
    def broken(prompt, *, system, max_tokens):
        raise HTTPException(503, "로컬 AI(Ollama)가 준비되지 않았습니다.")
    chosen = agent.plan(UBUNTU, broken)
    assert chosen["source"] == "rules" and "Ollama" in chosen["note"]
    assert [c["id"] for c in chosen["commands"]][:2] == ["apt_upgradable", "reboot_required"] and "web_servers" in [c["id"] for c in chosen["commands"]]
    rhel = agent.plan({"os_id": "rocky", "ports": [22]}, None)
    assert [c["id"] for c in rhel["commands"]][:2] == ["dnf_updates", "needs_restarting"] and "web_servers" not in [c["id"] for c in rhel["commands"]]
    empty = agent.plan(UBUNTU, lambda prompt, *, system, max_tokens: ({"commands": [{"id": "dnf_updates"}]}, "m", {}))
    assert empty["source"] == "rules" and "AI가 고른 명령이 없어" in empty["note"]


def test_collect_runs_only_catalog_commands_and_keeps_failures_as_findings():
    executed = []

    def run_command(command):
        executed.append(command)
        if command.startswith("ufw"):
            raise RuntimeError("ufw: command not found")
        return "x" * 5000
    server_info = {"listening_ports": [{"port": 22}, {"port": 443}], "services": ["ssh.service"], "architecture": "aarch64", "platform": "aws"}
    result = agent.collect(server_info, {"id": "ubuntu", "pretty_name": "Ubuntu 24.04"}, run_command,
                           lambda prompt, *, system, max_tokens: ({"commands": [{"id": "firewall", "reason": "방화벽"}, {"id": "os_support", "reason": "EOL"}]}, "qwen2.5:7b", {"input_tokens": 1, "output_tokens": 1}))
    assert executed == [agent.CATALOG["firewall"]["command"], agent.CATALOG["os_support"]["command"]]
    firewall, support = result["results"]
    assert firewall["ok"] is False and "command not found" in firewall["output"] and firewall["purpose"] == agent.CATALOG["firewall"]["purpose"]
    assert support["ok"] is True and len(support["output"]) == agent.MAX_OUTPUT_CHARS + 2 and support["output"].endswith("…")
    assert result["source"] == "ai" and result["model"] == "qwen2.5:7b"
