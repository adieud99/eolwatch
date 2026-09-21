from __future__ import annotations

import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5

import paramiko
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings


COMMANDS = {
    "uptime": "cut -d. -f1 /proc/uptime",
    "cpu": "LC_ALL=C top -bn1 | awk '/Cpu\\(s\\)/ {print 100-$8; exit}'",
    "memory": "awk '/MemTotal/{t=$2}/MemAvailable/{a=$2} END{if(t>0) printf \"%.2f\", (t-a)*100/t}' /proc/meminfo",
    "disk": "df -P -x tmpfs -x devtmpfs | awk 'NR>1 {print $6 \"|\" $5}'",
    "process": "ps -eo comm= | sort | uniq -c | sort -nr | head -20",
    "packages": "if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package}|${Version}\\n'; elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}|%{VERSION}-%{RELEASE}\\n'; fi",
    "os_release": "cat /etc/os-release",
    "architecture": "uname -m",
}


@dataclass
class CollectionFailure(Exception):
    stage: str
    code: str
    message: str


def _number(value: str, name: str) -> float:
    try:
        return float(value.strip())
    except (TypeError, ValueError) as exc:
        raise CollectionFailure("PARSE", f"INVALID_{name.upper()}", f"{name} 값을 해석할 수 없습니다") from exc


def parse_disks(output: str) -> list[dict[str, Any]]:
    disks = []
    for line in output.splitlines():
        if "|" not in line:
            continue
        mount, percent = line.rsplit("|", 1)
        try:
            used = float(percent.strip().rstrip("%"))
        except ValueError:
            continue
        disks.append({"mount": mount.strip(), "used_percent": used})
    return disks


def parse_processes(output: str) -> list[dict[str, Any]]:
    result = []
    for line in output.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) == 2 and parts[0].isdigit():
            result.append({"count": int(parts[0]), "name": parts[1]})
    return result


def parse_packages(output: str, limit: int = 20000) -> list[dict[str, str]]:
    result = []
    for line in output.splitlines()[:limit]:
        if "|" not in line:
            continue
        name, version = line.split("|", 1)
        if name.strip() and version.strip():
            result.append({"name": name.strip(), "version": version.strip()})
    return result


def health_level(cpu: float, memory: float, max_disk: float) -> str:
    highest = max(cpu, memory, max_disk)
    if highest >= 90:
        return "CRITICAL"
    if highest >= 80:
        return "WARN"
    return "NORMAL"


def packages_to_cyclonedx(asset: models.Asset, packages: list[dict[str, str]], generated_at: datetime) -> dict[str, Any]:
    timestamp = generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    root_ref = f"urn:eolwatch:asset:{asset.asset_tag}"
    components = []
    depends_on = []
    for package in sorted(packages, key=lambda item: (item["name"], item["version"])):
        name = quote(package["name"], safe=".+-_")
        version = quote(package["version"], safe=".+-_:~")
        purl = f"pkg:generic/{name}@{version}"
        depends_on.append(purl)
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": package["name"],
                "version": package["version"],
                "purl": purl,
                "properties": [{"name": "eolwatch:discovery-source", "value": "ssh-package-manager"}],
            }
        )
    serial = uuid5(NAMESPACE_URL, f"{asset.asset_tag}:{timestamp}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": "EOLWatch SSH Collector", "version": "0.2.0"}]},
            "component": {"type": "platform", "bom-ref": root_ref, "name": asset.name, "version": asset.asset_tag},
        },
        "components": components,
        "dependencies": [{"ref": root_ref, "dependsOn": depends_on}],
    }


def packages_to_spdx(
    asset: models.Asset,
    packages: list[dict[str, str]],
    generated_at: datetime,
    package_context: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    """SSH로 발견한 운영 패키지를 SPDX 2.3 시스템 SBOM으로 변환한다."""
    timestamp = generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    serial = uuid5(NAMESPACE_URL, f"spdx:{asset.asset_tag}:{timestamp}")
    root_ref = f"SPDXRef-Asset-{uuid5(NAMESPACE_URL, asset.asset_tag).hex}"
    root_purl = f"pkg:generic/eolwatch-host@{quote(asset.asset_tag, safe='.-_')}"
    spdx_packages = [
        {
            "SPDXID": root_ref,
            "name": asset.name,
            "versionInfo": asset.asset_tag,
            "supplier": f"Organization: {asset.manufacturer or '운영 조직'}",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "OPERATING_SYSTEM",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": root_purl,
                }
            ],
        }
    ]
    relationships = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_ref}
    ]
    package_context = package_context or {}
    distro_id = package_context.get("id", "generic").lower()
    distro_version = package_context.get("version_id", "unknown")
    architecture = package_context.get("architecture", "unknown")
    debian_family = distro_id in {"ubuntu", "debian", "linuxmint", "pop"}
    purl_type = "deb" if debian_family else "rpm" if distro_id != "generic" else "generic"
    supplier_name = {
        "ubuntu": "Canonical",
        "debian": "Debian Project",
        "amzn": "Amazon Linux",
        "rhel": "Red Hat",
        "rocky": "Rocky Enterprise Software Foundation",
        "almalinux": "AlmaLinux OS Foundation",
    }.get(distro_id, distro_id if distro_id != "generic" else "NOASSERTION")
    for package in sorted(packages, key=lambda item: (item["name"], item["version"])):
        name = quote(package["name"], safe=".+-_")
        version = quote(package["version"], safe=".+-_:~")
        namespace = f"/{distro_id}" if distro_id != "generic" else ""
        qualifier = f"?arch={quote(architecture, safe='._-')}&distro={quote(distro_id + '-' + distro_version, safe='._-')}"
        purl = f"pkg:{purl_type}{namespace}/{name}@{version}{qualifier}"
        package_ref = f"SPDXRef-Package-{uuid5(NAMESPACE_URL, purl).hex}"
        spdx_packages.append(
            {
                "SPDXID": package_ref,
                "name": package["name"],
                "versionInfo": package["version"],
                "supplier": "NOASSERTION" if supplier_name == "NOASSERTION" else f"Organization: {supplier_name}",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "primaryPackagePurpose": "LIBRARY",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": purl,
                    }
                ],
            }
        )
        relationships.append(
            {"spdxElementId": root_ref, "relationshipType": "CONTAINS", "relatedSpdxElement": package_ref}
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{asset.asset_tag}-system-sbom",
        "documentNamespace": f"https://eolwatch.local/spdx/{quote(asset.asset_tag, safe='.-_')}/{serial}",
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: EOLWatch SSH Collector-0.3.0"],
        },
        "documentDescribes": [root_ref],
        "packages": spdx_packages,
        "relationships": relationships,
    }


def parse_os_release(output: str, architecture: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.lower()] = value.strip().strip('"')
    values["architecture"] = architecture.strip() or "unknown"
    return values


def _run_command(client: paramiko.SSHClient, name: str, command: str) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=20)
    exit_code = stdout.channel.recv_exit_status()
    error = stderr.read().decode("utf-8", errors="replace").strip()
    output = stdout.read().decode("utf-8", errors="replace")
    if exit_code != 0:
        raise CollectionFailure("COMMAND", f"{name.upper()}_EXIT_{exit_code}", error or f"{name} 명령이 실패했습니다")
    return output


def collect_over_ssh(asset: models.Asset) -> dict[str, Any]:
    settings = get_settings()
    if not asset.ip_address or not asset.ssh_username:
        raise CollectionFailure("CONNECT", "TARGET_NOT_CONFIGURED", "IP 주소와 SSH 계정이 필요합니다")
    key_path: Optional[str] = settings.ssh_private_key_path or None
    if key_path and not Path(key_path).is_file():
        raise CollectionFailure("AUTH", "KEY_NOT_FOUND", "설정한 SSH 개인키 파일이 없습니다")

    client = paramiko.SSHClient()
    if settings.ssh_known_hosts_path:
        client.load_host_keys(settings.ssh_known_hosts_path)
    else:
        client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy() if settings.ssh_strict_host_key else paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=asset.ip_address,
            port=asset.ssh_port,
            username=asset.ssh_username,
            key_filename=key_path,
            timeout=settings.ssh_connect_timeout_seconds,
            banner_timeout=settings.ssh_connect_timeout_seconds,
            auth_timeout=settings.ssh_connect_timeout_seconds,
            look_for_keys=not bool(key_path),
            allow_agent=not bool(key_path),
        )
        raw = {name: _run_command(client, name, command) for name, command in COMMANDS.items()}
    except paramiko.AuthenticationException as exc:
        raise CollectionFailure("AUTH", "AUTHENTICATION_FAILED", "SSH 키 인증에 실패했습니다") from exc
    except (paramiko.SSHException, socket.timeout, OSError) as exc:
        raise CollectionFailure("CONNECT", type(exc).__name__.upper(), str(exc)) from exc
    finally:
        client.close()

    cpu = _number(raw["cpu"], "cpu")
    memory = _number(raw["memory"], "memory")
    uptime = int(_number(raw["uptime"], "uptime"))
    disks = parse_disks(raw["disk"])
    max_disk = max((item["used_percent"] for item in disks), default=0.0)
    return {
        "cpu_percent": round(cpu, 2),
        "memory_percent": round(memory, 2),
        "max_disk_percent": round(max_disk, 2),
        "uptime_seconds": uptime,
        "health_level": health_level(cpu, memory, max_disk),
        "disk_details": disks,
        "process_details": parse_processes(raw["process"]),
        "packages": parse_packages(raw["packages"]),
        "package_context": parse_os_release(raw["os_release"], raw["architecture"]),
    }


def run_collection(db: Session, asset_id: int, trigger_type: str = "MANUAL") -> models.CollectionJob:
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise CollectionFailure("CONNECT", "ASSET_NOT_FOUND", "자산이 없습니다")
    job = models.CollectionJob(
        asset_id=asset_id,
        trigger_type=trigger_type,
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    try:
        metrics = collect_over_ssh(asset)
        packages = metrics.pop("packages")
        package_context = metrics.pop("package_context")
        db.add(
            models.CheckResult(
                collection_job_id=job.id,
                raw_metrics={"package_count": len(packages), "packages": packages, "package_context": package_context},
                **metrics,
            )
        )
        job.status = "SUCCESS"
    except CollectionFailure as failure:
        job.status = "FAILED"
        job.failure_stage = failure.stage
        job.failure_code = failure.code
        job.failure_message = failure.message[:2000]
    job.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(job)
    return job
