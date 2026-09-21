import pytest
from datetime import datetime, timezone

from app.models import Asset
from app.services.collector import health_level, packages_to_cyclonedx, parse_disks, parse_packages, parse_processes
from app.services.sbom import validate_cyclonedx_schema


def test_collector_parsers():
    assert parse_disks("/|42%\n/data|91%\n") == [
        {"mount": "/", "used_percent": 42.0},
        {"mount": "/data", "used_percent": 91.0},
    ]
    assert parse_processes("  4 nginx\n  1 postgres\n") == [
        {"count": 4, "name": "nginx"},
        {"count": 1, "name": "postgres"},
    ]
    assert parse_packages("openssl|3.0.2\nnginx|1.24.0\ninvalid\n") == [
        {"name": "openssl", "version": "3.0.2"},
        {"name": "nginx", "version": "1.24.0"},
    ]
    assert health_level(30, 50, 79) == "NORMAL"
    assert health_level(80, 50, 40) == "WARN"
    assert health_level(20, 91, 30) == "CRITICAL"


def test_package_inventory_becomes_cyclonedx():
    asset = Asset(asset_tag="SRV-001", name="DB 서버", asset_type="server")
    document = packages_to_cyclonedx(
        asset,
        [{"name": "openssl", "version": "3.0.2"}, {"name": "nginx", "version": "1.24.0"}],
        datetime(2026, 9, 11, 0, 0, tzinfo=timezone.utc),
    )
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.7"
    assert len(document["components"]) == 2
    assert len(document["dependencies"][0]["dependsOn"]) == 2
    validate_cyclonedx_schema(document, "1.7")


def test_server_info_parsers_cover_hardware_cloud_and_network():
    from app.services.collector import (
        build_server_info, detect_platform, parse_cloud_metadata, parse_disk_totals, parse_ip_addresses,
        parse_listening_ports, parse_services,
    )

    assert parse_cloud_metadata("") is None
    assert parse_cloud_metadata("<html>not json</html>") is None
    cloud = parse_cloud_metadata('{"instanceId": "i-0abc", "instanceType": "t3.small", "region": "ap-northeast-2", "availabilityZone": "ap-northeast-2a", "accountId": "1234", "imageId": "ami-1"}')
    assert cloud == {"provider": "aws", "instance_id": "i-0abc", "instance_type": "t3.small", "region": "ap-northeast-2", "availability_zone": "ap-northeast-2a", "account_id": "1234", "image_id": "ami-1"}
    assert parse_disk_totals("/|53687091200|21474836480\n/boot|bad|1\n") == [{"mount": "/", "total_bytes": 53687091200, "used_bytes": 21474836480}]
    assert parse_ip_addresses("enp0s3|10.0.2.15/24\nlo|\n") == [{"interface": "enp0s3", "address": "10.0.2.15/24"}]
    assert parse_listening_ports("tcp|0.0.0.0:22\ntcp|[::]:22\ntcp|127.0.0.1:5432\ntcp|0.0.0.0:22\nbad line\n") == [
        {"protocol": "tcp", "address": "0.0.0.0", "port": 22},
        {"protocol": "tcp", "address": "[::]", "port": 22},
        {"protocol": "tcp", "address": "127.0.0.1", "port": 5432},
    ]
    assert parse_services("ssh.service\nnginx.service\nnot-a-service\nssh.service\n") == ["ssh", "nginx"]
    assert detect_platform("kvm", "QEMU", "Standard PC", None) == "kvm"
    assert detect_platform("", "Dell Inc.", "PowerEdge R750", None) == "physical"
    assert detect_platform("", "", "", None) == "unknown"
    assert detect_platform("kvm", "Amazon EC2", "t3.small", None) == "aws"
    assert detect_platform("oracle", "innotek GmbH", "VirtualBox", None) == "oracle"

    raw = {
        "hostname": "lab-vm-01\n", "kernel": "6.8.0-45-generic\n", "cpu_model": "Intel(R) Core(TM) i7\n", "cpu_cores": "4\n",
        "memory_total": "8147300\n", "disk_totals": "/|53687091200|21474836480\n", "virtualization": "oracle\n",
        "dmi_vendor": "innotek GmbH\n", "dmi_product": "VirtualBox\n", "cloud_metadata": "",
        "ip_addresses": "enp0s3|10.0.2.15/24\n", "listening_ports": "tcp|0.0.0.0:22\n", "services": "ssh.service\n",
    }
    info = build_server_info(raw, {"pretty_name": "Ubuntu 24.04.1 LTS", "id": "ubuntu", "version_id": "24.04", "architecture": "x86_64"})
    assert info["hostname"] == "lab-vm-01" and info["kernel"] == "6.8.0-45-generic"
    assert info["os_name"] == "Ubuntu 24.04.1 LTS" and info["os_id"] == "ubuntu" and info["architecture"] == "x86_64"
    assert info["cpu_model"] == "Intel(R) Core(TM) i7" and info["cpu_cores"] == 4 and info["memory_total_mb"] == 7956
    assert info["platform"] == "oracle" and info["cloud"] is None
    assert info["ip_addresses"] == [{"interface": "enp0s3", "address": "10.0.2.15/24"}]
    assert info["listening_ports"][0]["port"] == 22 and info["services"] == ["ssh"]

    empty = build_server_info({}, {})
    assert empty["platform"] == "unknown" and empty["cpu_cores"] is None and empty["disks"] == [] and empty["services"] == []


def test_command_failure_reports_the_servers_first_line():
    from types import SimpleNamespace
    from app.services.collector import CollectionFailure, _run_command
    class Chan:
        def recv_exit_status(self): return 142
    class Stream:
        def __init__(self, data): self.data = data; self.channel = Chan()
        def read(self): return self.data
    client = SimpleNamespace(exec_command=lambda *a, **k: (None, Stream(b'Please login as the user "ubuntu" rather than the user "root".\n'), Stream(b"")))
    with pytest.raises(CollectionFailure) as failure:
        _run_command(client, "uptime", "cut -d. -f1 /proc/uptime")
    assert failure.value.code == "UPTIME_EXIT_142" and 'login as the user "ubuntu"' in failure.value.message
