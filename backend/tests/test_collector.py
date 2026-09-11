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
