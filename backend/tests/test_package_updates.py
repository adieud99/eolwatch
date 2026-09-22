"""Package-manager cross-check of grype's fixed-version verdicts."""
from __future__ import annotations

import json

import pytest

from app.services import package_updates as pu

APT_OUTPUT = """MANAGER=apt
REFRESHED=yes
Listing...
curl/resolute-updates,resolute-security 8.18.0-1ubuntu2.5 amd64 [upgradable from: 8.18.0-1ubuntu2.1]
libssl3t64/resolute-updates,resolute-security 3.5.5-1ubuntu3.5 amd64 [upgradable from: 3.5.5-1ubuntu3]
linux-aws/resolute-updates,resolute-security 7.0.0-1012.12 amd64 [upgradable from: 7.0.0-1006.6]
"""


def test_apt_and_rpm_outputs_are_parsed():
    apt = pu.parse_updates(APT_OUTPUT)
    assert apt["manager"] == "apt" and apt["refreshed"] is True
    assert apt["packages"]["libssl3t64"] == {"candidate": "3.5.5-1ubuntu3.5", "installed": "3.5.5-1ubuntu3"}
    assert set(apt["packages"]) == {"curl", "libssl3t64", "linux-aws"}
    rpm = pu.parse_updates("MANAGER=rpm\nREFRESHED=yes\n\nopenssl.x86_64   1:3.0.7-27.el9   baseos\nkernel.x86_64  5.14.0-503.el9  baseos\n")
    assert rpm["manager"] == "rpm" and rpm["packages"]["openssl"]["candidate"] == "1:3.0.7-27.el9" and "kernel" in rpm["packages"]
    none = pu.parse_updates("MANAGER=none\n")
    assert none["manager"] is None and none["packages"] == {}
    assert pu.parse_updates(json.dumps({"artifacts": []}))["manager"] is None  # garbage is not an update list


@pytest.mark.parametrize("a,b,expected", [
    ("3.5.5-1ubuntu3.5", "3.5.5-1ubuntu3.2", 1), ("3.5.5-1ubuntu3", "3.5.5-1ubuntu3.2", -1), ("3.5.5-1ubuntu3.2", "3.5.5-1ubuntu3.2", 0),
    ("1:2.7-2ubuntu1.1", "2.7-2ubuntu1.1", 1), ("2:9.1.2141-1ubuntu4.9", "2:9.1.2141-1ubuntu4.2", 1), ("1.0~rc1", "1.0", -1),
    ("7.0.0-1012.12", "7.0.0-1006.6", 1), ("8.18.0-1ubuntu2.5", "8.18.0-1ubuntu2.10", -1), ("1.2a", "1.2", 1), ("1.2", "1.2+dfsg", -1),
])
def test_debian_version_ordering(a, b, expected):
    assert pu.compare_versions(a, b) == expected
    assert pu.compare_versions(b, a) == -expected


def test_remote_command_forces_an_english_locale():
    assert pu.REMOTE_COMMAND.startswith("export LC_ALL=C LANG=C;")
    assert pu.parse_updates("MANAGER=apt\nREFRESHED=yes\ncurl/x 8.1 amd64 [업그레이드 가능 (현재): 8.0]\n")["packages"] == {}  # what a Korean locale would print


def test_fix_check_says_what_the_repository_really_offers():
    updates = pu.parse_updates(APT_OUTPUT)
    assert pu.fix_check("libssl3t64", ["3.5.5-1ubuntu3.2"], updates) == pu.UPDATE_AVAILABLE
    assert pu.fix_check("libssl3t64", ["3.5.5-1ubuntu3.9"], updates) == pu.UPDATE_BELOW_FIX
    assert pu.fix_check("vim", ["2:9.1.2141-1ubuntu4.9"], updates) == pu.NO_UPDATE_FOUND      # nothing to upgrade: suspect
    assert pu.fix_check("vim", [], updates) is None                                          # no fix expected: nothing to check
    assert pu.fix_check("vim", ["1"], None) is None and pu.fix_check("vim", ["1"], {"manager": None, "packages": {}}) is None


def test_apk_and_zypper_outputs_are_parsed():
    from app.services.package_updates import parse_updates
    apk = parse_updates("MANAGER=apk\nREFRESHED=yes\nopenssl-3.1.4-r5 < 3.1.4-r6\nbusybox-1.36.1-r15 < 1.36.1-r19\n")
    assert apk["manager"] == "apk" and apk["packages"]["openssl"] == {"candidate": "3.1.4-r6", "installed": "3.1.4-r5"}
    zyp = parse_updates("MANAGER=zypper\nREFRESHED=yes\nS | Repository | Name | Current Version | Available Version | Arch\n--+---\nv | Main | curl | 8.0.1-150400.5.44.1 | 8.0.1-150400.5.47.1 | x86_64\n")
    assert zyp["packages"]["curl"] == {"candidate": "8.0.1-150400.5.47.1", "installed": "8.0.1-150400.5.44.1"}
