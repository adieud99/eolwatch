"""Fixed scan profiles shared by web analysis validation and the executor."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Optional, Tuple


DEFAULT_SCAN_SCOPE = "ubuntu-dpkg-installed"
ZIP_SCAN_SCOPE = "source-zip"
GIT_SCAN_SCOPE = "source-git"


@dataclass(frozen=True)
class AnalysisProfile:
    cataloger: Optional[str]
    package_type: Optional[str]
    description: str
    exclusions: Tuple[str, ...] = ()


ANALYSIS_PROFILES = {
    DEFAULT_SCAN_SCOPE: AnalysisProfile(
        cataloger="dpkg-db-cataloger",
        package_type="deb",
        description="Installed dpkg packages of an Ubuntu or Debian server; application dependencies and container images are excluded.",
        # The dpkg cataloger only reads /var/lib/dpkg (+ /etc/os-release for the distro). Everything else is
        # walked just to build syft's file index, which on a 1 GB EC2 got the process OOM-killed after the
        # kernel upgrade. Skip the trees that hold most files and no dpkg data. /usr/lib itself stays: syft reads
        # /usr/lib/os-release (the /etc/os-release symlink target) to name the distro and build pkg:deb PURLs;
        # without those grype falls back to upstream-version matching, the classic false-positive source.
        exclusions=("./proc/**", "./sys/**", "./dev/**", "./run/**", "./boot/**", "./snap/**", "./var/lib/snapd/**",
                    "./usr/lib/modules/**", "./usr/lib/x86_64-linux-gnu/**", "./usr/lib/aarch64-linux-gnu/**", "./usr/lib/python3*/**", "./usr/lib/firmware/**", "./usr/lib/systemd/**", "./usr/lib/udev/**", "./usr/lib64/**", "./usr/libexec/**", "./usr/bin/**", "./usr/sbin/**", "./usr/include/**",
                    "./usr/src/**", "./usr/share/**", "./lib/**", "./lib64/**", "./bin/**", "./sbin/**", "./var/cache/**",
                    "./var/log/**", "./var/tmp/**", "./tmp/**", "./home/**", "./root/**", "./opt/**", "./srv/**", "./mnt/**", "./media/**"),
    ),
    ZIP_SCAN_SCOPE: AnalysisProfile(
        cataloger=None, package_type=None,
        description="Installed and declared dependencies in an immutable source ZIP; nested archives and application execution are excluded.",
        exclusions=("./.git/**",),
    ),
    GIT_SCAN_SCOPE: AnalysisProfile(
        cataloger=None, package_type=None,
        description="Declared dependencies in a shallow, read-only clone of a Git repository; no build, install or application execution.",
        exclusions=("./.git/**",),
    ),
}
SUPPORTED_SCAN_SCOPES = frozenset(ANALYSIS_PROFILES)
SOURCE_SCAN_SCOPES = frozenset((ZIP_SCAN_SCOPE, GIT_SCAN_SCOPE))


def normalize_project_name(value: str) -> str:
    name = value.strip()
    # Anything a person would call a project, except path separators and control characters.
    if not re.fullmatch(r"[\w(\[][\w .()\[\]+#&@,'-]{0,79}", name, flags=re.UNICODE) or ".." in name:
        raise ValueError("프로젝트명은 1~80자이며 / \\ 같은 경로 문자는 쓸 수 없습니다.")
    return name


def normalize_repository_url(value: Optional[str]) -> str:
    """Only https URLs without embedded credentials, fragments or shell-significant characters."""
    url = (value or "").strip()
    if (not re.fullmatch(r"https://[A-Za-z0-9.\-]+(?::[0-9]{1,5})?/[A-Za-z0-9._~%/\-]+", url)
            or "@" in url or "//" in url[8:] or len(url) > 500 or ".." in url):
        raise ValueError("저장소 주소는 계정 정보가 없는 https:// 주소여야 합니다.")
    return url.rstrip("/")


def normalize_git_ref(value: Optional[str]) -> Optional[str]:
    ref = (value or "").strip()
    if not ref:
        return None
    if ref.startswith("-") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/\-]{0,199}", ref) or ".." in ref or ref.endswith(".lock"):
        raise ValueError("브랜치·태그 이름 형식이 올바르지 않습니다.")
    return ref


def scope_identity(profile: str, project_name: Optional[str] = None) -> str:
    if profile in SOURCE_SCAN_SCOPES:
        return profile + ":" + normalize_project_name(project_name or "")
    if profile not in SUPPORTED_SCAN_SCOPES:
        raise ValueError("지원하지 않는 분석 범위입니다.")
    return profile
