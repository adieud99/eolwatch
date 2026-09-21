"""Fixed scan profiles shared by web analysis validation and the executor."""
from __future__ import annotations

from dataclasses import dataclass
import posixpath
import re
from typing import Optional, Tuple


DEFAULT_SCAN_SCOPE = "ubuntu-dpkg-installed"
DEMO_PYTHON_SCAN_SCOPE = "demo-python-venv"
SSH_PYTHON_SCAN_SCOPE = "ssh-python-environment"
SSH_PROJECT_SCAN_SCOPE = "ssh-project-directory"
ZIP_SCAN_SCOPE = "source-zip"


@dataclass(frozen=True)
class AnalysisProfile:
    cataloger: Optional[str]
    package_type: Optional[str]
    relative_directory: Optional[str]
    description: str
    exclusions: Tuple[str, ...] = ()


ANALYSIS_PROFILES = {
    DEFAULT_SCAN_SCOPE: AnalysisProfile(
        cataloger="dpkg-db-cataloger",
        package_type="deb",
        relative_directory=None,
        description="Installed Ubuntu dpkg packages; application dependencies and container images are excluded.",
        exclusions=("./proc/**", "./sys/**", "./dev/**", "./run/**"),
    ),
    DEMO_PYTHON_SCAN_SCOPE: AnalysisProfile(
        # In pinned Syft 1.51.1 python-package-cataloger reads declared packages;
        # this cataloger reads the installed Python package metadata instead.
        cataloger="python-installed-package-cataloger",
        package_type="python",
        relative_directory="eolwatch-demo/.venv",
        description="Installed Python packages in the SSH user's fixed ~/eolwatch-demo/.venv; OS packages and requirements files are excluded.",
    ),
    SSH_PYTHON_SCAN_SCOPE: AnalysisProfile(
        cataloger="python-installed-package-cataloger", package_type="python", relative_directory=None,
        description="Installed Python package metadata in the selected absolute SSH directory; no application code is executed.",
    ),
    SSH_PROJECT_SCAN_SCOPE: AnalysisProfile(
        cataloger=None, package_type=None, relative_directory=None,
        description="Installed and declared dependencies in the selected SSH project directory; no build or dependency installation.",
        exclusions=("./.git/**",),
    ),
    ZIP_SCAN_SCOPE: AnalysisProfile(
        cataloger=None, package_type=None, relative_directory=None,
        description="Installed and declared dependencies in an immutable source ZIP; nested archives and application execution are excluded.",
        exclusions=("./.git/**",),
    ),
}
SUPPORTED_SCAN_SCOPES = frozenset(ANALYSIS_PROFILES)
PATH_SCAN_SCOPES = frozenset((SSH_PYTHON_SCAN_SCOPE, SSH_PROJECT_SCAN_SCOPE))


def normalize_target_path(value: Optional[str]) -> str:
    if (not isinstance(value, str) or not value.startswith("/") or value.startswith("//")
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or ".." in value.split("/")):
        raise ValueError("앱 경로는 상위 이동(..)이 없는 절대 경로여야 합니다.")
    normalized = posixpath.normpath(value)
    if normalized == "/" or len(normalized) > 220:
        raise ValueError("앱 디렉터리를 지정하세요. 경로는 최대 220자입니다.")
    return normalized


def normalize_project_name(value: str) -> str:
    name = value.strip()
    if not re.fullmatch(r"[\w][\w .-]{0,79}", name, flags=re.UNICODE):
        raise ValueError("프로젝트명은 1~80자의 문자·숫자·공백·점·밑줄·하이픈으로 입력하세요.")
    return name


def scope_identity(profile: str, target_path: Optional[str] = None, project_name: Optional[str] = None) -> str:
    if profile in PATH_SCAN_SCOPES:
        return profile + ":" + normalize_target_path(target_path)
    if profile == ZIP_SCAN_SCOPE:
        return profile + ":" + normalize_project_name(project_name or "")
    if profile not in SUPPORTED_SCAN_SCOPES:
        raise ValueError("지원하지 않는 분석 범위입니다.")
    if target_path:
        raise ValueError("이 분석 범위에서는 앱 경로를 지정할 수 없습니다.")
    return profile
