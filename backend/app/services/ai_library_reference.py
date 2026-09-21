"""AI library reference: the dependency list for a source tree that has no lockfile.

Syft can only name components it finds pinned in a lockfile or manifest. Many student and
demo repositories ship none, so the scan used to stop with EMPTY_COLLECTION. This step reads
the evidence a human reviewer would (import statements, unpinned manifests) and asks the AI
to name the registry packages and their most likely versions. The result is an SPDX 2.3
document whose creator and per-package comments say the versions are AI estimates; grype then
matches it like any other SBOM. Nothing here runs the source.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, Optional
import uuid

from packageurl import PackageURL

SYSTEM_PROMPT = (
    "너는 소스 코드에서 사용 라이브러리를 식별하는 보조자다. 주어진 import 목록과 의존성 파일 조각만 근거로 삼는다. "
    "각 항목은 패키지 저장소(PyPI·npm·Maven·Go·RubyGems·Packagist·crates.io)에 실제로 있는 이름으로 적는다. "
    "예: import yaml→PyPI PyYAML, cv2→opencv-python, sklearn→scikit-learn, PIL→Pillow, bs4→beautifulsoup4, dotenv→python-dotenv. "
    "버전은 의존성 파일에 적힌 값(하한이면 그 값)을 우선 쓰고, 없으면 프로젝트 시점에 널리 쓰인 안정 버전 하나를 추정해 confidence를 low로 둔다. "
    "표준 라이브러리, 프로젝트 안의 자체 모듈, 근거 없는 라이브러리는 넣지 않는다. "
    'JSON 객체 하나만 답한다: {"libraries":[{"ecosystem":"pypi|npm|maven|golang|gem|composer|cargo","name":"...","version":"...","confidence":"high|medium|low","evidence":"근거 한 줄"}]}'
)

MANIFEST_FILES = ("requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "environment.yml",
                  "package.json", "build.gradle", "build.gradle.kts", "pom.xml", "go.mod", "Gemfile", "composer.json", "Cargo.toml")
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build", "target", "vendor", ".idea", ".vscode", "site-packages"}
SOURCE_SUFFIXES = {".py": "pypi", ".js": "npm", ".jsx": "npm", ".ts": "npm", ".tsx": "npm", ".mjs": "npm", ".cjs": "npm",
                   ".java": "maven", ".kt": "maven", ".go": "golang", ".rb": "gem", ".php": "composer", ".rs": "cargo"}
MAX_FILES = 400
MAX_FILE_BYTES = 200 * 1024
MAX_MANIFESTS = 6
MAX_MANIFEST_CHARS = 1500
MAX_IMPORTS_PER_ECOSYSTEM = 60
MAX_LIBRARIES = 40
NAME_PATTERN = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9._\-/@:]{0,120}$")
VERSION_PATTERN = re.compile(r"^v?[0-9][0-9A-Za-z.\-+_]{0,60}$")
ECOSYSTEMS = {"pypi": "pypi", "npm": "npm", "maven": "maven", "golang": "golang", "gem": "gem", "composer": "composer", "cargo": "cargo"}

IMPORT_PATTERNS = {
    "pypi": [re.compile(r"^\s*import\s+([A-Za-z_][A-Za-z0-9_]*)", re.M), re.compile(r"^\s*from\s+([A-Za-z_][A-Za-z0-9_]*)[.\w]*\s+import", re.M)],
    "npm": [re.compile(r"""(?:import|export)\s[^'"\n]*?from\s+['"]([^'"\n]+)['"]"""), re.compile(r"""import\s+['"]([^'"\n]+)['"]"""),
            re.compile(r"""require\(\s*['"]([^'"\n]+)['"]\s*\)""")],
    "maven": [re.compile(r"^\s*import\s+(?:static\s+)?([a-z][\w]*(?:\.[\w]+){1,3})", re.M)],
    "golang": [re.compile(r"""^\s*(?:import\s+)?(?:\w+\s+)?"([a-z0-9][\w.\-]*\.[a-z]{2,}/[^"\n]+)"\s*$""", re.M)],
    "gem": [re.compile(r"""^\s*require\s+['"]([A-Za-z0-9_\-/]+)['"]""", re.M)],
    "composer": [re.compile(r"^\s*use\s+([A-Z][\w]*(?:\\[\w]+)+)", re.M)],
    "cargo": [re.compile(r"^\s*(?:extern\s+crate|use)\s+([a-z][a-z0-9_]*)", re.M)],
}
PYTHON_STDLIB = getattr(sys, "stdlib_module_names", None) or {
    "os", "sys", "re", "json", "time", "datetime", "math", "random", "typing", "pathlib", "collections", "itertools", "functools",
    "subprocess", "logging", "unittest", "argparse", "io", "csv", "sqlite3", "threading", "asyncio", "http", "urllib", "socket",
    "hashlib", "base64", "uuid", "copy", "enum", "dataclasses", "abc", "string", "textwrap", "shutil", "tempfile", "glob", "struct",
    "pickle", "queue", "signal", "traceback", "warnings", "contextlib", "inspect", "importlib", "email", "html", "xml", "decimal",
    "fractions", "statistics", "secrets", "operator", "heapq", "bisect", "array", "zipfile", "tarfile", "gzip", "configparser", "platform",
}
JS_BUILTINS = {"fs", "path", "os", "http", "https", "url", "util", "crypto", "events", "stream", "child_process", "assert", "buffer",
               "net", "zlib", "readline", "querystring", "worker_threads", "cluster", "dns", "tls", "dgram", "process", "vm", "module"}
JAVA_BUILTIN_PREFIXES = ("java.", "javax.", "jakarta.", "kotlin.", "kotlinx.", "android.", "sun.", "jdk.")


# Import name -> PyPI project, for the cases small models keep getting wrong even when told.
PYPI_ALIASES = {"pil": "Pillow", "yaml": "PyYAML", "cv2": "opencv-python", "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
                "dotenv": "python-dotenv", "jwt": "PyJWT", "dateutil": "python-dateutil", "mysqldb": "mysqlclient", "attr": "attrs",
                "crypto": "pycryptodome", "serial": "pyserial", "openssl": "pyOpenSSL", "magic": "python-magic", "ldap": "python-ldap",
                "docx": "python-docx", "pptx": "python-pptx", "telegram": "python-telegram-bot", "discord": "discord.py", "socks": "PySocks",
                "nacl": "PyNaCl", "zmq": "pyzmq", "flask_sqlalchemy": "Flask-SQLAlchemy", "flask_cors": "Flask-Cors", "flask_login": "Flask-Login",
                "flask_wtf": "Flask-WTF", "wtforms": "WTForms", "googleapiclient": "google-api-python-client", "skimage": "scikit-image",
                "gi": "PyGObject", "Levenshtein": "python-Levenshtein", "markdown": "Markdown", "psycopg": "psycopg", "sqlalchemy": "SQLAlchemy"}


class LibraryReferenceError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _local_names(root: Path, files: list[Path]) -> set[str]:
    """Top-level names defined by the project itself (packages, modules, directories) so they are not sent as libraries."""
    names = set()
    for child in root.iterdir():
        names.add(child.stem.lower())
    for file in files:
        names.add(file.stem.lower())
        names.update(part.lower() for part in file.relative_to(root).parts[:-1])
    return names


def _walk(root: Path) -> list[Path]:
    files: list[Path] = []
    for directory, subdirs, names in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(names):
            path = Path(directory) / name
            if path.suffix in SOURCE_SUFFIXES or name in MANIFEST_FILES:
                files.append(path)
            if len(files) >= MAX_FILES:
                return files
    return files


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _import_name(ecosystem: str, raw: str) -> Optional[str]:
    if ecosystem == "pypi":
        return None if raw in PYTHON_STDLIB or raw.startswith("_") else raw
    if ecosystem == "npm":
        if raw.startswith((".", "/", "~", "@/", "node:")) or raw in JS_BUILTINS:
            return None
        parts = raw.split("/")
        return "/".join(parts[:2]) if raw.startswith("@") else parts[0]
    if ecosystem == "maven":
        return None if raw.startswith(JAVA_BUILTIN_PREFIXES) else ".".join(raw.split(".")[:3])
    if ecosystem == "golang":
        return "/".join(raw.split("/")[:3])
    if ecosystem == "cargo":
        return None if raw in {"std", "core", "alloc", "crate", "self", "super"} else raw
    return raw


def gather_evidence(directory: str | Path) -> dict[str, Any]:
    """What the AI is allowed to see: capped import names per ecosystem and the head of each manifest."""
    root = Path(directory)
    files = _walk(root)
    local = _local_names(root, files)
    imports: dict[str, dict[str, int]] = {}
    manifests: list[dict[str, str]] = []
    newest = 0.0
    scanned = 0
    for path in files:
        text = _read(path)
        if not text:
            continue
        try:
            newest = max(newest, path.stat().st_mtime)
        except OSError:
            pass
        if path.name in MANIFEST_FILES:
            if len(manifests) < MAX_MANIFESTS:
                manifests.append({"file": str(path.relative_to(root)), "head": text[:MAX_MANIFEST_CHARS]})
            continue
        scanned += 1
        ecosystem = SOURCE_SUFFIXES[path.suffix]
        for pattern in IMPORT_PATTERNS.get(ecosystem, []):
            for match in pattern.findall(text):
                name = _import_name(ecosystem, match)
                if name and name.lower() not in local:
                    bucket = imports.setdefault(ecosystem, {})
                    bucket[name] = bucket.get(name, 0) + 1
    compact = {eco: [name for name, _ in sorted(bucket.items(), key=lambda item: (-item[1], item[0]))[:MAX_IMPORTS_PER_ECOSYSTEM]]
               for eco, bucket in imports.items()}
    year = datetime.fromtimestamp(newest, tz=timezone.utc).year if newest else None
    return {"source_files": scanned, "manifests": manifests, "imports": compact, "newest_file_year": year}


def build_prompt(evidence: dict[str, Any]) -> str:
    counts = ", ".join(f"{eco} {len(names)}개" for eco, names in (evidence.get("imports") or {}).items())
    ask = ("소스에서 쓰는 외부 라이브러리와 버전을 추정하라. imports는 소스 파일의 import 이름(생태계별), manifests는 의존성 파일 앞부분이다. "
           f"imports의 모든 생태계({counts or '없음'})를 빠짐없이 다루어 import 이름마다 해당 패키지를 하나씩 적고, manifests의 의존성도 모두 적는다.")
    if evidence.get("newest_file_year"):
        ask += f" 프로젝트의 가장 최근 파일은 {evidence['newest_file_year']}년 것이다."
    body = {"imports": evidence.get("imports") or {}, "manifests": evidence.get("manifests") or []}
    return ask + "\n" + json.dumps(body, ensure_ascii=False, separators=(",", ":"))


def _purl(ecosystem: str, name: str, version: str) -> Optional[str]:
    try:
        if ecosystem == "maven":
            group, _, artifact = name.rpartition(":")
            if not group:
                group, _, artifact = name.rpartition(".")
            if not group or not artifact:
                return None
            return PackageURL(type="maven", namespace=group, name=artifact, version=version).to_string()
        if ecosystem == "npm" and name.startswith("@") and "/" in name:
            scope, _, package = name.partition("/")
            return PackageURL(type="npm", namespace=scope, name=package, version=version).to_string()
        if ecosystem == "golang":
            namespace, _, package = name.rpartition("/")
            return PackageURL(type="golang", namespace=namespace or None, name=package, version=version).to_string()
        if ecosystem == "composer" and "/" in name:
            vendor, _, package = name.partition("/")
            return PackageURL(type="composer", namespace=vendor, name=package, version=version).to_string()
        if ecosystem == "pypi":
            name = name.lower().replace("_", "-")
        return PackageURL(type=ecosystem, name=name, version=version).to_string()
    except ValueError:
        return None


def validate_libraries(answer: dict[str, Any], evidence: Optional[dict[str, Any]] = None) -> list[dict[str, str]]:
    """Keep only well-formed entries; the AI's shape is never trusted blindly.

    A version that no manifest mentions is a guess whatever the model claims, so its confidence is capped at low.
    """
    rows = answer.get("libraries") if isinstance(answer, dict) else None
    manifest_text = " ".join(m.get("head", "") for m in (evidence or {}).get("manifests") or []).lower()
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        ecosystem = ECOSYSTEMS.get(str(row.get("ecosystem", "")).lower().strip())
        name = str(row.get("name", "")).strip()
        if ecosystem == "pypi":
            name = PYPI_ALIASES.get(name.lower(), name)
        version = str(row.get("version", "")).strip().lstrip("^~=<>! ")
        if not ecosystem or not NAME_PATTERN.match(name) or not VERSION_PATTERN.match(version):
            continue
        purl = _purl(ecosystem, name, version)
        if not purl or purl in seen:
            continue
        seen.add(purl)
        confidence = str(row.get("confidence", "low")).lower()
        if confidence not in {"high", "medium", "low"} or (evidence is not None and name.lower() not in manifest_text):
            confidence = "low"
        result.append({"ecosystem": ecosystem, "name": name, "version": version, "purl": purl, "confidence": confidence,
                       "evidence": str(row.get("evidence", ""))[:160]})
        if len(result) >= MAX_LIBRARIES:
            break
    return result


def to_spdx(libraries: list[dict[str, str]], *, project_name: str, model: str, evidence: dict[str, Any]) -> dict[str, Any]:
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    packages = []
    for index, library in enumerate(libraries, start=1):
        packages.append({
            "SPDXID": f"SPDXRef-Package-{index}",
            "name": library["name"], "versionInfo": library["version"],
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "supplier": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": library["purl"]}],
            "comment": f"AI 추정 · 신뢰도 {library['confidence']}" + (f" · 근거: {library['evidence']}" if library["evidence"] else ""),
        })
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project_name} (AI library reference)",
        "documentNamespace": f"https://eolwatch.local/spdx/ai-reference/{uuid.uuid4()}",
        "creationInfo": {"created": created, "creators": ["Tool: EOLWatch-AI-Library-Reference", f"Tool: {model}"],
                         "comment": (f"잠금 파일이 없어 AI가 import {sum(len(v) for v in (evidence.get('imports') or {}).values())}건과 "
                                     f"의존성 파일 {len(evidence.get('manifests') or [])}개를 근거로 추정한 목록입니다. 버전은 추정값이며 실제 설치 버전과 다를 수 있습니다.")},
        "packages": packages,
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": package["SPDXID"]} for package in packages],
    }


def reference_libraries(directory: str | Path, *, project_name: str,
                        complete_json: Callable[..., tuple[dict[str, Any], str, dict[str, int]]]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (spdx_document, manifest_entry). Raises LibraryReferenceError when there is nothing to go on or the AI fails."""
    evidence = gather_evidence(directory)
    if not evidence["imports"] and not evidence["manifests"]:
        raise LibraryReferenceError("NO_EVIDENCE", "소스에서 import 문이나 의존성 파일을 찾지 못해 AI 라이브러리 참조를 할 수 없습니다.")
    prompt = build_prompt(evidence)
    try:
        answer, model, usage = complete_json(prompt, system=SYSTEM_PROMPT)
    except Exception as error:  # provider errors carry a user-facing message in .detail
        detail = getattr(error, "detail", None) or str(error)
        raise LibraryReferenceError("AI_UNAVAILABLE", f"AI 라이브러리 참조에 실패했습니다: {detail}") from error
    libraries = validate_libraries(answer, evidence)
    if not libraries:
        raise LibraryReferenceError("NO_LIBRARIES", "AI가 근거 있는 외부 라이브러리를 찾지 못했습니다.")
    spdx = to_spdx(libraries, project_name=project_name, model=model, evidence=evidence)
    entry = {"model": model, "library_count": len(libraries), "prompt_chars": len(prompt), "source_files": evidence["source_files"],
             "manifests": [m["file"] for m in evidence["manifests"]], "input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens"),
             "libraries": [{k: library[k] for k in ("ecosystem", "name", "version", "confidence")} for library in libraries]}
    return spdx, entry
