"""Conservative package/version matching for OSV records.

Ordering follows https://ossf.github.io/osv-schema/ (range event pseudocode).
PEP 440 and SemVer are delegated to their maintained parser libraries. We do
not compare Git hashes or apply SemVer ordering to arbitrary ecosystems.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any, Optional

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError
from packaging.utils import canonicalize_name
from packaging.version import Version as PythonVersion
from packageurl import PackageURL
from semantic_version import Version as SemVersion


SEVERITY_RANK = {"UNKNOWN": 0, "NONE": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "golang": "Go", "cargo": "crates.io",
              "maven": "Maven", "nuget": "NuGet", "gem": "RubyGems", "composer": "Packagist",
              "hex": "Hex", "pub": "Pub", "swift": "SwiftURL", "hackage": "Hackage"}


def parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\d[Tt]\d\d:\d\d:\d\d(?:\.\d+)?(?:[Zz]|[+-]\d\d:\d\d)", value):
        raise ValueError("RFC 3339 timestamp required")
    # OSV emits nanoseconds, while Python 3.9 accepts microseconds only.
    normalized = re.sub(r"(\.\d{6})\d+", r"\1", value).upper().replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def maximum_severity(values: list[str]) -> str:
    normalized = [value if value in SEVERITY_RANK else "UNKNOWN" for value in values]
    return max(normalized or ["UNKNOWN"], key=lambda value: SEVERITY_RANK[value])


def severity(item: dict[str, Any], affected: Optional[list[dict[str, Any]]] = None) -> str:
    """Use the highest valid supplied base rating, including package ratings."""
    ratings = []
    scopes = [item, *(affected or [])]
    for scope in scopes:
        value = (scope.get("database_specific") or {}).get("severity")
        if isinstance(value, str):
            value = value.upper()
            value = "MEDIUM" if value == "MODERATE" else value
            if value in SEVERITY_RANK:
                ratings.append(value)
        for metric in scope.get("severity") or []:
            if not isinstance(metric, dict) or not isinstance(metric.get("score"), str):
                continue
            parser = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}.get(metric.get("type"))
            if parser is None:
                continue
            try:
                # The library uses FIRST's version-specific qualitative scales.
                ratings.append(parser(metric["score"]).severities()[0].upper())
            except (CVSSError, ValueError, TypeError, ArithmeticError):
                continue
    return maximum_severity(ratings)


@dataclass(frozen=True)
class PackageContext:
    purl: PackageURL
    version: Optional[str]

    @property
    def ecosystem(self) -> Optional[str]:
        return ECOSYSTEMS.get(self.purl.type)


def package_context(component: Any) -> PackageContext:
    try:
        parsed = PackageURL.from_string(component.purl)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f"구성요소 {component.id}의 PURL이 올바르지 않습니다") from exc
    version = component.version or parsed.version
    if parsed.version and component.version and parsed.version != component.version:
        # A normalized equivalent (e.g. PyPI 1.0 == 1.0.0) is safe; otherwise
        # querying one value while recommending against another is not.
        context = PackageContext(parsed, component.version)
        try:
            equivalent = _version(context, parsed.version, "ECOSYSTEM") == _version(context, component.version, "ECOSYSTEM")
        except ValueError:
            equivalent = False
        if not equivalent:
            raise ValueError(f"구성요소 {component.id}의 PURL 버전과 설치 버전이 다릅니다")
    return PackageContext(parsed, version)


def osv_query(context: PackageContext) -> Optional[dict[str, Any]]:
    if not context.version:
        return None
    # Parse the version field; '@' may instead be an npm scope or URL qualifier.
    query: dict[str, Any] = {"package": {"purl": context.purl.to_string()}}
    if not context.purl.version:
        query["version"] = context.version
    return query


def _identity(purl: PackageURL) -> tuple[str, Optional[str], str]:
    name = canonicalize_name(purl.name) if purl.type == "pypi" else purl.name
    return purl.type, purl.namespace, name


def package_matches(context: PackageContext, package: dict[str, Any]) -> bool:
    purl = context.purl
    if package.get("purl"):
        try:
            affected_purl = PackageURL.from_string(package["purl"])
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("OSV affected.package.purl이 올바르지 않습니다") from exc
        if affected_purl.version:
            raise ValueError("OSV affected.package.purl에는 버전이 없어야 합니다")
        if _identity(purl) != _identity(affected_purl):
            return False
        if any(purl.qualifiers.get(key) != value for key, value in affected_purl.qualifiers.items()):
            return False
        if affected_purl.subpath and affected_purl.subpath != purl.subpath:
            return False
        # Still check the required ecosystem/name: a contradictory advisory
        # identifier must not turn another package's fix into our recommendation.
        if context.ecosystem and package["ecosystem"] != context.ecosystem:
            return False
    elif context.ecosystem != package["ecosystem"]:
        # OS version ordering is unsupported, but exact distro identity can
        # still establish the package association returned by OSV.
        distro = purl.qualifiers.get("distro", "")
        expected = package["ecosystem"].split(":")
        if not (purl.type == "deb" and purl.namespace in {"debian", "ubuntu"}
                and len(expected) >= 2 and expected[0].lower() == purl.namespace
                and distro == f"{purl.namespace}-{expected[1]}"):
            return False
    expected_name = f"{purl.namespace}/{purl.name}" if purl.namespace else purl.name
    if purl.type == "maven" and purl.namespace:
        expected_name = f"{purl.namespace}:{purl.name}"
    if purl.type in {"deb", "rpm", "apk"}:
        expected_name = purl.name
    actual_name = package["name"]
    if purl.type == "pypi":
        expected_name, actual_name = canonicalize_name(expected_name), canonicalize_name(actual_name)
    elif purl.type == "nuget":
        expected_name, actual_name = expected_name.lower(), actual_name.lower()
    return actual_name in {expected_name, "*"}


def _version(context: PackageContext, value: str, range_type: str) -> Any:
    if range_type == "ECOSYSTEM" and context.ecosystem == "PyPI":
        return PythonVersion(value)
    if range_type == "SEMVER" or (range_type == "ECOSYSTEM" and context.ecosystem in {"npm", "Go", "crates.io"}):
        # Go package versions conventionally include a v prefix. Do not coerce
        # arbitrary malformed/partial ecosystem versions into semantic versions.
        if context.ecosystem == "Go" and value.startswith("v"):
            value = value[1:]
        parsed = SemVersion(value)
        # SemVer ignores build metadata for precedence (library equality does
        # not), so remove it before both ordering and equality comparisons.
        return SemVersion(major=parsed.major, minor=parsed.minor, patch=parsed.patch, prerelease=parsed.prerelease)
    raise ValueError("이 버전 순서는 지원하지 않습니다")


def _range_match(context: PackageContext, version_range: dict[str, Any], installed: str) -> tuple[Optional[bool], list[str]]:
    kind = version_range["type"]
    if kind == "GIT":
        return None, []
    try:
        version = _version(context, installed, kind)
        events = []
        limits = []
        for event in version_range["events"]:
            field, value = next(iter(event.items()))
            if field == "limit":
                limits.append(None if value == "*" else _version(context, value, kind))
            else:
                boundary = None if field == "introduced" and value == "0" else _version(context, value, kind)
                events.append((boundary, field, value))
        if limits and not any(limit is None or version < limit for limit in limits):
            return False, []
        events.sort(key=lambda event: (event[0] is not None, event[0]))
        # Conflicting events at equal precedence have no defined safe fix.
        for previous, current in zip(events, events[1:]):
            if previous[0] == current[0] and previous[1] != current[1]:
                return None, []
        affected = False
        for boundary, field, _value in events:
            if field == "introduced" and (boundary is None or version >= boundary):
                affected = True
            elif field == "fixed" and version >= boundary:
                affected = False
            elif field == "last_affected" and version > boundary:
                affected = False
        if not affected:
            return False, []
        # Only the next fixed event closes the interval containing this version.
        # A later branch's fix does not apply to an earlier installed branch.
        for boundary, field, value in events:
            if boundary is not None and boundary > version:
                if field != "fixed":
                    return True, []
                if limits and not any(limit is None or boundary < limit for limit in limits):
                    return True, []
                return True, [value]
        return True, []
    except (ValueError, TypeError, AttributeError):
        return None, []


@dataclass
class AdvisoryMatch:
    affected: Optional[bool]
    fixed_versions: list[str]
    entries: list[dict[str, Any]]


def _entries_match(context: PackageContext, entries: list[dict[str, Any]], installed: str) -> tuple[Optional[bool], set[str]]:
    states: list[Optional[bool]] = []
    fixed: set[str] = set()
    for entry in entries:
        # OSV enumerations use exact ecosystem version strings. Version ordering
        # comes from ranges; do not reinterpret a Git tag enumeration as PEP440.
        if installed in entry.get("versions", []):
            states.append(True)
        ranges = entry.get("ranges", [])
        for version_range in ranges:
            state, candidates = _range_match(context, version_range, installed)
            states.append(state)
            fixed.update(candidates)
        if not ranges and not entry.get("versions"):
            states.append(None)
    state = True if True in states else (None if None in states else False)
    return state, fixed


def match_advisory(context: PackageContext, item: dict[str, Any]) -> AdvisoryMatch:
    if item.get("withdrawn"):
        return AdvisoryMatch(False, [], [])
    entries = [entry for entry in item["affected"] if package_matches(context, entry["package"])]
    if not entries:
        return AdvisoryMatch(False, [], [])
    if not context.version:
        return AdvisoryMatch(None, [], entries)
    state, candidates = _entries_match(context, entries, context.version)
    # A candidate must be outside every matching affected range. Unsupported
    # overlapping ranges make remediation unknown, even if another range fixes.
    safe = [candidate for candidate in candidates if _entries_match(context, entries, candidate)[0] is False]
    return AdvisoryMatch(state, sort_versions(context, safe), entries)


def safe_fixed_versions(context: PackageContext, candidates: list[str], advisories: list[dict[str, Any]]) -> list[str]:
    """A CVE alias must not recommend a version another alias still affects."""
    entries = [entry for item in advisories for entry in item["affected"] if package_matches(context, entry["package"])]
    return sort_versions(context, [candidate for candidate in candidates
                                   if _entries_match(context, entries, candidate)[0] is False])


def sort_versions(context: PackageContext, versions: list[str]) -> list[str]:
    try:
        return sorted(set(versions), key=lambda value: (_version(context, value, "ECOSYSTEM"), value))
    except ValueError:
        try:
            return sorted(set(versions), key=lambda value: (_version(context, value, "SEMVER"), value))
        except ValueError:
            return sorted(set(versions))


def validate_advisory(item: Any, expected_id: Optional[str] = None) -> dict[str, Any]:
    """Validate fields consumed by the importer before it performs any writes."""
    if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"].strip():
        raise ValueError("OSV 상세 응답의 id가 없습니다")
    if expected_id is not None and item["id"] != expected_id:
        raise ValueError("OSV 상세 응답 id가 요청과 다릅니다")
    for field in ("summary", "details", "published", "modified", "withdrawn"):
        if field in item and not isinstance(item[field], str):
            raise ValueError(f"OSV {field} 형식이 올바르지 않습니다")
    for field in ("published", "modified", "withdrawn"):
        if field in item:
            try:
                parse_timestamp(item[field])
            except ValueError as exc:
                raise ValueError(f"OSV {field} 날짜가 올바르지 않습니다") from exc
    if not isinstance(item.get("aliases", []), list) or any(not isinstance(v, str) for v in item.get("aliases", [])):
        raise ValueError("OSV aliases 형식이 올바르지 않습니다")
    if not isinstance(item.get("references", []), list) or any(not isinstance(v, dict) for v in item.get("references", [])):
        raise ValueError("OSV references 형식이 올바르지 않습니다")
    entries = item.get("affected", [] if item.get("withdrawn") else None)
    if not isinstance(entries, list):
        raise ValueError("OSV affected 목록이 없습니다")
    for scope in [item, *entries]:
        if not isinstance(scope, dict):
            raise ValueError("OSV affected 항목이 올바르지 않습니다")
        if not isinstance(scope.get("database_specific", {}), dict) or not isinstance(scope.get("severity", []), list):
            raise ValueError("OSV 심각도 형식이 올바르지 않습니다")
    for entry in entries:
        package = entry.get("package")
        if not isinstance(package, dict) or any(not isinstance(package.get(key), str) or not package[key].strip() for key in ("ecosystem", "name")):
            raise ValueError("OSV affected.package 식별자가 없습니다")
        if not isinstance(entry.get("versions", []), list) or any(not isinstance(v, str) for v in entry.get("versions", [])):
            raise ValueError("OSV versions 형식이 올바르지 않습니다")
        ranges = entry.get("ranges", [])
        if not isinstance(ranges, list):
            raise ValueError("OSV ranges 형식이 올바르지 않습니다")
        for version_range in ranges:
            if not isinstance(version_range, dict) or version_range.get("type") not in {"GIT", "SEMVER", "ECOSYSTEM"}:
                raise ValueError("OSV range type이 올바르지 않습니다")
            events = version_range.get("events")
            if not isinstance(events, list) or not events:
                raise ValueError("OSV range events가 없습니다")
            fields = set()
            for event in events:
                if not isinstance(event, dict) or len(event) != 1 or next(iter(event)) not in {"introduced", "fixed", "last_affected", "limit"}:
                    raise ValueError("OSV range event가 올바르지 않습니다")
                field, value = next(iter(event.items()))
                if not isinstance(value, str) or not value:
                    raise ValueError("OSV range 버전이 올바르지 않습니다")
                fields.add(field)
            if "introduced" not in fields or {"fixed", "last_affected"} <= fields:
                raise ValueError("OSV range 경계가 올바르지 않습니다")
    return item
