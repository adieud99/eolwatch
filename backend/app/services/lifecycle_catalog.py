"""Public endoflife.date metadata only; inventory never leaves this process.

Schema: https://endoflife.date/docs/api/v1/openapi.yml
eoas = active support; eol = standard support including security; eoes =
extended/commercial support. Extended support is informational, not entitlement.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Optional
from urllib.parse import urljoin, urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .. import models


API_ROOT = "https://endoflife.date/api/v1/"
MAX_BYTES = 2 * 1024 * 1024
MAX_AGE = timedelta(hours=24)
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,119}\Z")
LIFECYCLE_FIELDS = ("eol_date", "support_end_date", "security_end_date", "lifecycle_source_url", "verified_at")


class CatalogError(ValueError):
    pass


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


def timestamp(value, required=False):
    if value is None and not required:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\d[Tt]\d\d:\d\d:\d\d(?:\.\d+)?(?:[Zz]|[+-]\d\d:\d\d)", value):
        raise CatalogError("공개 제공처의 시간 형식이 올바르지 않습니다.")
    try:
        return datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", value).upper().replace("Z", "+00:00"))
    except ValueError as error:
        raise CatalogError("공개 제공처의 시간 값이 올바르지 않습니다.") from error


def valid_url(value):
    if isinstance(value, str) and not any(ord(char) < 32 for char in value):
        try:
            parsed = urlsplit(value)
            if parsed.scheme in {"http", "https"} and parsed.netloc and not parsed.username and not parsed.password:
                return value
        except ValueError:
            pass
    return None


def validate_document(raw: bytes, slug: Optional[str]):
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise CatalogError("공개 응답에 중복 필드가 있습니다.")
            value[key] = item
        return value
    try:
        text = raw.decode("utf-8")
        document = json.loads(text, object_pairs_hook=unique_pairs,
                              parse_constant=lambda _value: (_ for _ in ()).throw(CatalogError("잘못된 JSON 수치입니다.")))
    except (UnicodeError, ValueError) as error:
        raise CatalogError("공개 제공처가 유효한 JSON을 반환하지 않았습니다.") from error
    if (not isinstance(document, dict) or not isinstance(document.get("schema_version"), str)
            or not document["schema_version"].startswith("1.")):
        raise CatalogError("지원하지 않는 공개 카탈로그 스키마입니다.")
    generated = timestamp(document.get("generated_at"), required=True)
    modified = timestamp(document.get("last_modified"))
    result = document.get("result")
    if slug is None:
        if not isinstance(result, list) or len(result) > 10000:
            raise CatalogError("공개 제품 목록이 올바르지 않습니다.")
        names = set()
        for item in result:
            if (not isinstance(item, dict) or not isinstance(item.get("name"), str)
                    or not SLUG.fullmatch(item["name"]) or item["name"] in names
                    or not isinstance(item.get("label"), str)):
                raise CatalogError("공개 제품 식별정보가 올바르지 않습니다.")
            names.add(item["name"])
        if "total" in document and (type(document["total"]) is not int or document["total"] != len(result)):
            raise CatalogError("공개 제품 목록의 총 건수가 응답과 다릅니다.")
    else:
        if not isinstance(result, dict) or result.get("name") != slug or not isinstance(result.get("releases"), list):
            raise CatalogError("선택한 공개 제품과 응답이 일치하지 않습니다. 공개 목록을 다시 조회하세요.")
        releases = result["releases"]
        if len(releases) > 10000:
            raise CatalogError("지원 주기 개수가 허용 범위를 초과했습니다.")
        names = set()
        for release in releases:
            if (not isinstance(release, dict) or not isinstance(release.get("name"), str)
                    or not 1 <= len(release["name"]) <= 100 or release["name"] in names
                    or type(release.get("isEol")) is not bool or "eolFrom" not in release):
                raise CatalogError("공개 제품의 지원 주기가 올바르지 않습니다.")
            names.add(release["name"])
            for field in ("eolFrom", "eoasFrom", "eoesFrom"):
                value = release.get(field)
                if value is not None:
                    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\d", value):
                        raise CatalogError("날짜가 확정되지 않은 값을 종료일로 변환할 수 없습니다.")
                    try:
                        date.fromisoformat(value)
                    except ValueError as error:
                        raise CatalogError("공개 제공처의 종료일이 올바르지 않습니다.") from error
            for field in ("isEoas", "isMaintained"):
                if field in release and type(release[field]) is not bool:
                    raise CatalogError("공개 제공처의 지원 상태가 올바르지 않습니다.")
            if "isEoes" in release and release["isEoes"] is not None and type(release["isEoes"]) is not bool:
                raise CatalogError("공개 제공처의 연장 지원 상태가 올바르지 않습니다.")
    return text, generated, modified


def cache_key(slug):
    return "products" if slug is None else "product:" + slug


def cached(db, slug=None, lock=False):
    query = select(models.LifecycleCatalogCache).where(models.LifecycleCatalogCache.cache_key == cache_key(slug))
    if lock:
        query = query.with_for_update().execution_options(populate_existing=True)
    return db.scalar(query)


def cache_read(item, now=None):
    now = now or datetime.now(timezone.utc)
    checked = utc(item.last_checked_at) if item and not item.last_error else None
    fresh = checked or (utc(item.fetched_at) if item else None)
    return {
        "available": bool(item and item.raw_document),
        "source_url": item.source_url if item else None,
        "content_sha256": item.content_sha256 if item else None,
        "fetched_at": item.fetched_at if item else None,
        "provider_generated_at": item.provider_generated_at if item else None,
        "provider_last_modified": item.provider_last_modified if item else None,
        "last_checked_at": item.last_checked_at if item else None,
        "last_error": item.last_error if item else None,
        "last_error_at": item.last_error_at if item else None,
        "stale": fresh is None or now - fresh > MAX_AGE,
    }


def payload(item):
    return json.loads(item.raw_document)["result"] if item and item.raw_document else None


def fetch_public(url, etag=None):
    """Bounded GET, provider-only redirects, no cookies or inventory payload."""
    headers = {"Accept": "application/json", "User-Agent": "EOLWatch-public-lifecycle-catalog/1"}
    if etag:
        headers["If-None-Match"] = etag
    with httpx.Client(timeout=20, follow_redirects=False, trust_env=False) as client:
        for _ in range(4):
            with client.stream("GET", url, headers=headers) as response:
                if response.status_code in {301, 302, 307, 308}:
                    redirect = urljoin(url, response.headers.get("location", ""))
                    parsed = urlsplit(redirect)
                    if (not redirect.startswith(API_ROOT) or parsed.hostname != "endoflife.date"
                            or parsed.scheme != "https" or parsed.query or parsed.fragment or parsed.username):
                        raise CatalogError("공개 제공처 외부로 이동하는 응답을 거부했습니다.")
                    url = redirect
                    continue
                if response.status_code == 304:
                    return None, response.headers.get("etag") or etag
                if response.status_code != 200:
                    raise CatalogError(f"공개 제공처 조회 실패(HTTP {response.status_code}). 이전 자료를 유지합니다.")
                data = bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data) > MAX_BYTES:
                        raise CatalogError("공개 응답이 2 MiB 제한을 초과했습니다. 이전 자료를 유지합니다.")
                return bytes(data), response.headers.get("etag")
    raise CatalogError("공개 제공처의 이동 응답이 너무 많습니다.")


def refresh(db, slug=None):
    if slug is not None:
        listing = payload(cached(db)) or []
        if not SLUG.fullmatch(slug) or slug not in {entry["name"] for entry in listing}:
            raise CatalogError("먼저 공개 제품 목록을 조회하고 그 목록에서 제품을 선택하세요.")
    source = API_ROOT + ("products/" if slug is None else "products/" + slug + "/")
    row = cached(db, slug, lock=True)
    if row is None:
        row = models.LifecycleCatalogCache(cache_key=cache_key(slug), source_url=source)
        db.add(row)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            row = cached(db, slug, lock=True)
    now = datetime.now(timezone.utc)
    try:
        data, etag = fetch_public(source, row.etag)
        if data is not None:
            text, generated, modified = validate_document(data, slug)
            row.raw_document = text
            row.content_sha256 = hashlib.sha256(data).hexdigest()
            row.fetched_at = now
            row.provider_generated_at = generated
            row.provider_last_modified = modified
        elif not row.raw_document:
            raise CatalogError("저장된 공개 자료 없이 304 응답을 받았습니다.")
        row.etag = etag if isinstance(etag, str) and len(etag) <= 1024 and not any(ord(char) < 32 for char in etag) else None
        row.last_error = None
        row.last_error_at = None
    except (CatalogError, httpx.HTTPError) as error:
        # Do not expose remote bodies or transport configuration in the UI.
        row.last_error = str(error)[:500] if isinstance(error, CatalogError) else "공개 제공처에 연결하지 못했습니다. 이전 자료를 유지합니다."
        row.last_error_at = now
    row.last_checked_at = now
    db.commit()
    db.refresh(row)
    return row


def lifecycle_values(product):
    return {key: getattr(product, key).isoformat() if isinstance(getattr(product, key), (date, datetime))
            else getattr(product, key) for key in LIFECYCLE_FIELDS}


def product_revision(product):
    # Include identity: a preview must not apply after the product was renamed.
    values = {**lifecycle_values(product), **{key: getattr(product, key) for key in
              ("id", "product_type", "vendor", "name", "version", "purl", "cpe")}}
    return hashlib.sha256(json.dumps(values, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def proposal(product, row, release_cycle):
    public = payload(row)
    if not public:
        raise CatalogError("선택한 공개 제품의 저장된 자료가 없습니다. 공개 일정 조회를 먼저 실행하세요.")
    release = next((item for item in public["releases"] if item["name"] == release_cycle), None)
    if release is None:
        raise CatalogError("공개 자료에서 선택한 지원 주기를 찾을 수 없습니다.")
    links = public.get("links") if isinstance(public.get("links"), dict) else {}
    policy_url = valid_url(links.get("releasePolicy"))
    source = policy_url or row.source_url
    before = lifecycle_values(product)
    after = {**before, "security_end_date": release.get("eolFrom"), "lifecycle_source_url": source}
    cache = cache_read(row)
    blocked = None
    if not release.get("eolFrom"):
        blocked = "종료일이 확정되지 않아 날짜를 적용할 수 없습니다. 지원 상태와 공식 정책을 확인하세요."
    if cache["stale"] or cache["last_error"]:
        blocked = "공개 자료가 오래됐거나 최신 조회에 실패했습니다. 공개 일정을 다시 조회한 뒤 적용하세요."
    return {
        "product_slug": public["name"], "release_cycle": release["name"],
        "release": release, "cache": cache, "before": before, "after": after,
        "expected_product_revision": product_revision(product), "expected_catalog_sha256": row.content_sha256,
        "can_apply": blocked is None, "blocked_reason": blocked,
        "notes": ["선택한 공개 제품·지원 주기가 설치 제품에 적용되는지는 관리자가 확인합니다.",
                  "표준 지원 종료일만 보안지원 종료일에 적용합니다. 일반 지원·EOL 수동 날짜와 구성요소 개별 날짜는 유지합니다.",
                  "연장 지원은 별도 계약 조건이며 이 작업으로 적용하지 않습니다.",
                  "공개 카탈로그 수집 시각은 공급자 정책을 사람이 확인한 시각과 다릅니다."],
    }
