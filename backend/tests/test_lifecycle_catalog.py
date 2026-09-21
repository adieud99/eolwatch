"""Public metadata cache, explicit mapping, provenance and concurrent edits."""
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
import hashlib
import json

from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker

from app import middleware, models
from app.db import Base, get_db
from app.routers import lifecycle_catalog, products
from app.services import lifecycle_catalog as service
from app.services.auth import create_access_token
from app.services.component_lifecycle import effective_component_lifecycle


def envelope(result):
    return {"schema_version": "1.2.1", "generated_at": datetime.now(timezone.utc).isoformat(), "result": result}


def catalog():
    return envelope([{"name": "postgresql", "label": "PostgreSQL", "category": "database"},
                     {"name": "python", "label": "Python", "category": "language"}])


def details():
    return envelope({"name": "postgresql", "label": "PostgreSQL", "links": {
        "html": "https://endoflife.date/postgresql", "releasePolicy": "https://www.postgresql.org/support/versioning/"},
        "releases": [{"name": "16", "label": "16", "isEol": False, "eolFrom": "2028-11-09",
                      "eoasFrom": "2027-01-01", "eoesFrom": "2035-01-01", "isMaintained": True},
                     {"name": "unknown", "label": "Unknown date", "isEol": True, "eolFrom": None}]})


@pytest.fixture
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'catalog.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(middleware, "SessionLocal", factory)
    app = FastAPI()
    app.middleware("http")(middleware.authenticate_and_audit)
    app.include_router(lifecycle_catalog.router, prefix="/api")
    app.include_router(products.router, prefix="/api")
    def session():
        with factory() as db:
            yield db
    app.dependency_overrides[get_db] = session
    with factory() as db:
        users = [models.User(username=role.lower(), role=role, active=True, password_hash="unused") for role in ("ADMIN", "VIEWER")]
        db.add_all(users)
        product = models.ProductRelease(id=1, product_type="APPLICATION", vendor="Private Supplier", name="Private Product",
                                        version="secret-build-123", security_end_date=date(2027, 1, 1), support_end_date=date(2026, 1, 1),
                                        lifecycle_source_url="https://example.test/manual", verified_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
        db.add(product)
        db.add_all([models.ProductRelease(id=i, name=f"Package {i:02}", version="1.0") for i in range(2, 25)])
        sbom = models.SbomDocument(serial_number="catalog-private", spec_version="2.3", raw_document={"private": "never send"})
        db.add(sbom); db.flush()
        db.add_all([models.Component(sbom_id=sbom.id, product_release_id=1, bom_ref="inherited", name="first"),
                    models.Component(sbom_id=sbom.id, product_release_id=1, bom_ref="override", name="second",
                                     support_end_date=date(2040, 1, 1), lifecycle_source_url="https://example.test/override")])
        db.commit()
        tokens = {user.role: create_access_token(user)[0] for user in users}
    calls = []
    def fetch(url, etag=None):
        calls.append((url, etag))
        value = catalog() if url.endswith("/products/") else details()
        return json.dumps(value).encode(), '"catalog-etag"'
    monkeypatch.setattr(service, "fetch_public", fetch)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + tokens["ADMIN"]
        yield client, factory, calls, tokens
    engine.dispose()


def ready(client):
    assert client.post("/api/lifecycle-catalog/refresh", json={}).status_code == 200
    assert client.post("/api/lifecycle-catalog/refresh", json={"product_slug": "postgresql"}).status_code == 200


def preview(client, cycle="16"):
    response = client.get("/api/lifecycle-catalog/preview/1", params={"product_slug": "postgresql", "release_cycle": cycle})
    assert response.status_code == 200, response.text
    return response.json()


def application(value, cycle="16"):
    return {"product_id": 1, "product_slug": "postgresql", "release_cycle": cycle,
            **{key: value[key] for key in ("expected_product_revision", "expected_catalog_sha256")}}


def test_gets_are_local_only_refresh_sends_only_catalog_selected_public_slug(env):
    client, _, calls, _ = env
    assert client.get("/api/lifecycle-catalog/products").json()["cache"]["available"] is False
    assert client.get("/api/lifecycle-catalog/products/postgresql").json()["releases"] == []
    assert calls == []
    assert client.post("/api/lifecycle-catalog/refresh", json={"product_slug": "private-product"}).status_code == 422
    assert calls == []
    ready(client)
    assert [value[0] for value in calls] == [service.API_ROOT + "products/", service.API_ROOT + "products/postgresql/"]
    assert "secret-build" not in str(calls) and "Private" not in str(calls)
    count = len(calls)
    preview(client)
    assert len(calls) == count


def test_explicit_preview_apply_preserves_manual_fields_overrides_and_original_evidence(env):
    client, factory, _, _ = env
    ready(client)
    value = preview(client)
    assert value["before"]["security_end_date"] == "2027-01-01"
    assert value["after"]["security_end_date"] == "2028-11-09"
    assert value["release"]["eoesFrom"] == "2035-01-01"
    assert client.get("/api/products/1").json()["security_end_date"] == "2027-01-01"
    response = client.post("/api/lifecycle-catalog/apply", json=application(value))
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["product"]["security_end_date"] == "2028-11-09"
    assert result["product"]["support_end_date"] == "2026-01-01"
    assert result["product"]["verified_at"] == value["before"]["verified_at"]
    assert result["application"]["applied_at"] and result["application"]["fetched_at"]
    with factory() as db:
        history = db.scalar(select(models.LifecycleCatalogApplication))
        assert hashlib.sha256(history.source_document.encode()).hexdigest() == history.source_sha256
        components = db.scalars(select(models.Component).order_by(models.Component.id)).all()
        assert effective_component_lifecycle(components[0])[0] == date(2028, 11, 9)
        assert effective_component_lifecycle(components[1])[0] == date(2040, 1, 1)
    history = client.get("/api/lifecycle-catalog/applications?product_id=1").json()
    assert history["total"] == 1 and "source_document" not in str(history)


@pytest.mark.parametrize("change", ["product", "catalog"])
def test_stale_preview_conflicts_without_overwriting(env, change):
    client, factory, _, _ = env
    ready(client); value = preview(client)
    with factory() as db:
        if change == "product":
            db.get(models.ProductRelease, 1).security_end_date = date(2044, 1, 1)
        else:
            service.cached(db, "postgresql").content_sha256 = "b" * 64
        db.commit()
    response = client.post("/api/lifecycle-catalog/apply", json=application(value))
    assert response.status_code == 409
    with factory() as db:
        assert db.scalar(select(func.count(models.LifecycleCatalogApplication.id))) == 0
        assert db.get(models.ProductRelease, 1).security_end_date == (date(2044, 1, 1) if change == "product" else date(2027, 1, 1))


@pytest.mark.parametrize("target", ["product", "cache"])
def test_compare_and_set_detects_write_after_apply_read_even_without_row_locks(env, monkeypatch, target):
    client, factory, _, _ = env
    ready(client); value = preview(client)
    original = service.proposal
    def concurrent_write(product, row, cycle):
        result = original(product, row, cycle)
        with factory() as other:
            if target == "product":
                other.get(models.ProductRelease, 1).security_end_date = date(2044, 1, 1)
            else:
                service.cached(other, "postgresql").content_sha256 = "c" * 64
            other.commit()
        return result
    monkeypatch.setattr(service, "proposal", concurrent_write)
    response = client.post("/api/lifecycle-catalog/apply", json=application(value))
    assert response.status_code == 409, response.text
    with factory() as db:
        assert db.scalar(select(func.count(models.LifecycleCatalogApplication.id))) == 0
        if target == "product":
            assert db.get(models.ProductRelease, 1).security_end_date == date(2044, 1, 1)


def test_new_catalog_fetch_never_rewrites_applied_evidence_or_manual_dates(env, monkeypatch):
    client, factory, _, _ = env
    ready(client)
    value = preview(client)
    assert client.post("/api/lifecycle-catalog/apply", json=application(value)).status_code == 200
    with factory() as db:
        old_source = db.scalar(select(models.LifecycleCatalogApplication)).source_document
    changed = details(); changed["result"]["releases"][0]["eolFrom"] = "2029-01-01"
    monkeypatch.setattr(service, "fetch_public", lambda *_: (json.dumps(changed).encode(), '"changed"'))
    assert client.post("/api/lifecycle-catalog/refresh", json={"product_slug": "postgresql"}).status_code == 200
    assert client.get("/api/products/1").json()["security_end_date"] == "2028-11-09"
    with factory() as db:
        history = db.scalar(select(models.LifecycleCatalogApplication))
        assert history.source_document == old_source
        assert history.source_sha256 != service.cached(db, "postgresql").content_sha256


def test_unknown_end_date_is_visible_but_cannot_apply_a_fake_date(env):
    client, _, _, _ = env
    ready(client)
    value = preview(client, "unknown")
    assert value["release"]["isEol"] is True and value["release"]["eolFrom"] is None
    assert value["can_apply"] is False
    assert client.post("/api/lifecycle-catalog/apply", json=application(value, "unknown")).status_code == 422
    assert client.get("/api/products/1").json()["security_end_date"] == "2027-01-01"


@pytest.mark.parametrize("failure", ["http", "invalid", "timeout"])
def test_refresh_errors_keep_original_cache_hash_and_block_application(env, monkeypatch, failure):
    client, _, _, _ = env
    ready(client)
    before = client.get("/api/lifecycle-catalog/products/postgresql").json()
    def failed(*args):
        if failure == "http": raise service.CatalogError("공개 제공처 조회 실패(HTTP 429). 이전 자료를 유지합니다.")
        if failure == "timeout": raise httpx.ReadTimeout("private transport details should not appear")
        return b'{"invalid":true}', None
    monkeypatch.setattr(service, "fetch_public", failed)
    assert client.post("/api/lifecycle-catalog/refresh", json={"product_slug": "postgresql"}).status_code == 502
    after = client.get("/api/lifecycle-catalog/products/postgresql").json()
    assert after["releases"] == before["releases"]
    assert after["cache"]["content_sha256"] == before["cache"]["content_sha256"]
    assert after["cache"]["fetched_at"] == before["cache"]["fetched_at"]
    assert after["cache"]["last_error"] and after["cache"]["last_error_at"]
    assert "private transport" not in after["cache"]["last_error"]
    assert preview(client)["can_apply"] is False


def test_stale_cache_blocks_apply_and_304_revalidates_without_faking_new_body_fetch(env, monkeypatch):
    client, factory, _, _ = env
    ready(client)
    with factory() as db:
        row = service.cached(db, "postgresql")
        row.fetched_at = row.last_checked_at = datetime.now(timezone.utc) - timedelta(days=2)
        db.commit()
    assert preview(client)["can_apply"] is False
    before = client.get("/api/lifecycle-catalog/products/postgresql").json()["cache"]
    monkeypatch.setattr(service, "fetch_public", lambda *_: (None, '"catalog-etag"'))
    assert client.post("/api/lifecycle-catalog/refresh", json={"product_slug": "postgresql"}).status_code == 200
    after = client.get("/api/lifecycle-catalog/products/postgresql").json()["cache"]
    assert after["content_sha256"] == before["content_sha256"] and after["fetched_at"] == before["fetched_at"]
    assert after["last_checked_at"] != before["last_checked_at"] and after["stale"] is False
    assert preview(client)["can_apply"] is True


def test_pages_search_scope_auth_and_manual_timestamp_meaning(env):
    client, _, _, tokens = env
    first = client.get("/api/lifecycle-catalog/local-products?limit=20").json()
    second = client.get("/api/lifecycle-catalog/local-products?limit=20&offset=20").json()
    assert first["total"] == second["total"] == 24 and len(second["items"]) == 4
    assert {item["id"] for item in first["items"]}.isdisjoint(item["id"] for item in second["items"])
    assert client.get("/api/lifecycle-catalog/local-products?q=secret-build").json()["total"] == 1
    assert client.get("/api/lifecycle-catalog/local-products?limit=101").status_code == 422
    old = client.get("/api/products/1").json()["verified_at"]
    assert client.patch("/api/products/1", json={"security_end_date": "2027-01-01"}).json()["verified_at"] == old
    ready(client)
    client.headers["Authorization"] = "Bearer " + tokens["VIEWER"]
    value = preview(client)
    assert client.post("/api/lifecycle-catalog/apply", json=application(value)).status_code == 403
    assert client.post("/api/lifecycle-catalog/refresh", json={}).status_code == 403
    assert client.get("/api/lifecycle-catalog/applications?product_id=1").status_code == 200
    del client.headers["Authorization"]
    assert client.get("/api/lifecycle-catalog/products").status_code == 401


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(schema_version="2.0"),
    lambda value: value.update(generated_at="not-a-time"),
    lambda value: value["result"].update(name="wrong-product"),
    lambda value: value["result"]["releases"].append(deepcopy(value["result"]["releases"][0])),
    lambda value: value["result"]["releases"][0].update(eolFrom=True),
    lambda value: value["result"]["releases"][0].update(eolFrom="2028-02-31"),
    lambda value: value["result"]["releases"][0].update(isEol="false"),
])
def test_invalid_public_response_is_rejected(mutate):
    value = details(); mutate(value)
    with pytest.raises(service.CatalogError):
        service.validate_document(json.dumps(value).encode(), "postgresql")


def test_transport_uses_get_only_and_blocks_external_redirects(monkeypatch):
    requests = []
    def handle(request):
        requests.append(request)
        return httpx.Response(301, headers={"Location": "https://outside.test/private"})
    real = httpx.Client
    monkeypatch.setattr(service.httpx, "Client", lambda **kwargs: real(transport=httpx.MockTransport(handle), **kwargs))
    with pytest.raises(service.CatalogError, match="외부"):
        service.fetch_public(service.API_ROOT + "products/")
    assert len(requests) == 1 and requests[0].method == "GET" and requests[0].content == b""


def test_public_response_size_limit(monkeypatch):
    real = httpx.Client
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, content=b"x" * (service.MAX_BYTES + 1)))
    monkeypatch.setattr(service.httpx, "Client", lambda **kwargs: real(transport=transport, **kwargs))
    with pytest.raises(service.CatalogError, match="2 MiB"):
        service.fetch_public(service.API_ROOT + "products/")
