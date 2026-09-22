"""Package identity must never merge unrelated releases into one product record."""
from fastapi import HTTPException
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app import models
from app.db import Base
from app.services.sbom import _normalize_product


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'identity.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def package(**values):
    return {"type": "library", "name": "identity-demo", "version": "1.0", "supplier": "Vendor",
            "purl": "pkg:pypi/identity-demo@1.0", **values}


def test_versionless_purl_keeps_two_releases_separate(db):
    old = models.ProductRelease(product_type="LIBRARY", vendor="Vendor", name="identity-demo", version="1.0",
                                purl="pkg:pypi/identity-demo")
    db.add(old); db.flush()
    new = _normalize_product(db, package(version="2.0", purl="pkg:pypi/identity-demo"))
    assert new.id != old.id
    assert new.version == "2.0" and new.purl == "pkg:pypi/identity-demo@2.0"
    assert _normalize_product(db, package(purl="pkg:pypi/identity-demo")).id == old.id


def test_canonical_purl_qualifiers_case_and_name_are_reused(db):
    first = _normalize_product(db, package(name="Identity_Demo", purl="pkg:pypi/Identity_Demo@1.0?b=2&a=1"))
    second = _normalize_product(db, package(purl="pkg:pypi/identity-demo@1.0?a=1&b=2"))
    assert first.id == second.id
    assert first.purl == "pkg:pypi/identity-demo@1.0?a=1&b=2"


def test_legacy_qualifier_order_same_identity_reuses_canonical_candidate(db):
    old = models.ProductRelease(product_type="LIBRARY", vendor="Vendor", name="identity-demo", version="1.0",
                                purl="pkg:pypi/identity-demo@1.0?z=2&a=1")
    db.add(old); db.flush()
    assert _normalize_product(db, package(purl="pkg:pypi/identity-demo@1.0?a=1&z=2")).id == old.id


def test_purl_and_cpe_resolving_to_two_products_fail(db):
    one = _normalize_product(db, package())
    two = models.ProductRelease(product_type="LIBRARY", name="other", version="1.0", cpe="cpe:2.3:a:vendor:other:1.0:*:*:*:*:*:*:*")
    db.add(two); db.flush()
    with pytest.raises(HTTPException, match="PURL과 CPE"):
        _normalize_product(db, package(cpe=two.cpe))
    assert db.get(models.ProductRelease, one.id).cpe is None


@pytest.mark.parametrize("changes", [
    {"version": "2.0"}, {"purl": "invalid-purl"},
    {"purl": "pkg:npm/identity-demo@1.0"}, {"purl": "pkg:pypi/identity-demo@1.0?repository_url=https://other.example"},
])
def test_conflicting_or_invalid_identity_is_explicit(db, changes):
    _normalize_product(db, package())
    with pytest.raises(HTTPException) as caught:
        _normalize_product(db, package(**changes))
    assert caught.value.status_code == 422


def test_cpe_only_same_identifier_different_version_does_not_inherit(db):
    _normalize_product(db, package(purl=None, cpe="cpe:2.3:a:vendor:identity-demo:*:*:*:*:*:*:*:*"))
    with pytest.raises(HTTPException, match="서로 다른 버전"):
        _normalize_product(db, package(version="2.0", purl=None, cpe="cpe:2.3:a:vendor:identity-demo:*:*:*:*:*:*:*:*"))


def test_purl_version_fills_missing_component_version_and_namespaces_stay_distinct(db):
    first = _normalize_product(db, package(name="scope-a", version=None, purl="pkg:npm/%40a/pkg@1.2.0"))
    second = _normalize_product(db, package(name="scope-b", version=None, purl="pkg:npm/%40b/pkg@1.2.0"))
    assert first.version == second.version == "1.2.0"
    assert first.id != second.id
    assert len(db.scalars(select(models.ProductRelease)).all()) == 2


def test_exact_identifier_free_identity_remains_backward_compatible(db):
    one = _normalize_product(db, package(purl=None))
    two = _normalize_product(db, package(purl=None))
    assert one.id == two.id


def test_equivalent_pypi_embedded_version_is_accepted(db):
    item = _normalize_product(db, package(version="1.0.0"))
    assert item.version == "1.0.0" and item.purl.endswith("@1.0")


@pytest.mark.parametrize("unknown", ["UNKNOWN", "N/A", None])
def test_placeholder_version_uses_embedded_version(db, unknown):
    item = _normalize_product(db, package(version=unknown))
    assert item.version == "1.0"


def test_cpe_only_upstream_does_not_absorb_distro_package(db):
    cpe = "cpe:2.3:a:vendor:identity-demo:1.0:*:*:*:*:*:*:*"
    _normalize_product(db, package(purl=None, cpe=cpe))
    with pytest.raises(HTTPException, match="배포판"):
        _normalize_product(db, package(purl="pkg:deb/ubuntu/identity-demo@1.0?distro=ubuntu-24.04", cpe=cpe))
