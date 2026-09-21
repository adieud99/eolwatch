"""Legacy SBOM comparison conserves every package version and occurrence."""
from copy import deepcopy
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app import models
from app.db import Base
from app.routers.sboms import compare_sboms


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'sbom-comparison.db'}")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        for index in (1, 2):
            session.add(models.SbomDocument(id=index, serial_number=f"comparison-{index}", bom_format="SPDX", spec_version="2.3",
                                            component_count=0, raw_document={"sentinel": "large raw document"}))
        session.commit()
        yield session
    engine.dispose()


def add(db, sbom_id, version, *, purl=None, name="demo", licenses=None, hashes=None, supplier="upstream"):
    record = models.Component(sbom_id=sbom_id, bom_ref=uuid4().hex,
                              name=name, version=version, purl=purl or (f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}"),
                              supplier=supplier, licenses=licenses or [], hashes=hashes or [])
    db.add(record); db.flush()
    return record


def conserved(result, before, after):
    assert result.unchanged_count + len(result.changed) + len(result.removed) == before
    assert result.unchanged_count + len(result.changed) + len(result.added) == after


def test_existing_single_version_change_shape_is_preserved(db):
    add(db, 1, "1.0"); add(db, 2, "2.0")
    result = compare_sboms(1, 2, db)
    assert result.model_dump() == {
        "base_sbom_id": 1, "target_sbom_id": 2, "added": [], "removed": [], "unchanged_count": 0,
        "changed": [{"identity": "pkg:pypi/demo", "name": "demo", "before_version": "1.0", "after_version": "2.0", "purl": "pkg:pypi/demo@2.0"}],
    }
    conserved(result, 1, 1)


def test_retained_version_is_not_overwritten_by_another_version(db):
    add(db, 1, "1.0"); add(db, 1, "2.0")
    add(db, 2, "2.0"); add(db, 2, "3.0")
    result = compare_sboms(1, 2, db)
    assert result.unchanged_count == 1
    assert [(row.before_version, row.after_version) for row in result.changed] == [("1.0", "3.0")]
    assert result.added == result.removed == []
    conserved(result, 2, 2)


def test_every_version_of_added_and_removed_package_survives(db):
    for version in ("1.0", "2.0", "3.0"):
        add(db, 1, version, name="removed")
    for version in ("4.0", "5.0"):
        add(db, 2, version, name="added")
    result = compare_sboms(1, 2, db)
    assert {row.before_version for row in result.removed} == {"1.0", "2.0", "3.0"}
    assert {row.after_version for row in result.added} == {"4.0", "5.0"}
    conserved(result, 3, 2)


def test_ambiguous_multiple_version_transitions_are_added_removed_not_invented_pairs(db):
    for version in ("1.0", "2.0"):
        add(db, 1, version)
    for version in ("3.0", "4.0"):
        add(db, 2, version)
    result = compare_sboms(1, 2, db)
    assert not result.changed and result.unchanged_count == 0
    assert {row.before_version for row in result.removed} == {"1.0", "2.0"}
    assert {row.after_version for row in result.added} == {"3.0", "4.0"}
    conserved(result, 2, 2)


def test_duplicate_occurrences_are_counted_and_extra_copy_is_added(db):
    for _ in range(2):
        add(db, 1, "1.0")
    for _ in range(3):
        add(db, 2, "1.0")
    result = compare_sboms(1, 2, db)
    assert result.unchanged_count == 2
    assert len(result.added) == 1 and result.added[0].after_version == "1.0"
    assert not result.changed
    conserved(result, 2, 3)


def test_duplicate_occurrences_same_transition_remain_separate_changes(db):
    for _ in range(2):
        add(db, 1, "1.0"); add(db, 2, "2.0")
    result = compare_sboms(1, 2, db)
    assert len(result.changed) == 2
    assert all(row.before_version == "1.0" and row.after_version == "2.0" for row in result.changed)
    conserved(result, 2, 2)


def test_exact_signatures_match_before_same_version_metadata_changes(db):
    add(db, 1, "1.0", licenses=[{"expression": "MIT"}])
    add(db, 1, "1.0", licenses=[{"expression": "Apache-2.0"}])
    add(db, 2, "1.0", licenses=[{"expression": "Apache-2.0"}])
    add(db, 2, "1.0", licenses=[{"expression": "BSD-3-Clause"}])
    result = compare_sboms(1, 2, db)
    assert result.unchanged_count == 1
    assert len(result.changed) == 1
    assert result.changed[0].before_version == result.changed[0].after_version == "1.0"
    conserved(result, 2, 2)


def test_hash_dictionary_key_order_and_versionless_occurrences_are_stable(db):
    add(db, 1, None, hashes=[{"alg": "SHA-256", "content": "abc"}])
    add(db, 2, None, hashes=[{"content": "abc", "alg": "SHA-256"}])
    result = compare_sboms(1, 2, db)
    assert result.unchanged_count == 1
    conserved(result, 1, 1)


def test_purl_scope_namespace_qualifiers_and_case_are_not_collapsed(db):
    add(db, 1, "1.0", purl="pkg:npm/%40first/demo", name="demo")
    add(db, 2, "1.0", purl="pkg:npm/%40second/demo", name="demo")
    add(db, 1, "1.0", purl="pkg:pypi/demo@1.0?arch=arm64")
    add(db, 2, "1.0", purl="pkg:pypi/demo@1.0?arch=x86_64")
    add(db, 1, "1.0", purl="pkg:maven/org.example/Case@1.0")
    add(db, 2, "1.0", purl="pkg:maven/org.example/case@1.0")
    result = compare_sboms(1, 2, db)
    assert result.unchanged_count == 0 and not result.changed
    assert len(result.added) == len(result.removed) == 3
    conserved(result, 3, 3)


def test_normalized_pypi_names_and_qualifier_order_are_equivalent(db):
    add(db, 1, "1.0", purl="pkg:pypi/Demo_Foo@1.0?arch=arm64&distro=test")
    add(db, 2, "1.0", purl="pkg:pypi/demo.foo@1.0?distro=test&arch=arm64")
    assert compare_sboms(1, 2, db).unchanged_count == 1


def test_purl_version_is_used_when_component_version_field_is_missing(db):
    add(db, 1, None, purl="pkg:pypi/demo@1.0")
    add(db, 1, None, purl="pkg:pypi/demo@2.0")
    add(db, 2, None, purl="pkg:pypi/demo@2.0")
    result = compare_sboms(1, 2, db)
    assert result.unchanged_count == 1
    assert [row.before_version for row in result.removed] == ["1.0"]
    conserved(result, 2, 1)


def test_comparing_same_document_keeps_all_occurrences_and_does_not_read_raw(db):
    for version in ("1.0", "1.0", "2.0"):
        add(db, 1, version)
    db.commit()
    statements = []
    def record(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement.lower())
    event.listen(db.bind, "before_cursor_execute", record)
    try:
        result = compare_sboms(1, 1, db)
    finally:
        event.remove(db.bind, "before_cursor_execute", record)
    assert result.unchanged_count == 3
    assert not result.changed and not result.added and not result.removed
    assert all("raw_document" not in statement and "raw_report" not in statement for statement in statements)


def test_missing_document_is_404_and_comparison_does_not_mutate_components(db):
    before = add(db, 1, "1.0"); add(db, 2, "2.0")
    db.commit()
    columns = list(models.Component.__table__.columns)
    original = deepcopy({column.name: getattr(before, column.name) for column in columns})
    compare_sboms(1, 2, db)
    assert {column.name: getattr(before, column.name) for column in columns} == original
    with pytest.raises(HTTPException) as caught:
        compare_sboms(1, 999, db)
    assert caught.value.status_code == 404
