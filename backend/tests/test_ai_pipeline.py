"""In-pipeline AI: library reference for sources without a lockfile."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import HTTPException
import pytest

from app.config import Settings
from app.services import ai_advisor, ai_library_reference as reference, analysis_executor as executor
from app.services.sbom import validate_spdx_schema


def _project(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "app").mkdir()
    (root / "app" / "__init__.py").write_text("")
    (root / "app" / "views.py").write_text("import os\nimport yaml\nfrom flask import Flask\nfrom app import helpers\nimport requests\n")
    (root / "app" / "helpers.py").write_text("import json\nimport requests\n")
    (root / "web").mkdir()
    (root / "web" / "index.js").write_text("import React from 'react'\nconst fs = require('fs')\nconst _ = require('lodash')\nimport './style.css'\n")
    (root / "package.json").write_text('{"dependencies": {"react": "^18.2.0", "lodash": "^4.17.20"}}')
    (root / "node_modules").mkdir()
    (root / "node_modules" / "evil.js").write_text("require('should-not-appear')\n")
    return root


def test_evidence_keeps_third_party_imports_and_manifest_heads(tmp_path):
    evidence = reference.gather_evidence(_project(tmp_path / "src"))
    assert evidence["imports"]["pypi"] == ["requests", "flask", "yaml"]  # by count then name; stdlib and own modules dropped
    assert evidence["imports"]["npm"] == ["lodash", "react"]
    assert [m["file"] for m in evidence["manifests"]] == ["package.json"]
    assert evidence["source_files"] == 3 and "should-not-appear" not in json.dumps(evidence)


def test_answer_is_validated_and_turned_into_spdx_with_purls():
    answer = {"libraries": [
        {"ecosystem": "pypi", "name": "PyYAML", "version": ">=6.0", "confidence": "high", "evidence": "import yaml"},
        {"ecosystem": "npm", "name": "@babel/core", "version": "7.20.0", "confidence": "medium"},
        {"ecosystem": "pypi", "name": "PIL", "version": "9.0.0", "confidence": "high"},                # import name, not the project
        {"ecosystem": "pypi", "name": "PyYAML", "version": "6.0", "confidence": "low"},        # duplicate purl
        {"ecosystem": "pypi", "name": "../etc", "version": "1"},                               # bad name
        {"ecosystem": "pypi", "name": "flask", "version": "latest"},                           # bad version
        {"ecosystem": "swift", "name": "x", "version": "1"},                                   # unknown ecosystem
        "garbage",
    ]}
    libraries = reference.validate_libraries(answer)
    assert [l["purl"] for l in libraries] == ["pkg:pypi/pyyaml@6.0", "pkg:npm/%40babel/core@7.20.0", "pkg:pypi/pillow@9.0.0"]
    assert libraries[2]["name"] == "Pillow" and libraries[2]["confidence"] == "high"  # no evidence given: the model's word stands
    spdx = reference.to_spdx(libraries, project_name="demo", model="gpt-5-mini", evidence={"imports": {"pypi": ["yaml"]}, "manifests": []})
    validate_spdx_schema(spdx)
    assert spdx["creationInfo"]["creators"] == ["Tool: EOLWatch-AI-Library-Reference", "Tool: gpt-5-mini"]
    assert "AI 추정 · 신뢰도 high · 근거: import yaml" == spdx["packages"][0]["comment"]
    assert spdx["packages"][0]["externalRefs"][0]["referenceLocator"] == "pkg:pypi/pyyaml@6.0"


@pytest.fixture
def source_pipeline(tmp_path, monkeypatch):
    """A source-git scan where syft finds nothing pinned; records the commands the executor runs."""
    settings = Settings(analysis_artifacts_dir=str(tmp_path / "artifacts"), analysis_cache_dir=str(tmp_path / "cache"))
    state = {"commands": [], "stages": []}
    monkeypatch.setattr(executor, "_tools", lambda *_args: (Path("/tools/syft"), Path("/tools/grype"), "Linux aarch64"))
    monkeypatch.setattr(executor, "_connect", lambda *_args: (_ for _ in ()).throw(AssertionError("no SSH")))
    monkeypatch.setattr(executor, "_clone_repository", lambda run, *_a: str(_project(run.directory / "source")))

    def local(self, name, argv, timeout, env, output=None):
        state["commands"].append((name, argv))
        path = self.directory / (output or name + ".stdout.log")
        if name == "syft-scan":
            path.write_text(json.dumps({"artifacts": [], "source": {"metadata": {"path": str(self.directory / "source")}},
                                        "descriptor": {"configuration": {"catalogers": {"used": []}}}}))
        elif name == "grype-scan":
            path.write_text(json.dumps({"descriptor": {"name": "grype", "db": {}}, "matches": []}))
        else:
            path.write_text("{}")
        return path
    monkeypatch.setattr(executor._Run, "local", local)
    snapshot = {"id": 5, "asset_tag": "GH-web-api", "scan_scope": "source-git:web-api", "profile": "source-git", "project_name": "web-api", "input_type": "git",
                "git_url": "https://github.com/example/web-api", "git_ref": "main"}
    return settings, state, snapshot


def test_lockfile_less_source_is_scanned_from_ai_library_reference(tmp_path, source_pipeline, monkeypatch):
    settings, state, snapshot = source_pipeline
    prompts = []

    def fake_complete_json(prompt, *, system, max_tokens=1500):
        prompts.append((prompt, system))
        return ({"libraries": [{"ecosystem": "pypi", "name": "Flask", "version": "2.2.2", "confidence": "low", "evidence": "from flask import"},
                               {"ecosystem": "npm", "name": "lodash", "version": "4.17.20", "confidence": "high", "evidence": "package.json ^4.17.20"}]},
                "gpt-5-mini", {"input_tokens": 310, "output_tokens": 80})
    monkeypatch.setattr(ai_advisor, "complete_json", fake_complete_json)
    bundle = executor.execute_analysis(snapshot, tmp_path / "job", settings, state["stages"].append)
    prompt, system = prompts[0]
    assert '"flask"' in prompt and '"lodash"' in prompt and "package.json" in prompt and "PyPI" in system
    assert bundle["sbom"]["creationInfo"]["creators"][0] == "Tool: EOLWatch-AI-Library-Reference"
    assert [p["externalRefs"][0]["referenceLocator"] for p in bundle["sbom"]["packages"]] == ["pkg:pypi/flask@2.2.2", "pkg:npm/lodash@4.17.20"]
    assert [p["comment"].split(" · ")[1] for p in bundle["sbom"]["packages"]] == ["신뢰도 low", "신뢰도 high"]  # flask is not in any manifest
    names = [name for name, _ in state["commands"]]
    assert "syft-convert-spdx" not in names and "grype-scan" in names
    grype = next(argv for name, argv in state["commands"] if name == "grype-scan")
    assert grype[1] == "sbom:" + str((tmp_path / "job").resolve() / "sbom.spdx.json")
    manifest = json.loads((tmp_path / "job" / "manifest.json").read_text())
    assert manifest["ai_library_reference"]["status"] == "ok" and manifest["ai_library_reference"]["library_count"] == 2
    assert manifest["ai_library_reference"]["input_tokens"] == 310 and manifest["package_count"] == 0
    assert state["stages"] == ["COLLECTING", "SCANNING", "IMPORTING"]


def test_ai_failure_keeps_the_honest_empty_collection_error(tmp_path, source_pipeline, monkeypatch):
    settings, state, snapshot = source_pipeline
    monkeypatch.setattr(ai_advisor, "complete_json", lambda *a, **k: (_ for _ in ()).throw(HTTPException(503, "AI가 설정되지 않았습니다. OPENAI_API_KEY를 설정하세요.")))
    with pytest.raises(executor.AnalysisExecutionError) as failure:
        executor.execute_analysis(snapshot, tmp_path / "job", settings, state["stages"].append)
    assert failure.value.code == "EMPTY_COLLECTION"
    assert "AI 라이브러리 참조도 실패" in failure.value.message and "OPENAI_API_KEY" in failure.value.message
    manifest = json.loads((tmp_path / "job" / "manifest.json").read_text())
    assert manifest["ai_library_reference"] == {"status": "failed", "error_code": "AI_UNAVAILABLE"}


def test_pipeline_ai_can_be_switched_off(tmp_path, source_pipeline, monkeypatch):
    settings, state, snapshot = source_pipeline
    settings.ai_pipeline = False
    monkeypatch.setattr(ai_advisor, "complete_json", lambda *a, **k: (_ for _ in ()).throw(AssertionError("AI must not be called")))
    with pytest.raises(executor.AnalysisExecutionError) as failure:
        executor.execute_analysis(snapshot, tmp_path / "job", settings, state["stages"].append)
    assert failure.value.code == "EMPTY_COLLECTION" and "AI" not in failure.value.message
