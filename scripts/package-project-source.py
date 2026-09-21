#!/usr/bin/env python3
"""Build an explicit source/manifest-only ZIP for EOLWatch's upload analysis."""
from pathlib import Path
import hashlib
import json
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / "reports" / "eolwatch-project-source.zip"
    output.parent.mkdir(parents=True, exist_ok=True)
    files = [root / name for name in ("README.md", "backend/requirements.txt", "frontend/package.json", "frontend/package-lock.json")]
    for directory, suffixes in (("backend/app", {".py"}), ("frontend/src", {".jsx", ".js", ".css"})):
        files.extend(path for path in (root / directory).rglob("*")
                     if path.is_file() and not path.is_symlink() and path.suffix in suffixes
                     and not any(part in {"__pycache__", "node_modules"} for part in path.parts)
                     and ".test." not in path.name)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(set(files)):
            archive.write(path, path.relative_to(root).as_posix())
    with zipfile.ZipFile(output) as archive:
        assert archive.testzip() is None
        entries = archive.namelist()
    print(json.dumps({"file": str(output), "entries": len(entries), "bytes": output.stat().st_size,
                      "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
