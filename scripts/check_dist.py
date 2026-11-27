#!/usr/bin/env python3
"""Verify pymdcage wheel and source distribution contents."""
from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path
from typing import List


def _fail(errors: List[str], message: str) -> None:
    errors.append(message)


def _check_wheel(path: Path, errors: List[str]) -> None:
    with zipfile.ZipFile(str(path), "r") as archive:
        names = archive.namelist()
        if "pymdcage/py.typed" not in names:
            _fail(errors, "wheel is missing pymdcage/py.typed")
        if not any(name.startswith("pymdcage/") and name.endswith("__init__.py") for name in names):
            _fail(errors, "wheel is missing the pymdcage package")
        for name in names:
            normalized = name.replace("\\", "/")
            if normalized.startswith("tests/") or "/tests/" in normalized:
                _fail(errors, "wheel contains test files: " + normalized)
            if normalized.endswith((".pyc", ".pyo")) or "__pycache__" in normalized:
                _fail(errors, "wheel contains bytecode cache content: " + normalized)
            if normalized.endswith((".pem", ".key", ".p12", ".pfx")):
                _fail(errors, "wheel contains key-like content: " + normalized)
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            _fail(errors, "wheel must contain exactly one METADATA file")
        else:
            metadata = archive.read(metadata_names[0]).decode("utf-8", "replace")
            if "Name: pymdcage" not in metadata:
                _fail(errors, "wheel METADATA has the wrong package name")
            if "Requires-Python: >=3.9" not in metadata:
                _fail(errors, "wheel METADATA is missing Requires-Python >=3.9")
            if "Requires-Dist:" in metadata:
                _fail(errors, "wheel declares a runtime dependency")
            home_posix = "/" + "Users" + "/"
            home_windows = "\\" + "Users" + "\\"
            if home_posix in metadata or home_windows in metadata:
                _fail(errors, "wheel metadata contains a local user path")


def _check_sdist(path: Path, errors: List[str]) -> None:
    with tarfile.open(str(path), "r:gz") as archive:
        names = archive.getnames()
        if not any(name.endswith("/pymdcage/py.typed") or name.endswith("/src/pymdcage/py.typed") for name in names):
            _fail(errors, "sdist is missing pymdcage/py.typed")
        if not any(name.endswith("/pyproject.toml") for name in names):
            _fail(errors, "sdist is missing pyproject.toml")
        if not any(name.endswith("/src/pymdcage/__init__.py") for name in names):
            _fail(errors, "sdist is missing src/pymdcage/__init__.py")
        if not any(name.endswith("/README.md") for name in names):
            _fail(errors, "sdist is missing README.md")
        if not any(name.endswith("/tests/test_api.py") for name in names):
            _fail(errors, "sdist is missing the test suite")
        for name in names:
            normalized = name.replace("\\", "/")
            if normalized.endswith((".pyc", ".pyo")) or "__pycache__" in normalized:
                _fail(errors, "sdist contains bytecode cache content: " + normalized)
            if normalized.endswith((".pem", ".key", ".p12", ".pfx")):
                _fail(errors, "sdist contains key-like content: " + normalized)
        pkg_info_names = [name for name in names if len(name.split("/")) == 2 and name.endswith("/PKG-INFO")]
        if len(pkg_info_names) != 1:
            _fail(errors, "sdist must contain exactly one PKG-INFO file")
        else:
            extracted = archive.extractfile(pkg_info_names[0])
            if extracted is None:
                _fail(errors, "sdist PKG-INFO cannot be read")
            else:
                metadata = extracted.read().decode("utf-8", "replace")
                if "Name: pymdcage" not in metadata:
                    _fail(errors, "sdist PKG-INFO has the wrong package name")
                if "Requires-Python: >=3.9" not in metadata:
                    _fail(errors, "sdist PKG-INFO is missing Requires-Python >=3.9")
                if "Requires-Dist:" in metadata:
                    _fail(errors, "sdist declares a runtime dependency")


def check_dist(dist: Path) -> List[str]:
    errors: List[str] = []
    if not dist.is_dir():
        return ["distribution directory does not exist: " + str(dist)]
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1:
        _fail(errors, "expected exactly one wheel, found " + str(len(wheels)))
    if len(sdists) != 1:
        _fail(errors, "expected exactly one sdist, found " + str(len(sdists)))
    if wheels:
        _check_wheel(wheels[0], errors)
    if sdists:
        _check_sdist(sdists[0], errors)
    return errors


def main(argv: List[str]) -> int:
    dist = Path(argv[1]) if len(argv) > 1 else Path("dist")
    errors = check_dist(dist)
    if errors:
        for error in errors:
            print("check_dist: " + error, file=sys.stderr)
        return 1
    print("distribution contents verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
