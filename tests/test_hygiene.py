"""Repository, packaging, and supply-chain hygiene tests."""
from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {".git", "__pycache__", ".pytest_cache", "build", "dist", ".eggs"}
TEXT_SUFFIXES = {
    ".py", ".md", ".toml", ".txt", ".yml", ".yaml", ".in", ".typed", ".gitignore", ".gitattributes"
}


def repo_files():
    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if completed.returncode == 0 and completed.stdout:
            return [ROOT / part.decode("utf-8") for part in completed.stdout.split(b"\0") if part]
    except (OSError, ValueError):
        pass
    # sdist/source-tree fallback for an uncommitted checkout: inspect the same files
    # setuptools would see, while excluding regenerable caches and output folders.
    files = []
    for base, dirs, names in os.walk(str(ROOT)):
        dirs[:] = [name for name in dirs if name not in EXCLUDED_DIRS and not name.endswith(".egg-info")]
        for name in names:
            path = Path(base) / name
            if name in {".DS_Store"} or name.endswith((".pyc", ".pyo")):
                continue
            files.append(path)
    return sorted(files)


def text_files():
    return [path for path in repo_files() if path.is_file() and (path.suffix in TEXT_SUFFIXES or path.name in {"LICENSE", "MANIFEST.in", ".gitignore", ".gitattributes", "py.typed"})]


class RepositoryHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = repo_files()
        cls.text_files = text_files()

    def test_repository_file_discovery_is_nonempty(self):
        self.assertGreaterEqual(len(self.files), 20)

    def test_no_em_dash(self):
        offenders = [str(path.relative_to(ROOT)) for path in self.text_files if "\u2014" in path.read_text("utf-8")]
        self.assertEqual(offenders, [])

    def test_no_en_dash(self):
        offenders = [str(path.relative_to(ROOT)) for path in self.text_files if "\u2013" in path.read_text("utf-8")]
        self.assertEqual(offenders, [])

    def test_no_local_user_paths(self):
        offenders = []
        for path in self.text_files:
            text = path.read_text("utf-8")
            if ("/" + "Users/") in text or ("/" + "home/") in text:
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_no_personal_contact_or_address(self):
        forbidden = ["someone" + "@gmail.com", "handle-redacted" + "286", "Exampleton" + " Manor"]
        offenders = []
        for path in self.text_files:
            text = path.read_text("utf-8")
            if any(value in text for value in forbidden):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_no_coauthored_by_trailer(self):
        offenders = [str(path.relative_to(ROOT)) for path in self.text_files if ("Co-Authored" + "-By") in path.read_text("utf-8")]
        self.assertEqual(offenders, [])

    def test_no_secret_prefixes(self):
        prefixes = ["tskey" + "-", "s" + "k-", "gh" + "p_", "github" + "_pat_", "AK" + "IA", "x" + "ox", "gs" + "k_", "nvapi" + "-", "tvly" + "-", "AI" + "za"]
        offenders = []
        for path in self.text_files:
            text = path.read_text("utf-8")
            if any(value in text for value in prefixes):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_no_trailing_whitespace(self):
        offenders = []
        for path in self.text_files:
            for line in path.read_text("utf-8").splitlines():
                if line.endswith((" ", "\t")):
                    offenders.append(str(path.relative_to(ROOT)))
                    break
        self.assertEqual(offenders, [])

    def test_text_files_end_in_newline(self):
        offenders = []
        for path in self.text_files:
            data = path.read_bytes()
            if data and not data.endswith(b"\n"):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_no_nul_bytes(self):
        offenders = [str(path.relative_to(ROOT)) for path in self.files if b"\0" in path.read_bytes()]
        self.assertEqual(offenders, [])

    def test_no_compiled_python_files(self):
        offenders = [str(path.relative_to(ROOT)) for path in self.files if path.suffix in {".pyc", ".pyo"}]
        self.assertEqual(offenders, [])

    def test_no_build_or_cache_directories_in_source_tree(self):
        offenders = []
        for path in self.files:
            relative = path.relative_to(ROOT)
            if any(part in EXCLUDED_DIRS or part.endswith(".egg-info") for part in relative.parts):
                offenders.append(str(relative))
        self.assertEqual(offenders, [])

    def test_py_typed_is_present(self):
        self.assertTrue((ROOT / "src" / "pymdcage" / "py.typed").is_file())

    def test_package_has_no_tests_inside_wheel_package(self):
        offenders = [path for path in (ROOT / "src" / "pymdcage").iterdir() if path.name.startswith("test")]
        self.assertEqual(offenders, [])

    def test_pyproject_zero_runtime_dependencies(self):
        text = (ROOT / "pyproject.toml").read_text("utf-8")
        self.assertIn('dependencies = []', text)

    def test_pyproject_requires_python(self):
        text = (ROOT / "pyproject.toml").read_text("utf-8")
        self.assertIn('requires-python = ">=3.9"', text)

    def test_pyproject_version(self):
        text = (ROOT / "pyproject.toml").read_text("utf-8")
        self.assertIn('version = "1.0.0"', text)

    def test_console_script_is_configured(self):
        text = (ROOT / "pyproject.toml").read_text("utf-8")
        self.assertIn('pymdcage = "pymdcage.cli:main"', text)

    def test_mit_license_header(self):
        text = (ROOT / "LICENSE").read_text("utf-8")
        self.assertIn("MIT License", text)
        self.assertIn("Copyright (c) 2026 draarivpatel-ui", text)

    def test_ci_uses_supported_python_matrix(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn(version, text)
        self.assertIn("ubuntu-24.04", text)

    def test_publish_uses_oidc_environment(self):
        text = (ROOT / ".github" / "workflows" / "publish.yml").read_text("utf-8")
        self.assertIn("id-token: write", text)
        self.assertIn("name: pypi", text)
        self.assertIn("pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086", text)
        self.assertIn("--require-hashes -r .github/requirements-build.txt", text)
        self.assertNotIn("workflow_dispatch", text)

    def test_required_project_files_exist(self):
        for name in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md", "MANIFEST.in"):
            self.assertTrue((ROOT / name).is_file(), name)

    def test_examples_exist(self):
        for name in ("basic_usage.py", "custom_policy.py", "safe.md", "unsafe.md", "prompt_injection.md"):
            self.assertTrue((ROOT / "examples" / name).is_file(), name)

    def test_python_files_compile_without_writing_bytecode(self):
        for path in self.files:
            if path.suffix == ".py":
                compile(path.read_bytes(), str(path), "exec")

    def test_no_disallowed_network_or_subprocess_in_library(self):
        forbidden = ["urllib.request", "requests.", "subprocess", "socket."]
        offenders = []
        for path in (ROOT / "src" / "pymdcage").glob("*.py"):
            text = path.read_text("utf-8")
            if any(value in text for value in forbidden):
                offenders.append(path.name)
        self.assertEqual(offenders, [])

    def test_no_recursive_calls_in_scanner(self):
        # There is intentionally no recursive descent parser: scanning is iterative.
        text = (ROOT / "src" / "pymdcage" / "scanner.py").read_text("utf-8")
        self.assertNotIn("def scan_inline(\n        scan_inline(", text)
        self.assertNotIn("return scan_inline(", text)


if __name__ == "__main__":
    unittest.main()
