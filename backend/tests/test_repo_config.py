"""
==============================================================================
Module Name:   test_repo_config.py
Description:   Guards for repository configuration: the GitHub Actions
               workflows parse and wire up correctly (notably the monthly
               OUI update), dev dependencies stay unpinned, the ruff/mypy
               ignore lists keep the agent directory, and the legacy root
               tests/ directory stays gone.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-21
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         pytest backend/tests/test_repo_config.py
Notes:         Requires Python 3.10+ and PyYAML (listed in requirements-dev.txt).
==============================================================================
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
OUI_WORKFLOW = WORKFLOWS / "update-oui.yml"


def _load(path: Path) -> dict[Any, Any]:
    doc = yaml.safe_load(path.read_text())
    assert isinstance(doc, dict), f"{path.name} is not a YAML mapping"
    return doc


def _triggers(doc: dict[Any, Any]) -> dict[Any, Any]:
    # YAML 1.1 (PyYAML) reads a bare `on:` key as the boolean True.
    triggers = doc.get("on", doc.get(True))
    assert isinstance(triggers, dict), "workflow has no `on:` mapping"
    return triggers


def _steps(doc: dict[Any, Any]) -> list[dict[Any, Any]]:
    return [step for job in doc["jobs"].values() for step in job["steps"]]


@pytest.mark.parametrize("path", sorted(WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_every_workflow_parses_and_defines_jobs(path: Path) -> None:
    doc = _load(path)
    assert "name" in doc
    assert _triggers(doc)
    assert doc["jobs"]


class TestUpdateOuiWorkflow:
    def test_runs_monthly_and_can_be_started_by_hand(self) -> None:
        triggers = _triggers(_load(OUI_WORKFLOW))

        crons = [entry["cron"] for entry in triggers["schedule"]]
        assert crons == ["0 0 1 * *"]  # 00:00 UTC on the 1st of each month
        assert "workflow_dispatch" in triggers
        assert triggers["workflow_dispatch"]["inputs"]["mode"]["options"] == ["pr", "commit"]
        assert triggers["workflow_dispatch"]["inputs"]["mode"]["default"] == "pr"

    def test_runs_the_update_script_and_it_exists(self) -> None:
        runs = [step["run"] for step in _steps(_load(OUI_WORKFLOW)) if "run" in step]
        assert any("scripts/update-manuf-db.sh" in run for run in runs)

        script = REPO_ROOT / "scripts" / "update-manuf-db.sh"
        assert script.is_file()
        assert os.access(script, os.X_OK), "the workflow runs it directly, so it must be executable"

    def test_tracks_the_file_the_script_actually_writes(self) -> None:
        """The database is the gzip file backend/app/data/manuf.gz (there is no
        plain `manuf`); the workflow and the script must agree on it."""
        doc = _load(OUI_WORKFLOW)
        oui_file = doc["env"]["OUI_FILE"]

        assert oui_file == "backend/app/data/manuf.gz"
        assert (REPO_ROOT / oui_file).is_file()
        assert oui_file in (REPO_ROOT / "scripts" / "update-manuf-db.sh").read_text()

    def test_compares_decompressed_content_not_gzip_bytes(self) -> None:
        detect = next(s for s in _steps(_load(OUI_WORKFLOW)) if s.get("id") == "diff")["run"]
        checksum_lines = [line for line in detect.splitlines() if "sha256sum" in line]

        assert len(checksum_lines) == 2  # the committed file and the freshly downloaded one
        for line in checksum_lines:
            assert "gzip -dc" in line, f"hashes compressed bytes: {line.strip()}"

    def test_publishing_only_happens_for_a_real_change(self) -> None:
        steps = _steps(_load(OUI_WORKFLOW))
        publishing = [s for s in steps if "git push" in s.get("run", "")]
        assert publishing, "no step pushes the update"
        for step in publishing:
            assert "steps.diff.outputs.changed == 'true'" in step["if"]

    def test_tests_run_before_anything_is_published(self) -> None:
        names = [s.get("name", "") for s in _steps(_load(OUI_WORKFLOW))]
        test_at = next(i for i, n in enumerate(names) if n.startswith("Test against"))
        for i, step in enumerate(_steps(_load(OUI_WORKFLOW))):
            if "git push" in step.get("run", ""):
                assert i > test_at

    def test_permissions_are_read_only_except_for_the_one_job(self) -> None:
        doc = _load(OUI_WORKFLOW)
        assert doc["permissions"] == {"contents": "read"}
        assert doc["jobs"]["update"]["permissions"] == {
            "contents": "write",
            "pull-requests": "write",
        }

    def test_does_not_interpolate_expressions_into_shell_scripts(self) -> None:
        """`${{ ... }}` inside `run:` is substituted before the shell runs, so
        untrusted values there are a script-injection hole; pass them via env."""
        for step in _steps(_load(OUI_WORKFLOW)):
            assert "${{" not in step.get("run", ""), step.get("name")

    def test_cannot_overlap_itself_and_cannot_run_forever(self) -> None:
        doc = _load(OUI_WORKFLOW)
        assert doc["concurrency"]["group"] == "update-oui"
        assert doc["concurrency"]["cancel-in-progress"] is False
        assert doc["jobs"]["update"]["timeout-minutes"] <= 30


class TestDevDependencies:
    def test_none_are_pinned_with_double_equals(self) -> None:
        """New dev dependencies use >= (a floor), never == (a pin)."""
        lines = (REPO_ROOT / "requirements-dev.txt").read_text().splitlines()
        requirements = [ln.strip() for ln in lines if ln.strip() and not ln.startswith(("#", "-"))]

        assert requirements
        assert [r for r in requirements if "==" in r] == []

    def test_pyyaml_is_declared_because_these_tests_import_it(self) -> None:
        text = (REPO_ROOT / "requirements-dev.txt").read_text()
        assert re.search(r"^pyyaml>=\d", text, flags=re.IGNORECASE | re.MULTILINE)


class TestIgnoreLists:
    """The agent tooling directory must stay out of every linter, and the
    configuration shims must stay out of mypy."""

    def _pyproject(self) -> str:
        return (REPO_ROOT / "pyproject.toml").read_text()

    def test_ruff_keeps_excluding_the_agent_directory(self) -> None:
        assert re.search(r'extend-exclude\s*=\s*\[[^\]]*"\.agents"', self._pyproject())

    def test_mypy_excludes_the_agent_directory_and_the_root_shims(self) -> None:
        match = re.search(r"^exclude\s*=\s*\[(.*?)\]", self._pyproject(), re.MULTILINE | re.DOTALL)
        assert match, "no mypy exclude list"
        excludes = match.group(1)
        assert r"^\\.agents/" in excludes
        assert r"^main\\.py$" in excludes
        assert r"^dashboard\\.py$" in excludes

    def test_the_agent_directory_exists_so_the_excludes_are_not_dead_config(self) -> None:
        assert (REPO_ROOT / ".agents").is_dir()


class TestLegacyTestsDirectoryIsGone:
    def test_there_is_no_root_level_tests_directory(self) -> None:
        assert not (REPO_ROOT / "tests").exists()

    def test_pytest_collects_only_the_backend_and_cli_suites(self) -> None:
        text = (REPO_ROOT / "pyproject.toml").read_text()
        assert 'testpaths = ["backend/tests", "cli/tests"]' in text

    def test_no_config_still_points_at_the_old_directory(self) -> None:
        text = (REPO_ROOT / "pyproject.toml").read_text()
        assert not re.search(r'"\^tests/"', text)
