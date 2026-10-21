"""
==============================================================================
Module Name:   test_update_manuf_script.py
Description:   Tests for scripts/update-manuf-db.sh, run for real against
               file:// URLs so nothing touches the network or the repo's own
               backend/app/data/manuf.gz.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-21
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         pytest backend/tests/test_update_manuf_script.py
Notes:         Requires Python 3.10+ and bash, curl and gzip on PATH (the
               tests skip on systems without them, e.g. plain Windows).
==============================================================================
"""

from __future__ import annotations

import gzip
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "update-manuf-db.sh"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or not all(shutil.which(tool) for tool in ("bash", "curl", "gzip")),
    reason="needs bash, curl and gzip",
)


def _manuf_text(entries: int, header: str = "# Wireshark manuf database (fixture)") -> str:
    lines = [header]
    lines += [
        f"{(i >> 16) & 255:02X}:{(i >> 8) & 255:02X}:{i & 255:02X}\tV{i}\tVendor number {i}"
        for i in range(1, entries + 1)
    ]
    return "\n".join(lines) + "\n"


def _run(
    tmp_path: Path, source: Path | str, *, min_entries: int | None = 3
) -> subprocess.CompletedProcess[str]:
    url = source if isinstance(source, str) else f"file://{source}"
    env = {**os.environ, "MANUF_SOURCE_URL": url, "MANUF_DEST": str(tmp_path / "out" / "manuf.gz")}
    if min_entries is not None:
        env["MANUF_MIN_ENTRIES"] = str(min_entries)
    else:
        env.pop("MANUF_MIN_ENTRIES", None)
    return subprocess.run(
        ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60, check=False
    )


@pytest.fixture
def dest(tmp_path: Path) -> Path:
    return tmp_path / "out" / "manuf.gz"


def _source(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "manuf"
    path.write_text(text)
    return path


class TestSuccessfulUpdate:
    def test_writes_the_downloaded_database_gzipped(self, tmp_path: Path, dest: Path) -> None:
        text = _manuf_text(5)
        result = _run(tmp_path, _source(tmp_path, text))

        assert result.returncode == 0, result.stderr
        assert gzip.decompress(dest.read_bytes()).decode() == text
        assert "5 OUI entries" in result.stdout

    def test_creates_the_destination_directory(self, tmp_path: Path, dest: Path) -> None:
        assert not dest.parent.exists()
        assert _run(tmp_path, _source(tmp_path, _manuf_text(5))).returncode == 0
        assert dest.is_file()

    def test_output_is_deterministic(self, tmp_path: Path, dest: Path) -> None:
        """No timestamp or file name in the gzip header: re-running on an
        unchanged database must not produce a different file (and so must
        not show up as a change in git)."""
        source = _source(tmp_path, _manuf_text(5))
        assert _run(tmp_path, source).returncode == 0
        first = dest.read_bytes()
        os.utime(source, (1, 1))  # a different mtime on the source must not matter either
        assert _run(tmp_path, source).returncode == 0

        assert dest.read_bytes() == first

    def test_result_is_world_readable_and_leaves_no_temp_files(
        self, tmp_path: Path, dest: Path
    ) -> None:
        assert _run(tmp_path, _source(tmp_path, _manuf_text(5))).returncode == 0

        assert stat.S_IMODE(dest.stat().st_mode) == 0o644
        assert [p.name for p in dest.parent.iterdir()] == ["manuf.gz"]

    def test_replaces_an_existing_file(self, tmp_path: Path, dest: Path) -> None:
        dest.parent.mkdir()
        dest.write_bytes(gzip.compress(b"old"))
        text = _manuf_text(5)

        assert _run(tmp_path, _source(tmp_path, text)).returncode == 0
        assert gzip.decompress(dest.read_bytes()).decode() == text

    def test_oui_range_lines_count_as_entries(self, tmp_path: Path, dest: Path) -> None:
        text = "# Wireshark manuf\n" + "".join(
            f"00:1B:C{i:X}:00:00:00/36\tShort{i}\tLong name {i}\n" for i in range(5)
        )
        assert _run(tmp_path, _source(tmp_path, text), min_entries=5).returncode == 0


class TestRefusesBadDownloads:
    """Each of these must exit non-zero and leave the existing file alone."""

    OLD = gzip.compress(b"previous database")

    def _assert_refused(
        self, result: subprocess.CompletedProcess[str], dest: Path, message: str
    ) -> None:
        assert result.returncode != 0
        assert message in result.stderr
        assert dest.read_bytes() == self.OLD, "the existing database was modified"
        assert [p.name for p in dest.parent.iterdir()] == ["manuf.gz"], (
            "a temp file was left behind"
        )

    def _seed(self, dest: Path) -> None:
        dest.parent.mkdir()
        dest.write_bytes(self.OLD)

    def test_a_page_that_is_not_a_wireshark_file(self, tmp_path: Path, dest: Path) -> None:
        self._seed(dest)
        result = _run(tmp_path, _source(tmp_path, "<html>404 Not Found</html>\n"))
        self._assert_refused(result, dest, "doesn't look like a Wireshark manuf file")

    def test_an_error_page_that_merely_mentions_wireshark(self, tmp_path: Path, dest: Path) -> None:
        """The old header-only check let this through and replaced a good
        database with an HTML page."""
        self._seed(dest)
        source = _source(tmp_path, "<html><title>Wireshark - temporarily down</title></html>\n")
        result = _run(tmp_path, source, min_entries=None)  # the default threshold (1000)
        self._assert_refused(result, dest, "only 0 OUI entries found")

    def test_a_truncated_file(self, tmp_path: Path, dest: Path) -> None:
        self._seed(dest)
        result = _run(tmp_path, _source(tmp_path, _manuf_text(4)), min_entries=10)
        self._assert_refused(result, dest, "only 4 OUI entries found (expected at least 10)")

    def test_a_download_that_fails(self, tmp_path: Path, dest: Path) -> None:
        self._seed(dest)
        result = _run(tmp_path, f"file://{tmp_path}/does-not-exist")
        assert result.returncode != 0
        assert dest.read_bytes() == self.OLD
        assert [p.name for p in dest.parent.iterdir()] == ["manuf.gz"]

    def test_the_default_threshold_is_not_trivially_small(self, tmp_path: Path, dest: Path) -> None:
        self._seed(dest)
        # 999 entries is below the documented default of 1000
        result = _run(tmp_path, _source(tmp_path, _manuf_text(999)), min_entries=None)
        self._assert_refused(result, dest, "only 999 OUI entries found (expected at least 1000)")

        assert (
            _run(tmp_path, _source(tmp_path, _manuf_text(1000)), min_entries=None).returncode == 0
        )


class TestScriptItself:
    def test_is_executable_and_has_a_bash_shebang(self) -> None:
        assert os.access(SCRIPT, os.X_OK)
        assert SCRIPT.read_text().startswith("#!/usr/bin/env bash\n")

    def test_has_valid_bash_syntax(self) -> None:
        result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    @pytest.mark.skipif(not shutil.which("shellcheck"), reason="shellcheck not installed")
    def test_passes_shellcheck(self) -> None:
        result = subprocess.run(["shellcheck", str(SCRIPT)], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout

    def test_default_destination_is_the_bundled_database(self) -> None:
        text = SCRIPT.read_text()
        assert "backend/app/data/manuf.gz" in text
        assert (REPO_ROOT / "backend" / "app" / "data" / "manuf.gz").is_file()

    def test_default_source_is_wiresharks_automated_manuf_file(self) -> None:
        assert "https://www.wireshark.org/download/automated/data/manuf" in SCRIPT.read_text()
