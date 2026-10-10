#!/usr/bin/env python3
"""
==============================================================================
Module Name:   run.py
Description:   Implementation and logic for run.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 run.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

import os
import sys
import subprocess
import platform
from pathlib import Path


def check_python_version():
    if sys.version_info < (3, 10):
        print(
            f"Error: Python 3.10 or higher is required. You are running Python {sys.version_info.major}.{sys.version_info.minor}."
        )
        sys.exit(1)


def is_stale(stamp_file: Path, source_files: list[Path]) -> bool:
    if not stamp_file.exists():
        return True
    stamp_time = stamp_file.stat().st_mtime
    for sf in source_files:
        if sf.exists() and sf.stat().st_mtime > stamp_time:
            return True
    return False


def mark_fresh(stamp_file: Path):
    stamp_file.parent.mkdir(parents=True, exist_ok=True)
    stamp_file.touch()


def main():
    check_python_version()

    root_dir = Path(__file__).parent.resolve()
    os.chdir(root_dir)

    is_windows = platform.system() == "Windows"
    venv_dir = root_dir / ".venv"

    if is_windows:
        venv_bin = venv_dir / "Scripts"
        python_exe = venv_bin / "python.exe"
        pip_exe = venv_bin / "pip.exe"
        cli_exe = venv_bin / "arp-atlas.exe"
    else:
        venv_bin = venv_dir / "bin"
        python_exe = venv_bin / "python"
        pip_exe = venv_bin / "pip"
        cli_exe = venv_bin / "arp-atlas"

    reqs_txt = root_dir / "requirements.txt"
    cli_reqs = root_dir / "cli" / "pyproject.toml"
    py_stamp = venv_dir / ".deps_installed_stamp"

    if is_stale(py_stamp, [reqs_txt, cli_reqs]) or not cli_exe.exists():
        print("Checking and installing Python dependencies...")
        if not venv_dir.exists():
            subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)

        subprocess.run(
            [str(python_exe), "-m", "pip", "install", "--upgrade", "pip", "-q"], check=True
        )
        if reqs_txt.exists():
            subprocess.run([str(pip_exe), "install", "-r", str(reqs_txt)], check=True)
        if cli_reqs.exists():
            subprocess.run([str(pip_exe), "install", "-e", str(root_dir / "cli")], check=True)
        mark_fresh(py_stamp)

    # Execution
    args = sys.argv[1:]
    try:
        subprocess.run([str(python_exe), "main.py"] + args)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
