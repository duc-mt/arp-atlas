@echo off
REM ==============================================================================
REM Script Name:   run.bat
REM Description:   Windows batch launcher for ARP Atlas
REM Usage:         run.bat [options]
REM ==============================================================================
setlocal EnableDelayedExpansion

cd /d "%~dp0.."

REM 1. If virtual environment exists, use its Python directly
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" "%~dp0run.py" %*
    exit /b %ERRORLEVEL%
)

REM 2. Otherwise locate Windows Python Launcher (py -3) or system python
where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py -3 "%~dp0run.py" %*
    exit /b %ERRORLEVEL%
)

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python "%~dp0run.py" %*
    exit /b %ERRORLEVEL%
)

echo [ERROR] Python 3.10+ is required but not found in PATH. >&2
echo Please install Python 3.10+ (https://www.python.org/) and ensure "Add Python to PATH" is checked. >&2
exit /b 1
