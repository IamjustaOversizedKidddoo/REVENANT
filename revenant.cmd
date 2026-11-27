@echo off
REM REVENANT launcher - run `.\revenant <args>` from the repo root.
REM
REM Self-bootstrapping: on first run it creates a local .venv and installs REVENANT
REM into it, so the command works on a fresh clone with NO manual setup and never
REM depends on a system-wide `revenant` being on PATH. After that it just runs.
REM Delete the .venv folder to force a clean rebuild.
setlocal
set "HERE=%~dp0"
set "VENV=%HERE%.venv"
set "VPY=%VENV%\Scripts\python.exe"

REM 1. Create the virtual environment if it is missing. Try the py launcher first,
REM    then fall back to python on PATH. No inline && / || and no parentheses in
REM    echoed text -- both confuse cmd.exe inside a block.
if not exist "%VPY%" (
    echo [revenant setup] Creating virtual environment in .venv ...
    py -3 -m venv "%VENV%" 2>nul
    if not exist "%VPY%" python -m venv "%VENV%" 2>nul
    if not exist "%VPY%" (
        echo [revenant setup] ERROR: could not create a virtual environment.
        echo [revenant setup] Install Python 3.11+ from https://python.org and retry.
        exit /b 1
    )
)

REM 2. Install REVENANT into the venv once. The sentinel file avoids reinstalling on
REM    every run. Installing with the venv's own Python guarantees it lands in the
REM    venv -- it can never silently fall back to a --user install off PATH.
if not exist "%VENV%\.revenant_installed" (
    echo [revenant setup] Installing REVENANT into the virtual environment, first run only ...
    REM Merge pip's stderr into stdout so a benign setuptools warning on first run is
    REM not surfaced as a red error by PowerShell. The errorlevel check still catches
    REM a real install failure (it reads the exit code, not the stream).
    "%VPY%" -m pip install --upgrade pip --quiet 2>&1
    "%VPY%" -m pip install -e "%HERE%." --quiet --no-warn-script-location 2>&1
    if errorlevel 1 (
        echo [revenant setup] ERROR: dependency install failed. See the output above.
        exit /b 1
    )
    echo installed> "%VENV%\.revenant_installed"
    echo [revenant setup] Ready.
    echo.
)

REM 3. Run through the venv's Python and the path-independent entrypoint, so this
REM    works whether or not the console-script .exe was created or is on PATH.
"%VPY%" "%HERE%revenant.py" %*
exit /b %ERRORLEVEL%
