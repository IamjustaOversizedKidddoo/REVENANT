@echo off
REM REVENANT launcher — run `.\revenant <args>` from the repo root without activating
REM the virtualenv. Prefers the installed console script, falls back to the venv
REM Python running revenant.py, then to whatever `python` is on PATH.
setlocal
set "HERE=%~dp0"
if exist "%HERE%.venv\Scripts\revenant.exe" (
    "%HERE%.venv\Scripts\revenant.exe" %*
) else if exist "%HERE%.venv\Scripts\python.exe" (
    "%HERE%.venv\Scripts\python.exe" "%HERE%revenant.py" %*
) else (
    python "%HERE%revenant.py" %*
)
exit /b %ERRORLEVEL%
