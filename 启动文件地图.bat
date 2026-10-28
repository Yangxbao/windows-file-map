@echo off
rem ============================================================
rem  FileMap Helper - start local helper server (read-only)
rem  This serves index.html and enables the "open in Explorer"
rem  button. Close this window to stop the service.
rem ============================================================
cd /d "%~dp0"
set PY=
where python >nul 2>nul && set PY=python
if not defined PY where py >nul 2>nul && set PY=py
if not defined PY (
  echo [ERROR] Python 3 not found. Please install Python 3 first.
  pause
  exit /b 1
)
%PY% serve.py
pause
