@echo off
rem ============================================================
rem  FileMap Helper - regenerate the read-only scan + reports
rem  This NEVER modifies/moves/deletes any of your files.
rem  It only writes files into this tool folder.
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
echo Starting read-only scan ... (this may take several minutes)
%PY% fm_scan.py
echo.
echo Done. You can open index.html again.
pause
