@echo off
rem ============================================================
rem  FileMap Helper - admin retry for previously denied folders
rem  READ-ONLY: this only re-runs fm_scan.py --admin-retry, which
rem  re-attempts enumeration of directories that failed with
rem  "access denied" during the normal scan. It NEVER modifies,
rem  moves or deletes any file, and never changes any ACL.
rem  It will ask for Windows administrator approval (UAC).
rem =================================================-----------
cd /d "%~dp0"
set PY=
where python >nul 2>nul && set PY=python
if not defined PY where py >nul 2>nul && set PY=py
if not defined PY (
  echo [ERROR] Python 3 not found. Please install Python 3 first.
  pause
  exit /b 1
)
echo Requesting administrator approval for a READ-ONLY targeted retry...
powershell -NoProfile -Command "Start-Process -FilePath '%PY%' -ArgumentList 'fm_scan.py --admin-retry' -WorkingDirectory '%~dp0' -Verb RunAs"
echo.
echo If a UAC prompt appeared and you approved it, the retry runs in a
echo separate administrator console window. Close that window when done.
pause
