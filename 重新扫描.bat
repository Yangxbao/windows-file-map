@echo off
rem ============================================================
rem  FileMap - full read-only rescan (CN: 重新扫描)
rem  This NEVER modifies/moves/deletes any of your files.
rem  It only writes data files inside this tool folder.
rem  NOTE: keep this .bat pure ASCII - cmd misparses UTF-8/GBK
rem  batch files with Chinese text (offset bug after chcp).
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
echo Starting read-only scan ... (a few minutes; you can open the
echo web page any time to watch live progress)
%PY% fm_scan.py
echo.
echo Done. Start the app with: 启动文件地图.bat  (or: python serve.py)
pause
