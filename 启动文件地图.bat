@echo off
rem ============================================================
rem  FileMap - local helper server (CN product name below)
rem  CN name: BenJi WenJianDiTu yu YiJianQingLi ZhuShou
rem  This starts the local server (127.0.0.1 only) and opens the
rem  app in your browser. Close this window to stop the service.
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
%PY% serve.py
pause
