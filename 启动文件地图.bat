@echo off
chcp 65001 >nul
rem ============================================================
rem  本机文件地图与一键清理助手 - 启动本地服务
rem  关闭此窗口即停止服务。全程只读盘点；清理功能需在本工具
rem  页面内单独启用（一次性确认），只清理白名单中的安全项目。
rem ============================================================
cd /d "%~dp0"
set PY=
where python >nul 2>nul && set PY=python
if not defined PY where py >nul 2>nul && set PY=py
if not defined PY (
  echo [错误] 未找到 Python 3，请先安装 Python 3。
  pause
  exit /b 1
)
%PY% serve.py
pause
