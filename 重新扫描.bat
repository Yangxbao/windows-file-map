@echo off
chcp 65001 >nul
rem ============================================================
rem  本机文件地图与一键清理助手 - 重新执行全量只读扫描
rem  绝不修改/移动/删除任何原始文件；只更新本工具目录内的数据。
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
echo 正在启动只读扫描（可能需要几分钟，期间可随时打开网页查看进度）...
%PY% fm_scan.py
echo.
echo 扫描完成，可打开网页查看最新地图。
pause
