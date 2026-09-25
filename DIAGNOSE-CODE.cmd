@echo off
setlocal
cd /d "%~dp0"
set "ZANJIR_PYTHON=python"
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" set "ZANJIR_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
"%ZANJIR_PYTHON%" -X utf8 scan_code.py --diagnose-latest
if errorlevel 1 echo Diagnostika tugallanmadi. Ushbu oynadagi xabarni yuboring.
pause
