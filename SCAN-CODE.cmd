@echo off
setlocal
cd /d "%~dp0"
set "ZANJIR_PYTHON=python"
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" set "ZANJIR_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
echo crAPI manbasi Semgrep va Gitleaks bilan tekshiriladi.
echo Natija Zanjirning Kod va sirlar bolimida korinadi.
"%ZANJIR_PYTHON%" -X utf8 scan_code.py
if errorlevel 1 goto failed
echo Tekshiruv tugadi. Topilmalar qolda tekshirilishi kerak.
pause
exit /b 0
:failed
echo Tekshiruv toliq tugamadi. Hisobotda xato holati saqlandi.
pause
exit /b 1
