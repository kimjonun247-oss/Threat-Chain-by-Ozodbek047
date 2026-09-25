@echo off
setlocal
cd /d "%~dp0"
set "ZANJIR_PYTHON=python"
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" set "ZANJIR_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
echo crAPI konfiguratsiyasidan dalil olinadi. Docker Desktop ochiq tursin.
echo Xizmatlar sozlamasi ozgarmaydi. Image qayta yuklanmaydi.
"%ZANJIR_PYTHON%" -X utf8 pilot_evidence.py
if errorlevel 1 goto failed
echo Dalil olindi. Bu hali amaliy xavfsizlik testi tasdiqlandi degani emas.
echo Natijani Codex davom ettirib tahlil qiladi.
pause
exit /b 0
:failed
echo Dalil olish tugallanmadi. Ushbu oynani ochiq qoldiring.
pause
exit /b 1
