@echo off
setlocal
cd /d "%~dp0"
set "ZANJIR_PYTHON=python"
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" set "ZANJIR_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
echo crAPI manba + online CVE + ruxsatli lokal web + image tekshiruvi.
echo Docker Desktop va crAPI avval ishga tushgan bolishi kerak.
echo Bu oyna tugamaguncha uni yopmang. Natijalar Zanjir interfeysida saqlanadi.
"%ZANJIR_PYTHON%" -X utf8 check_all.py --target crapi-full --web-target pilot-crapi --image-target pilot-crapi-web --online
if errorlevel 1 goto incomplete
echo Barcha tanlangan bosqichlar tugadi. Bu barcha zaifliklar topildi degani emas.
goto done
:incomplete
echo Tekshiruvda qisman yoki tugallanmagan bosqich bor. Interfeysda har bir bosqich holatini koring.
:done
pause
