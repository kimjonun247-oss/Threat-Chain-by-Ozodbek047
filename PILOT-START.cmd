@echo off
setlocal
cd /d "%~dp0"
set "ZANJIR_PYTHON=python"
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" set "ZANJIR_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
echo 1/3 Docker tayyorligi tekshirilmoqda...
"%ZANJIR_PYTHON%" -X utf8 pilot.py check
if errorlevel 1 goto failed
echo 2/3 crAPI fayllari yuklanmoqda. Internet kerak. Oynani ochiq qoldiring.
"%ZANJIR_PYTHON%" -X utf8 pilot.py pull
if errorlevel 1 goto failed
echo 3/3 Ajratilgan crAPI sinov muhiti ishga tushirilmoqda...
"%ZANJIR_PYTHON%" -X utf8 pilot.py start
if errorlevel 1 goto failed
echo Xizmatlar tayyor. Brauzerda http://127.0.0.1:18888/ ni oching.
echo Bu hali xavfsizlik topilmasi tasdiqlandi degani emas.
pause
exit /b 0
:failed
echo Jarayon tugallanmadi. Yuqoridagi xato matnini Codex suhbatiga yuboring.
echo Docker Desktop ochiq va Engine running holatida bolishi kerak.
pause
exit /b 1
