@echo off
setlocal
cd /d "%~dp0"
set "ZANJIR_PYTHON=python"
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" set "ZANJIR_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
echo 4 ta TLS nazorat sinovi bajariladi. Docker Desktop ochiq tursin.
echo crAPI ozgarmaydi. Image qayta yuklanmaydi. Sinov konteyneri keyin olib tashlanadi.
"%ZANJIR_PYTHON%" -X utf8 pilot_tls.py run
if errorlevel 1 goto failed
echo 4 ta nazorat otdi. Natija saqlandi; Codex uni tahlil qiladi.
echo Bu crAPI tarmogida hujum yoli borligini hali isbotlamaydi.
pause
exit /b 0
:failed
echo Sinov toliq tasdiqlanmadi. Ushbu oynani ochiq qoldiring.
echo Natija pilot\runtime va pilot\tls-runs papkalarida saqlandi.
pause
exit /b 1
