@echo off
setlocal
cd /d "%~dp0"
set "ZANJIR_PYTHON=python"
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" set "ZANJIR_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
echo crAPI mahalliy kirishi tuzatiladi. Docker Desktop ochiq tursin.
echo Image fayllari qayta yuklanmaydi. Sinov bazasi saqlanadi.
"%ZANJIR_PYTHON%" -X utf8 pilot.py repair-access
if errorlevel 1 goto failed
echo Tayyor: http://127.0.0.1:18888/
echo Sahifa javob berdi. Xavfsizlik sinovi hali bajarilmagan.
pause
exit /b 0
:failed
echo Tuzatish yoki sahifa tekshiruvi tugallanmadi. Shu oynani ochiq qoldiring.
echo Natija pilot\runtime papkasida saqlandi.
pause
exit /b 1
