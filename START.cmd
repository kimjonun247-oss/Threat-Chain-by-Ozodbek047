@echo off
cd /d "%~dp0"
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" (
  "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" -X utf8 app.py %*
  goto done
)
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 -X utf8 app.py %*
  goto done
)
where python >nul 2>nul
if %errorlevel% equ 0 (
  python -X utf8 app.py %*
  goto done
)
echo Python 3.10 yoki yangiroq versiya kerak.
:done
pause
