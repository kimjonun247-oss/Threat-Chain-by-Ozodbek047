@echo off
setlocal
cd /d "%~dp0"
echo crAPI manbasi tekshiriladi va yetishmagan fayllar nusxalanadi.
echo Mavjud fayllar ochirilmaydi yoki almashtirilmaydi.
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" (
  "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" -X utf8 bundle_crapi.py %*
  goto result
)
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 -X utf8 bundle_crapi.py %*
  goto result
)
where python >nul 2>nul
if %errorlevel% equ 0 (
  python -X utf8 bundle_crapi.py %*
  goto result
)
echo Python 3.10 yoki yangiroq versiya kerak.
pause
exit /b 1
:result
set "BUNDLE_EXIT=%errorlevel%"
if not "%BUNDLE_EXIT%"=="0" (
  echo Nusxa olish yakunlanmadi. Yuqoridagi sababni tekshiring.
) else (
  echo Tayyor. Bu manba nusxasi; boshqa kompyuterda Python va skanerlar ham kerak.
)
pause
exit /b %BUNDLE_EXIT%
