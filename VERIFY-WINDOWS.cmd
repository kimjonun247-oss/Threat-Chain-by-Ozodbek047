@echo off
rem ThreatChain: barcha skanerlarni shu Windows mashinasida uchidan-uchigacha tekshiradi.
rem Natija: validation-runs\platform-windows.json
rem Tekshiruv bir necha daqiqa oladi; oynani yopmang.
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py -3) || (set PY=python)
%PY% setup_all.py
%PY% verify_platform.py
echo.
echo Natija fayli: validation-runs\platform-windows.json
pause
