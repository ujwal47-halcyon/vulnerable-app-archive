@echo off
title CloudPeak - IDOR Training Lab (CTF Edition)
echo.
echo  ============================================================
echo   CloudPeak - IDOR Training Lab (CTF Edition)
echo   Deliberately vulnerable - LOCAL USE ONLY
echo  ============================================================
echo.
cd /d "%~dp0"

echo  [1/2] Installing dependencies (if needed)...
python -m pip install -r requirements.txt --quiet

echo  [2/2] Starting the server...
echo.
echo  Open your browser at:  http://localhost:5000
echo  Press Ctrl+C in this window to stop the server.
echo.
python app.py
pause
