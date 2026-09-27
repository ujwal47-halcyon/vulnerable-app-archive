@echo off
cls
echo ==============================================================
echo   MediLink Health - 2026 Intermediate Bug Bounty CTF
echo ==============================================================
echo.
echo   URL:          http://localhost:5000
echo   Demo login:   jordan@medilink.health / Jordan#2026
echo   Vault:        http://localhost:5000/vault
echo   Deadline:     August 19, 2026
echo.
echo   Progress is saved in the data\ folder and survives restarts.
echo   Run locally only. Never deploy this intentionally vulnerable app.
echo ==============================================================
echo.
python -m pip install -r requirements.txt
python app.py
pause
