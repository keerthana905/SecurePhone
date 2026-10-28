@echo off
title SecurePhone Server (http://127.0.0.1:5000)
cd /d "%~dp0"
echo Starting SecurePhone on http://127.0.0.1:5000 ...
start "" "http://127.0.0.1:5000"
python app.py
pause
