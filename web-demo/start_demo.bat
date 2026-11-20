@echo off
cd /d "%~dp0"
start "1 - Demo server" cmd /k python web_demo.py
timeout /t 2 /nobreak >nul
start "2 - Public link (copy the https link shown here)" cmd /k ssh -o ServerAliveInterval=60 -R 80:localhost:8000 nokey@localhost.run
start "" http://localhost:8000/dashboard
