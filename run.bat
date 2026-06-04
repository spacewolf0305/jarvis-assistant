@echo off
title J.A.R.V.I.S — Cybersecurity AI Voice Assistant
color 0B

echo.
echo     ╔══════════════════════════════════════════╗
echo     ║   J.A.R.V.I.S v2.0                      ║
echo     ║   Cybersecurity AI Voice Assistant       ║
echo     ╚══════════════════════════════════════════╝
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.11+ from https://python.org
    pause
    exit /b 1
)

:: Install dependencies
echo [*] Installing dependencies...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies.
    echo Try: pip install -r requirements.txt
    pause
    exit /b 1
)

echo [*] Dependencies installed successfully.
echo [*] Starting JARVIS...
echo.

:: Launch JARVIS
python jarvis.py

pause
