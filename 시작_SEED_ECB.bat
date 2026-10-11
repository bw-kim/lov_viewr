@echo off
cd /d "%~dp0"
python seed_ecb_tool.py
if errorlevel 1 pause
