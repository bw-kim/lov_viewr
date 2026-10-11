@echo off
cd /d "%~dp0"
python SEED_ECB_portable.py
if errorlevel 1 pause
