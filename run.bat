@echo off
setlocal
cd /d "%~dp0"
python -m pip install -r requirements.txt
python windows_admin_tool.py
pause
