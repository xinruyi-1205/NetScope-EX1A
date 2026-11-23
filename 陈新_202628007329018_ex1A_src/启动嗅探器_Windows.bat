@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 main.py
) else (
    python main.py
)
if errorlevel 1 (
    echo.
    echo 启动失败。请确认已安装 Python 3.10+，且已勾选 PATH。
    echo 真实抓包还需要先安装 Npcap：https://npcap.com/
    pause
)
