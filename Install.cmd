@echo off
rem Double-click to install: puts a "Cisco VPN" shortcut on your desktop and in the Start menu,
rem then opens a small window that asks for your VPN login once.
setlocal
set "SCRIPT=%~dp0cisco-vpn-autologin.ps1"
if not exist "%SCRIPT%" (
    echo Please unzip the download first: right-click the zip file, choose "Extract All",
    echo then double-click Install.cmd in the unzipped folder.
    echo.
    pause
    exit /b 1
)
rem Clear the "downloaded from the internet" mark so Windows lets the script run.
powershell.exe -NoProfile -Command "Unblock-File -LiteralPath $env:SCRIPT"
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%SCRIPT%" -Install
