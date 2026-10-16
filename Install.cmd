@echo off
rem Double-click to install: asks for your VPN login once, then puts
rem "Cisco VPN Connect" and "Cisco VPN Disconnect" on your desktop.
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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -Install
echo.
pause
