@echo off
REM Start server + cloudflared tunnel in separate windows
REM Usage: double-click start-tunnel.bat or run from terminal

echo Starting Email Panel server + Cloudflare Tunnel...

start "Email Panel Server" /D "%~dp0.." cmd /k "npm start"

timeout /t 3 /nobreak >nul

start "Cloudflare Tunnel" cmd /k ""C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://localhost:3000"

echo.
echo Two windows opened:
echo   1. Email Panel Server (port 3000)
echo   2. Cloudflare Tunnel (check for trycloudflare.com URL)
echo.
echo Open the https://xxx.trycloudflare.com URL from the tunnel window in your browser.
echo Close both windows to stop.
