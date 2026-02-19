# Simple PowerShell start script for the project
# Run from project root in PowerShell:
#   .\start.ps1

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host "Starting Cloudflare Email Panel (server + bot)..."
# Run bot in a background process so the server can stay in the foreground.
$botProcess = Start-Process -FilePath "node" -ArgumentList "bot.js" -WorkingDirectory $root -NoNewWindow -PassThru
Write-Host "Bot started (PID $($botProcess.Id))."

Write-Host "Starting server (node server.js)..."
try {
  node server.js
} finally {
  if ($botProcess -and -not $botProcess.HasExited) {
    Write-Host "Stopping bot..."
    Stop-Process -Id $botProcess.Id -Force
  }
}
