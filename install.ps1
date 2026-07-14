$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Write-Host "Setup stopped: Node.js 22 or newer is required. Install Node.js from https://nodejs.org/ and run this setup again."
  exit 1
}

node .\install.mjs
Read-Host "Press Enter to close"
