$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
& .\.venv\Scripts\python.exe -m witness.local start
if ($LASTEXITCODE -ne 0) { throw 'Witness startup failed' }
& .\scripts\observer.ps1
