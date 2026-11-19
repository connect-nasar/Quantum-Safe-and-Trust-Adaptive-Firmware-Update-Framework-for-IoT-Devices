$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
New-Item -ItemType Directory -Force (Join-Path $projectRoot 'bin') | Out-Null
$goExe = Join-Path $projectRoot '.tools\go\bin\go.exe'
if (-not (Test-Path -LiteralPath $goExe)) { $goExe = (Get-Command go -ErrorAction Stop).Source }
Push-Location (Join-Path $projectRoot 'engine')
try {
    & $goExe build -trimpath -o ..\bin\witness-engine.exe .
    if ($LASTEXITCODE -ne 0) { throw 'Engine build failed' }
} finally { Pop-Location }
