$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot
if (-not (Test-Path .venv\Scripts\python.exe)) { python -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install -r requirements.lock
if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed' }
$goExe = Join-Path $projectRoot '.tools\go\bin\go.exe'
if (-not (Test-Path $goExe)) {
    New-Item -ItemType Directory -Force .tools | Out-Null
    $releases = Invoke-RestMethod 'https://go.dev/dl/?mode=json&include=all'
    $release = $releases | Where-Object version -eq 'go1.27.3'
    $archive = $release.files | Where-Object { $_.os -eq 'windows' -and $_.arch -eq 'amd64' -and $_.kind -eq 'archive' }
    if (-not $archive) { throw 'Pinned Go release not available' }
    Invoke-WebRequest ('https://dl.google.com/go/' + $archive.filename) -OutFile .tools\go.zip
    if ((Get-FileHash .tools\go.zip -Algorithm SHA256).Hash.ToLower() -ne $archive.sha256) { throw 'Go SHA256 verification failed' }
    Expand-Archive .tools\go.zip .tools -Force
}
& .\scripts\build.ps1
& .\.venv\Scripts\python.exe -m witness.native
if ($LASTEXITCODE -ne 0) { throw 'XMSS integration adapter build failed; GCC and shared crypto-libs sources are required' }
