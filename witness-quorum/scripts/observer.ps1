$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot
$pidFile = Join-Path $projectRoot 'runtime\observer.pid'
if (Test-Path -LiteralPath $pidFile) {
    $observerPid = [int](Get-Content -LiteralPath $pidFile)
    $existing = Get-CimInstance Win32_Process -Filter "ProcessId=$observerPid"
    if ($existing -and $existing.CommandLine -like '*witness.dashboard*') { Write-Output 'Observer already running: http://127.0.0.1:9080'; exit }
}
$proc = Start-Process -FilePath (Join-Path $projectRoot '.venv\Scripts\python.exe') -ArgumentList '-m','witness.dashboard' -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $projectRoot 'runtime\observer.log') -RedirectStandardError (Join-Path $projectRoot 'runtime\observer.err.log')
Set-Content -LiteralPath $pidFile -Value $proc.Id
Write-Output 'Observer: http://127.0.0.1:9080'
