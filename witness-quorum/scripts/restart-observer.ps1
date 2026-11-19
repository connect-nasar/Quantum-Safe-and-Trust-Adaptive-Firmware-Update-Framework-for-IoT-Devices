$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$pidFile = Join-Path $projectRoot 'runtime\observer.pid'
if (Test-Path -LiteralPath $pidFile) {
    $observerPid = [int](Get-Content -LiteralPath $pidFile)
    $existing = Get-CimInstance Win32_Process -Filter "ProcessId=$observerPid"
    if ($existing -and $existing.CommandLine -like '*witness.dashboard*') { & taskkill /PID $observerPid /T /F | Out-Null }
    Remove-Item -LiteralPath $pidFile
}
& (Join-Path $PSScriptRoot 'observer.ps1')
