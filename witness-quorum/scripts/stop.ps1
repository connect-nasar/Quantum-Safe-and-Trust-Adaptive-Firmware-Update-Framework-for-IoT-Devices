$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
& .\.venv\Scripts\python.exe -m witness.local stop
$pidFile = Join-Path (Get-Location) 'runtime\observer.pid'
if (Test-Path -LiteralPath $pidFile) {
    $observerPid = [int](Get-Content -LiteralPath $pidFile)
    $existing = Get-CimInstance Win32_Process -Filter "ProcessId=$observerPid"
    if ($existing -and $existing.CommandLine -like '*witness.dashboard*') { & taskkill /PID $observerPid /T /F | Out-Null }
    Remove-Item -LiteralPath $pidFile
}
