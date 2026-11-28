param([ValidateRange(1024,65535)][int]$Port=4180,[switch]$HistoryOnly)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $root
$started=$false
try {
    if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
        throw "Port $Port is already in use. Close the existing web session or choose -Port."
    }
    if (-not $HistoryOnly) {
        $config='config/host.investigation.example.json'
        & .\scripts\Start-Lab.ps1 -PromptCacheMiB 0 -Config $config
        $started=$true
        & .\.venv\Scripts\python.exe scripts/sync_vm.py
        if ($LASTEXITCODE) { throw 'Source sync failed.' }
        & .\.venv\Scripts\python.exe scripts/verify_lab.py --config $config
        if ($LASTEXITCODE) { throw 'VM verification failed.' }
    }
    Write-Host "StealerLab: http://127.0.0.1:$Port  (Ctrl+C to close)"
    $webArgs=@('--port',$Port)
    if ($HistoryOnly) { $webArgs+='--history-only' }
    & .\.venv\Scripts\python.exe -m lab_web.server @webArgs
} finally {
    try {
        if ($started) { & .\scripts\Stop-Lab.ps1 }
    } finally {
        Pop-Location
    }
}
