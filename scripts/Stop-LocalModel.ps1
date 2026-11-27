$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$receiptPath = Join-Path $projectRoot 'evidence\local\ollama\process.json'
if (-not (Test-Path -LiteralPath $receiptPath)) { throw 'No model process receipt' }
$receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
$proc = Get-Process -Id $receipt.pid -ErrorAction SilentlyContinue
if ($null -eq $proc) { Write-Output 'Recorded model server is already stopped'; exit 0 }
$recordedStart = [DateTimeOffset]$receipt.started
if ($proc.Path -ne $receipt.executable -or $proc.StartTime.ToUniversalTime().Ticks -ne $recordedStart.UtcDateTime.Ticks) {
    throw 'PID was reused or process identity differs; refusing to stop it'
}
try {
    $loaded = Invoke-RestMethod -Uri ($receipt.endpoint + '/api/ps') -TimeoutSec 10
    foreach ($model in $loaded.models) {
        $body = @{model=$model.name; keep_alive=0} | ConvertTo-Json -Compress
        Invoke-RestMethod -Uri ($receipt.endpoint + '/api/generate') -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 10 | Out-Null
    }
} catch { }
Stop-Process -Id $proc.Id
Write-Output 'Stopped project-owned Ollama server'
