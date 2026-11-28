param([ValidateRange(0,1024)][int]$PromptCacheMiB = 256)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$vmrun='C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$vmx=Join-Path $projectRoot 'private\lab-vm\StealerLab.vmx'
$running=& $vmrun list
if (-not ($running -contains $vmx)) {
    $otherLab=$running | Where-Object { $_ -match '[\\/]StealerLab\.vmx$' -and $_ -ne $vmx }
    if ($otherLab) { throw 'Another StealerLab VM is running with the shared lab IP; stop that lab first' }
    & $vmrun -T ws start $vmx nogui
    if ($LASTEXITCODE -ne 0) { throw 'VM failed to start' }
}
$ready=$false
for ($attempt=0;$attempt -lt 12;$attempt++) {
    & ssh -i private/lab-vm/admin_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=private/lab-vm/known_hosts -o ConnectTimeout=3 labadmin@192.168.56.101 'test -f /opt/stealer-lab/BOOTSTRAP_READY' 2>$null
    if ($LASTEXITCODE -eq 0) { $ready=$true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) { throw 'VM is booting or SSH is unavailable; inspect it and retry' }
$epoch=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
& ssh -i private/lab-vm/admin_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=private/lab-vm/known_hosts labadmin@192.168.56.101 "sudo date -u -s '@$epoch'; sudo systemctl start stealer-lab.service"
if ($LASTEXITCODE -ne 0) { throw 'VM service failed' }
$listener = Get-NetTCPConnection -LocalPort 11435 -State Listen -ErrorAction SilentlyContinue
if (-not $listener) {
    & .\scripts\Start-LocalModel.ps1 -ModelDirectory (Join-Path $projectRoot 'private\ollama-models') -PromptCacheMiB $PromptCacheMiB
} else {
    $receipt = Get-Content -LiteralPath 'evidence/local/ollama/process.json' -Raw | ConvertFrom-Json
    $owned = Get-Process -Id $receipt.pid -ErrorAction Stop
    $recordedStart = [DateTimeOffset]$receipt.started
    if ($listener.OwningProcess -ne $receipt.pid -or $owned.Path -ne $receipt.executable -or
        $owned.StartTime.ToUniversalTime().Ticks -ne $recordedStart.UtcDateTime.Ticks -or
        $receipt.model_directory -ne (Join-Path $projectRoot 'private\ollama-models')) {
        throw 'Existing port owner/model store differs from project receipt; refusing to reuse it'
    }
    if ($PSBoundParameters.ContainsKey('PromptCacheMiB') -and $receipt.prompt_cache_mib -ne $PromptCacheMiB) {
        throw "Existing project server uses cache $($receipt.prompt_cache_mib) MiB. Stop the project model server before starting a different cache configuration."
    }
}
& '.\.venv\Scripts\python.exe' scripts/wait_lab_ready.py
if ($LASTEXITCODE -ne 0) { throw 'VM/model not ready; do not start the demo yet' }
Write-Output 'Lab ready; use scripts/Run-Demo.ps1.'
