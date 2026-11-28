$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$vmrun='C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$vmx=Join-Path $projectRoot 'private\lab-vm\StealerLab.vmx'
$owner=Get-Content -Raw -LiteralPath 'evidence/local/ollama/process.json' | ConvertFrom-Json
function Get-RunningLab {
    $running=& $vmrun -T ws list
    if ($LASTEXITCODE -ne 0) { throw 'VMware did not return the current VM inventory' }
    return $running -contains $vmx
}
& .\scripts\Stop-LocalModel.ps1
if (Get-RunningLab) {
    & ssh -i private/lab-vm/admin_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=private/lab-vm/known_hosts -o ConnectTimeout=5 labadmin@192.168.56.101 'sudo poweroff'
    # SSH may disconnect during a successful shutdown. Verify the VM itself.
    $deadline=[DateTime]::UtcNow.AddSeconds(45)
    while (Get-RunningLab) {
        if ([DateTime]::UtcNow -ge $deadline) {throw 'Project VM is still running after graceful shutdown'}
        Start-Sleep -Milliseconds 500
    }
}
$process=Get-Process -Id $owner.pid -ErrorAction SilentlyContinue
$ownerPresent=$null -ne $process -and $process.Path -eq $owner.executable -and
    $process.StartTime.ToUniversalTime().Ticks -eq ([DateTimeOffset]$owner.started).UtcDateTime.Ticks
$port=([Uri]$owner.endpoint).Port
$listeners=@(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)
if ($ownerPresent -or $listeners.Count -gt 0) {throw 'The model server or its listening port is still active'}
$gpuMemory=@()
$smi=Get-Command nvidia-smi.exe -ErrorAction SilentlyContinue
if ($smi) {
    $observed=& $smi.Source --query-gpu=memory.used,memory.total --format=csv,noheader,nounits
    if ($LASTEXITCODE -eq 0) {
        $gpuMemory=@(foreach ($row in $observed) {
            if ($row -match '^\s*(\d+),\s*(\d+)\s*$') {
                [ordered]@{used_mib=[int]$Matches[1]; total_mib=[int]$Matches[2]}
            }
        })
    }
}
$record=[ordered]@{
    checked_at=[DateTime]::UtcNow.ToString('o')
    project_ollama_pid=$owner.pid
    project_ollama_process_present=$ownerPresent
    project_port=$port
    port_listeners=$listeners.Count
    project_vm_listed=(Get-RunningLab)
    gpu_observations=$gpuMemory
    scope='The VM inventory and listener were checked on the project host. GPU memory includes other applications.'
}
if ($record.project_vm_listed) {throw 'Project VM reappeared during verification'}
$record | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 -LiteralPath 'evidence/local/runtime-stopped-latest.json'
Write-Output 'Project VM and model server are stopped. Checked evidence/local/runtime-stopped-latest.json.'
