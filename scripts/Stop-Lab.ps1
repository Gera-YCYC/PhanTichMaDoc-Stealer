$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
& .\scripts\Stop-LocalModel.ps1
& ssh -i private/lab-vm/admin_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=private/lab-vm/known_hosts -o ConnectTimeout=5 labadmin@192.168.56.101 'sudo poweroff'
Write-Output 'Requested graceful shutdown of the project VM.'
