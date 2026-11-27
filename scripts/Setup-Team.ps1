param([ValidateSet('Download','Prepare','Finish')][string]$Stage='Download')
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
if (-not (Test-Path '.venv\Scripts\python.exe')) {
    & py -3 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.11+ for Windows, including the py launcher' }
}
$python=Join-Path $projectRoot '.venv\Scripts\python.exe'
function Run-Python {
    & $python @args
    if ($LASTEXITCODE -ne 0) { throw 'Setup step failed; read the error above. Do not continue.' }
}
if ($Stage -eq 'Download') {
    Run-Python -m pip install -r requirements-host.txt pycdlib==1.14.0
    Run-Python scripts/fetch_setup_assets.py
    Run-Python scripts/fetch_analysis_tools.py
    Run-Python scripts/fetch_release_assets.py
    Run-Python scripts/restore_release_model.py
    Write-Output 'Assets verified. Configure VMware VMnet1 as documented, then run -Stage Prepare.'
} elseif ($Stage -eq 'Prepare') {
    $network=Get-NetIPAddress -InterfaceAlias '*VMnet1*' -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (-not ($network | Where-Object { $_.IPAddress -eq '192.168.56.1' -and $_.PrefixLength -eq 24 })) {
        throw 'VMnet1 must be host-only 192.168.56.1/24. Follow docs/TEAM_SETUP.md; other networks are not changed automatically.'
    }
    Run-Python scripts/prepare_lab_vm.py
    $vmrun='C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    & $vmrun -T ws start (Join-Path $projectRoot 'private\lab-vm\StealerLab.vmx') nogui
    if ($LASTEXITCODE -ne 0) { throw 'VM start failed' }
    Write-Output 'VM started. Wait for bootstrap (about 1-3 minutes), then run -Stage Finish.'
} else {
    Run-Python scripts/finish_lab_setup.py
    Run-Python scripts/import_release_samples.py
    & .\scripts\Start-Lab.ps1
    Write-Output 'Run verify_lab.py, then the two public demos in docs/TEAM_SETUP.md.'
}
