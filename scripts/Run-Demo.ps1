param([ValidateSet('public_gomorrah.bin','public_agenttesla.bin','public_luna.bin','public_python2024.bin','public_mercurial.bin')][string]$Sample='public_gomorrah.bin', [ValidateSet(1,3)][int]$Runs=1)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$env:STEALER_LAB_TOKEN=(Get-Content -LiteralPath 'config/lab.token' -Raw).Trim()
& '.\.venv\Scripts\python.exe' agent_react.py --config config/host.example.json --sample $Sample --runs $Runs --public-demo --live
exit $LASTEXITCODE
