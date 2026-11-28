param(
    [ValidateSet('public_gomorrah.bin','public_agenttesla.bin','public_luna.bin','public_python2024.bin','public_mercurial.bin')][string]$Sample='public_gomorrah.bin',
    [ValidateSet(1,3)][int]$Runs=1,
    [ValidateSet('baseline','cards-7b','cards-8b','coverage-8b')][string]$Profile='baseline'
)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$env:STEALER_LAB_TOKEN=(Get-Content -LiteralPath 'config/lab.token' -Raw).Trim()
$profileConfig = @{
    'baseline' = 'config/host.example.json'
    'cards-7b' = 'config/host.cards-candidate.example.json'
    'cards-8b' = 'config/host.cards-qwen3-candidate.example.json'
    'coverage-8b' = 'config/host.coverage-qwen3.example.json'
}[$Profile]
Write-Output "Demo profile: $Profile ($profileConfig)"
& '.\.venv\Scripts\python.exe' agent_react.py --config $profileConfig --sample $Sample --runs $Runs --public-demo --live
exit $LASTEXITCODE
