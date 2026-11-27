param([ValidateSet('baseline','candidate-8b')][string]$Profile='baseline',
      [ValidateSet('real-v1','real-v3')][string]$CorpusProfile='real-v3')
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$config=if ($Profile -eq 'candidate-8b') {'config/host.cards-qwen3-candidate.example.json'} else {'config/host.yara-7b.example.json'}
$env:STEALER_LAB_TOKEN=(Get-Content -LiteralPath 'config/lab.token' -Raw).Trim()
try {
    $manifest=if ($CorpusProfile -eq 'real-v3') {'eval/corpora/real-yara-development-v3.json'} else {'eval/corpora/real-yara-v1.json'}
    & '.\.venv\Scripts\python.exe' -m stealer_agent.yara_corpus --config $config --profile $CorpusProfile --manifest $manifest
    if ($LASTEXITCODE -ne 0) { throw 'YARA experiment incomplete; inspect the private run summary.' }
} finally {
    Remove-Item Env:STEALER_LAB_TOKEN -ErrorAction SilentlyContinue
}
