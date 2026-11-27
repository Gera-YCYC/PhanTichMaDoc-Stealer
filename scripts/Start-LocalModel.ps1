param(
    [string]$OllamaExe = '',
    [string]$ModelDirectory = '',
    [int]$Port = 11435,
    [ValidateRange(0,1024)][int]$PromptCacheMiB = 256
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $OllamaExe) {
    $discovered = Get-Command ollama.exe -ErrorAction SilentlyContinue
    $candidates = @(
        $(if ($discovered) { $discovered.Source }),
        (Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'),
        'M:\Tools\Mountain-Ollama\0.40.17\runtime\ollama.exe'
    )
    $OllamaExe = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}
if (-not $ModelDirectory) { $ModelDirectory = Join-Path $projectRoot 'private\ollama-models' }
$receiptDirectory = Join-Path $projectRoot 'evidence\local\ollama'
New-Item -ItemType Directory -Force -Path $receiptDirectory | Out-Null
if (-not $OllamaExe -or -not (Test-Path -LiteralPath $OllamaExe)) { throw 'Install Ollama for Windows or pass -OllamaExe with an existing runtime path' }
if (-not (Test-Path -LiteralPath $ModelDirectory)) { throw 'Existing model directory not found' }
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    throw "Port $Port is already occupied; inspect its owner before reusing it"
}
$env:OLLAMA_HOST = "127.0.0.1:$Port"
$env:OLLAMA_MODELS = $ModelDirectory
$env:OLLAMA_NO_CLOUD = '1'
$env:OLLAMA_NOPRUNE = '1'
$env:OLLAMA_NUM_PARALLEL = '1'
$env:OLLAMA_MAX_LOADED_MODELS = '1'
$env:OLLAMA_CONTEXT_LENGTH = '4096'
# Bound the underlying llama-server's cross-request prompt cache. This is
# separate from num_ctx/KV and otherwise grew past 2 GiB during this lab.
$env:LLAMA_ARG_CACHE_RAM = [string]$PromptCacheMiB
$proc = Start-Process -FilePath $OllamaExe -ArgumentList 'serve' -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $receiptDirectory 'stdout.log') -RedirectStandardError (Join-Path $receiptDirectory 'stderr.log')
$receipt = @{ pid=$proc.Id; executable=$OllamaExe; started=$proc.StartTime.ToUniversalTime().ToString('o'); endpoint="http://127.0.0.1:$Port"; model_directory=$ModelDirectory; prompt_cache_mib=$PromptCacheMiB }
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $receiptDirectory 'process.json') -Encoding utf8
$receipt | ConvertTo-Json
