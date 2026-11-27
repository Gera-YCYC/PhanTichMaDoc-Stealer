# Collect known OS utilities without executing them. Binaries stay private.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$stage = Join-Path $projectRoot 'private\clean-corpus'
New-Item -ItemType Directory -Force -Path $stage | Out-Null
$sources = @(
    'C:\Windows\System32\where.exe', 'C:\Windows\System32\whoami.exe',
    'C:\Windows\System32\ipconfig.exe', 'C:\Windows\System32\findstr.exe',
    'C:\Windows\System32\sort.exe', 'C:\Windows\System32\ping.exe',
    'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe',
    'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
)
$rows = foreach ($source in $sources) {
    $item = Get-Item -LiteralPath $source
    $signature = Get-AuthenticodeSignature -LiteralPath $source
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "Missing valid Microsoft signature: $source"
    }
    $digest = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    $name = 'clean_ms_' + $item.BaseName.ToLowerInvariant() + '.bin'
    $destination = Join-Path $stage $name
    if (Test-Path -LiteralPath $destination) {
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $digest) {
            throw "Existing corpus differs; preserve its lock before creating another version: $name"
        }
    } else { Copy-Item -LiteralPath $source -Destination $destination }
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $digest) {
        throw 'Copied bytes changed during collection'
    }
    [ordered]@{
        sample=$name; sha256=$digest; bytes=$item.Length; positive=$false
        source_path=$source; file_version=$item.VersionInfo.FileVersion
        product=$item.VersionInfo.ProductName; signature_status=[string]$signature.Status
        publisher=$signature.SignerCertificate.Subject
        label_basis='Known Microsoft OS/developer utility with valid Authenticode signature; expected non-stealer, not proof of harmlessness in every use'
    }
}
$manifest = [ordered]@{
    schema_version=1; collected_at=[DateTimeOffset]::UtcNow.ToString('o')
    dataset_origin='genuine-signed-microsoft-utilities'; sample_execution=$false
    redistribution='Metadata only in Git; obtain binaries from each authorized Windows installation'
    rows=@($rows)
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $stage 'manifest.json') -Encoding utf8
Write-Output "Verified and copied $($rows.Count) clean candidates into private/clean-corpus; no sample executed."
