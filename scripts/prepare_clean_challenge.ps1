# Independent clean challenge, collected before scanning the frozen YARA rules.
# Binaries remain private and are never executed.
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$stage=Join-Path $projectRoot 'private\clean-challenge'
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$framework=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$managedNames=@('AddInProcess','AddInProcess32','AddInUtil','AppLaunch','aspnet_compiler',
 'aspnet_regbrowsers','aspnet_regiis','aspnet_regsql','aspnet_state','aspnet_wp','CasPol',
 'ComSvcConfig','csc','cvtres','DataSvcUtil','dfsvc','EdmGen','ilasm','InstallUtil','jsc',
 'Microsoft.Workflow.Compiler','MSBuild','mscorsvw','ngen','ngentask','RegAsm','RegSvcs',
 'ServiceModelReg','SMSvcHost','vbc','WsatConfig')
$sources=@('where','whoami','ipconfig','findstr','sort','ping') | ForEach-Object {Join-Path $env:WINDIR "System32\$_.exe"}
$sources+=@($managedNames | ForEach-Object {Join-Path $framework "$_.exe"})
$rows=foreach($source in $sources) {
 $item=Get-Item -LiteralPath $source
 $signature=Get-AuthenticodeSignature -LiteralPath $source
 if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
   throw "Missing valid Microsoft signature: $source"
 }
 $digest=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
 $name='clean_ms_'+$item.BaseName.ToLowerInvariant()+'.bin'
 $target=Join-Path $stage $name
 if(Test-Path -LiteralPath $target) {
   if((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $digest) {throw 'Existing challenge bytes differ'}
 } else {Copy-Item -LiteralPath $source -Destination $target}
 if((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $digest) {throw 'Copy hash mismatch'}
 [ordered]@{sample=$name;sha256=$digest;bytes=$item.Length;positive=$false;source_path=$source;
   file_version=$item.VersionInfo.FileVersion;signature_status=[string]$signature.Status;
   publisher=$signature.SignerCertificate.Subject;label_basis='Known signed Microsoft utility, expected non-stealer'}
}
$manifest=[ordered]@{schema_version=1;sample_execution=$false;collected_at=[DateTimeOffset]::UtcNow.ToString('o');
 dataset_origin='signed-windows-challenge-37';rows=@($rows)}
$manifestPath=Join-Path $stage 'windows-manifest.json'
if(Test-Path -LiteralPath $manifestPath) {throw 'Challenge manifest exists; preserve it and use a new revision'}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Output "Verified $($rows.Count) signed Windows utilities; no execution."
