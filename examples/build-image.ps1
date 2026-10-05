$ErrorActionPreference = 'Stop'
$repoName = 'catesin/awg-mikrotik-arm'
$manifestDigest = 'sha256:6e1fe2a0ede54bf28fd1560a1483e5c5f352c9cdf1e7c00ce6c0483ca8a999e8'
$outputRoot = Join-Path $PSScriptRoot 'current-oci'
$blobRoot = Join-Path $outputRoot 'blobs\sha256'
New-Item -ItemType Directory -Force -Path $blobRoot | Out-Null
$registryToken = (Invoke-RestMethod -Uri ('https://auth.docker.io/token?service=registry.docker.io&scope=repository:' + $repoName + ':pull')).token
$headers = @{ Authorization = 'Bearer ' + $registryToken; Accept = 'application/vnd.oci.image.manifest.v1+json' }
$registryBase = 'https://registry-1.docker.io/v2/' + $repoName
$manifestFile = Join-Path $blobRoot $manifestDigest.Substring(7)
Invoke-WebRequest -UseBasicParsing -Uri ($registryBase + '/manifests/' + $manifestDigest) -Headers $headers -OutFile $manifestFile
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $manifestFile).Hash.ToLowerInvariant() -ne $manifestDigest.Substring(7)) { throw 'Manifest hash mismatch' }
$manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
$descriptors = @($manifest.config) + @($manifest.layers)
foreach ($descriptor in $descriptors) {
    $targetFile = Join-Path $blobRoot $descriptor.digest.Substring(7)
    Invoke-WebRequest -UseBasicParsing -Uri ($registryBase + '/blobs/' + $descriptor.digest) -Headers $headers -OutFile $targetFile
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $targetFile).Hash.ToLowerInvariant() -ne $descriptor.digest.Substring(7)) { throw ('Blob hash mismatch: ' + $descriptor.digest) }
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
$index = @{schemaVersion=2;mediaType='application/vnd.oci.image.index.v1+json';manifests=@(@{mediaType='application/vnd.oci.image.manifest.v1+json';digest=$manifestDigest;size=(Get-Item -LiteralPath $manifestFile).Length;platform=@{architecture='arm';os='linux';variant='v7'}})}
[System.IO.File]::WriteAllText((Join-Path $outputRoot 'index.json'),($index | ConvertTo-Json -Depth 5 -Compress),$utf8)
[System.IO.File]::WriteAllText((Join-Path $outputRoot 'oci-layout'),'{"imageLayoutVersion":"1.0.0"}',$utf8)
$archiveFile = Join-Path $PSScriptRoot 'awg3-arm-current.tar'
tar -cf $archiveFile -C $outputRoot 'blobs' 'index.json' 'oci-layout'
if ($LASTEXITCODE -ne 0) { throw 'Archive creation failed' }
[pscustomobject]@{Image=$repoName;Manifest=$manifestDigest;ArchiveBytes=(Get-Item -LiteralPath $archiveFile).Length;ArchiveSHA256=(Get-FileHash -LiteralPath $archiveFile -Algorithm SHA256).Hash}
