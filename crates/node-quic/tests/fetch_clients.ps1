param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'isolated/target/test-clients'),
    [ValidateSet('windows-amd64','linux-amd64','linux-arm64','all')][string]$Platform = 'all'
)
$ErrorActionPreference = 'Stop'
$quicLock = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'clients-lock.json') -Raw | ConvertFrom-Json
$quicOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $quicOutput -Force | Out-Null
foreach ($quicAsset in $quicLock.assets) {
    if ($Platform -ne 'all' -and $Platform -ne $quicAsset.platform) { continue }
    $quicArchive = Join-Path $quicOutput $quicAsset.name
    if (-not (Test-Path -LiteralPath $quicArchive)) {
        Invoke-WebRequest -Uri $quicAsset.url -OutFile $quicArchive
    }
    $quicDigest = (Get-FileHash -LiteralPath $quicArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($quicDigest -ne $quicAsset.sha256) { throw "Official client archive SHA256 mismatch: $($quicAsset.name)" }
    $quicExecutable = Join-Path $quicOutput $quicAsset.executable
    if (-not (Test-Path -LiteralPath $quicExecutable)) {
        if ($quicAsset.name.EndsWith('.zip')) {
            Expand-Archive -LiteralPath $quicArchive -DestinationPath $quicOutput
        } else {
            & tar -xzf $quicArchive -C $quicOutput
            if ($LASTEXITCODE -ne 0) { throw 'Failed to extract official client archive' }
        }
    }
    $quicExecutableDigest = (Get-FileHash -LiteralPath $quicExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($quicExecutableDigest -ne $quicAsset.executable_sha256) { throw "Official client executable SHA256 mismatch: $($quicAsset.executable)" }
    [PSCustomObject]@{
        Version = $quicLock.version
        Platform = $quicAsset.platform
        ArchiveSHA256 = $quicDigest
        Executable = $quicExecutable
        ExecutableSHA256 = $quicExecutableDigest
    }
}
