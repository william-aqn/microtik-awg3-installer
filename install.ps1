param(
    [switch]$Diag,
    [switch]$DryRun,
    [string]$HostName,
    [string]$Config,
    [string]$Lan,
    [string]$Bridge,
    [string]$Wan,
    [string]$Disk,
    [switch]$NoMode,
    [string]$OutputDir,
    [string]$Rollback,
    [string]$UserName = 'admin',
    [int]$Port = 22
)
$ErrorActionPreference = 'Stop'
$baseUrl = 'https://raw.githubusercontent.com/william-aqn/microtik-awg3-installer/main'
$pythonSha256 = '97be6222d4abd1e6eba3443241b698fa35144677c5f22a0d5f00af37c330ea4c'
$runtimeRoot = Join-Path $env:LOCALAPPDATA 'awg-mikrotik'
$venvPath = Join-Path $runtimeRoot 'venv'
$pythonPath = Join-Path $venvPath 'Scripts\python.exe'
$scriptPath = Join-Path $runtimeRoot 'awg-mikrotik.py'
try {
    if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
        throw 'Python 3.10+ with the py launcher is required. Install it from python.org and retry.'
    }
    & py -3 -c "import sys; assert sys.version_info >= (3,10), 'Python 3.10+ required'"
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.10+ is required.' }
    New-Item -ItemType Directory -Force -Path $runtimeRoot | Out-Null
    if (-not (Test-Path -LiteralPath $pythonPath)) {
        & py -3 -m venv $venvPath
        if ($LASTEXITCODE -ne 0) { throw 'Could not create the virtual environment.' }
    }
    & $pythonPath -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('paramiko') else 1)"
    if ($LASTEXITCODE -ne 0) {
        & $pythonPath -m pip install --disable-pip-version-check 'paramiko==4.0.0'
        if ($LASTEXITCODE -ne 0) { throw 'Paramiko installation failed.' }
    }
    $validScript = (Test-Path -LiteralPath $scriptPath) -and
        ((Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash.ToLowerInvariant() -eq $pythonSha256)
    if (-not $validScript) {
        $localSource = Join-Path $PSScriptRoot 'awg-mikrotik.py'
        if (Test-Path -LiteralPath $localSource) {
            Copy-Item -LiteralPath $localSource -Destination $scriptPath
        } else {
            Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/awg-mikrotik.py" -OutFile $scriptPath
        }
        if ((Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pythonSha256) {
            throw 'Installer SHA256 mismatch; execution stopped.'
        }
    }
    $wizardArgs = @('--user', $UserName, '--port', $Port.ToString())
    if ($Diag) { $wizardArgs += '--diag' }
    if ($DryRun) { $wizardArgs += '--dry-run' }
    if ($NoMode) { $wizardArgs += '--no-mode' }
    foreach ($pair in @(
        @('--host', $HostName), @('--config', $Config), @('--lan', $Lan),
        @('--bridge', $Bridge), @('--wan', $Wan), @('--disk', $Disk),
        @('--output', $OutputDir), @('--rollback', $Rollback)
    )) {
        if ($pair[1]) { $wizardArgs += $pair }
    }
    & $pythonPath $scriptPath @wizardArgs
    exit $LASTEXITCODE
} catch {
    $message = 'Installer bootstrap failed: ' + $_.Exception.Message
    $message | Set-Content -LiteralPath 'awg-bootstrap-error.txt' -Encoding UTF8
    Write-Error "$message`nSee awg-bootstrap-error.txt; check Python, HTTPS, pip and directory permissions."
    exit 1
}
