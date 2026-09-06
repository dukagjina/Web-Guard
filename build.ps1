param([switch]$CleanGenerated)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

function Remove-GeneratedArtifacts {
    $targets = @(
        (Join-Path $PSScriptRoot "build"),
        (Join-Path $PSScriptRoot "dist"),
        (Join-Path $PSScriptRoot ".pytest_cache"),
        (Join-Path $PSScriptRoot "web_guard\__pycache__"),
        (Join-Path $PSScriptRoot "tests\__pycache__"),
        (Join-Path $PSScriptRoot "tools\__pycache__")
    )
    $prefix = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
    foreach ($target in $targets) {
        if (-not (Test-Path -LiteralPath $target)) { continue }
        $full = [IO.Path]::GetFullPath($target)
        if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clean outside Web Guard: $full"
        }
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}

if ($CleanGenerated) {
    Remove-GeneratedArtifacts
    Write-Host "Removed generated build output and local caches."
    exit 0
}

$projectPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $projectPython -PathType Leaf)) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        throw "Python was not found. Create .venv as described in README.md first."
    }
    $projectPython = $pythonCommand.Source
}

$database = Join-Path $PSScriptRoot "data\guard.db"
$metadataFile = Join-Path $PSScriptRoot "data\guard-metadata.json"
$tldFile = Join-Path $PSScriptRoot "data\iana-tlds.txt"
if (-not (Test-Path -LiteralPath $tldFile -PathType Leaf)) {
    throw "The bundled IANA TLD snapshot is missing. Run python tools\update_iana_tlds.py first."
}
$rawFiles = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot "data\blocklists\raw") -File
$rebuildDatabase = -not (Test-Path -LiteralPath $database -PathType Leaf) -or -not (Test-Path -LiteralPath $metadataFile -PathType Leaf)
if (-not $rebuildDatabase) {
    $databaseTime = (Get-Item -LiteralPath $database).LastWriteTimeUtc
    $databaseSources = @($rawFiles) + @(Get-Item -LiteralPath $tldFile)
    $rebuildDatabase = $null -ne ($databaseSources | Where-Object { $_.LastWriteTimeUtc -gt $databaseTime } | Select-Object -First 1)
}
if ($rebuildDatabase) {
    & $projectPython "tools\build_blocklist_db.py"
    if ($LASTEXITCODE -ne 0) { throw "Threat database compilation failed" }
}

& $projectPython -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Tests failed" }

& $projectPython -m PyInstaller --noconfirm --clean "Web Guard Service.spec"
if ($LASTEXITCODE -ne 0) { throw "Service packaging failed" }
& $projectPython -m PyInstaller --noconfirm --clean "Web Guard.spec"
if ($LASTEXITCODE -ne 0) { throw "Application packaging failed" }

$serviceSource = Join-Path $PSScriptRoot "dist\Web Guard Service"
$appTarget = Join-Path $PSScriptRoot "dist\Web Guard"
$serviceTarget = Join-Path $appTarget "service"
if (-not (Test-Path -LiteralPath (Join-Path $serviceSource "Web Guard Service.exe") -PathType Leaf)) {
    throw "The packaged service executable is missing"
}
New-Item -ItemType Directory -Path $serviceTarget -Force | Out-Null
Copy-Item -Path (Join-Path $serviceSource "*") -Destination $serviceTarget -Recurse -Force
foreach ($document in @("README.md", "LICENSE", "COMMERCIAL_USE.md", "TRADEMARKS.md", "THIRD_PARTY_NOTICES.md", "SECURITY.md")) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $document) -Destination $appTarget -Force
}
Remove-Item -LiteralPath $serviceSource -Recurse -Force

$innoCandidates = @(
    (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
)
$compiler = $innoCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $compiler) { throw "Inno Setup 6 is required to create the installer" }
& $compiler (Join-Path $PSScriptRoot "installer.iss")
if ($LASTEXITCODE -ne 0) { throw "Installer packaging failed" }

$installer = Join-Path $PSScriptRoot "dist\Web-Guard-Setup.exe"
$hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText($installer + ".sha256", "$hash  Web-Guard-Setup.exe`n", [Text.UTF8Encoding]::new($false))

# The unpacked PyInstaller directory is staging input for Inno Setup only.
# Removing it prevents it from being mistaken for the installed application.
if (Test-Path -LiteralPath $appTarget) {
    Remove-Item -LiteralPath $appTarget -Recurse -Force
}
$legacyInstallerDirectory = Join-Path $PSScriptRoot "dist\installer"
if (Test-Path -LiteralPath $legacyInstallerDirectory) {
    Remove-Item -LiteralPath $legacyInstallerDirectory -Recurse -Force
}

if (Test-Path -LiteralPath (Join-Path $PSScriptRoot "build")) {
    Remove-Item -LiteralPath (Join-Path $PSScriptRoot "build") -Recurse -Force
}
$generatedCaches = @(
    (Join-Path $PSScriptRoot ".pytest_cache"),
    (Join-Path $PSScriptRoot "web_guard\__pycache__"),
    (Join-Path $PSScriptRoot "tests\__pycache__"),
    (Join-Path $PSScriptRoot "tools\__pycache__")
)
foreach ($cache in $generatedCaches) {
    if (Test-Path -LiteralPath $cache) {
        Remove-Item -LiteralPath $cache -Recurse -Force
    }
}
Write-Host "Built Web Guard installer at dist\Web-Guard-Setup.exe"
