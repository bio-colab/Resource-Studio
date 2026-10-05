[CmdletBinding()]
param(
    [ValidateSet('win-x64')]
    [string]$Runtime = 'win-x64',
    [string]$Version = '0.1.0',
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($env:ProgramFiles)) { $env:ProgramFiles = Join-Path $env:SystemDrive 'Program Files' }
if ([string]::IsNullOrWhiteSpace($env:ProgramW6432)) { $env:ProgramW6432 = $env:ProgramFiles }
if ([string]::IsNullOrWhiteSpace($env:CommonProgramFiles)) { $env:CommonProgramFiles = Join-Path $env:ProgramFiles 'Common Files' }
if ([string]::IsNullOrWhiteSpace($env:CommonProgramW6432)) { $env:CommonProgramW6432 = $env:CommonProgramFiles }
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$BuildRoot = Join-Path $Root 'build\windows-installer'
$WpfPublish = Join-Path $BuildRoot 'wpf-publish'
$CliDist = Join-Path $BuildRoot 'cli-dist'
$Stage = Join-Path $BuildRoot 'stage'
$Output = Join-Path $Root 'dist\windows'

function Invoke-Checked([object]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE" }
}

Remove-Item $BuildRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $WpfPublish, $CliDist, $Stage, $Output | Out-Null

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnet) { throw '.NET SDK 8 is required to build the WPF shell.' }
$py = Get-Command py -ErrorAction SilentlyContinue
if (-not $py) { throw 'Python launcher py.exe with Python 3.12 is required to freeze the CLI.' }

$project = Join-Path $Root 'windows\ResourceStudio.Windows\ResourceStudio.Windows.csproj'
Invoke-Checked $dotnet @(
    'publish', $project,
    '--configuration', 'Release',
    '--runtime', $Runtime,
    '--self-contained', 'true',
    '--output', $WpfPublish,
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:DebugType=None',
    '-p:DebugSymbols=false',
    ('-p:Version=' + $Version)
)

$env:PYTHONPATH = $Root
Invoke-Checked $py @('-3.12', '-m', 'PyInstaller', '--version')
Invoke-Checked $py @(
    '-3.12', '-m', 'PyInstaller',
    '--noconfirm', '--clean', '--onedir',
    '--name', 'ResourceStudioCli',
    '--distpath', $CliDist,
    '--workpath', (Join-Path $BuildRoot 'pyinstaller-work'),
    '--specpath', (Join-Path $BuildRoot 'pyinstaller-spec'),
    '--paths', $Root,
    '--collect-submodules', 'core',
    '--collect-all', 'lief',
    '--collect-all', 'capstone',
    (Join-Path $Root 'resource_studio_cli.py')
)

Copy-Item (Join-Path $WpfPublish '*') $Stage -Recurse -Force
Copy-Item (Join-Path $CliDist 'ResourceStudioCli\*') $Stage -Recurse -Force
Invoke-Checked $py @('-3.12', (Join-Path $Root 'installer\make-assets.py'))
Copy-Item (Join-Path $Root 'windows\ResourceStudio.Windows\Assets\resource-studio.ico') (Join-Path $Stage 'resource-studio.ico') -Force
$license = Get-Content (Join-Path $Root 'LICENSE') -Raw
$eula = "Resource Studio $Version - Installation Agreement`r`n`r`nBy selecting I Agree, you acknowledge that this distribution is provided under the Apache License, Version 2.0. The complete license text follows. The software is provided AS IS, without warranties; retain the license and notices when redistributing it.`r`n`r`n" + $license
Set-Content (Join-Path $Stage 'EULA.txt') $eula -Encoding UTF8
Set-Content (Join-Path $Stage 'INSTALLATION.txt') @"
Resource Studio $Version (Windows x64)

This package contains the self-contained WPF shell and bundled Resource Studio CLI from the published project revision.
The application does not require Python or the .NET runtime to be installed separately.
The CLI and WPF shell use Save As and keep the selected input file unchanged.
Project: https://github.com/bio-colab/Resource-Studio
Developer: Elias Sharar — aliasbio95@gmail.com
"@ -Encoding UTF8

if (-not $SkipInstaller) {
    $iscc = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if (-not $iscc) {
        $candidates = @(
            (Join-Path $env:USERPROFILE 'Desktop\InnoSetup\ISCC.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 7\ISCC.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
            'C:\Program Files\Inno Setup 7\ISCC.exe',
            'C:\Program Files (x86)\Inno Setup 7\ISCC.exe',
            'C:\Program Files\Inno Setup 6\ISCC.exe',
            'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
        )
        $candidate = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($candidate) { $iscc = Get-Command $candidate }
    }
    if (-not $iscc) { throw 'Inno Setup 7 ISCC.exe is required. Install it from https://jrsoftware.org/isinfo.php.' }
    $iss = Join-Path $Root 'installer\ResourceStudio.iss'
    Invoke-Checked $iscc @('/Qp', $iss, "/DAppVersion=$Version", "/DSourceDir=$Stage", "/DOutputDir=$Output")
}

Write-Host "Windows staging complete: $Stage"
if (-not $SkipInstaller) { Write-Host "Installer output: $Output" }
