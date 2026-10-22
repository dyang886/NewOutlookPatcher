# Builds x64\Release\publish\NewOutlookPatcher.exe: first the worker DLL (C++, embedded into the exe), then the GUI (.NET 8, single file).
# Requires Visual Studio 2022 (or its Build Tools) with the "Desktop development with C++" workload, and the .NET 8 SDK or newer.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
# MSBuild needs SolutionDir to end with a separator; a forward slash, because a trailing "\" would escape the closing quote on the command line
$solutionDir = "$root/"

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw 'Visual Studio not found (vswhere.exe is missing)' }
$msbuild = & $vswhere -latest -products * -version '[17.0,)' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) { throw 'MSBuild with the C++ x64 tools not found: install Visual Studio 2022 with the "Desktop development with C++" workload' }
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw '.NET SDK not found: install the .NET 8 SDK or newer' }

function Invoke-Step([string]$name, [scriptblock]$command) {
    Write-Host "==> $name" -ForegroundColor Cyan
    & $command
    if ($LASTEXITCODE) { throw "$name failed (exit code $LASTEXITCODE)" }
}

Invoke-Step 'Restoring NuGet packages' { & $msbuild "$root\NOP\worker\worker.vcxproj" -t:restore -p:RestorePackagesConfig=true "-p:SolutionDir=$solutionDir" -nologo -v:minimal }
# A full rebuild, so nothing from a diagnostic build (compiled with /DNOP_REMOTE_DEBUGGING) can end up in the exe
Invoke-Step 'Building worker (dxgi.dll)' { & $msbuild "$root\NOP\worker\worker.vcxproj" -t:Rebuild -p:Configuration=Release -p:Platform=x64 "-p:SolutionDir=$solutionDir" -nologo -v:minimal }
Invoke-Step 'Publishing GUI (NewOutlookPatcher.exe)' { dotnet publish "$root\NOP\gui\gui.csproj" -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true "-p:SolutionDir=$solutionDir" -o "$root\x64\Release\publish" -nologo }

Write-Host "Built $root\x64\Release\publish\NewOutlookPatcher.exe" -ForegroundColor Green
