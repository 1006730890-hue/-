param([switch]$Full, [switch]$RebuildFrontend, [string]$Python = '', [string]$IndexUrl = 'https://pypi.org/simple')
$ErrorActionPreference = 'Stop'
function Run-Checked([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $Exe" }
}
function Create-Env([string]$Folder) {
    $target = Join-Path $PSScriptRoot "$Folder\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $target)) {
        if ($Python) { Run-Checked $Python @('-m','venv',(Join-Path $PSScriptRoot $Folder)) }
        elseif (Get-Command py -ErrorAction SilentlyContinue) { Run-Checked 'py' @('-3.11','-m','venv',(Join-Path $PSScriptRoot $Folder)) }
        else { Run-Checked 'python' @('-m','venv',(Join-Path $PSScriptRoot $Folder)) }
    }
    Run-Checked $target @('-c','import sys; assert sys.version_info[:2] == (3,11), "Use Python 3.11"')
    return $target
}
$api = Create-Env 'backend\.venv'
$lock = Join-Path $PSScriptRoot 'backend\requirements-lock.txt'
if (Test-Path -LiteralPath $lock) { Run-Checked $api @('-m','pip','install','--index-url',$IndexUrl,'-r',$lock) }
else { Run-Checked $api @('-m','pip','install','--index-url',$IndexUrl,'-r',(Join-Path $PSScriptRoot 'backend\requirements-dev.txt')) }
$config = Join-Path $PSScriptRoot 'backend\.env'
if (-not (Test-Path -LiteralPath $config)) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'backend\.env.example') -Destination $config }
foreach ($client in @('frontend','后台')) {
    if ($RebuildFrontend -or -not (Test-Path -LiteralPath (Join-Path $PSScriptRoot "$client\dist\index.html"))) {
        Push-Location (Join-Path $PSScriptRoot $client)
        try { Run-Checked 'npm.cmd' @('ci','--no-audit','--no-fund'); Run-Checked 'npm.cmd' @('run','build') }
        finally { Pop-Location }
    }
}
if ($Full) {
    $infer = Create-Env 'backend\.venv-infer'
    Run-Checked $infer @('-m','pip','install','--index-url',$IndexUrl,'-r',(Join-Path $PSScriptRoot 'component_runtime\requirements-infer.txt'))
    $memory = Create-Env 'backend\.venv-memory'
    Run-Checked $memory @('-m','pip','install','--index-url',$IndexUrl,'-r',(Join-Path $PSScriptRoot 'component_runtime\requirements-memory.txt'))
}
Write-Host 'Installed. Start: .\start.ps1 -OpenBrowser'
