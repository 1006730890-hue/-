$ErrorActionPreference = 'Stop'
$file = Join-Path $PSScriptRoot 'backend\.duplex-runtime\processes.json'
if (-not (Test-Path -LiteralPath $file)) { return }
$root = [IO.Path]::GetFullPath($PSScriptRoot).Replace('/','\')
foreach ($record in (Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json)) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $($record.pid)" -ErrorAction SilentlyContinue
    if (-not $process -or -not $process.CommandLine) { continue }
    $command = $process.CommandLine.Replace('/','\')
    $executable = [IO.Path]::GetFullPath($process.ExecutablePath)
    $allowed = @([IO.Path]::GetFullPath([string]$record.executable))
    if ($record.base_executable) { $allowed += [IO.Path]::GetFullPath([string]$record.base_executable) }
    if ($command.Contains($root) -and $allowed -contains $executable) {
        Stop-Process -Id $record.pid -Force -ErrorAction SilentlyContinue
    }
}
Write-Host 'Stopped this checkout only.'
