param([switch]$Full, [switch]$OpenBrowser, [int]$Port = 8018, [string]$Python = '')
$ErrorActionPreference = 'Stop'
if (-not $Python) { $Python = Join-Path $PSScriptRoot 'backend\.venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $Python)) { throw 'Run .\setup.ps1 first.' }
$arguments = @('-X','utf8','-B',(Join-Path $PSScriptRoot 'tools\start.py'),'--port',"$Port")
if ($Full) { $arguments += '--full' }
& $Python @arguments
if ($LASTEXITCODE -ne 0) { throw 'Startup failed. See backend/.duplex-runtime/*.log.' }
if ($OpenBrowser) { Start-Process "http://127.0.0.1:$Port/" -WindowStyle Hidden }
