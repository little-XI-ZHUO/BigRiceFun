# Create a desktop shortcut for BigRiceFun with its own icon.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File create-shortcut.ps1
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$desktop = [Environment]::GetFolderPath('Desktop')
$lnk = Join-Path $desktop 'BigRiceFun.lnk'
$shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut($lnk)
$sc.TargetPath = Join-Path $dir 'BigRiceFun.bat'
$sc.WorkingDirectory = $dir
$sc.IconLocation = Join-Path $dir 'BigRiceFun.ico'
$sc.Description = 'BigRiceFun - intranet web asset mapping and web risk audit'
$sc.Save()
Write-Host "shortcut created: $lnk"
