# Rex's Ghost Recon — Windows. Per-user install, no admin.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = $here
if (-not (Test-Path (Join-Path $root "rex_ghost_recon.py"))) {
  $root = Split-Path $here -Parent
}
$scriptSrc = Join-Path $root "rex_ghost_recon.py"
$photo = Join-Path $root "assets\crew.jpg"
if (-not (Test-Path $scriptSrc)) { throw "rex_ghost_recon.py is not next to this installer" }
if (-not (Test-Path $photo)) { throw "assets\crew.jpg is missing" }

$py = $null
foreach ($name in @("py", "python", "python3")) {
  $cmd = Get-Command $name -ErrorAction SilentlyContinue
  if ($cmd) { $py = $cmd.Source; break }
}
if (-not $py) { throw "Install Python 3.9 or newer, then run this again." }

$dest = Join-Path $env:LOCALAPPDATA "RexGhostRecon"
New-Item -ItemType Directory -Force -Path (Join-Path $dest "assets") | Out-Null
Copy-Item $scriptSrc (Join-Path $dest "rex_ghost_recon.py") -Force
Copy-Item $photo (Join-Path $dest "assets\crew.jpg") -Force

$cmdFile = Join-Path $dest "rex-ghost-recon.cmd"
"@echo off`r`n`"$py`" `"$dest\rex_ghost_recon.py`" %*`r`n" | Set-Content -Encoding ASCII $cmdFile

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $userPath) { $userPath = "" }
if ($userPath -notlike "*${dest}*") {
  $joined = if ($userPath) { "$userPath;$dest" } else { $dest }
  [Environment]::SetEnvironmentVariable("Path", $joined, "User")
}

Write-Host "Installed $dest\rex_ghost_recon.py"
Write-Host "Open a new terminal and run: rex-ghost-recon"
Write-Host "Local desk: rex-ghost-recon --web"
