<#
    Reset-DNSGuard.ps1 - full recovery / clean-removal for DNSGuard.

    Use this when DNSGuard was removed abnormally (e.g. antivirus quarantined
    DNSGuard.exe) and the PC was left in a broken state: the adapters still point
    their DNS at 127.0.0.1 / ::1, but nothing is listening there, so name
    resolution fails and the machine looks "offline".

    It undoes EVERY change a normal DNSGuard install makes, each step guarded so
    one failure never stops the rest:

      1. Stop and delete the "DNSGuard" scheduled task.
      2. Stop any running DNSGuard.exe.
      3. Restore DNS on every adapter:
           - from the saved snapshot if it still exists, otherwise
           - reset any adapter still pointing at 127.0.0.1 / ::1 back to automatic (DHCP).
      4. Remove the "DNSGuard Local CA" root certificate from the machine store.
      5. Remove the browser DNS-over-HTTPS policies DNSGuard set (Chrome, Edge, Firefox).
      6. Remove the Add/Remove-Programs (Uninstall) registry entry.
      7. Remove the Start Menu "DNSGuard" folder.
      8. Clean the DNSGuard marker lines from the hosts file.
      9. Remove the C:\ProgramData\DNSGuard data folder.
     10. Flush the DNS resolver cache.

    Requires administrator rights. Harmless to run on a PC that never had
    DNSGuard, and safe to run more than once.

    Standalone use (RMM / Intune / remote shell), already elevated:
        powershell -NoProfile -ExecutionPolicy Bypass -File .\Reset-DNSGuard.ps1

    For double-click use, run Reset-DNSGuard.bat instead (it self-elevates).
#>

[CmdletBinding()]
param(
    # Reset DNS on EVERY adapter to automatic, not only the ones still pointing
    # at loopback. Use if an adapter was manually repointed after the breakage.
    [switch]$AllAdapters
)

$ErrorActionPreference = 'Continue'
$APP          = 'DNSGuard'
$TASK_NAME    = 'DNSGuard'
$CA_NAME      = 'DNSGuard Local CA'
$DataDir      = Join-Path $env:ProgramData 'DNSGuard'
$PrivateDir   = Join-Path $DataDir 'private'
$SnapshotFile = Join-Path $PrivateDir 'dns_snapshot.json'
$StartMenuDir = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\DNSGuard'
$HostsFile    = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$Loopback     = @('127.0.0.1','::1')

$ok = @(); $warn = @(); $adapterChanges = 0
function Good($m){ $script:ok   += $m; Write-Host "  [ OK ] $m"   -ForegroundColor Green }
function Warn($m){ $script:warn += $m; Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Step($m){ Write-Host "`n== $m" -ForegroundColor Cyan }

# --- admin check ----------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must run as Administrator." -ForegroundColor Red
    Write-Host "Right-click Reset-DNSGuard.bat and choose 'Run as administrator'," -ForegroundColor Red
    Write-Host "or run this .ps1 from an elevated PowerShell." -ForegroundColor Red
    exit 1
}

Write-Host "DNSGuard reset / recovery" -ForegroundColor White
Write-Host "Computer: $env:COMPUTERNAME   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# --- 1. scheduled task ----------------------------------------------------
Step "Removing the scheduled task"
try {
    $t = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    if ($t) {
        Stop-ScheduledTask   -TaskName $TASK_NAME -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction Stop
        Good "Deleted scheduled task '$TASK_NAME'."
    } else {
        schtasks.exe /End    /TN $TASK_NAME     2>$null | Out-Null
        schtasks.exe /Delete /TN $TASK_NAME /F  2>$null | Out-Null
        Good "No '$TASK_NAME' task present (nothing to delete)."
    }
} catch { Warn "Could not delete the scheduled task: $($_.Exception.Message)" }

# --- 2. running process ---------------------------------------------------
Step "Stopping any running DNSGuard process"
try {
    $procs = Get-Process $APP -ErrorAction SilentlyContinue
    if ($procs) { $procs | Stop-Process -Force -ErrorAction SilentlyContinue; Good "Stopped DNSGuard.exe." }
    else        { Good "DNSGuard.exe is not running." }
} catch { Warn "Could not stop DNSGuard.exe: $($_.Exception.Message)" }

# --- 3. DNS restore -------------------------------------------------------
Step "Restoring DNS on network adapters"

function Reset-AdapterAuto([int]$Index, [string]$Name) {
    try {
        Set-DnsClientServerAddress -InterfaceIndex $Index -ResetServerAddresses -ErrorAction Stop
        $script:adapterChanges++
        Good "Adapter '$Name' (if$Index): reset to automatic (DHCP)."
    } catch { Warn "Adapter '$Name' (if$Index): reset failed - $($_.Exception.Message)" }
}
function Set-AdapterServers([int]$Index, [string]$Name, [string[]]$Servers) {
    try {
        Set-DnsClientServerAddress -InterfaceIndex $Index -ServerAddresses $Servers -ErrorAction Stop
        $script:adapterChanges++
        Good "Adapter '$Name' (if$Index): restored to $($Servers -join ', ')."
    } catch { Warn "Adapter '$Name' (if$Index): restore failed - $($_.Exception.Message)" }
}
function Is-Ours([string[]]$servers) {
    if (-not $servers -or $servers.Count -eq 0) { return $false }
    foreach ($s in $servers) { if ($Loopback -notcontains $s) { return $false } }
    return $true
}

# Snapshot of each adapter's current DNS (both families), keyed by InterfaceGuid.
$adapters = @{}
foreach ($a in (Get-NetAdapter -ErrorAction SilentlyContinue)) {
    $v4 = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses) | Where-Object { $_ }
    $v6 = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses) | Where-Object { $_ }
    $adapters[$a.InterfaceGuid] = [pscustomobject]@{ Index=[int]$a.ifIndex; Name=[string]$a.Name; V4=$v4; V6=$v6 }
}

$snapshot = $null
if (Test-Path $SnapshotFile) {
    try { $snapshot = Get-Content -Raw -LiteralPath $SnapshotFile | ConvertFrom-Json }
    catch { Warn "DNS snapshot found but unreadable; falling back to automatic reset." }
}

$handled = @{}
if ($snapshot -and $snapshot.adapters) {
    Good "Using saved DNS snapshot."
    foreach ($guid in $snapshot.adapters.PSObject.Properties.Name) {
        $entry = $snapshot.adapters.$guid
        $cur   = $adapters[$guid]
        $index = if ($cur) { $cur.Index } elseif ($entry.index -ne $null) { [int]$entry.index } else { $null }
        if ($index -eq $null) { continue }
        $name  = if ($cur) { $cur.Name } else { [string]$entry.name }
        $servers = @(); if ($entry.v4_static) { $servers += $entry.v4_static }; if ($entry.v6_static) { $servers += $entry.v6_static }
        if ($servers.Count -gt 0) { Set-AdapterServers $index $name $servers } else { Reset-AdapterAuto $index $name }
        $handled[$index] = $true
    }
}

# Any adapter still pointing at loopback (or all adapters with -AllAdapters) that
# the snapshot did not cover: reset to automatic. This is the main fix after an
# antivirus removal, when the snapshot folder is gone.
foreach ($guid in $adapters.Keys) {
    $a = $adapters[$guid]
    if ($handled[$a.Index]) { continue }
    if ($AllAdapters -or (Is-Ours $a.V4) -or (Is-Ours $a.V6)) {
        Reset-AdapterAuto $a.Index $a.Name
    }
}
if ($adapterChanges -eq 0) { Good "No adapters were pointing at DNSGuard; none changed." }

# --- 4. root CA -----------------------------------------------------------
Step "Removing the DNSGuard root certificate"
$removedCert = $false
try {
    Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -match [regex]::Escape($CA_NAME) } |
        ForEach-Object { Remove-Item $_.PSPath -Force -ErrorAction SilentlyContinue; $script:removedCert = $true }
} catch {}
certutil.exe -delstore Root "$CA_NAME" 2>$null | Out-Null
if ($removedCert) { Good "Removed '$CA_NAME' from the Trusted Root store." }
else              { Good "No '$CA_NAME' certificate found (nothing to remove)." }

# --- 5. browser DoH / certificate policies --------------------------------
Step "Removing browser DNS-over-HTTPS policies"
function Remove-RegValue([string]$Path,[string]$Name){
    try { if (Test-Path $Path) { Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue } } catch {}
}
function Remove-RegKey([string]$Path){
    try { if (Test-Path $Path) { Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
}
Remove-RegValue 'HKLM:\SOFTWARE\Policies\Google\Chrome'  'DnsOverHttpsMode'
Remove-RegValue 'HKLM:\SOFTWARE\Policies\Google\Chrome'  'BuiltInDnsClientEnabled'
Remove-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'DnsOverHttpsMode'
Remove-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'BuiltInDnsClientEnabled'
Remove-RegKey   'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'
Remove-RegKey   'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Certificates'
Good "Restored browser DNS-over-HTTPS settings (Chrome, Edge, Firefox)."

# --- 6. Add/Remove Programs entry ----------------------------------------
Step "Removing the uninstall registry entry"
Remove-RegKey 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DNSGuard'
Good "Removed Add/Remove Programs entry (if present)."

# --- 7. Start Menu --------------------------------------------------------
Step "Removing Start Menu shortcuts"
try {
    if (Test-Path $StartMenuDir) { Remove-Item -LiteralPath $StartMenuDir -Recurse -Force -ErrorAction Stop; Good "Removed Start Menu folder." }
    else { Good "No Start Menu folder present." }
} catch { Warn "Could not remove Start Menu folder: $($_.Exception.Message)" }

# --- 8. hosts file --------------------------------------------------------
Step "Cleaning the hosts file"
try {
    if (Test-Path $HostsFile) {
        $lines = Get-Content -LiteralPath $HostsFile -ErrorAction Stop
        $kept  = $lines | Where-Object { $_ -notmatch 'dnsguard-[ab]\.invalid' -and $_ -notmatch 'DNSGuard:' }
        if ($kept.Count -ne $lines.Count) {
            Set-Content -LiteralPath $HostsFile -Value $kept -Encoding ASCII -ErrorAction Stop
            Good "Removed DNSGuard marker line(s) from hosts."
        } else { Good "No DNSGuard entries in hosts." }
    }
} catch { Warn "Could not edit hosts file: $($_.Exception.Message)" }

# --- 9. data folder -------------------------------------------------------
Step "Removing the DNSGuard data folder"
try {
    if (Test-Path $DataDir) {
        # Clear admin-only ACLs the installer set, so removal can't be blocked.
        icacls.exe "$DataDir" /reset /T /C /Q 2>$null | Out-Null
        Remove-Item -LiteralPath $DataDir -Recurse -Force -ErrorAction Stop
        Good "Removed $DataDir."
    } else { Good "No data folder present." }
} catch { Warn "Could not fully remove $DataDir : $($_.Exception.Message)" }

# --- 10. flush ------------------------------------------------------------
Step "Flushing the DNS cache"
try { ipconfig.exe /flushdns | Out-Null; Good "DNS resolver cache flushed." }
catch { Warn "Could not flush DNS cache: $($_.Exception.Message)" }

# --- summary --------------------------------------------------------------
Write-Host "`n--------------------------------------------------------" -ForegroundColor White
Write-Host "Done. $($ok.Count) step(s) OK, $($warn.Count) warning(s)." -ForegroundColor White
if ($warn.Count) { Write-Host "Review the [WARN] lines above." -ForegroundColor Yellow }
Write-Host "Test name resolution now, e.g.:  nslookup microsoft.com" -ForegroundColor White
Write-Host "If a browser still shows cached pages, fully close and reopen it." -ForegroundColor White

exit 0
