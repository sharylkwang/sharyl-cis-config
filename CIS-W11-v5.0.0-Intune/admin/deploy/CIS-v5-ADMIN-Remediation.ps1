# CIS v5.0.0 - ADMIN Cloud PC remediation (admin-safe)
# Same as the standard script but KEEPS WinRM + LanmanServer enabled (admin remote mgmt / shares)
# and re-enables Remote Desktop services first (SAFETY). Runs as SYSTEM via Intune.
# Replaces both earlier scripts. Covers 71 CIS recommendations that Intune cannot set directly:
#   - 39 service disables (Level 1 and Level 2, section 5)
#   - 16 registry settings + 7 'No One' user rights (section 2.2) + 2 null-session restrictions (section 2.3.10)
#   - 7 password and account-lockout settings (section 1, via net accounts: history 24, max/min age, min length, lockout)
#   - The Level 2 service disables are harmless on an L1-only scope; remove that section if preferred
# Deploy: Intune > Devices > Scripts and remediations > Platform scripts > Add. Set the three options:
#   - Run this script using the logged on credentials = No
#   - Enforce script signature check                  = No
#   - Run script in 64 bit PowerShell Host            = Yes
# (i.e. No / No / Yes.)
# Result log on device: C:\ProgramData\CIS-Admin-Remediation.log

$ErrorActionPreference = 'Continue'
$log = @()
$errs = @()
function Step { param([string]$Tag, [scriptblock]$Do)
    try { & $Do; $script:log += "OK  $Tag" }
    catch { $script:errs += "ERR $Tag :: $($_.Exception.Message)" }
}

function Set-RegDword {
    param([string]$Rec, [string]$Path, [string]$Name, [int]$Value, [string]$Note)
    Step "[$Rec] $Name = $Value ($Note)" {
        $full = "HKLM:\$Path"
        if (-not (Test-Path $full)) { New-Item -Path $full -Force | Out-Null }
        New-ItemProperty -Path $full -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    }
}


# ==================== CLOUD PC SAFETY (runs first) ====================
# Guarantees Remote Desktop stays reachable - re-enables RDP services and clears the
# deny switch in case an earlier hardening run disabled them. Harmless on a healthy device.
foreach ($svc in 'TermService','SessionEnv','UmRdpService') {
    Step "[SAFETY] ensure RDP service $svc enabled" {
        Set-Service -Name $svc -StartupType Automatic -ErrorAction Stop
        Start-Service -Name $svc -ErrorAction SilentlyContinue
    }
}
Step '[SAFETY] fDenyTSConnections = 0 (RDP allowed)' {
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -PropertyType DWord -Force | Out-Null
}
# =====================================================================

# ---------------- Section 5: services (CIS wants Disabled / Not Installed) ----------------
Step '[5.3] disable service Browser' {
    $s = Get-Service -Name 'Browser' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'Browser' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'Browser' -Force -ErrorAction SilentlyContinue }
}
Step '[5.7] disable service IISADMIN' {
    $s = Get-Service -Name 'IISADMIN' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'IISADMIN' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'IISADMIN' -Force -ErrorAction SilentlyContinue }
}
Step '[5.8] disable service irmon' {
    $s = Get-Service -Name 'irmon' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'irmon' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'irmon' -Force -ErrorAction SilentlyContinue }
}
Step '[5.10] disable service FTPSVC' {
    $s = Get-Service -Name 'FTPSVC' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'FTPSVC' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'FTPSVC' -Force -ErrorAction SilentlyContinue }
}
Step '[5.12] disable service sshd' {
    $s = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'sshd' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'sshd' -Force -ErrorAction SilentlyContinue }
}
Step '[5.23] disable service RpcLocator' {
    $s = Get-Service -Name 'RpcLocator' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'RpcLocator' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'RpcLocator' -Force -ErrorAction SilentlyContinue }
}
Step '[5.25] disable service RemoteAccess' {
    $s = Get-Service -Name 'RemoteAccess' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'RemoteAccess' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'RemoteAccess' -Force -ErrorAction SilentlyContinue }
}
Step '[5.27] disable service simptcp' {
    $s = Get-Service -Name 'simptcp' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'simptcp' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'simptcp' -Force -ErrorAction SilentlyContinue }
}
Step '[5.29] disable service sacsvr' {
    $s = Get-Service -Name 'sacsvr' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'sacsvr' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'sacsvr' -Force -ErrorAction SilentlyContinue }
}
Step '[5.30] disable service SSDPSRV' {
    $s = Get-Service -Name 'SSDPSRV' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'SSDPSRV' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'SSDPSRV' -Force -ErrorAction SilentlyContinue }
}
Step '[5.31] disable service upnphost' {
    $s = Get-Service -Name 'upnphost' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'upnphost' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'upnphost' -Force -ErrorAction SilentlyContinue }
}
Step '[5.32] disable service WMSvc' {
    $s = Get-Service -Name 'WMSvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'WMSvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'WMSvc' -Force -ErrorAction SilentlyContinue }
}
Step '[5.35] disable service WMPNetworkSvc' {
    $s = Get-Service -Name 'WMPNetworkSvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'WMPNetworkSvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'WMPNetworkSvc' -Force -ErrorAction SilentlyContinue }
}
Step '[5.36] disable service icssvc' {
    $s = Get-Service -Name 'icssvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'icssvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'icssvc' -Force -ErrorAction SilentlyContinue }
}
Step '[5.40] disable service W3SVC' {
    $s = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'W3SVC' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'W3SVC' -Force -ErrorAction SilentlyContinue }
}
Step '[5.41] disable service XboxGipSvc' {
    $s = Get-Service -Name 'XboxGipSvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'XboxGipSvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'XboxGipSvc' -Force -ErrorAction SilentlyContinue }
}
Step '[5.42] disable service XblAuthManager' {
    $s = Get-Service -Name 'XblAuthManager' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'XblAuthManager' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'XblAuthManager' -Force -ErrorAction SilentlyContinue }
}
Step '[5.43] disable service XblGameSave' {
    $s = Get-Service -Name 'XblGameSave' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'XblGameSave' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'XblGameSave' -Force -ErrorAction SilentlyContinue }
}
Step '[5.44] disable service XboxNetApiSvc' {
    $s = Get-Service -Name 'XboxNetApiSvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'XboxNetApiSvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'XboxNetApiSvc' -Force -ErrorAction SilentlyContinue }
}
# ---------------- Registry-only settings ----------------
Set-RegDword -Rec '2.3.11.4' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'SupportedEncryptionTypes' -Value 2147483640 -Note 'AES128+AES256+Future only'
Set-RegDword -Rec '2.3.11.7' -Path 'SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientConfidentiality' -Value 1 -Note 'Negotiate sealing'
Set-RegDword -Rec '18.4.4' -Path 'SOFTWARE\Microsoft\Cryptography\Wintrust\Config' -Name 'EnableCertPaddingCheck' -Value 1 -Note 'Certificate padding check'
Set-RegDword -Rec '18.6.4.1' -Path 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMDNS' -Value 0 -Note 'Disable mDNS'
Set-RegDword -Rec '18.6.4.2' -Path 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableNetbios' -Value 2 -Note 'Disable NetBIOS name resolution on public networks (0 also compliant)'
# 18.6.4.3 value name per CIS mirror = DisableIPv6DefaultDnsServers. VERIFY on device after deploy:
#   reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableIPv6DefaultDnsServers
Set-RegDword -Rec '18.6.4.3' -Path 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'DisableIPv6DefaultDnsServers' -Value 1 -Note 'Turn off default IPv6 DNS servers'
Set-RegDword -Rec '18.9.5.7' -Path 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'ConfigureKernelShadowStacksLaunch' -Value 1 -Note 'Kernel-mode hardware-enforced stack protection: enforcement mode'
Set-RegDword -Rec '18.9.31.1.1' -Path 'SOFTWARE\Policies\Microsoft\Netlogon\Parameters' -Name 'BlockNetbiosDiscovery' -Value 1 -Note 'Block NetBIOS-based DC discovery'
Set-RegDword -Rec '18.9.41.1' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM' -Name 'SamrChangeUserPasswordApiPolicy' -Value 1 -Note 'Block all change password RPC methods'
Set-RegDword -Rec '18.10.4.2' -Path 'SOFTWARE\Policies\Microsoft\Windows\Appx' -Name 'DisablePerUserUnsignedPackagesByDefault' -Value 1 -Note 'Block per-user unsigned packages'
Set-RegDword -Rec '18.10.42.4.1' -Path 'SOFTWARE\Policies\Microsoft\Windows Defender\Features' -Name 'PassiveRemediation' -Value 1 -Note 'EDR in block mode support flag (also enable EDR block mode in Defender portal)'
Set-RegDword -Rec '18.10.42.11.1.1.2' -Path 'SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection' -Name 'BruteForceProtectionConfiguredState' -Value 2 -Note 'Brute Force Protection: Audit (1=Block also compliant)'
Set-RegDword -Rec '18.10.42.11.x' -Path 'SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection' -Name 'RemoteEncryptionProtectionConfiguredState' -Value 2 -Note 'Remote Encryption Protection: Audit (1=Block also compliant)'
Set-RegDword -Rec '18.10.94.1.1' -Path 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoRebootWithLoggedOnUsers' -Value 0 -Note 'Auto-restart applies with logged on users'
Set-RegDword -Rec '18.11.1' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad' -Value 1 -Note 'Disable WPAD'
Set-RegDword -Rec '18.11.2' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'DisableProxyAuthenticationSchemes' -Value 256 -Note 'Restrict proxy auth schemes (287 = stricter, also compliant)'

# ---------------- 'No One' user rights (Settings Catalog cannot express an empty list) ----------------
# 2.2.1 SeTrustedCredManAccessPrivilege / 2.2.3 SeTcbPrivilege / 2.2.10 SeCreateTokenPrivilege
# 2.2.12 SeCreatePermanentPrivilege / 2.2.20 SeEnableDelegationPrivilege / 2.2.26 SeLockMemoryPrivilege
# 2.2.30 SeRelabelPrivilege
$inf = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeTrustedCredManAccessPrivilege =
SeTcbPrivilege =
SeCreateTokenPrivilege =
SeCreatePermanentPrivilege =
SeEnableDelegationPrivilege =
SeLockMemoryPrivilege =
SeRelabelPrivilege =
'@
Step '[2.2.x] No-One user rights via secedit' {
    $infPath = Join-Path $env:TEMP 'cis-norights.inf'
    $dbPath  = Join-Path $env:TEMP 'cis-norights.sdb'
    $inf | Out-File -FilePath $infPath -Encoding unicode -Force
    $p = Start-Process secedit -ArgumentList "/configure /db `"$dbPath`" /cfg `"$infPath`" /areas USER_RIGHTS /quiet" -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { throw "secedit exit code $($p.ExitCode)" }
    Remove-Item $infPath, $dbPath -Force -ErrorAction SilentlyContinue
}

# ---------------- 'None' anonymous-access lists (empty REG_MULTI_SZ) ----------------
Step '[2.3.10.6] NullSessionPipes = empty' {
    [Microsoft.Win32.Registry]::SetValue('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters', 'NullSessionPipes', [string[]]@(), [Microsoft.Win32.RegistryValueKind]::MultiString)
}
Step '[2.3.10.11] NullSessionShares = empty' {
    [Microsoft.Win32.Registry]::SetValue('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters', 'NullSessionShares', [string[]]@(), [Microsoft.Win32.RegistryValueKind]::MultiString)
}


# ---- L1 1.1.x / 1.2.x password + lockout policy (local security database) ----
Step '[1.1.1] password history 24' { net accounts /uniquepw:24 | Out-Null }
Step '[1.1.2] max password age 365' { net accounts /maxpwage:365 | Out-Null }
Step '[1.1.3] min password age 1' { net accounts /minpwage:1 | Out-Null }
Step '[1.1.4] min password length 14' { net accounts /minpwlen:14 | Out-Null }
Step '[1.2.1] lockout duration 15' { net accounts /lockoutduration:15 | Out-Null }
Step '[1.2.2] lockout threshold 5' { net accounts /lockoutthreshold:5 | Out-Null }
Step '[1.2.4] lockout window 15' { net accounts /lockoutwindow:15 | Out-Null }

# ---- L2 services (CIS wants Disabled / Not Installed) ----
Step '[5.1] disable service BTAGService' {
    $s = Get-Service -Name 'BTAGService' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'BTAGService' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'BTAGService' -Force -ErrorAction SilentlyContinue }
}
Step '[5.2] disable service bthserv' {
    $s = Get-Service -Name 'bthserv' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'bthserv' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'bthserv' -Force -ErrorAction SilentlyContinue }
}
Step '[5.4] disable service MapsBroker' {
    $s = Get-Service -Name 'MapsBroker' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'MapsBroker' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'MapsBroker' -Force -ErrorAction SilentlyContinue }
}
Step '[5.5] disable service GameInputSvc' {
    $s = Get-Service -Name 'GameInputSvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'GameInputSvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'GameInputSvc' -Force -ErrorAction SilentlyContinue }
}
Step '[5.6] disable service lfsvc' {
    $s = Get-Service -Name 'lfsvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'lfsvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'lfsvc' -Force -ErrorAction SilentlyContinue }
}
Step '[5.9] disable service lltdsvc' {
    $s = Get-Service -Name 'lltdsvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'lltdsvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'lltdsvc' -Force -ErrorAction SilentlyContinue }
}
Step '[5.11] disable service MSiSCSI' {
    $s = Get-Service -Name 'MSiSCSI' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'MSiSCSI' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'MSiSCSI' -Force -ErrorAction SilentlyContinue }
}
Step '[5.13] disable service PNRPsvc' {
    $s = Get-Service -Name 'PNRPsvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'PNRPsvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'PNRPsvc' -Force -ErrorAction SilentlyContinue }
}
Step '[5.14] disable service p2psvc' {
    $s = Get-Service -Name 'p2psvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'p2psvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'p2psvc' -Force -ErrorAction SilentlyContinue }
}
Step '[5.15] disable service p2pimsvc' {
    $s = Get-Service -Name 'p2pimsvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'p2pimsvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'p2pimsvc' -Force -ErrorAction SilentlyContinue }
}
Step '[5.16] disable service PNRPAutoReg' {
    $s = Get-Service -Name 'PNRPAutoReg' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'PNRPAutoReg' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'PNRPAutoReg' -Force -ErrorAction SilentlyContinue }
}
Step '[5.17] disable service Spooler' {
    $s = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'Spooler' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'Spooler' -Force -ErrorAction SilentlyContinue }
}
Step '[5.18] disable service wercplsupport' {
    $s = Get-Service -Name 'wercplsupport' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'wercplsupport' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'wercplsupport' -Force -ErrorAction SilentlyContinue }
}
Step '[5.19] disable service RasAuto' {
    $s = Get-Service -Name 'RasAuto' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'RasAuto' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'RasAuto' -Force -ErrorAction SilentlyContinue }
}
Step '[5.24] disable service RemoteRegistry' {
    $s = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'RemoteRegistry' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'RemoteRegistry' -Force -ErrorAction SilentlyContinue }
}
Step '[5.28] disable service SNMP' {
    $s = Get-Service -Name 'SNMP' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'SNMP' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'SNMP' -Force -ErrorAction SilentlyContinue }
}
Step '[5.33] disable service WerSvc' {
    $s = Get-Service -Name 'WerSvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'WerSvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'WerSvc' -Force -ErrorAction SilentlyContinue }
}
Step '[5.34] disable service Wecsvc' {
    $s = Get-Service -Name 'Wecsvc' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'Wecsvc' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'Wecsvc' -Force -ErrorAction SilentlyContinue }
}
Step '[5.37] disable service WpnService' {
    $s = Get-Service -Name 'WpnService' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'WpnService' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'WpnService' -Force -ErrorAction SilentlyContinue }
}
Step '[5.38] disable service PushToInstall' {
    $s = Get-Service -Name 'PushToInstall' -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name 'PushToInstall' -StartupType Disabled -ErrorAction Stop; Stop-Service -Name 'PushToInstall' -Force -ErrorAction SilentlyContinue }
}


# ---------------- report ----------------
$all = @()
if ($errs.Count) { $all += '===== ERRORS ====='; $all += $errs }
$all += $log
$all | Out-File -FilePath 'C:\ProgramData\CIS-Admin-Remediation.log' -Encoding utf8 -Force
$errs | ForEach-Object { Write-Output $_ }
Write-Output "CIS v5 combined remediation: $($log.Count) ok, $($errs.Count) errors. Log: C:\ProgramData\CIS-Admin-Remediation.log"
if ($errs.Count) { exit 1 } else { exit 0 }
