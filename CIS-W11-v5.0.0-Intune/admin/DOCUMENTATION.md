# Admin Cloud PC — CIS Windows 11 Hardening

## Overview

This hardens an **administrative Windows 365 Cloud PC** to the **CIS Windows 11 v5.0.0** benchmark using **Microsoft Intune** — applied as strictly as is safe, while keeping the tools an administrator needs (Remote Desktop, PowerShell, elevation, winget).

**Where it stands:** **474 of 515** CIS Level 1 + 2 settings are configured — **~92%** (Level 1 **97%**, Level 2 **77%**). Every remaining setting is accounted for, and there are **no unmanaged security gaps.** The evidence of enforcement is Intune's per-setting **"Succeeded"** status.

## Key things to note

1. **A scan will look low (~76%) — expected, not a gap.** Intune enforces via the Policy CSP; a scanner reads Group Policy and can't see ~80 enforced settings. Trust Intune's **"Succeeded"**, not the scan.
2. **A few settings are deliberately relaxed** to keep Remote Desktop, PowerShell, winget, and elevation working.
3. **25 settings are documented exceptions** needing a one-time risk-acceptance sign-off — enforcing them would break admin access, or Microsoft doesn't offer them in Intune.
4. **BitLocker (45 clauses) doesn't apply** — a Cloud PC has no physical disk.
5. **Nothing is skipped without a reason** — every gap is N/A, a documented exception, or a deliberate choice.

## Contents

1. [Deployed policies](#1-deployed-policies) — the four policies, and step-by-step how each was configured
2. [Coverage](#2-coverage) — summary and full tables (collapsible)
3. [What is not configured, and why](#3-what-is-not-configured-and-why) — not needed (no deviation) versus can't apply (needs a deviation)
4. [Extras policy settings](#4-extras-policy-settings) — Level-2 additions and Security Options
5. [LAPS settings](#5-laps-settings)
6. [Why an admin machine is set up differently](#6-why-an-admin-machine-is-set-up-differently)
7. [Running a CIS-CAT scan](#7-running-a-cis-cat-scan-optional-check) — the free Lite assessor, and how to read a low score

---

## 1. Deployed policies

| # | Deployment | Where in Intune | Covers |
|---|---|---|---|
| 1 | **CIS-v5-ADMIN-CloudPC.json** (base policy, ~360 settings) | Devices › Configuration | User rights, security options, firewall, audit, Defender, admin templates, SMB, VBS |
| 2 | **CIS-v5-ADMIN-Remediation.ps1** (script, 71 settings) | Devices › Scripts and remediations › Platform scripts | 39 service disables, 16 registry settings, 7 "No One" user rights, 7 password/lockout settings, 2 null-session restrictions |
| 3 | **CIS Admin Extras** (policy, 29 settings) | Devices › Configuration | One Settings Catalog policy holding **14 Level-2 top-ups**, **3 Local Policies Security Options** (cache previous logons = 4, force strong key protection = 1, rename administrator → **HTGM Admin**), **plus 12 hardening settings added in the rebuild** (VBS, camera, App Installer hardening, user rights, admin lockout — see Section 4) |
| 4 | **CIS LAPS** (policy, 8 settings) | Endpoint security › Account protection | Local admin password rotation to Entra ID |

The two deploy files are in `deploy/`; the **Extras** and **LAPS** policies are configured manually in Intune (Sections 4 and 5).

### How each piece was configured (step by step)

Do these in order. After each, wait for the device to check in and confirm the settings report **Succeeded**, then **reconnect over RDP to confirm access is retained** before moving on.

**1 — Base policy: import `CIS-v5-ADMIN-CloudPC.json`** (~360 settings)

1. Intune admin center → **Devices › Configuration › Create › Import policy**.
2. **Import** → browse to `deploy/CIS-v5-ADMIN-CloudPC.json` → name it (e.g. *CIS v5 ADMIN CloudPC*) → **Save**.
3. Open the policy → **Assignments** → add the admin Cloud PC group → **Save**.
4. Wait for check-in, then **View report** and confirm per-setting status **Succeeded**.

**2 — Remediation script: upload `CIS-v5-ADMIN-Remediation.ps1`** (71 settings Intune can't set directly)

1. **Devices › Scripts and remediations › Platform scripts › Add › Windows 10 and later**.
2. Name it → **Script settings** → upload `deploy/CIS-v5-ADMIN-Remediation.ps1`.
3. Set the three options: **Run using logged-on credentials = No**, **Enforce script signature check = No**, **Run script in 64-bit PowerShell Host = Yes** (No / No / Yes).
4. **Assignments** → the group → **Save**. It runs as SYSTEM at next check-in.
5. On-device log to confirm it ran: `C:\ProgramData\CIS-Admin-Remediation.log`.

**3 — CIS Admin Extras: build the Settings Catalog policy by hand** (29 settings)

1. **Devices › Configuration › Create › New policy › Windows 10 and later › Settings catalog**.
2. Name it **CIS Admin Extras**.
3. **Add settings** → search each of the 29 settings listed in **Section 4** → set the value shown. Watch the Section 4 notes: settings named "Allow …" are set to **Block**, and **#19 / #29** (User Rights) take a **list of accounts**.
4. **Assignments** → the group → **Save**; confirm all 29 report **Succeeded**.

*(This is also where the built-in Administrator is renamed to **HTGM Admin** — setting #17.)*

**4 — CIS LAPS: build the Account protection policy**

1. **Prerequisite (one-time):** entra.microsoft.com → **Devices › Device settings › Enable Microsoft Entra Local Administrator Password Solution (LAPS) = Yes**.
2. Intune → **Endpoint security › Account protection › Create Policy › Windows › Local admin password solution (Windows LAPS)**.
3. Name it **CIS LAPS** → set the values in **Section 5** (back up to Entra ID only, all-four complexity, length 15, age 30 days, post-auth reset 8 h + reset-and-log-off).
4. **Assignments** → the group → **Save**.
5. Verify: **Device check-in status = Succeeded**; retrieve the rotated password at **Devices › [the Cloud PC] › Local admin password**.

---

## 2. Coverage

**CIS v5 has 560 recommendations** — Level 1 (393), Level 2 (122), and **BitLocker (45, entirely N/A on a Cloud PC)**. Of the 515 Level 1 + 2 settings, **474 (~92%) are configured**. Every setting accounted for:

> **515 or 513?** Both are right — **515** counts every recommendation; **513** is only the automated ones a scanner checks (the CIS-CAT report scored **392 / 513**). The 2 extra are the manual renames: the **admin** account (done → HTGM Admin) and the **guest** account (**N/A — Guest is already disabled, so renaming protects nothing**).

| Status | Count | Needs a deviation? |
|---|---|---|
| **1. Configured — working** (a scan sees it) | ~393 | No |
| **2. Configured — working, but a scan can't see it** | ~81 | No |
| **3. Not configured** (why → table below) | 41 | 25 of 41 |
| **Level 1 + Level 2 total** | **515** | **25 need one** |

> Rows **1 + 2 = the 474 configured (~92%)**. Row 2 is enforced via the Policy CSP but invisible to a scan — **it still works; ignore the low scan score.**

**Why the 41 are not configured:**

| Why | Count | Needs a deviation? |
|---|---|---|
| Not needed — N/A on a Cloud PC (App Guard, printers, pen/touch…) | 16 | No |
| Off on purpose — enforcing it would break admin access, tools, or Windows features (RDP, winget, IPv6…) | 12 | **Yes** |
| Can't be set in Intune — not exposed by Microsoft, or needs an add-on licence (e.g. Brute-Force Protection) | 13 | **Yes** |
| **Total not configured** | **41** | **25 need one** |

**Plus BitLocker** — a **separate CIS profile** (not part of the 515): 45 clauses, all N/A (a Cloud PC has no disk). **515 + 45 = 560.** *(Total N/A = 16 + 45 = 61.)*

The two tables below list every CIS item and how it's set — collapsed by default; expand for line-by-line detail.

<details>
<summary><b>Level 1 — all 393 recommendations</b> (click to expand)</summary>

| CIS # | Setting | CIS requires | Status | Configured by |
|---|---|---|---|---|
| 1.1.1 | Ensure 'Enforce password history' is set to '24 or more password(s)' | '24 or more password(s)' | Done | Remediation script |
| 1.1.2 | Ensure 'Maximum password age' is set to '365 or fewer days, but not 0' | '365 or fewer days, but not 0' | Done | Remediation script |
| 1.1.3 | Ensure 'Minimum password age' is set to '1 or more day(s)' | '1 or more day(s)' | Done | Base admin policy (JSON) |
| 1.1.4 | Ensure 'Minimum password length' is set to '14 or more character(s)' | '14 or more character(s)' | Done | Remediation script |
| 1.1.5 | Ensure 'Password must meet complexity requirements' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 1.1.6 | Ensure 'Relax minimum password length limits' is set to 'Enabled' | 'Enabled' | No path | — |
| 1.1.7 | Ensure 'Store passwords using reversible encryption' is set to 'Disabled' | 'Disabled' | N/A | Disabled by default in Windows (already compliant) |
| 1.2.1 | Ensure 'Account lockout duration' is set to '15 or more minute(s)' | '15 or more minute(s)' | Done | Remediation script |
| 1.2.2 | Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0' | '5 or fewer invalid logon attempt(s), but not 0' | Done | Remediation script |
| 1.2.3 | Ensure 'Allow Administrator account lockout' is set to 'Enabled' | 'Enabled' | Done | CIS Admin Extras policy |
| 1.2.4 | Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)' | '15 or more minute(s)' | Done | Remediation script |
| 2.2.1 | Ensure 'Access Credential Manager as a trusted caller' is set to 'No One' | 'No One' | Done | Remediation script |
| 2.2.2 | Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users' | 'Administrators, Remote Desktop Users' | Done | Base admin policy (JSON) |
| 2.2.3 | Ensure 'Act as part of the operating system' is set to 'No One' | 'No One' | Done | Remediation script |
| 2.2.4 | Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE' | 'Administrators, LOCAL SERVICE, NETWORK SERVICE' | Done | CIS Admin Extras policy |
| 2.2.5 | Ensure 'Allow log on locally' is set to 'Administrators, Users' | 'Administrators, Users' | Done | Base admin policy (JSON) |
| 2.2.6 | Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' | 'Administrators, Remote Desktop Users' | Done | CIS Admin Extras policy |
| 2.2.7 | Ensure 'Back up files and directories' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.2.8 | Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE' | 'Administrators, LOCAL SERVICE' | Done | Base admin policy (JSON) |
| 2.2.9 | Ensure 'Create a pagefile' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.2.10 | Ensure 'Create a token object' is set to 'No One' | 'No One' | Done | Remediation script |
| 2.2.11 | Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' | 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' | Done | Base admin policy (JSON) |
| 2.2.12 | Ensure 'Create permanent shared objects' is set to 'No One' | 'No One' | Done | Remediation script |
| 2.2.13 | Ensure 'Create symbolic links' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.2.14 | Ensure 'Debug programs' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.2.15 | Ensure 'Deny access to this computer from the network' to include 'Guests, Local account' | (see benchmark) | Done | Base admin policy (JSON) |
| 2.2.16 | Ensure 'Deny log on as a batch job' to include 'Guests' | (see benchmark) | Done | Base admin policy (JSON) |
| 2.2.17 | Ensure 'Deny log on as a service' to include 'Guests' | (see benchmark) | Done | Base admin policy (JSON) |
| 2.2.18 | Ensure 'Deny log on locally' to include 'Guests' | (see benchmark) | Done | Base admin policy (JSON) |
| 2.2.19 | Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account' | (see benchmark) | Done | Base admin policy (JSON) |
| 2.2.20 | Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' | 'No One' | Done | Remediation script |
| 2.2.21 | Ensure 'Force shutdown from a remote system' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.2.22 | Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE, RESTRICTED SERVICES\PrintSpoolerService' | 'LOCAL SERVICE, NETWORK SERVICE, RESTRICTED SERVICES\PrintSpoolerService' | Done | Base admin policy (JSON) |
| 2.2.23 | Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE, RESTRICTED SERVICES\PrintSpoolerService' | 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE, RESTRICTED SERVICES\PrintSpoolerService' | Done | Base admin policy (JSON) |
| 2.2.24 | Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group' | 'Administrators, Window Manager\Window Manager Group' | Done | Base admin policy (JSON) |
| 2.2.25 | Ensure 'Load and unload device drivers' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.2.26 | Ensure 'Lock pages in memory' is set to 'No One' | 'No One' | Done | Remediation script |
| 2.2.29 | Ensure 'Manage auditing and security log' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.2.30 | Ensure 'Modify an object label' is set to 'No One' | 'No One' | Done | Remediation script |
| 2.2.31 | Ensure 'Modify firmware environment values' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.2.32 | Ensure 'Perform volume maintenance tasks' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.2.33 | Ensure 'Profile single process' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.2.34 | Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost' | 'Administrators, NT SERVICE\WdiServiceHost' | Done | Base admin policy (JSON) |
| 2.2.35 | Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE' | 'LOCAL SERVICE, NETWORK SERVICE' | Done | Base admin policy (JSON) |
| 2.2.36 | Ensure 'Restore files and directories' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.2.37 | Ensure 'Shut down the system' is set to 'Administrators, Users' | 'Administrators, Users' | Done | Base admin policy (JSON) |
| 2.2.38 | Ensure 'Take ownership of files or other objects' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.3.1.1 | Ensure 'Accounts: Guest account status' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 2.3.1.2 | Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.1.3 | Configure 'Accounts: Rename administrator account' | Rename to a non-default name | Done | CIS Admin Extras policy (→ HTGM Admin) |
| 2.3.1.4 | Configure 'Accounts: Rename guest account' | (see benchmark) | N/A | Guest account is disabled, so renaming protects nothing |
| 2.3.2.1 | Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.2.2 | Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 2.3.6.1 | Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.6.2 | Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.6.3 | Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.6.4 | Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 2.3.6.5 | Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0' | '30 or fewer days, but not 0' | Done | Base admin policy (JSON) |
| 2.3.6.6 | Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.7.2 | Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.7.3 | Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0' | '900 or fewer second(s), but not 0' | Done | Base admin policy (JSON) |
| 2.3.7.4 | Configure 'Interactive logon: Message text for users attempting to log on' | (see benchmark) | Done | Base admin policy (JSON) |
| 2.3.7.5 | Configure 'Interactive logon: Message title for users attempting to log on' | (see benchmark) | Done | Base admin policy (JSON) |
| 2.3.7.7 | Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days' | 'between 5 and 14 days' | Done | Base admin policy (JSON) |
| 2.3.7.8 | Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher | 'Lock Workstation' or higher | Done | Base admin policy (JSON) |
| 2.3.8.1 | Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.8.2 | Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 2.3.9.1 | Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)' | '15 or fewer minute(s)' | Done | Base admin policy (JSON) |
| 2.3.9.2 | Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.9.3 | Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.9.4 | Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher | 'Accept if provided by client' or higher | Done | Base admin policy (JSON) |
| 2.3.10.1 | Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 2.3.10.2 | Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.10.3 | Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.10.4 | Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.10.5 | Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 2.3.10.6 | Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None' | 'None' | Done | Remediation script |
| 2.3.10.7 | Ensure 'Network access: Remotely accessible registry paths' is configured | (see benchmark) | Done | Base admin policy (JSON) |
| 2.3.10.8 | Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured | (see benchmark) | Done | Base admin policy (JSON) |
| 2.3.10.9 | Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.10.10 | Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' | 'Administrators: Remote Access: Allow' | Done | Base admin policy (JSON) |
| 2.3.10.11 | Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' | 'None' | Done | Remediation script |
| 2.3.10.12 | Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves' | 'Classic - local users authenticate as themselves' | Done | Base admin policy (JSON) |
| 2.3.11.1 | Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.11.2 | Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 2.3.11.3 | Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 2.3.11.4 | Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' | 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' | Done | Remediation script |
| 2.3.11.5 | Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.11.6 | Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM' | 'Send NTLMv2 response only. Refuse LM & NTLM' | Done | Base admin policy (JSON) |
| 2.3.11.7 | Ensure 'Network security: LDAP client encryption requirements' is set to 'Negotiate sealing' or higher | 'Negotiate sealing' or higher | Done | Remediation script |
| 2.3.11.8 | Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher | 'Negotiate signing' or higher | Done | Base admin policy (JSON) |
| 2.3.11.9 | Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption' | 'Require NTLMv2 session security, Require 128-bit encryption' | Done | Base admin policy (JSON) |
| 2.3.11.10 | Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption' | 'Require NTLMv2 session security, Require 128-bit encryption' | Done | Base admin policy (JSON) |
| 2.3.11.11 | Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts' | 'Enable auditing for all accounts' | Done | Base admin policy (JSON) |
| 2.3.11.12 | Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher | 'Audit all' or higher | Done | Base admin policy (JSON) |
| 2.3.15.1 | Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.15.2 | Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.17.1 | Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.17.2 | Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' or higher | 'Prompt for consent on the secure desktop' or higher | Done | Base admin policy (JSON) |
| 2.3.17.3 | Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests' | 'Automatically deny elevation requests' | Relaxed | (deliberate) |
| 2.3.17.4 | Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.17.5 | Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.17.6 | Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.17.7 | Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 2.3.17.8 | Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 5.3 | Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.7 | Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.8 | Ensure 'Infrared monitor service (irmon)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.10 | Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.12 | Ensure 'OpenSSH SSH Server (sshd)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.23 | Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.25 | Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.27 | Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.29 | Ensure 'Special Administration Console Helper (sacsvr)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.30 | Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.31 | Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.32 | Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.35 | Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.36 | Ensure 'Windows Mobile Hotspot Service (icssvc)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.40 | Ensure 'World Wide Web Publishing Service (W3SVC)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.41 | Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.42 | Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.43 | Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.44 | Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 9.1.1 | Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)' | 'On (recommended)' | Done | Base admin policy (JSON) |
| 9.1.2 | Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)' | 'Block (default)' | Done | Base admin policy (JSON) |
| 9.1.3 | Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No' | 'No' | Done | Base admin policy (JSON) |
| 9.1.4 | Ensure 'Windows Firewall: Domain: Logging: Name' is configured | (see benchmark) | Done | Base admin policy (JSON) |
| 9.1.5 | Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater' | '16,384 KB or greater' | Done | Base admin policy (JSON) |
| 9.1.6 | Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes' | 'Yes' | Done | Base admin policy (JSON) |
| 9.1.7 | Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes' | 'Yes' | Done | Base admin policy (JSON) |
| 9.2.1 | Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)' | 'On (recommended)' | Done | Base admin policy (JSON) |
| 9.2.2 | Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)' | 'Block (default)' | Done | Base admin policy (JSON) |
| 9.2.3 | Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No' | 'No' | Done | Base admin policy (JSON) |
| 9.2.4 | Ensure 'Windows Firewall: Private: Logging: Name' is configured | (see benchmark) | Done | Base admin policy (JSON) |
| 9.2.5 | Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater' | '16,384 KB or greater' | Done | Base admin policy (JSON) |
| 9.2.6 | Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes' | 'Yes' | Done | Base admin policy (JSON) |
| 9.2.7 | Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes' | 'Yes' | Done | Base admin policy (JSON) |
| 9.3.1 | Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)' | 'On (recommended)' | Done | Base admin policy (JSON) |
| 9.3.2 | Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)' | 'Block (default)' | Done | Base admin policy (JSON) |
| 9.3.3 | Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No' | 'No' | Done | Base admin policy (JSON) |
| 9.3.4 | Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No' | 'No' | Done | Base admin policy (JSON) |
| 9.3.5 | Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No' | 'No' | Done | Base admin policy (JSON) |
| 9.3.6 | Ensure 'Windows Firewall: Public: Logging: Name' is configured | (see benchmark) | Done | Base admin policy (JSON) |
| 9.3.7 | Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater' | '16,384 KB or greater' | Done | Base admin policy (JSON) |
| 9.3.8 | Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes' | 'Yes' | Done | Base admin policy (JSON) |
| 9.3.9 | Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes' | 'Yes' | Done | Base admin policy (JSON) |
| 17.1.1 | Ensure 'Audit Credential Validation' is set to 'Success and Failure' | 'Success and Failure' | Done | Base admin policy (JSON) |
| 17.2.1 | Ensure 'Audit Application Group Management' is set to 'Success and Failure' | 'Success and Failure' | Done | Base admin policy (JSON) |
| 17.2.2 | Ensure 'Audit Security Group Management' is set to include 'Success' | include 'Success' | Done | Base admin policy (JSON) |
| 17.2.3 | Ensure 'Audit User Account Management' is set to 'Success and Failure' | 'Success and Failure' | Done | Base admin policy (JSON) |
| 17.3.1 | Ensure 'Audit PNP Activity' is set to include 'Success' | include 'Success' | Done | Base admin policy (JSON) |
| 17.3.2 | Ensure 'Audit Process Creation' is set to include 'Success' | include 'Success' | Done | Base admin policy (JSON) |
| 17.5.1 | Ensure 'Audit Account Lockout' is set to include 'Failure' | include 'Failure' | Done | Base admin policy (JSON) |
| 17.5.2 | Ensure 'Audit Group Membership' is set to include 'Success' | include 'Success' | Done | Base admin policy (JSON) |
| 17.5.3 | Ensure 'Audit Logoff' is set to include 'Success' | include 'Success' | Done | Base admin policy (JSON) |
| 17.5.4 | Ensure 'Audit Logon' is set to 'Success and Failure' | 'Success and Failure' | Done | Base admin policy (JSON) |
| 17.5.5 | Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure' | 'Success and Failure' | Done | Base admin policy (JSON) |
| 17.5.6 | Ensure 'Audit Special Logon' is set to include 'Success' | include 'Success' | Done | Base admin policy (JSON) |
| 17.6.1 | Ensure 'Audit Detailed File Share' is set to include 'Failure' | include 'Failure' | Done | Base admin policy (JSON) |
| 17.6.2 | Ensure 'Audit File Share' is set to 'Success and Failure' | 'Success and Failure' | Done | Base admin policy (JSON) |
| 17.6.3 | Ensure 'Audit Other Object Access Events' is set to 'Success and Failure' | 'Success and Failure' | Done | Base admin policy (JSON) |
| 17.6.4 | Ensure 'Audit Removable Storage' is set to 'Success and Failure' | 'Success and Failure' | Done | Base admin policy (JSON) |
| 17.7.1 | Ensure 'Audit Audit Policy Change' is set to include 'Success' | include 'Success' | Done | Base admin policy (JSON) |
| 17.7.2 | Ensure 'Audit Authentication Policy Change' is set to include 'Success' | include 'Success' | Done | Base admin policy (JSON) |
| 17.7.3 | Ensure 'Audit Authorization Policy Change' is set to include 'Success' | include 'Success' | Done | Base admin policy (JSON) |
| 17.7.4 | Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure' | 'Success and Failure' | Done | Base admin policy (JSON) |
| 17.7.5 | Ensure 'Audit Other Policy Change Events' is set to include 'Failure' | include 'Failure' | Done | Base admin policy (JSON) |
| 17.8.1 | Ensure 'Audit Sensitive Privilege Use' is set to 'Success' | 'Success' | Done | Base admin policy (JSON) |
| 17.9.1 | Ensure 'Audit IPsec Driver' is set to 'Success and Failure' | 'Success and Failure' | Done | Base admin policy (JSON) |
| 17.9.2 | Ensure 'Audit Other System Events' is set to 'Success and Failure' | 'Success and Failure' | Done | Base admin policy (JSON) |
| 17.9.3 | Ensure 'Audit Security State Change' is set to include 'Success' | include 'Success' | Done | Base admin policy (JSON) |
| 17.9.4 | Ensure 'Audit Security System Extension' is set to include 'Success' | include 'Success' | Done | Base admin policy (JSON) |
| 17.9.5 | Ensure 'Audit System Integrity' is set to 'Success and Failure' | 'Success and Failure' | Done | Base admin policy (JSON) |
| 18.1.1.1 | Ensure 'Prevent enabling lock screen camera' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.1.1.2 | Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.1.2.2 | Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.4.1 | Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.4.2 | Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)' | 'Enabled: Disable driver (recommended)' | Done | Base admin policy (JSON) |
| 18.4.3 | Ensure 'Configure SMB v1 server' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.4.4 | Ensure 'Enable Certificate Padding' is set to 'Enabled' | 'Enabled' | Done | Remediation script |
| 18.4.5 | Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.4.6 | Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)' | 'Enabled: P-node (recommended)' | Done | Base admin policy (JSON) |
| 18.4.7 | Ensure 'WDigest Authentication' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.5.1 | Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.5.2 | Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled' | 'Enabled: Highest protection, source routing is completely disabled' | Done | Base admin policy (JSON) |
| 18.5.3 | Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled' | 'Enabled: Highest protection, source routing is completely disabled' | Done | Base admin policy (JSON) |
| 18.5.5 | Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.5.7 | Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.5.9 | Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.5.12 | Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less' | 'Enabled: 90% or less' | Done | Base admin policy (JSON) |
| 18.6.4.1 | Ensure 'Configure multicast DNS (mDNS) protocol' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 18.6.4.2 | Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks' | 'Enabled: Disable NetBIOS name resolution on public networks' | Done | Remediation script |
| 18.6.4.4 | Ensure 'Turn off multicast name resolution' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.6.7.1 | Ensure 'Audit client does not support encryption' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.6.7.2 | Ensure 'Audit client does not support signing' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.6.7.3 | Ensure 'Audit insecure guest logon' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.6.7.4 | Ensure 'Enable authentication rate limiter' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.6.7.5 | Ensure 'Enable remote mailslots' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.6.7.6 | Ensure 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1' | 'Enabled: 3.1.1' | Done | Base admin policy (JSON) |
| 18.6.7.7 | Ensure 'Set authentication rate limiter delay (milliseconds)' is set to 'Enabled: 2000' or more | 'Enabled: 2000' or more | Done | Base admin policy (JSON) |
| 18.6.8.1 | Ensure 'Audit insecure guest logon' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.6.8.2 | Ensure 'Audit server does not support encryption' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.6.8.3 | Ensure 'Audit server does not support signing' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.6.8.4 | Ensure 'Enable insecure guest logons' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.6.8.5 | Ensure 'Enable remote mailslots' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.6.8.6 | Ensure 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1' | 'Enabled: 3.1.1' | Done | Base admin policy (JSON) |
| 18.6.8.7 | Ensure 'Require Encryption' is set to 'Enabled' | 'Enabled' | Done | CIS Admin Extras policy |
| 18.6.11.2 | Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.6.11.3 | Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.6.11.4 | Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.6.14.1 | Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication", "Require Integrity", and "Require Privacy" set for all NETLOGON and SYSVOL shares' | 'Enabled, with "Require Mutual Authentication", "Require Integrity", and "Require Privacy" set for all NETLOGON and SYSVOL shares' | Done | Base admin policy (JSON) |
| 18.6.21.1 | Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet' | 'Enabled: 3 = Prevent Wi-Fi when on Ethernet' | Done | Base admin policy (JSON) |
| 18.6.21.2 | Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled' | 'Enabled' | Done | CIS Admin Extras policy |
| 18.6.23.2.1 | Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.7.1 | Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.7.2 | Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled' | 'Enabled: Redirection Guard Enabled' | Done | Base admin policy (JSON) |
| 18.7.3 | Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP' | 'Enabled: RPC over TCP' | Done | Base admin policy (JSON) |
| 18.7.4 | Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default' | 'Enabled: Default' | Done | Base admin policy (JSON) |
| 18.7.5 | Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP' | 'Enabled: RPC over TCP' | Done | Base admin policy (JSON) |
| 18.7.6 | Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher | 'Enabled: Negotiate' or higher | Done | Base admin policy (JSON) |
| 18.7.7 | Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0' | 'Enabled: 0' | Done | Base admin policy (JSON) |
| 18.7.8 | Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.7.10 | Ensure 'Limits print driver installation to Administrators' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.7.11 | Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles' | 'Enabled: Limit Queue-specific files to Color profiles' | Done | Base admin policy (JSON) |
| 18.7.12 | Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt' | 'Enabled: Show warning and elevation prompt' | Done | Base admin policy (JSON) |
| 18.7.13 | Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt' | 'Enabled: Show warning and elevation prompt' | Done | Base admin policy (JSON) |
| 18.9.3.1 | Ensure 'Include command line in process creation events' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.4.1 | Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients' | 'Enabled: Force Updated Clients' | Done | Base admin policy (JSON) |
| 18.9.4.2 | Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.5.1 | Ensure 'Turn On Virtualization Based Security' is set to 'Enabled' | 'Enabled' | Done | CIS Admin Extras policy |
| 18.9.5.2 | Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher | 'Secure Boot' or higher | Done | Base admin policy (JSON) |
| 18.9.5.3 | Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock' | 'Enabled with UEFI lock' | Done | Base admin policy (JSON) |
| 18.9.5.4 | Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)' | 'True (checked)' | Done | Base admin policy (JSON) |
| 18.9.5.5 | Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' | 'Enabled with UEFI lock' | Done | Base admin policy (JSON) |
| 18.9.5.6 | Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.5.7 | Ensure 'Turn On Virtualization Based Security: Kernel- mode Hardware-enforced Stack Protection' is set to 'Enabled: Enabled in enforcement mode' | 'Enabled: Enabled in enforcement mode' | Done | Remediation script |
| 18.9.7.2 | Ensure 'Prevent automatic download of applications associated with device metadata' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.13.1 | Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical' | 'Enabled: Good, unknown and bad but critical' | Done | Base admin policy (JSON) |
| 18.9.17.1 | Ensure 'Enable / disable CLFS logfile authentication' is set to 'Enabled' | 'Enabled' | No path | — |
| 18.9.19.2 | Ensure 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE' | 'Enabled: FALSE' | Done | Base admin policy (JSON) |
| 18.9.19.3 | Ensure 'Configure security policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE' | 'Enabled: TRUE' | Done | Base admin policy (JSON) |
| 18.9.19.4 | Ensure 'Continue experiences on this device' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.9.19.5 | Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.9.20.1.2 | Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.20.1.6 | Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.26.1 | Ensure 'Configure password backup directory' is set to 'Enabled: Active Directory' or 'Enabled: Azure Active Directory' | 'Enabled: Active Directory' or 'Enabled: Azure Active Directory' | Done | CIS LAPS policy |
| 18.9.26.2 | Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' | 'Enabled' | Done | CIS LAPS policy |
| 18.9.26.3 | Ensure 'Enable password encryption' is set to 'Enabled' | 'Enabled' | Done | CIS LAPS policy |
| 18.9.26.4 | Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' or 'Passphrase' | 'Enabled: Large letters + small letters + numbers + special characters' or 'Passphrase' | Done | CIS LAPS policy |
| 18.9.26.5 | Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' | 'Enabled: 15 or more' | Done | CIS LAPS policy |
| 18.9.26.6 | Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' | 'Enabled: 30 or fewer' | Done | CIS LAPS policy |
| 18.9.26.7 | Ensure 'Post-authentication actions: Grace period (hours)' is set to 'Enabled: 8 or fewer hours, but not 0' | 'Enabled: 8 or fewer hours, but not 0' | Done | CIS LAPS policy |
| 18.9.26.8 | Ensure 'Post-authentication actions: Actions' is set to 'Enabled: Reset the password and logoff the managed account' or higher | 'Enabled: Reset the password and logoff the managed account' or higher | Done | CIS LAPS policy |
| 18.9.27.1 | Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.9.27.2 | Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock' | 'Enabled: Enabled with UEFI Lock' | Done | Base admin policy (JSON) |
| 18.9.29.1 | Ensure 'Block user from showing account details on sign-in' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.29.2 | Ensure 'Do not display network selection UI' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.29.3 | Ensure 'Do not enumerate connected users on domain- joined computers' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.29.4 | Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.9.29.5 | Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.29.6 | Ensure 'Turn off picture password sign-in' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.29.7 | Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.9.31.1.1 | Ensure 'Block NetBIOS-based discovery for domain controller location' is set to 'Enabled' | 'Enabled' | Done | Remediation script |
| 18.9.35.6.1 | Ensure 'Allow network connectivity during connected- standby (on battery)' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.9.35.6.2 | Ensure 'Allow network connectivity during connected- standby (plugged in)' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.9.35.6.5 | Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.35.6.6 | Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.37.1 | Ensure 'Configure Offer Remote Assistance' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.9.37.2 | Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.9.38.1 | Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.38.2 | Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' | 'Enabled: Authenticated' | Done | Base admin policy (JSON) |
| 18.9.41.1 | Ensure 'Configure SAM change password RPC methods policy' is set to 'Enabled: Block all change password RPC methods' | 'Enabled: Block all change password RPC methods' | Done | Remediation script |
| 18.9.53.1.1 | Ensure 'Enable Windows NTP Client' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.53.1.2 | Ensure 'Enable Windows NTP Server' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.9.54 | Ensure 'Configure the behavior of the sudo command' is set to 'Enabled: Disabled' | 'Enabled: Disabled' | Done | Base admin policy (JSON) |
| 18.10.4.2 | Ensure 'Not allow per-user unsigned packages to install by default (requires explicitly allow per install)' is set to 'Enabled' | 'Enabled' | Done | Remediation script |
| 18.10.4.3 | Ensure 'Prevent non-admin users from installing packaged Windows apps' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.5.1 | Ensure 'Let Windows apps activate with voice while the system is locked' is set to 'Enabled: Force Deny' | 'Enabled: Force Deny' | Done | Base admin policy (JSON) |
| 18.10.6.1 | Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.8.1 | Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.8.2 | Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands' | 'Enabled: Do not execute any autorun commands' | Done | Base admin policy (JSON) |
| 18.10.8.3 | Ensure 'Turn off Autoplay' is set to 'Enabled: All drives' | 'Enabled: All drives' | Done | Base admin policy (JSON) |
| 18.10.9.1.1 | Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.13.1 | Ensure 'Turn off cloud consumer account state content' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.13.3 | Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.14.1 | Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always' | 'Enabled: First Time' OR 'Enabled: Always' | Done | Base admin policy (JSON) |
| 18.10.15.1 | Ensure 'Do not display the password reveal button' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.15.2 | Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.15.3 | Ensure 'Prevent the use of security questions for local accounts' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.16.1 | Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data' | 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data' | Done | Base admin policy (JSON) |
| 18.10.16.3 | Ensure 'Do not show feedback notifications' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.16.4 | Ensure 'Enable OneSettings Auditing' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.17.1 | Ensure 'Download Mode' is NOT set to 'Enabled: Internet' | (see benchmark) | Done | Base admin policy (JSON) |
| 18.10.18.2 | Ensure 'Enable App Installer Experimental Features' is set to 'Disabled' | 'Disabled' | Done | CIS Admin Extras policy |
| 18.10.18.3 | Ensure 'Enable App Installer Hash Override' is set to 'Disabled' | 'Disabled' | Done | CIS Admin Extras policy |
| 18.10.18.4 | Ensure 'Enable App Installer Local Archive Malware Scan Override' is set to 'Disabled' | 'Disabled' | Done | CIS Admin Extras policy |
| 18.10.18.5 | Ensure 'Enable App Installer Microsoft Store Source Certificate Validation Bypass' is set to 'Disabled' | 'Disabled' | Done | CIS Admin Extras policy |
| 18.10.18.6 | Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled' | 'Disabled' | Done | CIS Admin Extras policy |
| 18.10.26.1.1 | Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.26.1.2 | Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' | 'Enabled: 32,768 or greater' | Done | Base admin policy (JSON) |
| 18.10.26.2.1 | Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.26.2.2 | Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater' | 'Enabled: 196,608 or greater' | Done | Base admin policy (JSON) |
| 18.10.26.3.1 | Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.26.3.2 | Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' | 'Enabled: 32,768 or greater' | Done | Base admin policy (JSON) |
| 18.10.26.4.1 | Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.26.4.2 | Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' | 'Enabled: 32,768 or greater' | Done | Base admin policy (JSON) |
| 18.10.29.3 | Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.29.4 | Ensure 'Do not apply the Mark of the Web tag to files copied from insecure sources' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.29.5 | Ensure 'Turn off heap termination on corruption' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.29.6 | Ensure 'Turn off shell protocol protected mode' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.41.1 | Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.42.4.1 | Ensure 'Enable EDR in block mode' is set to 'Enabled' | 'Enabled' | Done | Remediation script |
| 18.10.42.5.1 | Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.42.5.2 | Ensure 'Join Microsoft MAPS' is set to 'Enabled: Advanced' | 'Enabled: Advanced' | Done | Base admin policy (JSON) |
| 18.10.42.6.1.1 | Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled' | 'Enabled' | Relaxed | (deliberate) |
| 18.10.42.6.1.2 | Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured | (see benchmark) | Relaxed | (deliberate) |
| 18.10.42.6.3.1 | Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block' | 'Enabled: Block' | Done | Base admin policy (JSON) |
| 18.10.42.7.1 | Ensure 'Enable file hash computation feature' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.42.10.1 | Ensure 'Configure real-time protection and Security Intelligence Updates during OOBE' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.42.10.2 | Ensure 'Scan all downloaded files and attachments' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.42.10.3 | Ensure 'Turn off real-time protection' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.42.10.4 | Ensure 'Turn on behavior monitoring' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.42.10.5 | Ensure 'Turn on script scanning' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.42.11.1.1.2 | Ensure 'Configure Remote Encryption Protection Mode' is set to 'Enabled: Audit' or higher | 'Enabled: Audit' or higher | Done | Remediation script |
| 18.10.42.13.1 | Ensure 'Scan excluded files and directories during quick scans' is set to 'Enabled: 1' | 'Enabled: 1' | Done | Base admin policy (JSON) |
| 18.10.42.13.2 | Ensure 'Scan packed executables' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.42.13.3 | Ensure 'Scan removable drives' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.42.13.4 | Ensure 'Trigger a quick scan after X days without any scans' is set to 'Enabled: 7' | 'Enabled: 7' | Done | Base admin policy (JSON) |
| 18.10.42.13.5 | Ensure 'Turn on e-mail scanning' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.42.16 | Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block' | 'Enabled: Block' | Done | Base admin policy (JSON) |
| 18.10.42.17 | Ensure 'Control whether exclusions are visible to local users' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.43.1 | Ensure 'Allow auditing events in Microsoft Defender Application Guard' is set to 'Enabled' | 'Enabled' | N/A | — |
| 18.10.43.2 | Ensure 'Allow camera and microphone access in Microsoft Defender Application Guard' is set to 'Disabled' | 'Disabled' | N/A | — |
| 18.10.43.3 | Ensure 'Allow data persistence for Microsoft Defender Application Guard' is set to 'Disabled' | 'Disabled' | N/A | — |
| 18.10.43.4 | Ensure 'Allow files to download and save to the host operating system from Microsoft Defender Application Guard' is set to 'Disabled' | 'Disabled' | N/A | — |
| 18.10.43.5 | Ensure 'Configure Microsoft Defender Application Guard clipboard settings: Clipboard behavior setting' is set to 'Enabled: Enable clipboard operation from an isolated session to the host' | 'Enabled: Enable clipboard operation from an isolated session to the host' | N/A | — |
| 18.10.43.6 | Ensure 'Turn on Microsoft Defender Application Guard in Managed Mode' is set to 'Enabled: 1' | 'Enabled: 1' | N/A | — |
| 18.10.57.2.3 | Ensure 'Do not allow passwords to be saved' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.57.3.3.3 | Ensure 'Do not allow drive redirection' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.57.3.9.1 | Ensure 'Always prompt for password upon connection' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.57.3.9.2 | Ensure 'Require secure RPC communication' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.57.3.9.3 | Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL' | 'Enabled: SSL' | Done | Base admin policy (JSON) |
| 18.10.57.3.9.4 | Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.57.3.9.5 | Ensure 'Set client connection encryption level' is set to 'Enabled: High Level' | 'Enabled: High Level' | Done | Base admin policy (JSON) |
| 18.10.57.3.11.1 | Ensure 'Do not delete temp folders upon exit' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.58.1 | Ensure 'Prevent downloading of enclosures' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.59.3 | Ensure 'Allow Cortana' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.59.4 | Ensure 'Allow Cortana above lock screen' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.59.5 | Ensure 'Allow indexing of encrypted files' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.59.6 | Ensure 'Allow search and Cortana to use location' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.66.2 | Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.66.3 | Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.73.1 | Ensure 'Allow Recall to be enabled' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.77.1.1 | Ensure 'Automatic Data Collection' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.77.1.2 | Ensure 'Notify Malicious' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.77.1.3 | Ensure 'Notify Password Reuse' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.77.1.4 | Ensure 'Notify Unsafe App' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.77.1.5 | Ensure 'Service Enabled' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.77.2.1 | Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' | 'Enabled: Warn and prevent bypass' | Done | Base admin policy (JSON) |
| 18.10.79.1 | Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.80.1 | Ensure 'Enable ESS with Supported Peripherals' is set to 'Enabled: 1' | 'Enabled: 1' | Done | Base admin policy (JSON) |
| 18.10.81.2 | Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled' | 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled' | Done | Base admin policy (JSON) |
| 18.10.82.1 | Ensure 'Allow user control over installs' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.82.2 | Ensure 'Always install with elevated privileges' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.83.1 | Ensure 'Configure the transmission of the user's password in the content of MPR notifications sent by winlogon.' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.83.2 | Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.90.1.1 | Ensure 'Allow Basic authentication' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.90.1.2 | Ensure 'Allow unencrypted traffic' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.90.1.3 | Ensure 'Disallow Digest authentication' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.90.2.1 | Ensure 'Allow Basic authentication' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.90.2.3 | Ensure 'Allow unencrypted traffic' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.90.2.4 | Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.92.1 | Ensure 'Allow clipboard sharing with Windows Sandbox' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.92.3 | Ensure 'Allow networking in Windows Sandbox' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.93.2.1 | Ensure 'Prevent users from modifying settings' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.94.1.1 | Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 18.10.94.2.1 | Ensure 'Configure Automatic Updates' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.94.2.2 | Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day' | '0 - Every day' | Done | Base admin policy (JSON) |
| 18.10.94.2.3 | Ensure 'Enable features introduced via servicing that are off by default' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.94.2.4 | Ensure 'Remove access to “Pause updates” feature' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.94.4.1 | Ensure 'Manage preview builds' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.94.4.2 | Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days' | 'Enabled: 0 days' | Done | Base admin policy (JSON) |
| 18.10.94.4.3 | Ensure 'Enable optional updates' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.11.1 | Ensure 'Disable HTTP proxy features: Disable WPAD' is set to 'Enabled: Checked' | 'Enabled: Checked' | Done | Remediation script |
| 18.11.2 | Ensure 'Disable HTTP proxy features: Disable proxy authentication' is set to 'Enabled: Disable authentication over loopback interfaces' or higher | 'Enabled: Disable authentication over loopback interfaces' or higher | Done | Remediation script |
| 19.5.1.1 | Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 19.7.5.1 | Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 19.7.5.2 | Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 19.7.8.1 | Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 19.7.8.2 | Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 19.7.8.5 | Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 19.7.26.1 | Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |

</details>

<details>
<summary><b>Level 2 — all 122 recommendations</b> (click to expand)</summary>

| CIS # | Setting | CIS requires | Status | Configured by |
|---|---|---|---|---|
| 2.2.27 | Ensure 'Log on as a batch job' is set to 'Administrators' | 'Administrators' | Done | Base admin policy (JSON) |
| 2.2.28 | Ensure 'Log on as a service' is set to 'No One' | 'No One' | Relaxed | (deliberate) |
| 2.3.4.1 | Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled' | 'Enabled' | Done | CIS Admin Extras policy |
| 2.3.7.1 | Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 2.3.7.6 | Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)' | '4 or fewer logon(s)' | Done | CIS Admin Extras policy |
| 2.3.14.1 | Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted when the key is first used' or higher | 'User is prompted when the key is first used' or higher | Done | CIS Admin Extras policy |
| 5.1 | Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.2 | Ensure 'Bluetooth Support Service (bthserv)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.4 | Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.5 | Ensure 'GameInput Service (GameInputSvc)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.6 | Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.9 | Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.11 | Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.13 | Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.14 | Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.15 | Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.16 | Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.17 | Ensure 'Print Spooler (Spooler)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.18 | Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.19 | Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.20 | Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled' | 'Disabled' | Relaxed | Base policy / script (kept on) |
| 5.21 | Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled' | 'Disabled' | Relaxed | Base policy / script (kept on) |
| 5.22 | Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' is set to 'Disabled' | 'Disabled' | Relaxed | Base policy / script (kept on) |
| 5.24 | Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.26 | Ensure 'Server (LanmanServer)' is set to 'Disabled' | 'Disabled' | Relaxed | Base policy / script (kept on) |
| 5.28 | Ensure 'SNMP Service (SNMP)' is set to 'Disabled' or 'Not Installed' | 'Disabled' or 'Not Installed' | Done | Remediation script |
| 5.33 | Ensure 'Windows Error Reporting Service (WerSvc)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.34 | Ensure 'Windows Event Collector (Wecsvc)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.37 | Ensure 'Windows Push Notifications System Service (WpnService)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.38 | Ensure 'Windows PushToInstall Service (PushToInstall)' is set to 'Disabled' | 'Disabled' | Done | Remediation script |
| 5.39 | Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Disabled' | 'Disabled' | Relaxed | Base policy / script (kept on) |
| 18.1.3 | Ensure 'Allow Online Tips' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.5.4 | Ensure 'MSS: (DisableSavePassword) Prevent the dial-up password from being saved' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.5.6 | Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes' | 'Enabled: 300,000 or 5 minutes' | Done | Base admin policy (JSON) |
| 18.5.8 | Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses' is set to 'Disabled' | 'Disabled' | Done | CIS Admin Extras policy |
| 18.5.10 | Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3' | 'Enabled: 3' | Done | Base admin policy (JSON) |
| 18.5.11 | Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3' | 'Enabled: 3' | Done | Base admin policy (JSON) |
| 18.6.4.3 | Ensure 'Turn off default IPv6 DNS Servers' is set to 'Enabled' | 'Enabled' | No path | — |
| 18.6.5.1 | Ensure 'Enable Font Providers' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.6.9.1 | Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.6.9.2 | Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled' | 'Disabled' | Done | CIS Admin Extras policy |
| 18.6.10.2 | Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled' | 'Enabled' | No path | — |
| 18.6.19.2.1 | Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)') | (see benchmark) | Relaxed | IPv6 kept on — Microsoft advises against disabling |
| 18.6.20.1 | Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled' | 'Disabled' | Done | CIS Admin Extras policy |
| 18.6.20.2 | Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.7.9 | Ensure 'Configure Windows protected print' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.7.14 | Ensure 'Require IPPS for IPP printers' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.7.15 | Ensure 'Set TLS/SSL security policy for IPP printers: Disallow invalid certificate authority' is set to 'Enabled: Checked' | 'Enabled: Checked' | N/A | No local IPP printing on a Cloud PC |
| 18.7.16 | Ensure 'Set TLS/SSL security policy for IPP printers: Disallow non-server certificates' is set to 'Enabled: Checked' | 'Enabled: Checked' | N/A | No local IPP printing on a Cloud PC |
| 18.7.17 | Ensure 'Set TLS/SSL security policy for IPP printers: Disallow invalid certificate common name' is set to 'Enabled: Checked' | 'Enabled: Checked' | N/A | No local IPP printing on a Cloud PC |
| 18.7.18 | Ensure 'Set TLS/SSL security policy for IPP printers: Disallow invalid certificate date' is set to 'Enabled: Checked' | 'Enabled: Checked' | N/A | No local IPP printing on a Cloud PC |
| 18.8.1.1 | Ensure 'Turn off notifications network usage' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.8.2 | Ensure 'Remove Personalized Website Recommendations from the Recommended section in the Start Menu' is set to 'Enabled' | 'Enabled' | No path | — |
| 18.9.20.1.1 | Ensure 'Turn off access to the Store' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.20.1.3 | Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled' | 'Enabled' | N/A | No pen/touch input on a Cloud PC |
| 18.9.20.1.4 | Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled' | 'Enabled' | N/A | No pen/touch input on a Cloud PC |
| 18.9.20.1.5 | Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.20.1.7 | Ensure 'Turn off printing over HTTP' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.20.1.8 | Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.20.1.9 | Ensure 'Turn off Search Companion content file updates' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.20.1.10 | Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.20.1.11 | Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.20.1.12 | Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled' | 'Enabled' | Done | CIS Admin Extras policy |
| 18.9.20.1.13 | Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.20.1.14 | Ensure 'Turn off Windows Error Reporting' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.23.1 | Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic' | 'Enabled: Automatic' | Done | Base admin policy (JSON) |
| 18.9.28.1 | Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.9.33.1 | Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.9.33.2 | Ensure 'Allow upload of User Activities' is set to 'Disabled' | 'Disabled' | Done | CIS Admin Extras policy |
| 18.9.49.5.1 | Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.9.49.11.1 | Ensure 'Enable/Disable PerfTrack' is set to 'Disabled' | 'Disabled' | No path | — |
| 18.9.51.1 | Ensure 'Turn off the advertising ID' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.3.1 | Ensure 'Turn off API Sampling' is set to 'Enabled' | 'Enabled' | No path | — |
| 18.10.3.2 | Ensure 'Turn off Application Footprint' is set to 'Enabled' | 'Enabled' | No path | — |
| 18.10.3.3 | Ensure 'Turn off Install Tracing' is set to 'Enabled' | 'Enabled' | No path | — |
| 18.10.4.1 | Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.6.2 | Ensure 'Block launching Universal Windows apps with Windows Runtime API access from hosted content.' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.11.1 | Ensure 'Allow Use of Camera' is set to 'Disabled' | 'Disabled' | Done | CIS Admin Extras policy |
| 18.10.13.2 | Ensure 'Turn off cloud optimized content' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.16.2 | Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage' | 'Enabled: Disable Authenticated Proxy usage' | Done | Base admin policy (JSON) |
| 18.10.16.5 | Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.16.6 | Ensure 'Limit Dump Collection' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.18.1 | Ensure 'Enable App Installer' is set to 'Disabled' | 'Disabled' | Relaxed | Kept enabled — the admin needs winget |
| 18.10.18.7 | Ensure 'Enable Windows Package Manager command line interfaces' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.29.2 | Ensure 'Turn off account-based insights, recent, favorite, and recommended files in File Explorer' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.36.1 | Ensure 'Turn off location' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.40.1 | Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled' | 'Disabled' | Done | CIS Admin Extras policy |
| 18.10.42.8.1 | Ensure 'Convert warn verdict to block' is set to 'Enabled' | 'Enabled' | Done | CIS Admin Extras policy |
| 18.10.42.11.1.1.1 | Ensure 'Configure Brute-Force Protection aggressiveness' is set to 'Enabled: Medium' or higher | 'Enabled: Medium' or higher | No path | — |
| 18.10.42.11.1.2.1 | Ensure 'Configure how aggressively Remote Encryption Protection blocks threats' is set to 'Enabled: Medium' or higher | 'Enabled: Medium' or higher | Done | CIS Admin Extras policy |
| 18.10.42.12.1 | Ensure 'Configure Watson events' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.49.1 | Ensure 'Enable news and interests on the taskbar' is set to 'Disabled' | 'Disabled' | N/A | Feature replaced by Widgets on Windows 11 24H2 (see 3.2) |
| 18.10.50.1 | Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.56.1 | Ensure 'Turn off Push To Install service' is set to 'Enabled' | 'Enabled' | Done | CIS Admin Extras policy |
| 18.10.57.2.2 | Ensure 'Disable Cloud Clipboard integration for server-to-client data transfer' is set to 'Enabled' | 'Enabled' | No path | — |
| 18.10.57.3.2.1 | Ensure 'Allow users to connect remotely by using Remote Desktop Services' is set to 'Disabled' | 'Disabled' | Relaxed | (deliberate) |
| 18.10.57.3.3.1 | Ensure 'Allow UI Automation redirection' is set to 'Disabled' | 'Disabled' | No path | — |
| 18.10.57.3.3.2 | Ensure 'Do not allow COM port redirection' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.57.3.3.4 | Ensure 'Do not allow location redirection' is set to 'Enabled' | 'Enabled' | No path | — |
| 18.10.57.3.3.5 | Ensure 'Do not allow LPT port redirection' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.57.3.3.6 | Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.57.3.3.7 | Ensure 'Do not allow WebAuthn redirection' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.57.3.3.8 | Ensure 'Restrict clipboard transfer from server to client' is set to 'Enabled: Disable clipboard transfers from server to client' | 'Enabled: Disable clipboard transfers from server to client' | Done | Base admin policy (JSON) |
| 18.10.57.3.10.1 | Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)' | 'Enabled: 15 minutes or less, but not Never (0)' | Done | Base admin policy (JSON) |
| 18.10.57.3.10.2 | Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute' | 'Enabled: 1 minute' | Done | Base admin policy (JSON) |
| 18.10.59.2 | Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search' | 'Enabled: Disable Cloud Search' | Done | Base admin policy (JSON) |
| 18.10.59.7 | Ensure 'Allow search highlights' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.63.1 | Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled' | 'Enabled' | Done | CIS Admin Extras policy |
| 18.10.66.1 | Ensure 'Disable all apps from Microsoft Store' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.66.4 | Ensure 'Turn off the Store application' is set to 'Enabled' | 'Enabled' | Done | CIS Admin Extras policy |
| 18.10.72.1 | Ensure 'Allow widgets' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.81.1 | Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.82.3 | Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.88.1 | Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled' | 'Enabled' | Done | CIS Admin Extras policy |
| 18.10.88.2 | Ensure 'Turn on PowerShell Transcription' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 18.10.90.2.2 | Ensure 'Allow remote server management through WinRM' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.91.1 | Ensure 'Allow Remote Shell Access' is set to 'Disabled' | 'Disabled' | Done | Base admin policy (JSON) |
| 18.10.92.2 | Ensure 'Allow mapping folders into Windows Sandbox' is set to 'Disabled' | 'Disabled' | N/A | Windows Sandbox is an optional feature; not enabled/used on this device |
| 19.6.6.1.1 | Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 19.7.8.3 | Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 19.7.8.4 | Ensure 'Turn off all Windows spotlight features' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |
| 19.7.46.2.1 | Ensure 'Prevent Codec Download' is set to 'Enabled' | 'Enabled' | Done | Base admin policy (JSON) |

</details>

---

## 3. What is not configured, and why

Certain CIS clauses are not met. The first question for each is **"is this control relevant to this Cloud PC?"** — that decides whether a deviation is needed:

| State | What it means | Count | Deviation needed? |
|---|---|---|---|
| **Applied** (not visible to the scanner) | Enforced; the scanner reads an incorrect location | ~70 | **No** — compliant |
| **Not Applicable (N.A.)** | The control is not relevant here — no physical disk, no matching local hardware/feature, or the feature no longer exists | 61 (incl. 45 BitLocker) | **No** — nothing to comply with |
| **Unable to comply** | The control *is* relevant, but cannot be met — enforcing it would break the machine/Windows features, or the setting isn't available in Intune | 25 | **Yes** — deviation and risk acceptance |

---

### 3.1 Already configured — the scanner just can't see it

Configured and *Succeeded* in Intune — a scan just cannot see them. **No action.**

| Area | Count | Delivered by |
|---|---|---|
| Windows Firewall (Domain/Private/Public) | 23 | Base policy (Firewall CSP) |
| Windows LAPS | 8 | CIS LAPS policy |
| Extras policy (L2 top-ups, Security Options, admin rename, rebuild extras) | 29 | CIS Admin Extras policy |
| Other CSP-based base-policy settings (Autoplay, VBS, consumer accounts, App Installer hardening, SmartScreen…) | ~25 | Base policy |

**Evidence:** each policy reports *Succeeded* in Intune, corroborated by on-device checks (for example, `Get-NetFirewallProfile` confirms every firewall profile is enabled).

---

### 3.2 Not needed — does not apply to this Cloud PC

The control does not apply here — the risk or feature is absent. **No deviation.**

**BitLocker profile (~45 clauses).** A Cloud PC has no physical disk — Azure encrypts the virtual disks and manages Secure Boot/TPM. The whole profile is not applicable.

**Microsoft Defender Application Guard (6 clauses).** Microsoft removed the feature in Windows 11 24H2 — nothing to enable.

| CIS # | Clause |
|---|---|
| 18.10.43.1 | Allow auditing events in Application Guard = Enabled |
| 18.10.43.2 | Allow camera and microphone access in Application Guard = Disabled |
| 18.10.43.3 | Allow data persistence for Application Guard = Disabled |
| 18.10.43.4 | Allow files to download/save to the host OS from Application Guard = Disabled |
| 18.10.43.5 | Application Guard clipboard settings = Enabled (isolated → host only) |
| 18.10.43.6 | Turn on Application Guard in Managed Mode = Enabled: 1 |

**News and interests (18.10.49.1).** Replaced by **Widgets** in Windows 11 24H2; the legacy policy has nothing to act on and errors (65000) in Intune. Not Applicable.

**Store passwords using reversible encryption (1.1.7).** Disabled by default in Windows — already compliant. No deviation.

**No matching hardware or feature (7 clauses).** These protect features this device lacks — **no local printing, no pen/touch, no Windows Sandbox.** (Sandbox is off by default; if ever enabled, revisit 18.10.92.2.)

| CIS # | Clause | Why not applicable |
|---|---|---|
| 18.7.15–18.7.18 | IPP printer TLS/SSL security policy (4 clauses) | No local IPP printing on a Cloud PC |
| 18.9.20.1.3 | Turn off handwriting personalization data sharing | No pen or touch input |
| 18.9.20.1.4 | Turn off handwriting recognition error reporting | No pen or touch input |
| 18.10.92.2 | Allow mapping folders into Windows Sandbox | Optional feature; not enabled/used on this device |

**Rename guest account (2.3.1.4).** The Guest account is already disabled (2.3.1.1), so renaming it protects nothing. No deviation.

---

### 3.3 Can't apply — these need a deviation

Relevant, but cannot be met — **each needs a documented deviation.** Two categories:

#### 3.3a — Would break the admin machine (12)

Enforcing any would lock the admin out, remove remote management, block elevation, or break tooling/Windows features. Compensating controls remain: RDP uses NLA/TLS/high encryption; WinRM is signed/encrypted only; UAC still prompts; deny-RDP still applies to Guests and local accounts.

| CIS # | Level | Clause | What breaks if applied |
|---|---|---|---|
| 5.20 | L2 | Disable Remote Desktop Configuration (SessionEnv) | Part of the RDP stack; required for Cloud PC access |
| 5.21 | L2 | Disable Remote Desktop Services (TermService) | This is the RDP service; disabling it prevents all access |
| 5.22 | L2 | Disable RDS UserMode Port Redirector (UmRdpService) | Required for RDP |
| 5.26 | L2 | Disable Server (LanmanServer) | Disables administrative file shares (c$/admin$) |
| 5.39 | L2 | Disable WinRM | Disables remote management |
| 18.10.57.3.2.1 | L2 | Allow users to connect remotely (RDP) = Disabled | Complete lockout; RDP is the only means of access |
| 2.3.17.3 | L1 | UAC: automatically deny standard-user elevation | The administrator cannot elevate |
| 2.2.28 | L2 | Log on as a service = No One | May disrupt managed and Intune services |
| 18.10.42.6.1.1 | L1 | Configure ASR rules (Block) | Block mode may disrupt administrative scripts and tooling |
| 18.10.42.6.1.2 | L1 | ASR rule states (Block) | Sets each ASR rule to Block, which may disrupt administrative scripts and tooling |
| 18.10.18.1 | L2 | Enable App Installer = Disabled | Removes winget, which the admin needs to install tools |
| 18.6.19.2.1 | L2 | Disable IPv6 (DisabledComponents = 0xff) | Microsoft advises against fully disabling IPv6; can break Windows features |

#### 3.3b — The setting isn't available in Intune (13)

Microsoft has not exposed these to Intune (no Settings Catalog entry, no CSP), or the control needs an add-on licence this tenant does not hold. Low risk, but record each as a deviation.

| CIS # | Level | Clause |
|---|---|---|
| 1.1.6 | L1 | Relax minimum password length limits = Enabled (no effect — min length is already 14) |
| 18.6.4.3 | L2 | Turn off default IPv6 DNS Servers = Enabled |
| 18.6.10.2 | L2 | Turn off Microsoft Peer-to-Peer Networking Services = Enabled |
| 18.8.2 | L2 | Remove Personalized Website Recommendations from the Start Menu = Enabled |
| 18.9.17.1 | L1 | Enable/disable CLFS logfile authentication |
| 18.9.49.11.1 | L2 | Enable/Disable PerfTrack = Disabled |
| 18.10.3.1 | L2 | Turn off API Sampling = Enabled |
| 18.10.3.2 | L2 | Turn off Application Footprint = Enabled |
| 18.10.3.3 | L2 | Turn off Install Tracing = Enabled |
| 18.10.57.2.2 | L2 | Disable Cloud Clipboard integration (server-to-client) = Enabled |
| 18.10.57.3.3.1 | L2 | Allow UI Automation redirection = Disabled |
| 18.10.57.3.3.4 | L2 | Do not allow location redirection = Enabled |
| 18.10.42.11.1.1.1 | L2 | Brute-Force Protection aggressiveness = Medium |

---

### In total: 25 need a deviation

All fall under 3.3; everything else requires no action (3.1 is compliant, 3.2 is Not Applicable).

| Needs a deviation | Why | Section | Count |
|---|---|---|---|
| Would break the admin machine / Windows features | Enforcing it disrupts the machine | 3.3a | 12 |
| Setting isn't available in Intune (or needs a licence) | Cannot be delivered through Intune | 3.3b | 13 |
| **Total** | | | **25** |

**Statement for audit.** 100% compliance isn't attainable or meaningful on an Intune Cloud PC: about a third of the shortfall is a scanner limitation, the rest is settings Microsoft doesn't expose to Intune, deprecated features, BitLocker (platform-managed), and risk-accepted admin exceptions. Compliance is evidenced by Intune's *Succeeded* status.

---

## 4. Extras policy settings

**One** Settings Catalog policy — **29 settings** — combining the Level-2 top-ups, the Local Policies Security Options, and the extra hardening added in the rebuild. It is one policy, so it is one table.

**Intune location:** Devices › Configuration › `CIS Admin Extras` (Settings catalog policy)
**Assigned to:** the admin Cloud PC (All devices)

To recreate it, add each setting below in the Settings Catalog (search the name), then set the value. The **Category** column is where to find it.

| # | CIS # | Setting (search term) | Category | Value |
|---|---|---|---|---|
| 1 | 18.10.66.4 | Turn off the Store application | Windows Components › Store | **Enabled** |
| 2 | 18.10.56.1 | Turn off Push To Install service | Windows Components › Push to Install | **Enabled** |
| 3 | 18.10.63.1 | Disallow KMS Client Online AVS Validation | Licensing | **Block** |
| 4 | 18.10.42.8.1 | Enable Convert Warn To Block | Defender Antivirus | **Enabled** |
| 5 | 18.10.42.11.1.2.1 | Remote Encryption Protection Aggressiveness | Defender › Remediation | **Medium** |
| 6 | 18.10.42.11.1.1.2 | Remote Encryption Protection Configured State | Defender › Remediation | **Block** |
| 7 | 18.10.40.1 | Allow Message Sync | Windows Components › Messaging | **Block** (not allowed) |
| 8 | 18.9.33.2 | Upload User Activities | System › OS Policies (Privacy) | **Disabled** |
| 9 | 18.6.8.7 | Require Encryption | Network › Lanman Workstation | **Enabled** |
| 10 | 18.6.9.2 | Turn on Responder (RSPNDR) driver | Network › Link-Layer Topology Discovery | **Disabled** |
| 11 | 18.6.20.1 | Configuration of wireless settings using Windows Connect Now | Network › Windows Connect Now | **Disabled** |
| 12 | 18.5.8 | MSS: (PerformRouterDiscovery) | MSS (Legacy) | **Disabled** |
| 13 | 18.9.20.1.12 | Turn off the Windows Messenger CEIP | System › Internet Communication | **Enabled** |
| 14 | 18.10.88.1 | Turn on PowerShell Script Block Logging | Windows Components › Windows PowerShell | **Enabled** (invocation events off) |
| 15 | 2.3.7.6 | Interactive Logon: Number Of Previous Logons To Cache | Local Policies Security Options | **4** |
| 16 | 2.3.14.1 | System Cryptography: Force Strong Key Protection | Local Policies Security Options | **User is prompted when the key is first used** (1) |
| 17 | 2.3.1.3 | Accounts: Rename Administrator Account | Local Policies Security Options | **HTGM Admin** |
| 18 | 1.2.3 | Allow Administrator account lockout | Device Lock | **Enabled** |
| 19 | 2.2.4 | Adjust memory quotas for a process | User Rights | **Administrators, LOCAL SERVICE, NETWORK SERVICE** |
| 20 | 2.3.4.1 | Prevent users from installing printer drivers | Local Policies Security Options | **Enabled** |
| 21 | 18.6.21.2 | Prohibit connection to non-domain networks | Network › Windows Connection Manager | **Enabled** |
| 22 | 18.9.5.1 | Turn On Virtualization Based Security | Device Guard | **Enabled** |
| 23 | 18.10.11.1 | Allow Use of Camera | Camera | **Disabled** |
| 24 | 18.10.18.2 | Enable App Installer Experimental Features | Desktop App Installer | **Disabled** |
| 25 | 18.10.18.3 | Enable App Installer Hash Override | Desktop App Installer | **Disabled** |
| 26 | 18.10.18.4 | Enable App Installer Local Archive Malware Scan Override | Desktop App Installer | **Disabled** |
| 27 | 18.10.18.5 | Enable App Installer MS Store Source Certificate Validation Bypass | Desktop App Installer | **Disabled** |
| 28 | 18.10.18.6 | Enable App Installer ms-appinstaller protocol | Desktop App Installer | **Disabled** |
| 29 | 2.2.6 | Allow log on through Remote Desktop Services | User Rights | **Administrators, Remote Desktop Users** |

**Notes on the values**

- Where CIS wants a feature *disabled* but the Intune setting is named "Allow …", set it to **Block** (e.g. #7 Message Sync). Intune still reports *Succeeded*.
- **#17 Rename:** renaming the built-in Administrator to **HTGM Admin** is safe — Windows identifies the account by its fixed SID, not its name, so it keeps working and LAPS still manages it.
- **#22 VBS** needs a Cloud PC size that supports nested virtualization — confirm it reports *Succeeded*, don't assume. **#23 Camera = Disabled** also turns off Teams video — skip it if the admin needs video. **#18 admin lockout** is safe because LAPS provides a break-glass password.
- **#19 and #29 are User Rights** — add each account as a separate entry (e.g. *Administrators*, *Remote Desktop Users*).
- **Two L2 settings are deliberately not here** — 18.10.59.4 (Cortana above lock) and 18.10.49.1 (News and interests): already enforced by the base policy, and adding them here throws a per-setting error (65000). News and interests is a legacy 24H2 feature (Section 3.2).

**Do not add** winget-disable (18.10.18.1) or IPv6-disable (18.6.19.2.1) — they are kept the other way on purpose — and note that Brute-Force Protection (18.10.42.11.1.1.1) needs a Defender for Endpoint licence. All three are in the exceptions list — **see Section 3.3.**

*(Separately, 18.6.4.3 "Turn off default IPv6 DNS Servers" is delivered by the script, not this policy — see `deploy/CIS-v5-ADMIN-Remediation.ps1`; verify with `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableIPv6DefaultDnsServers`.)*

**Also in the policy:** *Allow users to connect remotely by using Remote Desktop Services* = **Enabled** (18.10.57.3.2.1) — the on/off switch that keeps RDP on (CIS would disable it; a Cloud PC needs it; also set by the base policy). Don't confuse it with **#29 / 2.2.6** (*Allow log on through RDS*): 18.10.57.3.2.1 is a **toggle**; 2.2.6 is a **User Right**, a list of accounts.

**After building the policy:** reconnect over RDP and confirm winget + elevation still work, and that each setting reports *Succeeded*.

## 5. LAPS settings

**Intune location:** Endpoint security › Account protection › `CIS LAPS`
**Profile type:** Local admin password solution (Windows LAPS)
**Assigned to:** the admin Cloud PC (All devices)
**Purpose:** rotate and escrow the built-in local administrator password to Entra ID (CIS 18.9.26.x), providing a recoverable break-glass account.

**Prerequisite (one-time):** entra.microsoft.com › Devices › Device settings › **Enable Microsoft Entra Local Administrator Password Solution (LAPS)** = **Yes**.

### Settings

| CIS # | Setting | Value set |
|---|---|---|
| 18.9.26.1 | Backup Directory | **Backup the password to Microsoft Entra ID only** |
| 18.9.26.2 | Password Expiration Protection | **Enabled** (if shown) |
| 18.9.26.4 | Password Complexity | **Large letters + small letters + numbers + special characters** |
| 18.9.26.5 | Password Length | **15** |
| 18.9.26.6 | Password Age (Days) | **30** |
| 18.9.26.7 | Post-authentication Reset Delay (hours) | **8** |
| 18.9.26.8 | Post-authentication Actions | **Reset the password and log off the managed account** |

**Administrator Account Name:** left blank (manages the built-in Administrator account, now renamed HTGM Admin; LAPS identifies the account by its security identifier, so the rename has no effect).
**Automatic Account Management:** disabled; not required by CIS v5.0.0.

### Retrieving the managed password (break-glass)
Intune (or Entra) › Devices › the Cloud PC › **Local admin password** displays the current rotated password, retrievable by an authorised administrator.

### Verification
- Intune › Endpoint security › Account protection › CIS LAPS › **Device check-in status** = **Succeeded**.
- Note: a scan may show LAPS as "Fail" (wrong location) — the Intune *Succeeded* status is authoritative.

---

## 6. Why an admin machine is set up differently

A strict CIS build suits a **standard end-user** Cloud PC. On an **administrator's** device, several settings would block access or tooling. This section lists what was relaxed, and why.

### The main point

**Almost every setting that would break an admin Cloud PC is Level 2, not Level 1.** Level 1 permits RDP logon and elevation, and *hardens* (not disables) PowerShell and winget. The admin-breaking settings — disabling RDP, the RDP/WinRM/file-sharing services, and App Installer — are all Level 2.

> Guidance: **on an administrative Cloud PC, apply Level 1 in full and apply Level 2 selectively.**

---

### Settings the admin must keep working

| CIS # | Level | What CIS asks for | Does it block the admin? | What this build does |
|---|---|---|---|---|
| **18.10.57.3.2.1** Allow users to connect remotely (RDS) | **L2** | **Disabled** (disables RDP) | Complete lockout; RDP is the only means of access to a Cloud PC | Set to **Enabled**; without RDP the device is unreachable. |
| **5.20 / 5.21 / 5.22** Disable SessionEnv / TermService / UmRdpService | **L2** | Disabled | Disables the RDP stack at the service level | **Not disabled**; excluded from the script. |
| **2.2.6** Allow log on through RDS | **L1** | Administrators, Remote Desktop Users | No; it *includes* Administrators | Retained; the administrator can log on remotely. |
| **2.2.2** Access this computer from the network | **L1** | Administrators, Remote Desktop Users | No; includes Administrators | Retained. |
| **2.2.19** Deny log on through RDS | **L1** | include Guests, **Local account** | No; an Entra administrator account is not a local account | Retained; denies only Guests and local accounts. |
| **2.3.17.2** UAC prompt for administrators | **L1** | Prompt for consent on the secure desktop (or stricter) | No; the administrator still elevates, following a prompt | Retained. |
| **2.3.17.3** UAC prompt for **standard users** | **L1** | **Automatically deny** | Blocks elevation **only if the account is a standard user** (not a local administrator) | The single Level 1 consideration. Either designate the account a local administrator (in which case the setting does not apply), or relax it to "Prompt for credentials"; this configuration adopts the latter. |
| **2.3.17.6** Run all admins in Admin Approval Mode | **L1** | Enabled | No; UAC remains enabled and elevation is still possible | Retained. |
| **18.10.82.2** Always install with elevated privileges | **L1** | Disabled | No; installation still uses the administrator's own elevation | Retained (sound security control). |
| **18.10.18.2–18.10.18.6** App Installer sub-settings | **L1** | Disabled (hash override, experimental features, ms-appinstaller protocol…) | No; these *harden* winget rather than disabling it | **Applied** in the rebuild (harden winget without disabling it). |
| **18.10.18.1** Enable App Installer | **L2** | **Disabled** (disables winget entirely) | Prevents installation of tools via winget | **Not applied**, so winget remains functional. |
| **5.39** Disable WinRM service | **L2** | Disabled | Removes remote management via WinRM | **WinRM retained.** |
| **18.10.90.2.2** Allow remote server management through WinRM | **L2** | Disabled | Removes remote management via WinRM | Retained. |
| **5.26** Disable Server (LanmanServer) | **L2** | Disabled | Disables administrative shares (c$/admin$) and file-share hosting | **LanmanServer retained.** |
| **18.10.42.6.1.1** Configure ASR rules | **L1** | Enabled (Block) | Block-mode ASR may disrupt administrative scripts and PSExec/WMI tooling | **Not applied at present**; deploy separately in **Audit** mode first. |
| **18.10.77.2.1** SmartScreen | **L1** | Enabled: Warn and prevent bypass | Prevents running an unknown *downloaded* executable, with no "run anyway" option | Retained. Workaround: right-click the file → Properties → **Unblock**. |
| **18.10.88.1 / 18.10.88.2** PowerShell script-block logging / transcription | **L2** | Enabled | No; these *log* activity rather than blocking PowerShell | Both enabled (no admin impact; useful audit trail). |

### Strict build vs this admin build

A strict build applies every item as written (fine for an end-user PC, not an admin one). This build relaxes only the items above.

| | Strict build (by-the-book, for a normal end-user PC) | This admin build |
|---|---|---|
| CIS target | L1 + L2 exactly as written | All of L1 + L2 minus the admin-hostile items |
| RDP | Enabled (the one exception every Cloud PC needs) | Enabled |
| PowerShell | Works (with logging) | Works (with logging) |
| Elevate to administrator | Standard users denied (2.3.17.3) | Prompt for credentials; elevation is always possible |
| ASR rules | Block | Left off (roll out in Audit first) |
| winget / App Installer | Disabled (L2) | Enabled |
| WinRM / LanmanServer | Disabled (L2) | Enabled |
| Suited to | A standard user's Cloud PC | A Cloud PC used for administration |

---

## 7. Running a CIS-CAT scan (optional check)

A CIS-CAT scan is an **optional cross-check, not the source of truth.** It always **under-reports** on an Intune Cloud PC (it reads Group Policy; Intune enforces via the Policy CSP). Use it only to spot a genuine miss among the settings it *can* see.

### Where to get it

**CIS-CAT Lite** is the free assessor from CIS.

- Download from **[learn.cisecurity.org/cis-cat-lite](https://learn.cisecurity.org/cis-cat-lite)** — sign up with an email address; **no licence key is required.**
- The download is a single zip that bundles the tool, a Java runtime, and a fixed set of benchmarks, **including CIS Microsoft Windows 11 Enterprise.**
- **Check the benchmark version it loads** — the Lite bundle can lag; if it's older than **v5.0.0**, note that in your evidence. (CIS-CAT Pro loads the full current library but isn't needed here.)

### Requirements

- Windows: the zip includes its own Java runtime — **no separate Java install is needed.**
- Run it **as administrator** (it reads local security policy).
- Extract the archive to a local path, for example `C:\CIS-CAT`.

### How to run it (on the Cloud PC, over RDP)

1. Copy the zip to the Cloud PC and extract it.
2. **Unblock the files first.** This build enforces SmartScreen "warn and prevent bypass" (18.10.77.2.1), so a downloaded executable is blocked with no *Run anyway*. In PowerShell:
   ```powershell
   Get-ChildItem -Path C:\CIS-CAT -Recurse | Unblock-File
   ```
3. Launch the assessor **as administrator** — the GUI (`Assessor-GUI.exe`) or the command line (`Assessor-CLI.bat`).
4. Select **CIS Microsoft Windows 11 Enterprise Benchmark**, then the profile — **Level 1**, or **Level 1 + Level 2**. (BitLocker is a separate profile and does not apply — Section 3.)
5. Run the assessment. An **HTML report** is written to the `reports\` folder; open it in a browser.

Command-line equivalent:

```
Assessor-CLI.bat -b benchmarks\<windows-11-benchmark>.xml -rp reports -html
```

### Reading the result

In this deployment the report scored **392 / 513 (~76%)** — and the shortfall is expected. The **392 pass** are exactly the settings the scanner can both see *and* verify (row 1 of the Section 2 table). Of the ~121 "Fail" results:

- **~81 are enforced but invisible to the scanner** — applied via the Policy CSP; the scan reads Group Policy and cannot see them. *Not a gap* (Section 2).
- **The rest are Not Applicable or documented deviations** — printers, pen/touch and other N/A items (Section 3.2), plus the **25** risk-accepted or can't-be-set exceptions (Section 3.3).

*(BitLocker is a separate profile and isn't part of the 513 — see Section 2.)*

Do not report the CIS-CAT percentage as the compliance figure. The authoritative record is Intune's **"Succeeded"** status.
