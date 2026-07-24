# CIS Windows 11 Hardening — Administrative Cloud PC

This repository hardens an administrative Windows 365 Cloud PC to the **CIS Windows 11 v5.0.0** benchmark
using **Microsoft Intune**. Roughly 500 settings are delivered by importing a small number of files rather
than by manual configuration. Because the device is used by an administrator, the benchmark is applied as
strictly as is safe while preserving Remote Desktop, PowerShell, elevation, and application installation.

*CIS Benchmark* — an industry security checklist for Windows. *Intune* — Microsoft's tool for configuring
managed devices. *Windows 365 Cloud PC* — a Windows 11 device hosted in Microsoft's cloud, accessed over
Remote Desktop.

## Repository contents

```
CIS-W11-v5.0.0-Intune/admin/
├── DOCUMENTATION.md         Full reference: deployment, every setting, and all exceptions
└── deploy/
    ├── CIS-v5-ADMIN-CloudPC.json      Imported into Intune
    └── CIS-v5-ADMIN-Remediation.ps1   Script for settings Intune cannot set directly
```

This file is the overview. **[`DOCUMENTATION.md`](CIS-W11-v5.0.0-Intune/admin/DOCUMENTATION.md)** is the
complete reference — deployment steps, coverage tables, and every exception.

## Components

The configuration consists of four components.

| Component | Type | Function |
|---|---|---|
| `CIS-v5-ADMIN-CloudPC.json` | Imported Intune policy (~360 settings) | Enforces the bulk of the benchmark: user rights, security options, firewall, audit policy, Microsoft Defender, administrative templates, SMB, and virtualization-based security. |
| `CIS-v5-ADMIN-Remediation.ps1` | Intune platform script (71 settings) | Applies 71 CIS recommendations that Intune cannot set directly: 39 service disables, 16 registry settings, 7 user rights set to "No One", 7 password and account-lockout settings, and 2 null-session restrictions. |
| **CIS Admin Extras** | Intune policy, configured manually (29 settings) | 14 Level-2 additions plus 3 Local Policies Security Options (cache previous logons = 4, force strong key protection = 1, rename of the administrator account to HTGM Admin), plus 12 further hardening settings added during the rebuild (VBS, camera, App Installer hardening, user rights, admin lockout). |
| **CIS LAPS** | Endpoint security policy | Rotates the built-in local administrator password and escrows it to Entra ID, providing a recoverable break-glass account. |

## Coverage

| Measure | Result |
|---|---|
| Level 1 | ~97% configured (380 of 393) |
| Level 2 | ~77% configured (94 of 122) |
| Overall | ~92% of applicable settings |
| Effective (excluding items that cannot apply) | ~93% |
| Genuine security gaps | 0 |

## Settings not applied

The shortfall from 100% falls into two groups. Neither represents an unmanaged security gap.

**Not a gap — no action required**

| Count | Reason |
|---|---|
| ~81 | Enforced, but not detectable by a compliance scan (a scanner limitation). |
| ~45 | BitLocker — not applicable; Cloud PC disks are encrypted by Azure. |
| 6 | Application Guard — the feature was removed from Windows 11. |
| 1 | News and interests — replaced by Widgets in Windows 11 24H2. |
| 7 | Not applicable to a Cloud PC — no printer (IPP), no pen/touch, no Windows Sandbox. |
| 1 | Guest-account rename — the Guest account is already disabled, so renaming protects nothing. |

**Documented exceptions — require a deviation and risk acceptance (25 total)**

| Count | Reason |
|---|---|
| 12 | Administrative exceptions — enforcement would break admin access or Windows features; risk-accepted. |
| 13 | Setting not available in Intune — not exposed by Microsoft, or needs an add-on licence. |

## Compliance scanning

A CIS-CAT scan reports a lower score (about 76% in this deployment — 392 of 513 automated checks) because it
reads the Group Policy registry, whereas Intune enforces settings through the Policy CSP. This is a
measurement limitation, not a security gap. The authoritative evidence of enforcement is the per-setting
"Succeeded" status in Intune.

## Notes

- The CIS benchmark PDF is not included in this repository owing to licensing restrictions; it is available
  from the [CIS Workbench](https://workbench.cisecurity.org/).
- This project is not affiliated with or endorsed by CIS. It contains only original settings created to satisfy
  the recommendations.
- The configuration is provided as-is and should be tested on a pilot device before wider deployment.
