# Tactic: Privilege Escalation

<a id="privilege-escalation"></a>

The adversary is trying to gain higher-level permissions.

## Most-observed in the Team Star Wolf corpus

- [T1548.003 — Sudo and Sudo Caching](/mitre/techniques/T1548-003.md) — 18.7% of machines
- [T1548.001 — Setuid and Setgid](/mitre/techniques/T1548-001.md) — 17.2% of machines
- [T1078 — Valid Accounts](/mitre/techniques/T1078.md) — 11.0% of machines
- [T1053.003 — Cron](/mitre/techniques/T1053-003.md) — 10.4% of machines
- [T1574 — Hijack Execution Flow](/mitre/techniques/T1574.md) — 2.5% of machines
- [T1068 — Exploitation for Privilege Escalation](/mitre/techniques/T1068.md) — 1.5% of machines
- [T1611 — Escape to Host](/mitre/techniques/T1611.md) — 1.3% of machines

**109 techniques** in this tactic (Team Star Wolf enriched pages):

- [T1037 — Boot or Logon Initialization Scripts](/mitre/techniques/T1037.md)
- [T1037.001 — Logon Script (Windows)](/mitre/techniques/T1037-001.md)
- [T1037.002 — Login Hook](/mitre/techniques/T1037-002.md)
- [T1037.003 — Network Logon Script](/mitre/techniques/T1037-003.md)
- [T1037.004 — RC Scripts](/mitre/techniques/T1037-004.md)
- [T1037.005 — Startup Items](/mitre/techniques/T1037-005.md)
- [T1053 — Scheduled Task/Job](/mitre/techniques/T1053.md)
- [T1053.002 — At](/mitre/techniques/T1053-002.md)
- [T1053.003 — Cron](/mitre/techniques/T1053-003.md) ⭐
- [T1053.005 — Scheduled Task](/mitre/techniques/T1053-005.md)
- [T1053.006 — Systemd Timers](/mitre/techniques/T1053-006.md)
- [T1053.007 — Container Orchestration Job](/mitre/techniques/T1053-007.md)
- [T1055 — Process Injection](/mitre/techniques/T1055.md)
- [T1055.001 — Dynamic-link Library Injection](/mitre/techniques/T1055-001.md)
- [T1055.002 — Portable Executable Injection](/mitre/techniques/T1055-002.md)
- [T1055.003 — Thread Execution Hijacking](/mitre/techniques/T1055-003.md)
- [T1055.004 — Asynchronous Procedure Call](/mitre/techniques/T1055-004.md)
- [T1055.005 — Thread Local Storage](/mitre/techniques/T1055-005.md)
- [T1055.008 — Ptrace System Calls](/mitre/techniques/T1055-008.md)
- [T1055.009 — Proc Memory](/mitre/techniques/T1055-009.md)
- [T1055.011 — Extra Window Memory Injection](/mitre/techniques/T1055-011.md)
- [T1055.012 — Process Hollowing](/mitre/techniques/T1055-012.md)
- [T1055.013 — Process Doppelgänging](/mitre/techniques/T1055-013.md)
- [T1055.014 — VDSO Hijacking](/mitre/techniques/T1055-014.md)
- [T1055.015 — ListPlanting](/mitre/techniques/T1055-015.md)
- [T1068 — Exploitation for Privilege Escalation](/mitre/techniques/T1068.md) ⭐
- [T1078 — Valid Accounts](/mitre/techniques/T1078.md) ⭐
- [T1078.001 — Default Accounts](/mitre/techniques/T1078-001.md)
- [T1078.002 — Domain Accounts](/mitre/techniques/T1078-002.md)
- [T1078.003 — Local Accounts](/mitre/techniques/T1078-003.md)
- [T1078.004 — Cloud Accounts](/mitre/techniques/T1078-004.md)
- [T1098 — Account Manipulation](/mitre/techniques/T1098.md)
- [T1098.001 — Additional Cloud Credentials](/mitre/techniques/T1098-001.md)
- [T1098.002 — Additional Email Delegate Permissions](/mitre/techniques/T1098-002.md)
- [T1098.003 — Additional Cloud Roles](/mitre/techniques/T1098-003.md)
- [T1098.004 — SSH Authorized Keys](/mitre/techniques/T1098-004.md)
- [T1098.005 — Device Registration](/mitre/techniques/T1098-005.md)
- [T1098.006 — Additional Container Cluster Roles](/mitre/techniques/T1098-006.md)
- [T1098.007 — Additional Local or Domain Groups](/mitre/techniques/T1098-007.md)
- [T1134 — Access Token Manipulation](/mitre/techniques/T1134.md)
- [T1134.001 — Token Impersonation/Theft](/mitre/techniques/T1134-001.md)
- [T1134.002 — Create Process with Token](/mitre/techniques/T1134-002.md)
- [T1134.003 — Make and Impersonate Token](/mitre/techniques/T1134-003.md)
- [T1134.004 — Parent PID Spoofing](/mitre/techniques/T1134-004.md)
- [T1134.005 — SID-History Injection](/mitre/techniques/T1134-005.md)
- [T1484 — Domain or Tenant Policy Modification](/mitre/techniques/T1484.md)
- [T1484.001 — Group Policy Modification](/mitre/techniques/T1484-001.md)
- [T1484.002 — Trust Modification](/mitre/techniques/T1484-002.md)
- [T1543 — Create or Modify System Process](/mitre/techniques/T1543.md)
- [T1543.001 — Launch Agent](/mitre/techniques/T1543-001.md)
- [T1543.002 — Systemd Service](/mitre/techniques/T1543-002.md)
- [T1543.003 — Windows Service](/mitre/techniques/T1543-003.md)
- [T1543.004 — Launch Daemon](/mitre/techniques/T1543-004.md)
- [T1543.005 — Container Service](/mitre/techniques/T1543-005.md)
- [T1546 — Event Triggered Execution](/mitre/techniques/T1546.md)
- [T1546.001 — Change Default File Association](/mitre/techniques/T1546-001.md)
- [T1546.002 — Screensaver](/mitre/techniques/T1546-002.md)
- [T1546.003 — Windows Management Instrumentation Event Subscription](/mitre/techniques/T1546-003.md)
- [T1546.004 — Unix Shell Configuration Modification](/mitre/techniques/T1546-004.md)
- [T1546.005 — Trap](/mitre/techniques/T1546-005.md)
- [T1546.006 — LC_LOAD_DYLIB Addition](/mitre/techniques/T1546-006.md)
- [T1546.007 — Netsh Helper DLL](/mitre/techniques/T1546-007.md)
- [T1546.008 — Accessibility Features](/mitre/techniques/T1546-008.md)
- [T1546.009 — AppCert DLLs](/mitre/techniques/T1546-009.md)
- [T1546.010 — AppInit DLLs](/mitre/techniques/T1546-010.md)
- [T1546.011 — Application Shimming](/mitre/techniques/T1546-011.md)
- [T1546.012 — Image File Execution Options Injection](/mitre/techniques/T1546-012.md)
- [T1546.013 — PowerShell Profile](/mitre/techniques/T1546-013.md)
- [T1546.014 — Emond](/mitre/techniques/T1546-014.md)
- [T1546.015 — Component Object Model Hijacking](/mitre/techniques/T1546-015.md)
- [T1546.016 — Installer Packages](/mitre/techniques/T1546-016.md)
- [T1546.017 — Udev Rules](/mitre/techniques/T1546-017.md)
- [T1546.018 — Python Startup Hooks](/mitre/techniques/T1546-018.md)
- [T1547 — Boot or Logon Autostart Execution](/mitre/techniques/T1547.md)
- [T1547.001 — Registry Run Keys / Startup Folder](/mitre/techniques/T1547-001.md)
- [T1547.002 — Authentication Package](/mitre/techniques/T1547-002.md)
- [T1547.003 — Time Providers](/mitre/techniques/T1547-003.md)
- [T1547.004 — Winlogon Helper DLL](/mitre/techniques/T1547-004.md)
- [T1547.005 — Security Support Provider](/mitre/techniques/T1547-005.md)
- [T1547.006 — Kernel Modules and Extensions](/mitre/techniques/T1547-006.md)
- [T1547.007 — Re-opened Applications](/mitre/techniques/T1547-007.md)
- [T1547.008 — LSASS Driver](/mitre/techniques/T1547-008.md)
- [T1547.009 — Shortcut Modification](/mitre/techniques/T1547-009.md)
- [T1547.010 — Port Monitors](/mitre/techniques/T1547-010.md)
- [T1547.012 — Print Processors](/mitre/techniques/T1547-012.md)
- [T1547.013 — XDG Autostart Entries](/mitre/techniques/T1547-013.md)
- [T1547.014 — Active Setup](/mitre/techniques/T1547-014.md)
- [T1547.015 — Login Items](/mitre/techniques/T1547-015.md)
- [T1548 — Abuse Elevation Control Mechanism](/mitre/techniques/T1548.md)
- [T1548.001 — Setuid and Setgid](/mitre/techniques/T1548-001.md) ⭐
- [T1548.002 — Bypass User Account Control](/mitre/techniques/T1548-002.md)
- [T1548.003 — Sudo and Sudo Caching](/mitre/techniques/T1548-003.md) ⭐
- [T1548.004 — Elevated Execution with Prompt](/mitre/techniques/T1548-004.md)
- [T1548.005 — Temporary Elevated Cloud Access](/mitre/techniques/T1548-005.md)
- [T1548.006 — TCC Manipulation](/mitre/techniques/T1548-006.md)
- [T1574 — Hijack Execution Flow](/mitre/techniques/T1574.md) ⭐
- [T1574.001 — DLL](/mitre/techniques/T1574-001.md)
- [T1574.004 — Dylib Hijacking](/mitre/techniques/T1574-004.md)
- [T1574.005 — Executable Installer File Permissions Weakness](/mitre/techniques/T1574-005.md)
- [T1574.006 — Dynamic Linker Hijacking](/mitre/techniques/T1574-006.md)
- [T1574.007 — Path Interception by PATH Environment Variable](/mitre/techniques/T1574-007.md)
- [T1574.008 — Path Interception by Search Order Hijacking](/mitre/techniques/T1574-008.md)
- [T1574.009 — Path Interception by Unquoted Path](/mitre/techniques/T1574-009.md)
- [T1574.010 — Services File Permissions Weakness](/mitre/techniques/T1574-010.md)
- [T1574.011 — Services Registry Permissions Weakness](/mitre/techniques/T1574-011.md)
- [T1574.012 — COR_PROFILER](/mitre/techniques/T1574-012.md)
- [T1574.013 — KernelCallbackTable](/mitre/techniques/T1574-013.md)
- [T1574.014 — AppDomainManager](/mitre/techniques/T1574-014.md)
- [T1611 — Escape to Host](/mitre/techniques/T1611.md) ⭐

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
