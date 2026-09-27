# D3FEND: System Configuration Permissions

<a id="system-configuration-permissions"></a>

**D3FEND tactic:** Harden  
**Digital artifacts:** System Configuration Database  

Restricting system configuration modifications to a specific user or group of users.

## ATT&CK techniques countered (14)

- [T0894](https://attack.mitre.org/techniques/T0894) — restricts
- [T1012 — Query Registry](/mitre/techniques/T1012.md) — restricts. Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.
- [T1112 — Modify Registry](/mitre/techniques/T1112.md) — restricts. Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution.
- [T1137.006 — Add-ins](/mitre/techniques/T1137-006.md) — restricts. Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system.
- [T1207 — Rogue Domain Controller](/mitre/techniques/T1207.md) — restricts. Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data.
- [T1218.014 — MMC](/mitre/techniques/T1218-014.md) — restricts. Adversaries may abuse mmc.exe to proxy execution of malicious .msc files.
- [T1543.003 — Windows Service](/mitre/techniques/T1543-003.md) — restricts. Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence.
- [T1546.012 — Image File Execution Options Injection](/mitre/techniques/T1546-012.md) — restricts. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers.
- [T1546.015 — Component Object Model Hijacking](/mitre/techniques/T1546-015.md) — restricts. Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects.
- [T1548.004 — Elevated Execution with Prompt](/mitre/techniques/T1548-004.md) — restricts. Adversaries may leverage the <code>AuthorizationExecuteWithPrivileges</code> API to escalate privileges by prompting the user for credentials.
- [T1552.002 — Credentials in Registry](/mitre/techniques/T1552-002.md) — restricts. Adversaries may search the Registry on compromised systems for insecurely stored credentials.
- [T1564.003 — Hidden Window](/mitre/techniques/T1564-003.md) — restricts. Adversaries may use hidden windows to conceal malicious activity from the plain sight of users.
- [T1564.005 — Hidden File System](/mitre/techniques/T1564-005.md) — restricts. Adversaries may use a hidden file system to conceal malicious activity from users and security tools.
- [T1614.001 — System Language Discovery](/mitre/techniques/T1614-001.md) — restricts. Adversaries may attempt to gather information about the system language of a victim in order to infer the geographical location of that host.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
