# D3FEND: System File Analysis

<a id="system-file-analysis"></a>

**D3FEND tactic:** Detect  
**Digital artifacts:** Operating System File  

Monitoring system files such as authentication databases, configuration files, system logs, and system executables for modification or tampering.

## ATT&CK techniques countered (11)

- [T0888](https://attack.mitre.org/techniques/T0888) — analyzes
- [T1003.007 — Proc Filesystem](/mitre/techniques/T1003-007.md) — analyzes. Adversaries may gather credentials from the proc filesystem or `/proc`.
- [T1018 — Remote System Discovery](/mitre/techniques/T1018.md) — analyzes. Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system.
- [T1036.003 — Rename Legitimate Utilities](/mitre/techniques/T1036-003.md) — analyzes. Adversaries may rename legitimate / system utilities to try to evade security mechanisms concerning the usage of those utilities.
- [T1055.009 — Proc Memory](/mitre/techniques/T1055-009.md) — analyzes. Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges.
- [T1070.002 — Clear Linux or Mac System Logs](/mitre/techniques/T1070-002.md) — analyzes. Adversaries may clear system logs to hide evidence of an intrusion.
- [T1543.002 — Systemd Service](/mitre/techniques/T1543-002.md) — analyzes. Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence.
- [T1548.003 — Sudo and Sudo Caching](/mitre/techniques/T1548-003.md) — analyzes. Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges.
- [T1556.003 — Pluggable Authentication Modules](/mitre/techniques/T1556-003.md) — analyzes. Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts.
- [T1574.006 — Dynamic Linker Hijacking](/mitre/techniques/T1574-006.md) — analyzes. Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries.
- [T1685.006 — Clear Linux or Mac System Logs](/mitre/techniques/T1685-006.md) — analyzes. Adversaries may clear system logs to hide evidence of an intrusion.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
