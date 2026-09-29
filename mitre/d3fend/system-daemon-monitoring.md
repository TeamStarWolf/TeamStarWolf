# D3FEND: System Daemon Monitoring

<a id="system-daemon-monitoring"></a>

**D3FEND tactic:** Detect  
**Digital artifacts:** Operating System Process  

Tracking changes to the state or configuration of critical system level processes.

## ATT&CK techniques countered (4)

- [T1053 — Scheduled Task/Job](/mitre/techniques/T1053.md) — monitors. Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.
- [T1053.005 — Scheduled Task](/mitre/techniques/T1053-005.md) — monitors. Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.
- [T1562.001 — Disable or Modify Tools](/mitre/techniques/T1562-001.md) — monitors. Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities.
- [T1685 — Disable or Modify Tools](/mitre/techniques/T1685.md) — monitors. Adversaries may disable, degrade, or tamper with security tools or applications (e.g., endpoint detection and response (EDR) tools, intrusion detection systems (IDS), antivirus, logging agents, sensors, etc.) to impair or reduce visibility of defensive capabilities.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
