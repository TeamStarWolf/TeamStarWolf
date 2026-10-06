# D3FEND: System Init Config Analysis

<a id="system-init-config-analysis"></a>

D3FEND tactic: Detect  
Digital artifacts: System Init Configuration  

Analysis of any system process startup configuration.

## ATT&CK techniques countered (6)

- [T1037.004: RC Scripts](/mitre/techniques/T1037-004.md): analyzes. Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup.
- [T1037.005: Startup Items](/mitre/techniques/T1037-005.md): analyzes. Adversaries may use startup items automatically executed at boot initialization to establish persistence.
- [T1547.001: Registry Run Keys / Startup Folder](/mitre/techniques/T1547-001.md): analyzes. Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.
- [T1562.009: Safe Mode Boot](/mitre/techniques/T1562-009.md): analyzes. Adversaries may abuse Windows safe mode to disable endpoint defenses.
- [T1574.011: Services Registry Permissions Weakness](/mitre/techniques/T1574-011.md): analyzes. Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
- [T1688: Safe Mode Boot](/mitre/techniques/T1688.md): analyzes. Adversaries may abuse Windows safe mode to disable endpoint defenses.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
