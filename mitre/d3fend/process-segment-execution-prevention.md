# D3FEND: Process Segment Execution Prevention

<a id="process-segment-execution-prevention"></a>

**D3FEND tactic:** Harden
**Digital artifacts:** Process Segment

Preventing execution of any address in a memory region other than the code segment.

## ATT&CK techniques countered (17)

- [T0820](https://attack.mitre.org/techniques/T0820) — neutralizes
- [T0866](https://attack.mitre.org/techniques/T0866) — neutralizes
- [T0874](https://attack.mitre.org/techniques/T0874) — neutralizes
- [T0890](https://attack.mitre.org/techniques/T0890) — neutralizes
- [T0894](https://attack.mitre.org/techniques/T0894) — neutralizes
- [T1033 — System Owner/User Discovery](/mitre/techniques/T1033.md) — neutralizes. Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.
- [T1055.012 — Process Hollowing](/mitre/techniques/T1055-012.md) — neutralizes. Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses.
- [T1056.004 — Credential API Hooking](/mitre/techniques/T1056-004.md) — neutralizes. Adversaries may hook into Windows application programming interface (API) functions and Linux system functions to collect user credentials.
- [T1068 — Exploitation for Privilege Escalation](/mitre/techniques/T1068.md) — neutralizes. Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.
- [T1189 — Drive-by Compromise](/mitre/techniques/T1189.md) — neutralizes. Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.
- [T1190 — Exploit Public-Facing Application](/mitre/techniques/T1190.md) — neutralizes. Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.
- [T1203 — Exploitation for Client Execution](/mitre/techniques/T1203.md) — neutralizes. Adversaries may exploit software vulnerabilities in client applications to execute code.
- [T1210 — Exploitation of Remote Services](/mitre/techniques/T1210.md) — neutralizes. Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.
- [T1211 — Exploitation for Defense Evasion](/mitre/techniques/T1211.md) — neutralizes. Adversaries may exploit a system or application vulnerability to bypass security features.
- [T1212 — Exploitation for Credential Access](/mitre/techniques/T1212.md) — neutralizes. Adversaries may exploit software vulnerabilities in an attempt to collect credentials.
- [T1218.013 — Mavinject](/mitre/techniques/T1218-013.md) — neutralizes. Adversaries may abuse mavinject.exe to proxy execution of malicious code.
- [T1620 — Reflective Code Loading](/mitre/techniques/T1620.md) — neutralizes. Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
