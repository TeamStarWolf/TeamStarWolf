# D3FEND: Process Code Segment Verification

<a id="process-code-segment-verification"></a>

**D3FEND tactic:** Detect
**Digital artifacts:** Process Code Segment

Comparing the "text" or "code" memory segments to a source of truth.

## ATT&CK techniques countered (11)

- [T0820](https://attack.mitre.org/techniques/T0820) — verifies
- [T0866](https://attack.mitre.org/techniques/T0866) — verifies
- [T0874](https://attack.mitre.org/techniques/T0874) — verifies
- [T0890](https://attack.mitre.org/techniques/T0890) — verifies
- [T1055.012 — Process Hollowing](/mitre/techniques/T1055-012.md) — verifies. Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses.
- [T1056.004 — Credential API Hooking](/mitre/techniques/T1056-004.md) — verifies. Adversaries may hook into Windows application programming interface (API) functions and Linux system functions to collect user credentials.
- [T1068 — Exploitation for Privilege Escalation](/mitre/techniques/T1068.md) — verifies. Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.
- [T1203 — Exploitation for Client Execution](/mitre/techniques/T1203.md) — verifies. Adversaries may exploit software vulnerabilities in client applications to execute code.
- [T1210 — Exploitation of Remote Services](/mitre/techniques/T1210.md) — verifies. Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.
- [T1211 — Exploitation for Defense Evasion](/mitre/techniques/T1211.md) — verifies. Adversaries may exploit a system or application vulnerability to bypass security features.
- [T1212 — Exploitation for Credential Access](/mitre/techniques/T1212.md) — verifies. Adversaries may exploit software vulnerabilities in an attempt to collect credentials.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
