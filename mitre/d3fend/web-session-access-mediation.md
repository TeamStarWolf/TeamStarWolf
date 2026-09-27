# D3FEND: Web Session Access Mediation

<a id="web-session-access-mediation"></a>

**D3FEND tactic:** Isolate
**Digital artifacts:** Service Application Process

Web session access mediation secures user sessions in web applications by employing robust authentication and integrity validation, along with adaptive threat mitigation techniques, to ensure that access to web resources is authorized and protected from session-related attacks.

## ATT&CK techniques countered (14)

- [T0806](https://attack.mitre.org/techniques/T0806) — isolates
- [T0813](https://attack.mitre.org/techniques/T0813) — isolates
- [T0814](https://attack.mitre.org/techniques/T0814) — isolates
- [T0819](https://attack.mitre.org/techniques/T0819) — isolates
- [T0821](https://attack.mitre.org/techniques/T0821) — isolates
- [T0878](https://attack.mitre.org/techniques/T0878) — isolates
- [T1003.001 — LSASS Memory](/mitre/techniques/T1003-001.md) — isolates. Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).
- [T1003.002 — Security Account Manager](/mitre/techniques/T1003-002.md) — isolates. Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored.
- [T1033 — System Owner/User Discovery](/mitre/techniques/T1033.md) — isolates. Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.
- [T1212 — Exploitation for Credential Access](/mitre/techniques/T1212.md) — isolates. Adversaries may exploit software vulnerabilities in an attempt to collect credentials.
- [T1505.002 — Transport Agent](/mitre/techniques/T1505-002.md) — isolates. Adversaries may abuse Microsoft transport agents to establish persistent access to systems.
- [T1550 — Use Alternate Authentication Material](/mitre/techniques/T1550.md) — isolates. Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.
- [T1556 — Modify Authentication Process](/mitre/techniques/T1556.md) — isolates. Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.
- [T1621 — Multi-Factor Authentication Request Generation](/mitre/techniques/T1621.md) — isolates. Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
