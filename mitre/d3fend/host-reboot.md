# D3FEND: Host Reboot

<a id="host-reboot"></a>

**D3FEND tactic:** Evict
**Digital artifacts:** Process

Initiating a host's reboot sequence to terminate all running processes.

## ATT&CK techniques countered (21)

- [T0806](https://attack.mitre.org/techniques/T0806) — terminates
- [T0813](https://attack.mitre.org/techniques/T0813) — terminates
- [T0814](https://attack.mitre.org/techniques/T0814) — terminates
- [T0819](https://attack.mitre.org/techniques/T0819) — terminates
- [T0821](https://attack.mitre.org/techniques/T0821) — terminates
- [T0823](https://attack.mitre.org/techniques/T0823) — terminates
- [T0878](https://attack.mitre.org/techniques/T0878) — terminates
- [T1003.001 — LSASS Memory](/mitre/techniques/T1003-001.md) — terminates. Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).
- [T1003.002 — Security Account Manager](/mitre/techniques/T1003-002.md) — terminates. Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored.
- [T1003.004 — LSA Secrets](/mitre/techniques/T1003-004.md) — terminates. Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts.
- [T1033 — System Owner/User Discovery](/mitre/techniques/T1033.md) — terminates. Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.
- [T1053 — Scheduled Task/Job](/mitre/techniques/T1053.md) — terminates. Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.
- [T1053.005 — Scheduled Task](/mitre/techniques/T1053-005.md) — terminates. Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.
- [T1212 — Exploitation for Credential Access](/mitre/techniques/T1212.md) — terminates. Adversaries may exploit software vulnerabilities in an attempt to collect credentials.
- [T1505.002 — Transport Agent](/mitre/techniques/T1505-002.md) — terminates. Adversaries may abuse Microsoft transport agents to establish persistent access to systems.
- [T1505.003 — Web Shell](/mitre/techniques/T1505-003.md) — terminates. Adversaries may backdoor web servers with web shells to establish persistent access to systems.
- [T1546.007 — Netsh Helper DLL](/mitre/techniques/T1546-007.md) — terminates. Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs.
- [T1550 — Use Alternate Authentication Material](/mitre/techniques/T1550.md) — terminates. Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.
- [T1556 — Modify Authentication Process](/mitre/techniques/T1556.md) — terminates. Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.
- [T1562.001 — Disable or Modify Tools](/mitre/techniques/T1562-001.md) — terminates. Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities.
- [T1621 — Multi-Factor Authentication Request Generation](/mitre/techniques/T1621.md) — terminates. Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
