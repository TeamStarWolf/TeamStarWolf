# CAPEC-581 — Security Software Footprinting

<a id="capec-581"></a>

**Abstraction:** Detailed  
**Status:** Draft  

Adversaries may attempt to get a listing of security tools that are installed on the system and their configurations. This may include security related system features (such as a built-in firewall or anti-spyware) as well as third-party security software.

## Mapped ATT&CK techniques (1)

- [T1518.001 — Security Software Discovery](/mitre/techniques/T1518-001.md)

## Mitigations

- Identify programs that may be used to acquire security tool information and block them by using a software restriction policy or tools that restrict program execution by using a process allowlist.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
