# CAPEC-555 — Remote Services with Stolen Credentials

<a id="capec-555"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Status:** Stable  

This pattern of attack involves an adversary that uses stolen credentials to leverage remote services such as RDP, telnet, SSH, and VNC to log into a system. Once access is gained, any number of malicious activities could be performed.

## Mapped ATT&CK techniques (3)

- [T1021 — Remote Services](/mitre/techniques/T1021.md)
- [T1114.002 — Remote Email Collection](/mitre/techniques/T1114-002.md)
- [T1133 — External Remote Services](/mitre/techniques/T1133.md)

## Related CWE (7)

- [CWE-522 — Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)
- [CWE-294 — Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html)
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html)
- [CWE-521 — Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

## Mitigations

- Disable RDP, telnet, SSH and enable firewall rules to block such traffic. Limit users and accounts that have remote interactive login access. Remove the Local Administrators group from the list of groups allowed to login through RDP. Limit remote u

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
