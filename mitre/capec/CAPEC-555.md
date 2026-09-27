# CAPEC-555 — Remote Services with Stolen Credentials

<a id="capec-555"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** 

This pattern of attack involves an adversary that uses stolen credentials to leverage remote services such as RDP, telnet, SSH, and VNC to log into a system. Once access is gained, any number of malicious activities could be performed.

## Mapped ATT&CK techniques (3)

- [T1021](/mitre/techniques/T1021.md)
- [T1114.002](/mitre/techniques/T1114-002.md)
- [T1133](/mitre/techniques/T1133.md)

## Related CWE (7)

[CWE-522](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md) [CWE-309](/CWE_REFERENCE.md) [CWE-294](/CWE_REFERENCE.md) [CWE-263](/CWE_REFERENCE.md) [CWE-262](/CWE_REFERENCE.md) [CWE-521](/CWE_REFERENCE.md)

**Mitigations:** ::Disable RDP, telnet, SSH and enable firewall rules to block such traffic. Limit users and accounts that have remote interactive login access. Remove the Local Administrators group from the list of groups allowed to login through RDP. Limit remote u


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
