# CAPEC-94 — Adversary in the Middle (AiTM)

<a id="capec-94"></a>

**Abstraction:** Meta  
**Typical severity:** Very High  
**Likelihood:** High

An adversary targets the communication between two components (typically client and server), in order to alter or obtain data from transactions. A general approach entails the adversary placing themself within the communication channel between the two components.

## Mapped ATT&CK techniques (1)

- [T1557](/mitre/techniques/T1557.md)

## Related CWE (5)

[CWE-300](/CWE_REFERENCE.md) [CWE-290](/CWE_REFERENCE.md) [CWE-593](/CWE_REFERENCE.md) [CWE-287](/CWE_REFERENCE.md) [CWE-294](/CWE_REFERENCE.md)

**Prerequisites:** ::There are two components communicating with each other.::An attacker is able to identify the nature and mechanism of communication between the two target components.::An attacker can eavesdrop on th

**Skills required:** ::SKILL:This attack can get sophisticated since the attack may use cryptography.:LEVEL:Medium::

**Mitigations:** ::Ensure Public Keys are signed by a Certificate Authority::Encrypt communications using cryptography (e.g., SSL/TLS)::Use Strong mutual authentication to always fully authenticate both ends of any communications channel.::Exchange public keys using 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
