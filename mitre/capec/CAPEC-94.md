# CAPEC-94 — Adversary in the Middle (AiTM)

<a id="capec-94"></a>

**Abstraction:** Meta  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Stable  

An adversary targets the communication between two components (typically client and server), in order to alter or obtain data from transactions. A general approach entails the adversary placing themself within the communication channel between the two components.

## Mapped ATT&CK techniques (1)

- [T1557 — Adversary-in-the-Middle](/mitre/techniques/T1557.md)

## Related CWE (5)

- [CWE-300 — Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)
- [CWE-290 — Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- [CWE-593 — Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created](https://cwe.mitre.org/data/definitions/593.html)
- [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-294 — Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

## Prerequisites

- There are two components communicating with each other.
- An attacker is able to identify the nature and mechanism of communication between the two target components.
- An attacker can eavesdrop on th

## Skills required

- This attack can get sophisticated since the attack may use cryptography.:LEVEL:Medium

## Mitigations

- Ensure Public Keys are signed by a Certificate Authority
- Encrypt communications using cryptography (e.g., SSL/TLS)
- Use Strong mutual authentication to always fully authenticate both ends of any communications channel.
- Exchange public keys using

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
