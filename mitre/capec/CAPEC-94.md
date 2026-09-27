# CAPEC-94 — Adversary in the Middle (AiTM)

<a id="capec-94"></a>

**Abstraction:** Meta  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Stable  

An adversary targets the communication between two components (typically client and server), in order to alter or obtain data from transactions. A general approach entails the adversary placing themself within the communication channel between the two components.

## Mapped ATT&CK techniques (1)

- [T1557 — Adversary-in-the-Middle](/mitre/techniques/T1557.md) — Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as Network Sniffing, Transmitted Data…

## Related CWE (5)

- [CWE-300 — Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html) — The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the integrity of the channel, in a way that allows the channel to be accessed or…
- [CWE-290 — Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html) — This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.
- [CWE-593 — Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created](https://cwe.mitre.org/data/definitions/593.html) — The product modifies the SSL context after connection creation has begun.
- [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html) — When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.
- [CWE-294 — Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html) — A capture-replay flaw exists when the design of the product makes it possible for a malicious user to sniff network traffic and bypass authentication by replaying it to the server in question to the same effect as the…

## Prerequisites

- There are two components communicating with each other.
- An attacker is able to identify the nature and mechanism of communication between the two target components.
- An attacker can eavesdrop on the communication between the target components.
- Strong mutual authentication is not used between the two target components yielding opportunity for attacker interposition.
- The communication occurs in clear (not encrypted) or with insufficient and spoofable encryption.

## Skills required

- [Medium] This attack can get sophisticated since the attack may use cryptography.

## Consequences

- Integrity / Modify Data
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality / Read Data

## Mitigations

- Ensure Public Keys are signed by a Certificate Authority
- Encrypt communications using cryptography (e.g., SSL/TLS)
- Use Strong mutual authentication to always fully authenticate both ends of any communications channel.
- Exchange public keys using a secure channel

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
