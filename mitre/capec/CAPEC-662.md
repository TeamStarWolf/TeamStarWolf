# CAPEC-662 — Adversary in the Browser (AiTB)

<a id="capec-662"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Stable  

An adversary exploits security vulnerabilities or inherent functionalities of a web browser, in order to manipulate traffic between two endpoints.

## Mapped ATT&CK techniques (1)

- [T1185 — Browser Session Hijacking](/mitre/techniques/T1185.md)

## Related CWE (2)

- [CWE-300 — Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)
- [CWE-494 — Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

## Prerequisites

- The adversary must install or convince a user to install a Trojan.
- There are two components communicating with each other.
- An attacker is able to identify the nature and mechanism of communication

## Skills required

- Tricking the victim into installing the Trojan is often the most difficult aspect of this attack. Afterwards, the remainder of this attack is

## Mitigations

- Ensure software and applications are only downloaded from legitimate and reputable sources, in addition to conducting integrity checks on the downloaded component.
- Leverage anti-malware tools, which can detect Trojan Horse malware.
- Use strong, ou

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
