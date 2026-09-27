# CAPEC-457 — USB Memory Attacks

<a id="capec-457"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary loads malicious code onto a USB memory stick in order to infect any system which the device is plugged in to. USB drives present a significant security risk for business and government agencies. Given the ability to integrate wireless functionality into a USB stick, it is possible to design malware that not only steals confidential data, but sniffs the network, or monitor keystrokes,

## Mapped ATT&CK techniques (2)

- [T1091 — Replication Through Removable Media](/mitre/techniques/T1091.md)
- [T1092 — Communication Through Removable Media](/mitre/techniques/T1092.md)

## Related CWE (1)

- [CWE-1299 — Missing Protection Mechanism for Alternate Hardware Interface](https://cwe.mitre.org/data/definitions/1299.html)

## Prerequisites

- Some level of physical access to the device being attacked.
- Information pertaining to the target organization on how to best execute a USB Drop Attack.

## Mitigations

- Ensure that proper, physical system access is regulated to prevent an adversary from physically connecting a malicious USB device themself.
- Use anti-virus and anti-malware tools which can prevent malware from executing if it finds its way onto a t

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
