# CAPEC-697 — DHCP Spoofing

<a id="capec-697"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low

An adversary masquerades as a legitimate Dynamic Host Configuration Protocol (DHCP) server by spoofing DHCP traffic, with the goal of redirecting network traffic or denying service to DHCP.

## Mapped ATT&CK techniques (1)

- [T1557.003](/mitre/techniques/T1557-003.md)

## Related CWE (1)

[CWE-923](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary must have access to a machine within the target LAN which can send DHCP offers to the target.::

**Skills required:** ::SKILL:The adversary must identify potential targets for DHCP Spoofing and craft network configurations to obtain the desired results.:LEVEL:Medium::

**Mitigations:** ::Design: MAC-Forced Forwarding::Implementation: Port Security and DHCP snooping::Implementation: Network-based Intrusion Detection Systems::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
