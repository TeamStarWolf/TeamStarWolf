# CAPEC-701 — Browser in the Middle (BiTM)

<a id="capec-701"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium

An adversary exploits the inherent functionalities of a web browser, in order to establish an unnoticed remote desktop connection in the victim's browser to the adversary's system. The adversary must deploy a web client with a remote desktop session that the victim can access.

## Related CWE (2)

[CWE-294](/CWE_REFERENCE.md) [CWE-345](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary must create a convincing web client to establish the connection. The victim then needs to be lured onto the adversary's webpage. In addition, the victim's machine must not use local au

**Skills required:** ::SKILL::LEVEL:Medium::

**Mitigations:** ::Implementation: Use strong, mutual authentication to fully authenticate with both ends of any communications channel::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
