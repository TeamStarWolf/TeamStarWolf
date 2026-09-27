# CAPEC-182 — Flash Injection

<a id="capec-182"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** High

An attacker tricks a victim to execute malicious flash content that executes commands or makes flash calls specified by the attacker. One example of this attack is cross-site flashing, an attacker controlled parameter to a reference call loads from content specified by the attacker.

## Related CWE (3)

[CWE-20](/CWE_REFERENCE.md) [CWE-184](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must be capable of running Flash applications. In some cases, the victim must follow an attacker-supplied link.::

**Skills required:** ::SKILL:The attacker needs to have knowledge of Flash, especially how to insert content the executes commands.:LEVEL:Medium::

**Mitigations:** ::Implementation: remove sensitive information such as user name and password in the SWF file.::Implementation: use validation on both client and server side.::Implementation: remove debug information.::Implementation: use SSL when loading external d


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
