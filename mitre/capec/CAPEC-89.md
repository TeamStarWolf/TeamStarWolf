# CAPEC-89 — Pharming

<a id="capec-89"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

A pharming attack occurs when the victim is fooled into entering sensitive data into supposedly trusted locations, such as an online bank site or a trading platform. An attacker can impersonate these supposedly trusted sites and have the victim be directed to their site rather than the originally intended one. Pharming does not require script injection or clicking on malicious links for the attack

## Related CWE (2)

[CWE-346](/CWE_REFERENCE.md) [CWE-350](/CWE_REFERENCE.md)

**Prerequisites:** ::Vulnerable DNS software or improperly protected hosts file or router that can be poisoned::A website that handles sensitive information but does not use a secure connection and a certificate that is

**Skills required:** ::SKILL:The attacker needs to be able to poison the resolver - DNS entries or local hosts file or router entry pointing to a trusted DNS server - in o

**Mitigations:** ::All sensitive information must be handled over a secure connection.::Known vulnerabilities in DNS or router software or in operating systems must be patched as soon as a fix has been released and tested.::End users must ensure that they provide sen


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
