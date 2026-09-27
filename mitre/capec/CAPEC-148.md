# CAPEC-148 — Content Spoofing

<a id="capec-148"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary's content instead of the owner's content. However, any content can be spoofed, including the conten

## Mapped ATT&CK techniques (1)

- [T1491](/mitre/techniques/T1491.md)

## Related CWE (1)

[CWE-345](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must provide content but fail to adequately protect it against modification.The adversary must have the means to alter data to which they are not authorized. If the content is to be modif


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
