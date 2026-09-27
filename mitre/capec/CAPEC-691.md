# CAPEC-691 — Spoof Open-Source Software Metadata

<a id="capec-691"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium

An adversary spoofs open-source software metadata in an attempt to masquerade malicious software as popular, maintained, and trusted.

## Mapped ATT&CK techniques (2)

- [T1195.001](/mitre/techniques/T1195-001.md)
- [T1195.002](/mitre/techniques/T1195-002.md)

## Related CWE (1)

[CWE-494](/CWE_REFERENCE.md)

**Prerequisites:** ::Identification of a popular open-source component whose metadata is to be spoofed.::

**Skills required:** ::SKILL:Ability to spoof a variety of software metadata to convince victims the source is trusted.:LEVEL:Medium::

**Mitigations:** ::Before downloading open-source software, perform precursory metadata checks to determine the author(s), frequency of updates, when the software was last updated, and if the software is widely leveraged.::Within package managers, look for conflictin


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
