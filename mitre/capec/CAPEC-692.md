# CAPEC-692 — Spoof Version Control System Commit Metadata

<a id="capec-692"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An adversary spoofs metadata pertaining to a Version Control System (VCS) (e.g., Git) repository's commits to deceive users into believing that the maliciously provided software is frequently maintained and originates from a trusted source.

## Related CWE (1)

[CWE-494](/CWE_REFERENCE.md)

**Prerequisites:** ::Identification of a popular open-source repository whose metadata is to be spoofed.::

**Skills required:** ::SKILL:Ability to spoof a variety of repository metadata to convince victims the source is trusted.:LEVEL:Medium::

**Mitigations:** ::Before downloading open-source software, perform precursory metadata checks to determine the author(s), frequency of updates, when the software was last updated, and if the software is widely leveraged.::Reference vulnerability databases to determi


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
