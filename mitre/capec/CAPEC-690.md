# CAPEC-690 — Metadata Spoofing

<a id="capec-690"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Medium

An adversary alters the metadata of a resource (e.g., file, directory, repository, etc.) to present a malicious resource as legitimate/credible.

**Prerequisites:** ::Identification of a resource whose metadata is to be spoofed::

**Skills required:** ::SKILL:Ability to spoof a variety of metadata to convince victims the source is trusted:LEVEL:Medium::

**Mitigations:** ::Validate metadata of resources such as authors, timestamps, and statistics.::Confirm the pedigree of open source packages and ensure the code being downloaded does not originate from another source.::Even if the metadata is properly checked and a u


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
