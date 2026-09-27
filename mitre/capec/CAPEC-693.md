# CAPEC-693 — StarJacking

<a id="capec-693"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An adversary spoofs software popularity metadata to deceive users into believing that a maliciously provided package is widely used and originates from a trusted source.

## Related CWE (1)

[CWE-494](/CWE_REFERENCE.md)

**Prerequisites:** ::Identification of a popular open-source package whose popularity metadata is to be used for the malicious package.::

**Skills required:** ::SKILL:Ability to provide a package to a package manager and associate a popular package's source code repository URL.:LEVEL:Low::

**Mitigations:** ::Before downloading open-source packages, perform precursory metadata checks to determine the author(s), frequency of updates, when the software was last updated, and if the software is widely leveraged.::Look for conflicting or non-unique repositor


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
