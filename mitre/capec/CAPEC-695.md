# CAPEC-695 — Repo Jacking

<a id="capec-695"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An adversary takes advantage of the redirect property of directly linked Version Control System (VCS) repositories to trick users into incorporating malicious code into their applications.

## Mapped ATT&CK techniques (1)

- [T1195.001](/mitre/techniques/T1195-001.md)

## Related CWE (2)

[CWE-494](/CWE_REFERENCE.md) [CWE-829](/CWE_REFERENCE.md)

**Prerequisites:** ::Identification of a popular repository that may be directly referenced in numerous software applications::A repository owner/maintainer who has recently changed their username or deleted their accou

**Skills required:** ::SKILL:Ability to create an account on a VCS hosting site and recreate an existing directory structure.:LEVEL:Low::SKILL:Ability to create malware th

**Mitigations:** ::Leverage dedicated package managers instead of directly linking to VCS repositories.::Utilize version pinning and lock files to prevent use of maliciously modified repositories.::Implement vendoring (i.e., including third-party dependencies locally


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
