# CAPEC-690: Metadata Spoofing

<a id="capec-690"></a>

Abstraction: Meta  
Typical severity: High  
Likelihood: Medium  
Status: Stable  

An adversary alters the metadata of a resource (e.g., file, directory, repository, etc.) to present a malicious resource as legitimate/credible.

## Prerequisites

- Identification of a resource whose metadata is to be spoofed

## Skills required

- [Medium] Ability to spoof a variety of metadata to convince victims the source is trusted

## Consequences

- Integrity / Modify Data
- Accountability / Hide Activities
- Access Control, Authorization / Execute Unauthorized Commands

## Mitigations

- Validate metadata of resources such as authors, timestamps, and statistics.
- Confirm the pedigree of open source packages and ensure the code being downloaded does not originate from another source.
- Even if the metadata is properly checked and a user believes it to be legitimate, there may still be a chance that they've been duped. Therefore, leverage automated testing techniques to determine where malicious areas of the code may exist.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
