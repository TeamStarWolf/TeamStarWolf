# CAPEC-690: Metadata Spoofing

<a id="capec-690"></a>

Abstraction: Meta  
Typical severity: High  
Likelihood: Medium  
Status: Stable  
OpenCRE: [CAPEC-690](https://opencre.org/smartlink/standard/CAPEC/690)  

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

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
