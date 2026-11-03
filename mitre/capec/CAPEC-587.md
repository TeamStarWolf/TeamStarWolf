# CAPEC-587: Cross Frame Scripting (XFS)

<a id="capec-587"></a>

Abstraction: Detailed  
Typical severity: High  
Status: Draft  

This attack pattern combines malicious Javascript and a legitimate webpage loaded into a concealed iframe. The malicious Javascript is then able to interact with a legitimate webpage in a manner that is unknown to the user. This attack usually leverages some element of social engineering in that an attacker must convinces a user to visit a web page that the attacker controls.

## Related CWE (1)

- [CWE-1021: Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html): The web application does not restrict or incorrectly restricts frame objects or UI layers that belong to another application or domain.

## Prerequisites

- The user's browser must have vulnerabilities in its implementation of the same-origin policy. It allows certain data in a loaded page to originate from different servers/domains.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Avoid clicking on untrusted links.
- Employ techniques such as frame busting, which is a method by which developers aim to prevent their site being loaded within a frame.

## Related pages

- [CAPEC-103: Clickjacking](/mitre/capec/CAPEC-103.md), also related to CWE-1021
- [CAPEC-181: Flash File Overlay](/mitre/capec/CAPEC-181.md), also related to CWE-1021
- [CAPEC-222: iFrame Overlay](/mitre/capec/CAPEC-222.md), also related to CWE-1021
- [CAPEC-504: Task Impersonation](/mitre/capec/CAPEC-504.md), also related to CWE-1021
- [CAPEC-506: Tapjacking](/mitre/capec/CAPEC-506.md), also related to CWE-1021
- [CAPEC-654: Credential Prompt Impersonation](/mitre/capec/CAPEC-654.md), also related to CWE-1021
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
