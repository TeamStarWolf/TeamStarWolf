# CAPEC-568: Capture Credentials via Keylogger

<a id="capec-568"></a>

Abstraction: Detailed  
Typical severity: High  
Status: Draft  

An adversary deploys a keylogger in an effort to obtain credentials directly from a system's user. After capturing all the keystrokes made by a user, the adversary can analyze the data and determine which string are likely to be passwords or other credential related information.

## Mapped ATT&CK techniques (1)

- [T1056.001: Keylogging](/mitre/techniques/T1056-001.md): Adversaries may log user keystrokes to intercept credentials as the user types them.

## Prerequisites

- The ability to install the keylogger, either in person or remote.

## Mitigations

- Strong physical security can help reduce the ability of an adversary to install a keylogger.

## Related pages

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
