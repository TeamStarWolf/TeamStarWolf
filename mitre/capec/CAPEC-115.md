# CAPEC-115: Authentication Bypass

<a id="capec-115"></a>

Abstraction: Meta  
Typical severity: Medium  
Status: Draft  

An attacker gains access to application, service, or device with the privileges of an authorized or privileged user by evading or circumventing an authentication mechanism. The attacker is therefore able to access protected data without authentication ever having taken place.

## Mapped ATT&CK techniques (1)

- [T1548: Abuse Elevation Control Mechanism](/mitre/techniques/T1548.md): Adversaries may circumvent mechanisms designed to control privilege elevation to gain higher-level permissions.

## Related CWE (1)

- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html): When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Prerequisites

- An authentication mechanism or subsystem implementing some form of authentication such as passwords, digest authentication, security certificates, etc.

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
