# CAPEC-216: Communication Channel Manipulation

<a id="capec-216"></a>

Abstraction: Meta  
Status: Stable  

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

## Related CWE (1)

- [CWE-306: Missing Authentication for Critical Functionality](https://cwe.mitre.org/data/definitions/306.html): The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.

## Prerequisites

- The target application must leverage an open communications channel.
- The channel on which the target communicates must be vulnerable to interception (e.g., adversary in the middle attack - CAPEC-94).

## Consequences

- Integrity / Read Data, Modify Data, Other
- Confidentiality / Read Data

## Mitigations

- Encrypt all sensitive communications using properly-configured cryptography.
- Design the communication system such that it associates proper authentication/authorization with each channel/message.

## Related pages

- [CAPEC-12: Choosing Message Identifier](/mitre/capec/CAPEC-12.md), also related to CWE-306
- [CAPEC-36: Using Unpublished Interfaces or Functionality](/mitre/capec/CAPEC-36.md), also related to CWE-306
- [CAPEC-62: Cross Site Request Forgery](/mitre/capec/CAPEC-62.md), also related to CWE-306
- [CAPEC-166: Force the System to Reset Values](/mitre/capec/CAPEC-166.md), also related to CWE-306
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
