# CAPEC-133: Try All Common Switches

<a id="capec-133"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

An attacker attempts to invoke all common switches and options in the target application for the purpose of discovering weaknesses in the target. For example, in some applications, adding a --debug switch causes debugging information to be displayed, which can sometimes reveal sensitive processing or configuration information to an attacker. This attack differs from other forms of API abuse in that the attacker is indiscriminately attempting to invoke options in the hope that one of them will work rather than specifically targeting a known option. Nonetheless, even if the attacker is familiar with the published options of a targeted application this attack method may still be fruitful as it might discover unpublicized functionality.

## Related CWE (1)

- [CWE-912: Hidden Functionality](https://cwe.mitre.org/data/definitions/912.html): The product contains functionality that is not documented, not part of the specification, and not accessible through an interface or command sequence that is obvious to the product's users or administrators.

## Prerequisites

- The attacker must be able to control the options or switches sent to the target.

## Mitigations

- Design: Minimize switch and option functionality to only that necessary for correct function of the command.
- Implementation: Remove all debug and testing options from production code.

## Related pages

- [CAPEC-190: Reverse Engineer an Executable to Expose Assumed Hidden Functionality](/mitre/capec/CAPEC-190.md), also related to CWE-912
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
