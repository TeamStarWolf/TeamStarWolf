# CAPEC-154: Resource Location Spoofing

<a id="capec-154"></a>

Abstraction: Meta  
Typical severity: Medium  
Likelihood: Medium  
Status: Stable  

An adversary deceives an application or user and convinces them to request a resource from an unintended location. By spoofing the location, the adversary can cause an alternate resource to be used, often one that the adversary controls and can be used to help them achieve their malicious goals.

## Related CWE (1)

- [CWE-451: User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html): The user interface (UI) does not properly represent critical information to the user, allowing the information - or its source - to be obscured or spoofed.

## Prerequisites

- None. All applications rely on file paths and therefore, in theory, they or their resources could be affected by this type of attack.

## Consequences

- Authorization / Execute Unauthorized Commands

## Mitigations

- Monitor network activity to detect any anomalous or unauthorized communication exchanges.

## Related pages

- [CAPEC-98: Phishing](/mitre/capec/CAPEC-98.md), also related to CWE-451
- [CAPEC-163: Spear Phishing](/mitre/capec/CAPEC-163.md), also related to CWE-451
- [CAPEC-164: Mobile Phishing](/mitre/capec/CAPEC-164.md), also related to CWE-451
- [CAPEC-173: Action Spoofing](/mitre/capec/CAPEC-173.md), also related to CWE-451
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/CHROME_ISOLATED_WEB_APPS_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
