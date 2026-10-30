# CAPEC-200: Removal of filters: Input filters, output filters, data masking

<a id="capec-200"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  
OpenCRE: [CAPEC-200](https://opencre.org/smartlink/standard/CAPEC/200)  

An attacker removes or disables filtering mechanisms on the target application. Input filters prevent invalid data from being sent to an application (for example, overly large inputs that might cause a buffer overflow or other malformed inputs that may not be correctly handled by an application). Input filters might also be designed to constrained executable content.

## Prerequisites

- The target application must utilize some sort of filtering mechanism (input, output, or data masking).

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
