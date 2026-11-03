# CAPEC-166: Force the System to Reset Values

<a id="capec-166"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

An attacker forces the target into a previous state in order to leverage potential weaknesses in the target dependent upon a prior configuration or state-dependent factors. Even in cases where an attacker may not be able to directly control the configuration of the targeted application, they may be able to reset the configuration to a prior state since many applications implement reset functions.

## Related CWE (3)

- [CWE-306: Missing Authentication for Critical Functionality](https://cwe.mitre.org/data/definitions/306.html): The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.
- [CWE-1221: Incorrect Register Defaults or Module Parameters](https://cwe.mitre.org/data/definitions/1221.html): Hardware description language code incorrectly defines register defaults or hardware Intellectual Property (IP) parameters to insecure values.
- [CWE-1232: Improper Lock Behavior After Power State Transition](https://cwe.mitre.org/data/definitions/1232.html): Register lock bit protection disables changes to system configuration once the bit is set.

## Prerequisites

- The targeted application must have a reset function that returns the configuration of the application to an earlier state.
- The reset functionality must be inadequately protected against use.

## Related pages

- [CAPEC-12: Choosing Message Identifier](/mitre/capec/CAPEC-12.md), also related to CWE-306
- [CAPEC-36: Using Unpublished Interfaces or Functionality](/mitre/capec/CAPEC-36.md), also related to CWE-306
- [CAPEC-62: Cross Site Request Forgery](/mitre/capec/CAPEC-62.md), also related to CWE-306
- [CAPEC-216: Communication Channel Manipulation](/mitre/capec/CAPEC-216.md), also related to CWE-306
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
