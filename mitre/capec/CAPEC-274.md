# CAPEC-274: HTTP Verb Tampering

<a id="capec-274"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

An attacker modifies the HTTP Verb (e.g. GET, PUT, TRACE, etc.) in order to bypass access restrictions. Some web environments allow administrators to restrict access based on the HTTP Verb used with requests. However, attackers can often provide a different HTTP Verb, or even provide a random string as a verb in order to bypass these protections. This allows the attacker to access data that should otherwise be protected.

## Related CWE (2)

- [CWE-302: Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html): The authentication scheme or implementation uses key data elements that are assumed to be immutable, but can be controlled or modified by the attacker.
- [CWE-654: Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html): A protection mechanism relies exclusively, or to a large extent, on the evaluation of a single condition or the integrity of a single object or entity in order to make a decision about granting access to restricted resources or functionality.

## Prerequisites

- The targeted system must attempt to filter access based on the HTTP verb used in requests.

## Mitigations

- Design: Ensure that only legitimate HTTP verbs are allowed.
- Design: Do not use HTTP verbs as factors in access decisions.

## Related pages

- [CAPEC-10: Buffer Overflow via Environment Variables](/mitre/capec/CAPEC-10.md), also related to CWE-302
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-302
- [CAPEC-21: Exploitation of Trusted Identifiers](/mitre/capec/CAPEC-21.md), also related to CWE-302
- [CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies](/mitre/capec/CAPEC-31.md), also related to CWE-302
- [CAPEC-39: Manipulating Opaque Client-based Data Tokens](/mitre/capec/CAPEC-39.md), also related to CWE-302
- [CAPEC-45: Buffer Overflow via Symbolic Links](/mitre/capec/CAPEC-45.md), also related to CWE-302
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
