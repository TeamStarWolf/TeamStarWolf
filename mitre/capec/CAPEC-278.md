# CAPEC-278: Web Services Protocol Manipulation

<a id="capec-278"></a>

Abstraction: Standard  
Status: Draft  

An adversary manipulates a web service related protocol to cause a web application or service to react differently than intended. This can either be performed through the manipulation of call parameters to include unexpected values, or by changing the called function to one that should normally be restricted or limited. By leveraging this pattern of attack, the adversary is able to gain access to data or resources normally restricted, or to cause the application or service to crash.

## Related CWE (1)

- [CWE-707: Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html): The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are met before being read from an upstream component or sent to a downstream component.

## Prerequisites

- The targeted application or service must rely on web service protocols in such a way that malicious manipulation of them can alter functionality.

## Mitigations

- Design: Range, size and value and consistency verification for any arguments supplied to applications and services from external sources and devise appropriate error response.
- Design: Ensure that function calls that should not be called by an unprivileged user are not accessible to them.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
