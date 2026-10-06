# CAPEC-4: Using Alternative IP Address Encodings

<a id="capec-4"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

This attack relies on the adversary using unexpected formats for representing IP addresses. Networked applications may expect network location information in a specific format, such as fully qualified domains names (FQDNs), URL, IP address, or IP Address ranges. If the location information is not validated against a variety of different possible encodings and formats, the adversary can use an alternate format to bypass application access control.

## Related CWE (2)

- [CWE-291: Reliance on IP Address for Authentication](https://cwe.mitre.org/data/definitions/291.html): The product uses an IP address for authentication.
- [CWE-173: Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html): The product does not properly handle when an input uses an alternate encoding that is valid for the control sphere to which the input is being sent.

## Prerequisites

- The target software must fail to anticipate all of the possible valid encodings of an IP/web address.
- The adversary must have the ability to communicate with the server.

## Skills required

- [Low] The adversary has only to try IP address format combinations.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Design: Default deny access control policies
- Design: Input validation routines should check and enforce both input data types and content against a positive specification. In regards to IP addresses, this should include the authorized manner for the application to represent IP addresses and not accept user specified IP addresses and IP address formats (such as ranges)
- Implementation: Perform input validation for all remote content.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
