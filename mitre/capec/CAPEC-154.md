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

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
