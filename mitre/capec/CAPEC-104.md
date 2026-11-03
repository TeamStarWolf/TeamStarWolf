# CAPEC-104: Cross Zone Scripting

<a id="capec-104"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

An attacker is able to cause a victim to load content into their web-browser that bypasses security zone controls and gain access to increased privileges to execute scripting code or other web objects such as unsigned ActiveX controls or applets. This is a privilege elevation attack targeted at zone-based web-browser security.

## Related CWE (5)

- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html): The product performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses.
- [CWE-638: Not Using Complete Mediation](https://cwe.mitre.org/data/definitions/638.html): The product does not perform access checks on a resource every time the resource is accessed by an entity, which can create resultant weaknesses if that entity's rights or privileges change over time.
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html): The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-116: Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html): The product prepares a structured message for communication with another component, but encoding or escaping of the data is either missing or done incorrectly.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.

## Prerequisites

- The target must be using a zone-aware browser.

## Skills required

- [Medium] Ability to craft malicious scripts or find them elsewhere and ability to identify functionality that is running web controls in the local zone and to find an injection vector into that functionality

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- Disable script execution.
- Ensure that sufficient input validation is performed for any potentially untrusted data before it is used in any privileged context or zone
- Limit the flow of untrusted data into the privileged areas of the system that run in the higher trust zone
- Limit the sites that are being added to the local machine zone and restrict the privileges of the code running in that zone to the bare minimum
- Ensure proper HTML output encoding before writing user supplied data to the page

## Related pages

- [CAPEC-73: User-Controlled Filename](/mitre/capec/CAPEC-73.md), also related to CWE-20 and CWE-116
- [CAPEC-81: Web Server Logs Tampering](/mitre/capec/CAPEC-81.md), also related to CWE-20 and CWE-116
- [CAPEC-85: AJAX Footprinting](/mitre/capec/CAPEC-85.md), also related to CWE-20 and CWE-116
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-20 and CWE-285
- [CAPEC-45: Buffer Overflow via Symbolic Links](/mitre/capec/CAPEC-45.md), also related to CWE-20 and CWE-285
- [CAPEC-69: Target Programs with Elevated Privileges](/mitre/capec/CAPEC-69.md), also related to CWE-250
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
