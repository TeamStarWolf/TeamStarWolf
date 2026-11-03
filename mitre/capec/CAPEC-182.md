# CAPEC-182: Flash Injection

<a id="capec-182"></a>

Abstraction: Standard  
Typical severity: Medium  
Likelihood: High  
Status: Draft  

An attacker tricks a victim to execute malicious flash content that executes commands or makes flash calls specified by the attacker. One example of this attack is cross-site flashing, an attacker controlled parameter to a reference call loads from content specified by the attacker.

## Related CWE (3)

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-184: Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html): The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are not allowed by policy or otherwise require other action to neutralize before additional processing takes place, but the list is incomplete.
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html): The product compares two entities in a security-relevant context, but the comparison is incorrect.

## Prerequisites

- The target must be capable of running Flash applications. In some cases, the victim must follow an attacker-supplied link.

## Skills required

- [Medium] The attacker needs to have knowledge of Flash, especially how to insert content the executes commands.

## Consequences

- Confidentiality / Other
- Integrity / Modify Data
- Confidentiality / Read Data
- Authorization / Execute Unauthorized Commands
- Accountability, Authentication, Authorization, Non-Repudiation / Gain Privileges
- Access Control, Authorization / Bypass Protection Mechanism

## Mitigations

- Implementation: remove sensitive information such as user name and password in the SWF file.
- Implementation: use validation on both client and server side.
- Implementation: remove debug information.
- Implementation: use SSL when loading external data
- Implementation: use crossdomain.xml file to allow the application domain to load stuff or the SWF file called by other domain.

## Related pages

- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-20, CWE-184 and 1 more
- [CAPEC-43: Exploiting Multiple Input Interpretation Layers](/mitre/capec/CAPEC-43.md), also related to CWE-20, CWE-184 and 1 more
- [CAPEC-71: Using Unicode Encoding to Bypass Validation Logic](/mitre/capec/CAPEC-71.md), also related to CWE-20, CWE-184 and 1 more
- [CAPEC-73: User-Controlled Filename](/mitre/capec/CAPEC-73.md), also related to CWE-20, CWE-184 and 1 more
- [CAPEC-120: Double Encoding](/mitre/capec/CAPEC-120.md), also related to CWE-20, CWE-184 and 1 more
- [CAPEC-6: Argument Injection](/mitre/capec/CAPEC-6.md), also related to CWE-184 and CWE-697
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
