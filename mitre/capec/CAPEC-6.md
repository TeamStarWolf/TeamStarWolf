# CAPEC-6: Argument Injection

<a id="capec-6"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: High  
Status: Draft  

An attacker changes the behavior or state of a targeted application through injecting data or command syntax through the targets use of non-validated and non-filtered arguments of exposed services or methods.

## Related CWE (6)

- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component](https://cwe.mitre.org/data/definitions/74.html): The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-146: Improper Neutralization of Expression/Command Delimiters](https://cwe.mitre.org/data/definitions/146.html): The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could be interpreted as expression or command delimiters when they are sent to a downstream component.
- [CWE-184: Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html): The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are not allowed by policy or otherwise require other action to neutralize before additional processing takes place, but the list is incomplete.
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html): The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command before it is sent to a downstream component.
- [CWE-185: Incorrect Regular Expression](https://cwe.mitre.org/data/definitions/185.html): The product specifies a regular expression in a way that causes data to be improperly matched or compared.
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html): The product compares two entities in a security-relevant context, but the comparison is incorrect.

## Prerequisites

- Target software fails to strip all user-supplied input of any content that could cause the shell to perform unexpected actions.
- Software must allow for unvalidated or unfiltered input to be executed on operating system shell, and, optionally, the system configuration must allow for output to be sent back to client.

## Skills required

- [Medium] The attacker has to identify injection vector, identify the operating system-specific commands, and optionally collect the output.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges
- Integrity / Modify Data
- Confidentiality / Read Data

## Mitigations

- Design: Do not program input values directly on command shell, instead treat user input as guilty until proven innocent. Build a function that takes user input and converts it to applications specific types and values, stripping or filtering out all unauthorized commands and characters in the process.
- Design: Limit program privileges, so if metacharacters or other methods circumvent program input validation routines and shell access is attained then it is not running under a privileged account. chroot jails create a sandbox for the application to execute in, making it more difficult for an attacker to elevate privilege even in the case that a compromise has occurred.
- Implementation: Implement an audit log that is written to a separate host, in the event of a compromise the audit log may be able to provide evidence and details of the compromise.

## Related pages

- [CAPEC-15: Command Delimiters](/mitre/capec/CAPEC-15.md), also related to CWE-78, CWE-146 and 3 more
- [CAPEC-43: Exploiting Multiple Input Interpretation Layers](/mitre/capec/CAPEC-43.md), also related to CWE-74, CWE-78 and 2 more
- [CAPEC-79: Using Slashes in Alternate Encoding](/mitre/capec/CAPEC-79.md), also related to CWE-74, CWE-185 and 1 more
- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-74, CWE-184 and 1 more
- [CAPEC-71: Using Unicode Encoding to Bypass Validation Logic](/mitre/capec/CAPEC-71.md), also related to CWE-74, CWE-184 and 1 more
- [CAPEC-120: Double Encoding](/mitre/capec/CAPEC-120.md), also related to CWE-74, CWE-184 and 1 more
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Year 1994 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1994.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
