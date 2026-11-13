# CAPEC-88: OS Command Injection

<a id="capec-88"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: High  
Status: Draft  

In this type of an attack, an adversary injects operating system commands into existing application functions. An application that uses untrusted input to build command strings is vulnerable. An adversary can leverage OS command injection in an application to elevate privileges, execute arbitrary commands and compromise the underlying operating system.

## Related CWE (4)

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html): The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command before it is sent to a downstream component.
- [CWE-88: Improper Neutralization of Argument Delimiters in a Command](https://cwe.mitre.org/data/definitions/88.html): The product constructs a string for a command to be executed by a separate component in another control sphere, but it does not properly delimit the intended arguments, options, or switches within that command string.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html): The product compares two entities in a security-relevant context, but the comparison is incorrect.

## Prerequisites

- User controllable input used as part of commands to the underlying operating system.

## Skills required

- [High] The attacker needs to have knowledge of not only the application to exploit but also the exact nature of commands that pertain to the target operating system. This may involve, though not always, knowledge of specific assembly commands for the platform.

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges, Bypass Protection Mechanism
- Confidentiality / Read Data

## Mitigations

- Use language APIs rather than relying on passing data to the operating system shell or command line. Doing so ensures that the available protection mechanisms in the language are intact and applicable.
- Filter all incoming data to escape or remove characters or strings that can be potentially misinterpreted as operating system or shell commands
- All application processes should be run with the minimal privileges required. Also, processes must shed privileges as soon as they no longer require them.

## Related pages

- [CAPEC-43: Exploiting Multiple Input Interpretation Layers](/mitre/capec/CAPEC-43.md), also related to CWE-20, CWE-78 and 1 more
- [CAPEC-6: Argument Injection](/mitre/capec/CAPEC-6.md), also related to CWE-78 and CWE-697
- [CAPEC-15: Command Delimiters](/mitre/capec/CAPEC-15.md), also related to CWE-78 and CWE-697
- [CAPEC-41: Using Meta-characters in E-mail Headers to Inject Malicious Payloads](/mitre/capec/CAPEC-41.md), also related to CWE-88 and CWE-697
- [CAPEC-108: Command Line Execution through SQL Injection](/mitre/capec/CAPEC-108.md), also related to CWE-20 and CWE-78
- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-20 and CWE-697
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Collabora Built-in CODE Server (richdocumentscode), CVE-2026-110447: Lab-Verified Exposure and Fix](/case-studies/NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Refrigeration-Controller Attacks on European Supermarkets and Blood Services, 2026: A Case Study](/case-studies/EUROPEAN_REFRIGERATION_ATTACKS_2026.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The BeyondTrust Remote Support and PRA Command Injection of 2026 (CVE-2026-1731): A Case Study](/case-studies/BEYONDTRUST_REMOTE_SUPPORT_CVE_2026_1731.md)
- [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md)
- [The Year 1994 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1994.md)
- [The Year 1996 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1996.md)
- [The Year 1997 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1997.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)
- [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md)
- [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md)
- [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md)
- [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)
- [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
