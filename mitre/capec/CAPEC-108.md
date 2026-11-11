# CAPEC-108: Command Line Execution through SQL Injection

<a id="capec-108"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: Low  
Status: Draft  

An attacker uses standard SQL injection methods to inject data into the command line for execution. This could be done directly through misuse of directives such as MSSQL_xp_cmdshell or indirectly through injection of data into the database that would be interpreted as shell commands. Sometime later, an unscrupulous backend application (or could be part of the functionality of the same application) fetches the injected data stored in the database and uses this data as command line arguments without performing proper validation. The malicious data escapes that data plane by spawning new commands to be executed on the host.

## Related CWE (5)

- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html): The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.
- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component](https://cwe.mitre.org/data/definitions/74.html): The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html): The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command before it is sent to a downstream component.
- [CWE-114: Process Control](https://cwe.mitre.org/data/definitions/114.html): Executing commands or loading libraries from an untrusted source or in an untrusted environment can cause an application to execute malicious commands (and payloads) on behalf of an attacker.

## Prerequisites

- The application does not properly validate data before storing in the database
- Backend application implicitly trusts the data stored in the database
- Malicious data is used on the backend as a command line argument

## Skills required

- [High] The attacker most likely has to be familiar with the internal functionality of the system to launch this attack. Without that knowledge, there are not many feedback mechanisms to give an attacker the indication of how to perform command injection or whether the attack is succeeding.

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Availability / Unreliable Execution
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- Disable MSSQL xp_cmdshell directive on the database
- Properly validate the data (syntactically and semantically) before writing it to the database.
- Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

## Related pages

- [CAPEC-43: Exploiting Multiple Input Interpretation Layers](/mitre/capec/CAPEC-43.md), also related to CWE-20, CWE-74 and 1 more
- [CAPEC-7: Blind SQL Injection](/mitre/capec/CAPEC-7.md), also related to CWE-20, CWE-74 and 1 more
- [CAPEC-6: Argument Injection](/mitre/capec/CAPEC-6.md), also related to CWE-74 and CWE-78
- [CAPEC-88: OS Command Injection](/mitre/capec/CAPEC-88.md), also related to CWE-20 and CWE-78
- [CAPEC-109: Object Relational Mapping Injection](/mitre/capec/CAPEC-109.md), also related to CWE-20 and CWE-89
- [CAPEC-110: SQL Injection through SOAP Parameter Tampering](/mitre/capec/CAPEC-110.md), also related to CWE-20 and CWE-89
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
