# CAPEC-234: Hijacking a privileged process

<a id="capec-234"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

An adversary gains control of a process that is assigned elevated privileges in order to execute arbitrary code with those privileges. Some processes are assigned elevated privileges on an operating system, usually through association with a particular user, group, or role. If an attacker can hijack this process, they will be able to assume its level of privilege in order to execute their own code.

## Related CWE (2)

- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html): The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.
- [CWE-648: Incorrect Use of Privileged APIs](https://cwe.mitre.org/data/definitions/648.html): The product does not conform to the API requirements for a function call that requires extra privileges.

## Prerequisites

- The targeted process or operating system must contain a bug that allows attackers to hijack the targeted process.

## Related pages

- [CAPEC-107: Cross Site Tracing](/mitre/capec/CAPEC-107.md), also related to CWE-648
- [CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs](/mitre/capec/CAPEC-1.md), also related to CWE-732
- [CAPEC-17: Using Malicious Files](/mitre/capec/CAPEC-17.md), also related to CWE-732
- [CAPEC-60: Reusing Session IDs (aka Session Replay)](/mitre/capec/CAPEC-60.md), also related to CWE-732
- [CAPEC-61: Session Fixation](/mitre/capec/CAPEC-61.md), also related to CWE-732
- [CAPEC-62: Cross Site Request Forgery](/mitre/capec/CAPEC-62.md), also related to CWE-732
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
