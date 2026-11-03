# CAPEC-194: Fake the Source of Data

<a id="capec-194"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Stable  

An adversary takes advantage of improper authentication to provide data or services under a falsified identity. The purpose of using the falsified identity may be to prevent traceability of the provided data or to assume the rights granted to another individual. One of the simplest forms of this attack would be the creation of an email message with a modified "From" field in order to appear that the message was sent from someone other than the actual sender. The root of the attack (in this case the email system) fails to properly authenticate the source and this results in the reader incorrectly performing the instructed action. Results of the attack vary depending on the details of the attack, but common results include privilege escalation, obfuscation of other attacks, and data corruption/manipulation.

## Related CWE (1)

- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html): When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Prerequisites

- This attack is only applicable when a vulnerable entity associates data or services with an identity. Without such an association, there would be no reason to fake the source.

## Consequences

- Integrity / Alter Execution Logic
- Integrity / Gain Privileges
- Integrity / Hide Activities

## Related pages

- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-287
- [CAPEC-57: Utilizing REST's Trust in the System Resource to Obtain Sensitive Data](/mitre/capec/CAPEC-57.md), also related to CWE-287
- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), also related to CWE-287
- [CAPEC-114: Authentication Abuse](/mitre/capec/CAPEC-114.md), also related to CWE-287
- [CAPEC-115: Authentication Bypass](/mitre/capec/CAPEC-115.md), also related to CWE-287
- [CAPEC-151: Identity Spoofing](/mitre/capec/CAPEC-151.md), also related to CWE-287
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
