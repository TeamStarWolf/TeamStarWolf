# CAPEC-134: Email Injection

<a id="capec-134"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

An adversary manipulates the headers and content of an email message by injecting data via the use of delimiter characters native to the protocol.

## Related CWE (1)

- [CWE-150: Improper Neutralization of Escape, Meta, or Control Sequences](https://cwe.mitre.org/data/definitions/150.html): The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could be interpreted as escape, meta, or control character sequences when they are sent to a downstream component.

## Prerequisites

- The target application must allow the user to send email to some recipient, to specify the content at least one header field in the message, and must fail to sanitize against the injection of command separators.
- The adversary must have the ability to access the target mail application.

## Related pages

- [CAPEC-41: Using Meta-characters in E-mail Headers to Inject Malicious Payloads](/mitre/capec/CAPEC-41.md), also related to CWE-150
- [CAPEC-81: Web Server Logs Tampering](/mitre/capec/CAPEC-81.md), also related to CWE-150
- [CAPEC-93: Log Injection-Tampering-Forging](/mitre/capec/CAPEC-93.md), also related to CWE-150
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
