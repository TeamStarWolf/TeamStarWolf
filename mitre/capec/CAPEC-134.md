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

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
