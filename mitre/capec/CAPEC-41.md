# CAPEC-41: Using Meta-characters in E-mail Headers to Inject Malicious Payloads

<a id="capec-41"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

This type of attack involves an attacker leveraging meta-characters in email headers to inject improper behavior into email programs. Email software has become increasingly sophisticated and feature-rich. In addition, email applications are ubiquitous and connected directly to the Web making them ideal targets to launch and propagate attacks. As the user demand for new functionality in email applications grows, they become more like browsers with complex rendering and plug in routines. As more email functionality is included and abstracted from the user, this creates opportunities for attackers. Virtually all email applications do not list email header information by default, however the email header contains valuable attacker vectors for the attacker to exploit particularly if the behavior of the email client application is known. Meta-characters are hidden from the user, but can contain scripts, enumerations, probes, and other attacks against the user's system.

## Related CWE (3)

- [CWE-150: Improper Neutralization of Escape, Meta, or Control Sequences](https://cwe.mitre.org/data/definitions/150.html): The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could be interpreted as escape, meta, or control character sequences when they are sent to a downstream component.
- [CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html): The product constructs a string for a command to be executed by a separate component in another control sphere, but it does not properly delimit the intended arguments, options, or switches within that command string.
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html): The product compares two entities in a security-relevant context, but the comparison is incorrect.

## Prerequisites

- This attack targets most widely deployed feature rich email applications, including web based email programs.

## Skills required

- [Low] To distribute email

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- Design: Perform validation on email header data
- Implementation: Implement email filtering solutions on mail server or on MTA, relay server.
- Implementation: Mail servers that perform strict validation may catch these attacks, because metacharacters are not allowed in many header variables such as dns names

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
