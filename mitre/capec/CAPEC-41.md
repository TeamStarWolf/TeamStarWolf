# CAPEC-41 — Using Meta-characters in E-mail Headers to Inject Malicious Payloads

<a id="capec-41"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This type of attack involves an attacker leveraging meta-characters in email headers to inject improper behavior into email programs. Email software has become increasingly sophisticated and feature-rich. In addition, email applications are ubiquitous and connected directly to the Web making them ideal targets to launch and propagate attacks. As the user demand for new functionality in email appli

## Related CWE (3)

- [CWE-150 — Improper Neutralization of Escape, Meta, or Control Sequences](https://cwe.mitre.org/data/definitions/150.html)
- [CWE-88 — Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)

## Prerequisites

- This attack targets most widely deployed feature rich email applications, including web based email programs.

## Skills required

- To distribute email:LEVEL:Low

## Mitigations

- Design: Perform validation on email header data
- Implementation: Implement email filtering solutions on mail server or on MTA, relay server.
- Implementation: Mail servers that perform strict validation may catch these attacks, because metacharacter

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
