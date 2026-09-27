# CAPEC-41 — Using Meta-characters in E-mail Headers to Inject Malicious Payloads

<a id="capec-41"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This type of attack involves an attacker leveraging meta-characters in email headers to inject improper behavior into email programs. Email software has become increasingly sophisticated and feature-rich. In addition, email applications are ubiquitous and connected directly to the Web making them ideal targets to launch and propagate attacks. As the user demand for new functionality in email appli

## Related CWE (3)

[CWE-150](/CWE_REFERENCE.md) [CWE-88](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::This attack targets most widely deployed feature rich email applications, including web based email programs.::

**Skills required:** ::SKILL:To distribute email:LEVEL:Low::

**Mitigations:** ::Design: Perform validation on email header data::Implementation: Implement email filtering solutions on mail server or on MTA, relay server.::Implementation: Mail servers that perform strict validation may catch these attacks, because metacharacter


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
