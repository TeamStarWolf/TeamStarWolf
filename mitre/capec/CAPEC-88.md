# CAPEC-88 — OS Command Injection

<a id="capec-88"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

In this type of an attack, an adversary injects operating system commands into existing application functions. An application that uses untrusted input to build command strings is vulnerable. An adversary can leverage OS command injection in an application to elevate privileges, execute arbitrary commands and compromise the underlying operating system.

## Related CWE (4)

[CWE-78](/CWE_REFERENCE.md) [CWE-88](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::User controllable input used as part of commands to the underlying operating system.::

**Skills required:** ::SKILL:The attacker needs to have knowledge of not only the application to exploit but also the exact nature of commands that pertain to the target o

**Mitigations:** ::Use language APIs rather than relying on passing data to the operating system shell or command line. Doing so ensures that the available protection mechanisms in the language are intact and applicable.::Filter all incoming data to escape or remove 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
