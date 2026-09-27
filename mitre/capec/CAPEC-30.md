# CAPEC-30 — Hijacking a Privileged Thread of Execution

<a id="capec-30"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** Low

An adversary hijacks a privileged thread of execution by injecting malicious code into a running process. By using a privleged thread to do their bidding, adversaries can evade process-based detection that would stop an attack that creates a new process. This can lead to an adversary gaining access to the process's memory and can also enable elevated privileges. The most common way to perform this

## Mapped ATT&CK techniques (1)

- [T1055.003](/mitre/techniques/T1055-003.md)

## Related CWE (1)

[CWE-270](/CWE_REFERENCE.md)

**Prerequisites:** ::The application in question employs a threaded model of execution with the threads operating at, or having the ability to switch to, a higher privilege level than normal users::In order to feasibly 

**Skills required:** ::SKILL:Hijacking a thread involves knowledge of how processes and threads function on the target platform, the design of the target application as we

**Mitigations:** ::Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.::Application Architects must be careful to d


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
