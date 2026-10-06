# CAPEC-30: Hijacking a Privileged Thread of Execution

<a id="capec-30"></a>

Abstraction: Standard  
Typical severity: Very High  
Likelihood: Low  
Status: Draft  

An adversary hijacks a privileged thread of execution by injecting malicious code into a running process. By using a privleged thread to do their bidding, adversaries can evade process-based detection that would stop an attack that creates a new process. This can lead to an adversary gaining access to the process's memory and can also enable elevated privileges. The most common way to perform this attack is by suspending an existing thread and manipulating its memory.

## Mapped ATT&CK techniques (1)

- [T1055.003: Thread Execution Hijacking](/mitre/techniques/T1055-003.md): Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges.

## Related CWE (1)

- [CWE-270: Privilege Context Switching Error](https://cwe.mitre.org/data/definitions/270.html): The product does not properly manage privileges while it is switching between different contexts that have different privileges or spheres of control.

## Prerequisites

- The application in question employs a threaded model of execution with the threads operating at, or having the ability to switch to, a higher privilege level than normal users
- In order to feasibly execute this class of attacks, the adversary must have the ability to hijack a privileged thread. This ability includes, but is not limited to, modifying environment variables that affect the process the thread belongs to, or calling native OS calls that can suspend and alter process memory. This does not preclude network-based attacks, but makes them conceptually more difficult to identify and execute.

## Skills required

- [High] Hijacking a thread involves knowledge of how processes and threads function on the target platform, the design of the target application as well as the ability to identify the primitives to be used or manipulated to hijack the thread.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.
- Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
