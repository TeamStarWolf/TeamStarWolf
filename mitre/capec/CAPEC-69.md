# CAPEC-69: Target Programs with Elevated Privileges

<a id="capec-69"></a>

Abstraction: Standard  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

This attack targets programs running with elevated privileges. The adversary tries to leverage a vulnerability in the running program and get arbitrary code to execute with elevated privileges.

## Related CWE (2)

- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html): The product performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses.
- [CWE-15: External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html): One or more system settings or configuration elements can be externally controlled by a user.

## Prerequisites

- The targeted program runs with elevated OS privileges.
- The targeted program accepts input data from the user or from another program.
- The targeted program is giving away information about itself. Before performing such attack, an eventual attacker may need to gather information about the services running on the host target. The more the host target is verbose about the services that are running (version number of application, etc.) the more information can be gather by an attacker.
- This attack often requires communicating with the host target services directly. For instance Telnet may be enough to communicate with the host target.

## Skills required

- [Low] An attacker can use a tool to scan and automatically launch an attack against known issues. A tool can also repeat a sequence of instructions and try to brute force the service on the host target, an example of that would be the flooding technique.
- [Medium] More advanced attack may require knowledge of the protocol spoken by the host service.

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges
- Availability / Resource Consumption

## Mitigations

- Apply the principle of least privilege.
- Validate all untrusted data.
- Apply the latest patches.
- Scan your services and disable the ones which are not needed and are exposed unnecessarily. Exposing programs increases the attack surface. Only expose the services which are needed and have security mechanisms such as authentication built around them.
- Avoid revealing information about your system (e.g., version of the program) to anonymous users.
- Make sure that your program or service fail safely. What happen if the communication protocol is interrupted suddenly? What happen if a parameter is missing? Does your system have resistance and resilience to attack? Fail safely when a resource exhaustion occurs.
- If possible use a sandbox model which limits the actions that programs can take. A sandbox restricts a program to a set of privileges and commands that make it difficult or impossible for the program to cause any damage.
- Check your program for buffer overflow and format String vulnerabilities which can lead to execution of malicious code.
- Monitor traffic and resource usage and pay attention if resource exhaustion occurs.
- Protect your log file from unauthorized modification and log forging.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
