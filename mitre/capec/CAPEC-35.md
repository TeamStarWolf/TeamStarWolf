# CAPEC-35 — Leverage Executable Code in Non-Executable Files

<a id="capec-35"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

An attack of this type exploits a system's trust in configuration and resource files. When the executable loads the resource (such as an image file or configuration file) the attacker has modified the file to either execute malicious code directly or manipulate the target process (e.g. application server) to execute based on the malicious configuration parameters. Since systems are increasingly in

## Mapped ATT&CK techniques (3)

- [T1027.006 — HTML Smuggling](/mitre/techniques/T1027-006.md) — Adversaries may smuggle data and files past content filters by hiding malicious payloads inside of seemingly benign HTML files.
- [T1027.009 — Embedded Payloads](/mitre/techniques/T1027-009.md) — Adversaries may embed payloads within other files to conceal malicious content from defenses.
- [T1564.009 — Resource Forking](/mitre/techniques/T1564-009.md) — Adversaries may abuse resource forks to hide malicious code or executables to evade detection and bypass security applications.

## Related CWE (8)

- [CWE-94 — Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html) — The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or…
- [CWE-96 — Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html) — The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before inserting the input into an executable resource, such as a library, configuration file, or…
- [CWE-95 — Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html) — The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before using the input in a dynamic evaluation call (e.g.
- [CWE-97 — Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html) — The product generates a web page, but does not neutralize or incorrectly neutralizes user-controllable input that could be interpreted as a server-side include (SSI) directive.
- [CWE-272 — Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html) — The elevated privilege level required to perform operations such as chroot() should be dropped immediately after the operation is performed.
- [CWE-59 — Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html) — The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.
- [CWE-282 — Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html) — The product assigns the wrong ownership, or does not properly verify the ownership, of an object or resource.
- [CWE-270 — Privilege Context Switching Error](https://cwe.mitre.org/data/definitions/270.html) — The product does not properly manage privileges while it is switching between different contexts that have different privileges or spheres of control.

## Prerequisites

- The attacker must have the ability to modify non-executable files consumed by the target software.

## Skills required

- To identify and execute against an over-privileged system interface:LEVEL:Low

## Mitigations

- Design: Enforce principle of least privilege
- Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.
- Imple

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
