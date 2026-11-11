# CAPEC-35: Leverage Executable Code in Non-Executable Files

<a id="capec-35"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

An attack of this type exploits a system's trust in configuration and resource files. When the executable loads the resource (such as an image file or configuration file) the attacker has modified the file to either execute malicious code directly or manipulate the target process (e.g. application server) to execute based on the malicious configuration parameters. Since systems are increasingly interrelated mashing up resources from local and remote sources the possibility of this attack occurring is high.

## Mapped ATT&CK techniques (3)

- [T1027.006: HTML Smuggling](/mitre/techniques/T1027-006.md): Adversaries may smuggle data and files past content filters by hiding malicious payloads inside of seemingly benign HTML files.
- [T1027.009: Embedded Payloads](/mitre/techniques/T1027-009.md): Adversaries may embed payloads within other files to conceal malicious content from defenses.
- [T1564.009: Resource Forking](/mitre/techniques/T1564-009.md): Adversaries may abuse resource forks to hide malicious code or executables to evade detection and bypass security applications.

## Related CWE (8)

- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html): The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.
- [CWE-96: Improper Neutralization of Directives in Statically Saved Code](https://cwe.mitre.org/data/definitions/96.html): The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before inserting the input into an executable resource, such as a library, configuration file, or template.
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code](https://cwe.mitre.org/data/definitions/95.html): The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before using the input in a dynamic evaluation call (e.g. "eval").
- [CWE-97: Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html): The product generates a web page, but does not neutralize or incorrectly neutralizes user-controllable input that could be interpreted as a server-side include (SSI) directive.
- [CWE-272: Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html): The elevated privilege level required to perform operations such as chroot() should be dropped immediately after the operation is performed.
- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html): The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.
- [CWE-282: Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html): The product assigns the wrong ownership, or does not properly verify the ownership, of an object or resource.
- [CWE-270: Privilege Context Switching Error](https://cwe.mitre.org/data/definitions/270.html): The product does not properly manage privileges while it is switching between different contexts that have different privileges or spheres of control.

## Prerequisites

- The attacker must have the ability to modify non-executable files consumed by the target software.

## Skills required

- [Low] To identify and execute against an over-privileged system interface

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Integrity / Modify Data
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Design: Enforce principle of least privilege
- Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.
- Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.
- Implementation: Implement host integrity monitoring to detect any unwanted altering of configuration files.
- Implementation: Ensure that files that are not required to execute, such as configuration files, are not over-privileged, i.e. not allowed to execute.

## Related pages

- [CAPEC-17: Using Malicious Files](/mitre/capec/CAPEC-17.md), also related to CWE-59, CWE-270 and 2 more
- [CAPEC-76: Manipulating Web Input to File System Calls](/mitre/capec/CAPEC-76.md), also related to CWE-59 and CWE-272
- [CAPEC-77: Manipulating User-Controlled Variables](/mitre/capec/CAPEC-77.md), also related to CWE-94 and CWE-96
- [CAPEC-101: Server Side Include (SSI) Injection](/mitre/capec/CAPEC-101.md), also related to CWE-97
- [CAPEC-30: Hijacking a Privileged Thread of Execution](/mitre/capec/CAPEC-30.md), also related to CWE-270
- [CAPEC-242: Code Injection](/mitre/capec/CAPEC-242.md), also related to CWE-94
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
