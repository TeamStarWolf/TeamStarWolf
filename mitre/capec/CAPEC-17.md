# CAPEC-17: Using Malicious Files

<a id="capec-17"></a>

Abstraction: Standard  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

An attack of this type exploits a system's configuration that allows an adversary to either directly access an executable file, for example through shell access; or in a possible worst case allows an adversary to upload a file and then execute it. Web servers, ftp servers, and message oriented middleware systems which have many integration points are particularly vulnerable, because both the programmers and the administrators must be in synch regarding the interfaces and the correct privileges for each interface.

## Mapped ATT&CK techniques (2)

- [T1574.005: Executable Installer File Permissions Weakness](/mitre/techniques/T1574-005.md): Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer.
- [T1574.010: Services File Permissions Weakness](/mitre/techniques/T1574-010.md): Adversaries may execute their own malicious payloads by hijacking the binaries used by services.

## Related CWE (7)

- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html): The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html): The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-272: Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html): The elevated privilege level required to perform operations such as chroot() should be dropped immediately after the operation is performed.
- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html): The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.
- [CWE-282: Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html): The product assigns the wrong ownership, or does not properly verify the ownership, of an object or resource.
- [CWE-270: Privilege Context Switching Error](https://cwe.mitre.org/data/definitions/270.html): The product does not properly manage privileges while it is switching between different contexts that have different privileges or spheres of control.
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html): The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Prerequisites

- System's configuration must allow an attacker to directly access executable files or upload files to execute. This means that any access control system that is supposed to mediate communications between the subject and the object is set incorrectly or assumes a benign environment.

## Skills required

- [Low] To identify and execute against an over-privileged system interface

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Integrity / Modify Data
- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Design: Enforce principle of least privilege
- Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.
- Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

## Related pages

- [CAPEC-35: Leverage Executable Code in Non-Executable Files](/mitre/capec/CAPEC-35.md), also related to CWE-59, CWE-270 and 2 more
- [CAPEC-76: Manipulating Web Input to File System Calls](/mitre/capec/CAPEC-76.md), also related to CWE-59, CWE-272 and 1 more
- [CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs](/mitre/capec/CAPEC-1.md), also related to CWE-285, CWE-693 and 1 more
- [CAPEC-127: Directory Indexing](/mitre/capec/CAPEC-127.md), also related to CWE-285, CWE-693 and 1 more
- [CAPEC-60: Reusing Session IDs (aka Session Replay)](/mitre/capec/CAPEC-60.md), also related to CWE-285 and CWE-732
- [CAPEC-51: Poison Web Service Registry](/mitre/capec/CAPEC-51.md), also related to CWE-285 and CWE-693
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/IVANTI_CONNECT_SECURE_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
