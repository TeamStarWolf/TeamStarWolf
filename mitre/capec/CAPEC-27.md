# CAPEC-27 — Leveraging Race Conditions via Symbolic Links

<a id="capec-27"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

This attack leverages the use of symbolic links (Symlinks) in order to write to sensitive files. An attacker can create a Symlink link to a target file not otherwise accessible to them. When the privileged program tries to create a temporary file with the same name as the Symlink link, it will actually write to the target file pointed to by the attackers' Symlink link. If the attacker can insert malicious content in the temporary file they will be writing to the sensitive file by using the Symlink. The race occurs because the system checks if the temporary file exists, then creates the file. The attacker would typically create the Symlink during the interval between the check and the creation of the temporary file.

## Related CWE (5)

- [CWE-367 — Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html) — The product checks the state of a resource before using that resource, but the resource's state can change between the check and the use in a way that invalidates the results of the check.
- [CWE-61 — UNIX Symbolic Link (Symlink) Following](https://cwe.mitre.org/data/definitions/61.html) — The product, when opening a file or directory, does not sufficiently account for when the file is a symbolic link that resolves to a target outside of the intended control sphere.
- [CWE-662 — Improper Synchronization](https://cwe.mitre.org/data/definitions/662.html) — The product utilizes multiple threads, processes, components, or systems to allow temporary access to a shared resource that can only be exclusive to one process at a time, but it does not properly synchronize these actions, which might cause simultaneous accesses of this resource by multiple threads or processes.
- [CWE-689 — Permission Race Condition During Resource Copy](https://cwe.mitre.org/data/definitions/689.html) — The product, while copying or cloning a resource, does not set the resource's permissions or access control until the copy is complete, leaving the resource exposed to other spheres while the copy is taking place.
- [CWE-667 — Improper Locking](https://cwe.mitre.org/data/definitions/667.html) — The product does not properly acquire or release a lock on a resource, leading to unexpected resource state changes and behaviors.

## Prerequisites

- The attacker is able to create Symlink links on the target host.
- Tainted data from the attacker is used and copied to temporary files.
- The target host does insecure temporary file creation.

## Skills required

- [Medium] This attack is sophisticated because the attacker has to overcome a few challenges such as creating symlinks on the target host during a precise timing, inserting malicious data in the temporary file and have knowledge about the temporary files created (file name and function which creates them).

## Consequences

- Integrity / Modify Data
- Confidentiality, Access Control, Authorization / Gain Privileges
- Availability / Resource Consumption

## Mitigations

- Use safe libraries when creating temporary files. For instance the standard library function mkstemp can be used to safely create temporary files. For shell scripts, the system utility mktemp does the same thing.
- Access to the directories should be restricted as to prevent attackers from manipulating the files. Denying access to a file can prevent an attacker from replacing that file with a link to a sensitive file.
- Follow the principle of least privilege when assigning access rights to files.
- Ensure good compartmentalization in the system to provide protected areas that can be trusted.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
