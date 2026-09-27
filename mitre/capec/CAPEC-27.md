# CAPEC-27 — Leveraging Race Conditions via Symbolic Links

<a id="capec-27"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

This attack leverages the use of symbolic links (Symlinks) in order to write to sensitive files. An attacker can create a Symlink link to a target file not otherwise accessible to them. When the privileged program tries to create a temporary file with the same name as the Symlink link, it will actually write to the target file pointed to by the attackers' Symlink link. If the attacker can insert m

## Related CWE (5)

[CWE-367](/CWE_REFERENCE.md) [CWE-61](/CWE_REFERENCE.md) [CWE-662](/CWE_REFERENCE.md) [CWE-689](/CWE_REFERENCE.md) [CWE-667](/CWE_REFERENCE.md)

**Prerequisites:** ::The attacker is able to create Symlink links on the target host.::Tainted data from the attacker is used and copied to temporary files.::The target host does insecure temporary file creation.::

**Skills required:** ::SKILL:This attack is sophisticated because the attacker has to overcome a few challenges such as creating symlinks on the target host during a preci

**Mitigations:** ::Use safe libraries when creating temporary files. For instance the standard library function mkstemp can be used to safely create temporary files. For shell scripts, the system utility mktemp does the same thing.::Access to the directories should b


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
