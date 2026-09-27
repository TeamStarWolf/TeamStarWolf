# CAPEC-45 — Buffer Overflow via Symbolic Links

<a id="capec-45"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This type of attack leverages the use of symbolic links to cause buffer overflows. An adversary can try to create or manipulate a symbolic link file such that its contents result in out of bounds data. When the target software processes the symbolic link file, it could potentially overflow internal buffers with insufficient bounds checking.

## Related CWE (9)

[CWE-120](/CWE_REFERENCE.md) [CWE-285](/CWE_REFERENCE.md) [CWE-302](/CWE_REFERENCE.md) [CWE-118](/CWE_REFERENCE.md) [CWE-119](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-680](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary can create symbolic link on the target host.::The target host does not perform correct boundary checking while consuming data from a resources.::

**Skills required:** ::SKILL:An adversary can simply overflow a buffer by inserting a long string into an adversary-modifiable injection vector. The result can be a DoS.:L

**Mitigations:** ::Pay attention to the fact that the resource you read from can be a replaced by a Symbolic link. You can do a Symlink check before reading the file and decide that this is not a legitimate way of accessing the resource.::Because Symlink can be modif


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
