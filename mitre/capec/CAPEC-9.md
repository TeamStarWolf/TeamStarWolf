# CAPEC-9 — Buffer Overflow in Local Command-Line Utilities

<a id="capec-9"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This attack targets command-line utilities available in a number of shells. An adversary can leverage a vulnerability found in a command-line utility to escalate privilege to root.

## Related CWE (8)

[CWE-120](/CWE_REFERENCE.md) [CWE-118](/CWE_REFERENCE.md) [CWE-119](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-680](/CWE_REFERENCE.md) [CWE-733](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::The target host exposes a command-line utility to the user.::The command-line utility exposed by the target host has a buffer overflow vulnerability that can be exploited.::

**Skills required:** ::SKILL:An adversary can simply overflow a buffer by inserting a long string into an adversary-modifiable injection vector. The result can be a DoS.:L

**Mitigations:** ::Carefully review the service's implementation before making it available to user. For instance you can use manual or automated code review to uncover vulnerabilities such as buffer overflow.::Use a language or compiler that performs automatic bound


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
