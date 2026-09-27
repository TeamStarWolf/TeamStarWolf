# CAPEC-654 — Credential Prompt Impersonation

<a id="capec-654"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An adversary, through a previously installed malicious application, impersonates a credential prompt in an attempt to steal a user's credentials.

## Mapped ATT&CK techniques (2)

- [T1056](/mitre/techniques/T1056.md)
- [T1548.004](/mitre/techniques/T1548-004.md)

## Related CWE (1)

[CWE-1021](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary must already have access to the target system via some means.::A legitimate task must exist that an adversary can impersonate to glean credentials.::

**Skills required:** ::SKILL:Once an adversary has gained access to the target system, impersonating a credential prompt is not difficult.:LEVEL:Low::

**Mitigations:** ::The only known mitigation to this attack is to avoid installing the malicious application on the device. However, to impersonate a running task the malicious application does need the GET_TASKS permission to be able to query the task list, and bein


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
