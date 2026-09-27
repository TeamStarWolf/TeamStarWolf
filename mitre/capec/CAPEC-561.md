# CAPEC-561 — Windows Admin Shares with Stolen Credentials

<a id="capec-561"></a>

**Abstraction:** Detailed  
**Typical severity:**   
**Likelihood:** 

An adversary guesses or obtains (i.e. steals or purchases) legitimate Windows administrator credentials (e.g. userID/password) to access Windows Admin Shares on a local machine or within a Windows domain.

## Mapped ATT&CK techniques (1)

- [T1021.002](/mitre/techniques/T1021-002.md)

## Related CWE (7)

[CWE-522](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md) [CWE-309](/CWE_REFERENCE.md) [CWE-294](/CWE_REFERENCE.md) [CWE-263](/CWE_REFERENCE.md) [CWE-262](/CWE_REFERENCE.md) [CWE-521](/CWE_REFERENCE.md)

**Prerequisites:** ::The system/application is connected to the Windows domain.::The target administrative share allows remote use of local admin credentials to log into domain systems.::The adversary possesses a list o

**Skills required:** ::SKILL:Once an adversary obtains a known Windows credential, leveraging it is trivial.:LEVEL:Low::

**Mitigations:** ::Do not reuse local administrator account credentials across systems.::Deny remote use of local admin credentials to log into domain systems.::Do not allow accounts to be a local administrator on more than one system.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
