# CAPEC-60 — Reusing Session IDs (aka Session Replay)

<a id="capec-60"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This attack targets the reuse of valid session ID to spoof the target system in order to gain privileges. The attacker tries to reuse a stolen session ID used previously during a transaction to perform spoofing and session hijacking. Another name for this type of attack is Session Replay.

## Mapped ATT&CK techniques (2)

- [T1134.001](/mitre/techniques/T1134-001.md)
- [T1550.004](/mitre/techniques/T1550-004.md)

## Related CWE (10)

[CWE-294](/CWE_REFERENCE.md) [CWE-290](/CWE_REFERENCE.md) [CWE-346](/CWE_REFERENCE.md) [CWE-384](/CWE_REFERENCE.md) [CWE-488](/CWE_REFERENCE.md) [CWE-539](/CWE_REFERENCE.md) [CWE-200](/CWE_REFERENCE.md) [CWE-285](/CWE_REFERENCE.md) [CWE-664](/CWE_REFERENCE.md) [CWE-732](/CWE_REFERENCE.md)

**Prerequisites:** ::The target host uses session IDs to keep track of the users.::Session IDs are used to control access to resources.::The session IDs used by the target host are not well protected from session theft.

**Skills required:** ::SKILL:If an attacker can steal a valid session ID, they can then try to be authenticated with that stolen session ID.:LEVEL:Low::SKILL:More sophisti

**Mitigations:** ::Always invalidate a session ID after the user logout.::Setup a session time out for the session IDs.::Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate adversary in the middle attacks (


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
