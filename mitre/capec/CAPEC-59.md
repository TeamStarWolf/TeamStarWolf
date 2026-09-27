# CAPEC-59 — Session Credential Falsification through Prediction

<a id="capec-59"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This attack targets predictable session ID in order to gain privileges. The attacker can predict the session ID used during a transaction to perform spoofing and session hijacking.

## Related CWE (11)

[CWE-290](/CWE_REFERENCE.md) [CWE-330](/CWE_REFERENCE.md) [CWE-331](/CWE_REFERENCE.md) [CWE-346](/CWE_REFERENCE.md) [CWE-488](/CWE_REFERENCE.md) [CWE-539](/CWE_REFERENCE.md) [CWE-200](/CWE_REFERENCE.md) [CWE-6](/CWE_REFERENCE.md) [CWE-285](/CWE_REFERENCE.md) [CWE-384](/CWE_REFERENCE.md) [CWE-693](/CWE_REFERENCE.md)

**Prerequisites:** ::The target host uses session IDs to keep track of the users.::Session IDs are used to control access to resources.::The session IDs used by the target host are predictable. For example, the session 

**Skills required:** ::SKILL:There are tools to brute force session ID. Those tools require a low level of knowledge.:LEVEL:Low::SKILL:Predicting Session ID may require mo

**Mitigations:** ::Use a strong source of randomness to generate a session ID.::Use adequate length session IDs::Do not use information available to the user in order to generate session ID (e.g., time).::Ideas for creating random numbers are offered by Eastlake [RFC


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
