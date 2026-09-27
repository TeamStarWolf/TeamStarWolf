# CAPEC-383 — Harvesting Information via API Event Monitoring

<a id="capec-383"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** 

An adversary hosts an event within an application framework and then monitors the data exchanged during the course of the event for the purpose of harvesting any important data leaked during the transactions. One example could be harvesting lists of usernames or userIDs for the purpose of sending spam messages to those users. One example of this type of attack involves the adversary creating an ev

## Mapped ATT&CK techniques (1)

- [T1056.004](/mitre/techniques/T1056-004.md)

## Related CWE (4)

[CWE-311](/CWE_REFERENCE.md) [CWE-319](/CWE_REFERENCE.md) [CWE-419](/CWE_REFERENCE.md) [CWE-602](/CWE_REFERENCE.md)

**Prerequisites:** ::The target software is utilizing application framework APIs::

**Mitigations:** ::Leverage encryption techniques during information transactions so as to protect them from attack patterns of this kind.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
