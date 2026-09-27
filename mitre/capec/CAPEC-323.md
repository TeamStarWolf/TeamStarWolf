# CAPEC-323 — TCP (ISN) Counter Rate Probe

<a id="capec-323"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Medium

This OS detection probe measures the average rate of initial sequence number increments during a period of time. Sequence numbers are incremented using a time-based algorithm and are susceptible to a timing analysis that can determine the number of increments per unit time. The result of this analysis is then compared against a database of operating systems and versions to determine likely operati

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)

**Prerequisites:** ::The ability to monitor and interact with network communications.Access to at least one host, and the privileges to interface with the network interface card.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
