# CAPEC-645 — Use of Captured Tickets (Pass The Ticket)

<a id="capec-645"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

An adversary uses stolen Kerberos tickets to access systems/resources that leverage the Kerberos authentication protocol. The Kerberos authentication protocol centers around a ticketing system which is used to request/grant access to services and to then access the requested services. An adversary can obtain any one of these tickets (e.g. Service Ticket, Ticket Granting Ticket, Silver Ticket, or G

## Mapped ATT&CK techniques (1)

- [T1550.003](/mitre/techniques/T1550-003.md)

## Related CWE (3)

[CWE-522](/CWE_REFERENCE.md) [CWE-294](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary needs physical access to the victim system.::The use of a third-party credential harvesting tool.::

**Skills required:** ::SKILL:Determine if Kerberos authentication is used on the server.:LEVEL:Low::SKILL:The adversary uses a third-party tool to obtain the necessary tic

**Mitigations:** ::Reset the built-in KRBTGT account password twice to invalidate the existence of any current Golden Tickets and any tickets derived from them.::Monitor system and domain logs for abnormal access.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
