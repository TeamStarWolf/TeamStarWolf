# CAPEC-65 — Sniff Application Code

<a id="capec-65"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

An adversary passively sniffs network communications and captures application code bound for an authorized client. Once obtained, they can use it as-is, or through reverse-engineering glean sensitive information or exploit the trust relationship between the client and server. Such code may belong to a dynamic update to the client, a patch being applied to a client component or any such interaction

## Mapped ATT&CK techniques (1)

- [T1040](/mitre/techniques/T1040.md)

## Related CWE (4)

[CWE-319](/CWE_REFERENCE.md) [CWE-311](/CWE_REFERENCE.md) [CWE-318](/CWE_REFERENCE.md) [CWE-693](/CWE_REFERENCE.md)

**Prerequisites:** ::The attacker must have the ability to place themself in the communication path between the client and server.::The targeted application must receive some application code from the server; for exampl

**Skills required:** ::SKILL:The attacker needs to setup a sniffer for a sufficient period of time so as to capture meaningful quantities of code. The presence of the snif

**Mitigations:** ::Design: Encrypt all communication between the client and server.::Implementation: Use SSL, SSH, SCP.::Operation: Use ifconfig/ipconfig or other tools to detect the sniffer installed in the network.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
