# CAPEC-469 — HTTP DoS

<a id="capec-469"></a>

**Abstraction:** Standard  
**Typical severity:** Low  
**Likelihood:** 

An attacker performs flooding at the HTTP level to bring down only a particular web application rather than anything listening on a TCP/IP connection. This denial of service attack requires substantially fewer packets to be sent which makes DoS harder to detect. This is an equivalent of SYN flood in HTTP. The idea is to keep the HTTP session alive indefinitely and then repeat that hundreds of time

## Mapped ATT&CK techniques (1)

- [T1499.002](/mitre/techniques/T1499-002.md)

## Related CWE (2)

[CWE-770](/CWE_REFERENCE.md) [CWE-772](/CWE_REFERENCE.md)

**Prerequisites:** ::HTTP protocol is usedWeb server used is vulnerable to denial of service via HTTP flooding::

**Mitigations:** ::Configuration: Configure web server software to limit the waiting period on opened HTTP sessions::Design: Use load balancing mechanisms::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
