# CAPEC-212 — Functionality Misuse

<a id="capec-212"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** Medium

An adversary leverages a legitimate capability of an application in such a way as to achieve a negative technical impact. The system functionality is not altered or modified but used in a way that was not intended. This is often accomplished through the overuse of a specific functionality or by leveraging functionality with design flaws that enables the adversary to gain access to unauthorized, se

## Related CWE (3)

[CWE-1242](/CWE_REFERENCE.md) [CWE-1246](/CWE_REFERENCE.md) [CWE-1281](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary has the capability to interact with the application directly.The target system does not adequately implement safeguards to prevent misuse of authorized actions/processes.::

**Skills required:** ::SKILL:General computer knowledge about how applications are launched, how they interact with input/output, and how they are configured.:LEVEL:Low::

**Mitigations:** ::Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purpos


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
