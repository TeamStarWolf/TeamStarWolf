# CAPEC-160 — Exploit Script-Based APIs

<a id="capec-160"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** 

Some APIs support scripting instructions as arguments. Methods that take scripted instructions (or references to scripted instructions) can be very flexible and powerful. However, if an attacker can specify the script that serves as input to these methods they can gain access to a great deal of functionality. For example, HTML pages support <script> tags that allow scripting languages to be embedd

## Related CWE (1)

[CWE-346](/CWE_REFERENCE.md)

**Prerequisites:** ::The target application must include the use of APIs that execute scripts.::The target application must allow the attacker to provide some or all of the arguments to one of these script interpretatio


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
