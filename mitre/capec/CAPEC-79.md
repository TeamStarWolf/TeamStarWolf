# CAPEC-79 — Using Slashes in Alternate Encoding

<a id="capec-79"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This attack targets the encoding of the Slash characters. An adversary would try to exploit common filtering problems related to the use of the slashes characters to gain access to resources on the target host. Directory-driven systems, such as file systems and databases, typically use the slash character to indicate traversal between directories or other container components. For murky historical

## Related CWE (11)

[CWE-173](/CWE_REFERENCE.md) [CWE-180](/CWE_REFERENCE.md) [CWE-181](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-73](/CWE_REFERENCE.md) [CWE-22](/CWE_REFERENCE.md) [CWE-185](/CWE_REFERENCE.md) [CWE-200](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md) [CWE-707](/CWE_REFERENCE.md)

**Prerequisites:** ::The application server accepts paths to locate resources.::The application server does insufficient input data validation on the resource path requested by the user.::The access right to resources a

**Skills required:** ::SKILL:An adversary can try variation of the slashes characters.:LEVEL:Low::SKILL:An adversary can use more sophisticated tool or script to scan a we

**Mitigations:** ::Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process. 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
