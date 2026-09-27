# CAPEC-540 — Overread Buffers

<a id="capec-540"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary attacks a target by providing input that causes an application to read beyond the boundary of a defined buffer. This typically occurs when a value influencing where to start or stop reading is set to reflect positions outside of the valid memory location of the buffer. This type of attack may result in exposure of sensitive information, a system crash, or arbitrary code execution.

## Related CWE (1)

- [CWE-125 — Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)

## Prerequisites

- For this type of attack to be successful, a few prerequisites must be met. First, the targeted software must be written in a language that enables fine grained buffer control. (e.g., c, c++) Second,

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
