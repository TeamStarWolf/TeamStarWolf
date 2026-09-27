# CAPEC-53 — Postfix, Null Terminate, and Backslash

<a id="capec-53"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

If a string is passed through a filter of some kind, then a terminal NULL may not be valid. Using alternate representation of NULL allows an adversary to embed the NULL mid-string while postfixing the proper data so that the filter is avoided. One example is a filter that looks for a trailing slash character. If a string insertion is possible, but the slash must exist, an alternate encoding of NUL

## Related CWE (7)

[CWE-158](/CWE_REFERENCE.md) [CWE-172](/CWE_REFERENCE.md) [CWE-173](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md) [CWE-707](/CWE_REFERENCE.md)

**Prerequisites:** ::Null terminators are not properly handled by the filter.::

**Skills required:** ::SKILL:An adversary needs to understand alternate encodings, what the filter looks for and the data format acceptable to the target API:LEVEL:Medium:

**Mitigations:** ::Properly handle Null characters. Make sure canonicalization is properly applied. Do not pass Null characters to the underlying APIs.::Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on th


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
