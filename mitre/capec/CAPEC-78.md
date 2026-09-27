# CAPEC-78 — Using Escaped Slashes in Alternate Encoding

<a id="capec-78"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This attack targets the use of the backslash in alternate encoding. An adversary can provide a backslash as a leading character and causes a parser to believe that the next character is special. This is called an escape. By using that trick, the adversary tries to exploit alternate ways to encode the same character which leads to filter problems and opens avenues to attack.

## Related CWE (10)

[CWE-180](/CWE_REFERENCE.md) [CWE-181](/CWE_REFERENCE.md) [CWE-173](/CWE_REFERENCE.md) [CWE-172](/CWE_REFERENCE.md) [CWE-73](/CWE_REFERENCE.md) [CWE-22](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md) [CWE-707](/CWE_REFERENCE.md)

**Prerequisites:** ::The application accepts the backlash character as escape character.::The application server does incomplete input data decoding, filtering and validation.::

**Skills required:** ::SKILL:The adversary can naively try backslash character and discover that the target host uses it as escape character.:LEVEL:Low::SKILL:The adversar

**Mitigations:** ::Verify that the user-supplied data does not use backslash character to escape malicious characters.::Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. In


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
