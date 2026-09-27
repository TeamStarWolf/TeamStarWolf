# CAPEC-80 — Using UTF-8 Encoding to Bypass Validation Logic

<a id="capec-80"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This attack is a specific variation on leveraging alternate encodings to bypass validation logic. This attack leverages the possibility to encode potentially harmful input in UTF-8 and submit it to applications not expecting or effective at validating this encoding standard making input filtering difficult. UTF-8 (8-bit UCS/Unicode Transformation Format) is a variable-length character encoding for

## Related CWE (9)

[CWE-173](/CWE_REFERENCE.md) [CWE-172](/CWE_REFERENCE.md) [CWE-180](/CWE_REFERENCE.md) [CWE-181](/CWE_REFERENCE.md) [CWE-73](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md) [CWE-692](/CWE_REFERENCE.md)

**Prerequisites:** ::The application's UTF-8 decoder accepts and interprets illegal UTF-8 characters or non-shortest format of UTF-8 encoding.::Input filtering and validating is not done properly leaving the door open t

**Skills required:** ::SKILL:An attacker can inject different representation of a filtered character in UTF-8 format.:LEVEL:Low::SKILL:An attacker may craft subtle encodin

**Mitigations:** ::The Unicode Consortium recognized multiple representations to be a problem and has revised the Unicode Standard to make multiple representations of the same code point with UTF-8 illegal. The UTF-8 Corrigendum lists the newly restricted UTF-8 range


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
