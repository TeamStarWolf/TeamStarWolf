# CAPEC-73 — User-Controlled Filename

<a id="capec-73"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

An attack of this type involves an adversary inserting malicious characters (such as a XSS redirection) into a filename, directly or indirectly that is then used by the target software to generate HTML text or other potentially executable content. Many websites rely on user-generated content and dynamically build resources like files, filenames, and URL links directly from user supplied data. In t

## Related CWE (8)

[CWE-20](/CWE_REFERENCE.md) [CWE-184](/CWE_REFERENCE.md) [CWE-96](/CWE_REFERENCE.md) [CWE-348](/CWE_REFERENCE.md) [CWE-116](/CWE_REFERENCE.md) [CWE-350](/CWE_REFERENCE.md) [CWE-86](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::The victim must trust the name and locale of user controlled filenames.::

**Skills required:** ::SKILL:To achieve a redirection and use of less trusted source, an attacker can simply edit data that the host uses to build the filename:LEVEL:Low::

**Mitigations:** ::Design: Use browser technologies that do not allow client side scripting.::Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.::Implementation: Perform input validation for all re


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
