# CAPEC-71 — Using Unicode Encoding to Bypass Validation Logic

<a id="capec-71"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An attacker may provide a Unicode string to a system component that is not Unicode aware and use that to circumvent the filter or cause the classifying mechanism to fail to properly understanding the request. That may allow the attacker to slip malicious data past the content filter and/or possibly cause the application to route the request incorrectly.

## Related CWE (11)

[CWE-176](/CWE_REFERENCE.md) [CWE-179](/CWE_REFERENCE.md) [CWE-180](/CWE_REFERENCE.md) [CWE-173](/CWE_REFERENCE.md) [CWE-172](/CWE_REFERENCE.md) [CWE-184](/CWE_REFERENCE.md) [CWE-183](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md) [CWE-692](/CWE_REFERENCE.md)

**Prerequisites:** ::Filtering is performed on data that has not be properly canonicalized.::

**Skills required:** ::SKILL:An attacker needs to understand Unicode encodings and have an idea (or be able to find out) what system components may not be Unicode aware.:L

**Mitigations:** ::Ensure that the system is Unicode aware and can properly process Unicode data. Do not make an assumption that data will be in ASCII.::Ensure that filtering or input validation is applied to canonical data.::Assume all input is malicious. Create an 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
