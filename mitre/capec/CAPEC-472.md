# CAPEC-472 — Browser Fingerprinting

<a id="capec-472"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** 

An attacker carefully crafts small snippets of Java Script to efficiently detect the type of browser the potential victim is using. Many web-based attacks need prior knowledge of the web browser including the version of browser to ensure successful exploitation of a vulnerability. Having this knowledge allows an attacker to target the victim with attacks that specifically exploit known or zero day

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)

**Prerequisites:** ::Victim's browser visits a website that contains attacker's Java ScriptJava Script is not disabled in the victim's browser::

**Mitigations:** ::Configuration: Disable Java Script in the browser::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
