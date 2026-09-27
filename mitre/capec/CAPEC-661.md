# CAPEC-661 — Root/Jailbreak Detection Evasion via Debugging

<a id="capec-661"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium

An adversary inserts a debugger into the program entry point of a mobile application to modify the application binary, with the goal of evading Root/Jailbreak detection. Mobile device users often Root/Jailbreak their devices in order to gain administrative control over the mobile operating system and/or to install third-party mobile applications that are not provided by authorized application stor

## Related CWE (1)

[CWE-489](/CWE_REFERENCE.md)

**Prerequisites:** ::A debugger must be able to be inserted into the targeted application.::

**Skills required:** ::SKILL:Knowledge about Root/Jailbreak detection and evasion techniques.:LEVEL:High::SKILL:Knowledge about runtime debugging.:LEVEL:Medium::

**Mitigations:** ::Instantiate checks within the application code that ensures debuggers are not attached.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
