# CAPEC-104 — Cross Zone Scripting

<a id="capec-104"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium

An attacker is able to cause a victim to load content into their web-browser that bypasses security zone controls and gain access to increased privileges to execute scripting code or other web objects such as unsigned ActiveX controls or applets. This is a privilege elevation attack targeted at zone-based web-browser security.

## Related CWE (5)

[CWE-250](/CWE_REFERENCE.md) [CWE-638](/CWE_REFERENCE.md) [CWE-285](/CWE_REFERENCE.md) [CWE-116](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must be using a zone-aware browser.::

**Skills required:** ::SKILL:Ability to craft malicious scripts or find them elsewhere and ability to identify functionality that is running web controls in the local zone

**Mitigations:** ::Disable script execution.::Ensure that sufficient input validation is performed for any potentially untrusted data before it is used in any privileged context or zone::Limit the flow of untrusted data into the privileged areas of the system that ru


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
