# CAPEC-181 — Flash File Overlay

<a id="capec-181"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An attacker creates a transparent overlay using flash in order to intercept user actions for the purpose of performing a clickjacking attack. In this technique, the Flash file provides a transparent overlay over HTML content. Because the Flash application is on top of the content, user actions, such as clicks, are caught by the Flash application rather than the underlying HTML. The action is then

## Related CWE (1)

[CWE-1021](/CWE_REFERENCE.md)

**Prerequisites:** ::The victim must be tricked into navigating to the attackers' decoy site and performing the actions on the decoy page.::The victim's browser must support invisible Flash overlays.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
